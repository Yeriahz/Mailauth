"""
mailauth/scoring.py - turns findings into a score, a risk band and a confidence
figure, using weights loaded entirely from configuration.

No weight is defined in this module. A finding code the config does not know
about raises at load time rather than scoring zero, because a silently
unweighted finding is how a scoring config rots without anyone noticing.

Confidence is deliberately not folded into the score. A gap we are unsure about
keeps its full weight and its low confidence, and both travel through to the
output, so a 70 built mostly from selector probes can be sorted apart from a 70
built from a missing DMARC record.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass, field, replace
from functools import cache
from pathlib import Path
from typing import Any

from .models import Confidence, DomainResult, Finding, Posture, ScoredFinding, Severity

DEFAULT_WEIGHTS_PATH = Path(__file__).with_name("weights.toml")

# A score cannot exceed this. Findings are not independent and adding enough of
# them would otherwise produce numbers that imply a precision the model does not
# have.
MAX_SCORE = 100


class WeightsError(ValueError):
    """Raised when a weights file is missing, malformed, or incomplete."""


@dataclass(frozen=True)
class Weight:
    weight: int
    confidence: Confidence
    rationale: str = ""


@dataclass(frozen=True)
class Weights:
    """A loaded, profile-resolved scoring configuration."""

    version: str
    schema_version: int
    profile: str
    entries: dict[str, Weight]
    risk_high: int = 60
    risk_medium: int = 30
    confidence_values: dict[Confidence, float] = field(
        default_factory=lambda: {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
        }
    )
    # Label boundaries for the aggregate confidence figure.
    label_high: float = 0.8
    label_medium: float = 0.5
    groups: dict[str, list[str]] = field(default_factory=dict)
    config_digest: str = ""
    algorithm_digest: str = ""
    profile_description: str = ""

    def group_cap(self, name: str) -> int:
        """Largest single member weight, which is what the group may total.

        Derived rather than configured: the members all assert the same fact, so
        the worst of them sets the price and the rest add nothing.
        """
        return max((self.get(code).weight for code in self.groups.get(name, [])), default=0)

    def area_stake(self, area: str) -> int:
        """The largest weight any single finding in this area can carry."""
        prefix = AREA_CODE_PREFIXES.get(area)
        if prefix is None:
            return 0
        return max(
            (e.weight for code, e in self.entries.items() if code.startswith(prefix)),
            default=0,
        )

    def area_ceiling(self, area: str) -> float:
        """Confidence ceiling for failing to observe this area, scaled by its stake.

        A flat ceiling read an unobserved BIMI lookup exactly like an unobserved
        DMARC one. BIMI's only finding is weight 0, so failing to read it costs
        the score nothing and must cost confidence nothing; DMARC drives the
        score and takes the full cap.

        Interpolates between no cap at all and the MEDIUM threshold, in
        proportion to how much the area could have contributed.

        A consequence worth knowing rather than rediscovering as a bug: because
        the scale is normalised by whichever area is heaviest, raising DMARC's
        weight loosens DKIM's ceiling even though DKIM's own informational stake
        has not changed. That is a deliberate accepted trade - the alternative is
        an absolute scale that would need its own hand-maintained maximum - but
        it does mean the ceilings move when any heavy weight moves.
        """
        stakes = {a: self.area_stake(a) for a in AREA_CODE_PREFIXES}
        heaviest = max(stakes.values(), default=0)
        if not heaviest:
            return 1.0
        share = stakes.get(area, 0) / heaviest
        # Algebraically the same as 1 - (1 - medium) * share, but exact at both
        # endpoints: the heaviest area returns label_medium itself rather than a
        # float a hair below it, which would tip the label to LOW at the boundary.
        return self.label_medium + (1.0 - self.label_medium) * (1.0 - share)

    @property
    def unobserved_ceiling(self) -> float:
        """Cap applied per unobserved area, derived from the MEDIUM threshold.

        Not a number of its own: one area we could not read should land the
        domain at MEDIUM, and the lowest figure that still earns MEDIUM is the
        MEDIUM threshold itself. See weights.toml.
        """
        return self.label_medium

    def confidence_label(self, value: float) -> Confidence:
        if value >= self.label_high:
            return Confidence.HIGH
        if value >= self.label_medium:
            return Confidence.MEDIUM
        return Confidence.LOW

    def get(self, code: str) -> Weight:
        try:
            return self.entries[code]
        except KeyError:
            raise WeightsError(
                f"finding code {code!r} has no entry in the weights file "
                f"({self.version}). Every code a check can emit must be weighted "
                f"explicitly, including with weight 0."
            ) from None

    def band(self, score: int) -> str:
        if score >= self.risk_high:
            return "high"
        if score >= self.risk_medium:
            return "medium"
        return "low"


# Which finding codes belong to each area the confidence cap can apply to. The
# area names match DomainResult.unobserved_areas.
AREA_CODE_PREFIXES: dict[str, str] = {
    "DMARC": "dmarc.",
    "DKIM": "dkim.",
    "MX": "mx.",
    "MTA-STS": "mtasts.",
    "TLS-RPT": "tlsrpt.",
    "BIMI": "bimi.",
}

DIGEST_LENGTH = 6
ALGORITHM_DIGEST_LENGTH = 4


def content_digest(
    profile: str,
    entries: dict[str, Weight],
    risk_high: int,
    risk_medium: int,
    confidence_values: dict[Confidence, float],
    label_high: float,
    label_medium: float,
    groups: dict[str, list[str]],
) -> str:
    """A short hash of everything in a weights file that affects a score.

    Derived rather than hand-maintained, because a version string someone has to
    remember to bump fails in exactly the case it exists to catch: a number
    edited and the bump forgotten. Two runs whose digests match were scored the
    same way; two that differ were not, and their scores are not comparable.

    Rationale text and comments are excluded on purpose. They carry no scoring
    meaning, and rewording one must not make a run look incomparable to its
    predecessor.
    """
    material = [
        f"profile={profile}",
        f"risk={risk_high},{risk_medium}",
        f"labels={label_high:.6f},{label_medium:.6f}",
        *(f"group:{n}={','.join(sorted(c))}" for n, c in sorted(groups.items())),
    ]
    material += [
        f"conf={level}:{confidence_values[level]:.6f}"
        for level in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)
    ]
    # Sorted so the digest depends on content rather than on file ordering.
    material += [
        f"{code}={entry.weight}:{entry.confidence}"
        for code, entry in sorted(entries.items())
    ]
    joined = "\n".join(material).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()[:DIGEST_LENGTH]


# ---------------------------------------------------------------------------
# the scoring-algorithm digest
# ---------------------------------------------------------------------------

# Why a behavioural fingerprint rather than a hash of this file's source.
#
# The content digest above covers the configuration. It is blind to a change in
# the algorithm that consumes it: a confidence ceiling, a compounding rule, an
# exclusive group. Each of those moves every score while leaving weights.toml
# byte-identical, so two runs either side would compare as though nothing had
# changed.
#
# Hashing the source of this module would catch those, and would also fire on
# every reworded comment and every reformatting pass. A signal that cries wolf
# on a docstring edit gets ignored within a week, which is worse than no signal.
#
# So the digest is taken from behaviour instead: score a fixed set of synthetic
# results against a fixed reference configuration and hash the outputs. It moves
# when scoring behaviour moves and stays put under refactoring. The reference
# config is defined here rather than read from weights.toml, so that the two
# digests stay independent axes - a weight edit must not look like an algorithm
# change.
#
# The tradeoff, stated plainly: this only detects changes the probes exercise.
# A new scoring behaviour that no probe touches is invisible to it.
#
# The mitigation is a test that traces which lines of score() the probes
# actually execute and fails if any are missed. That is a derived check rather
# than a list someone has to remember to update, so adding a branch without a
# probe fails the suite. It is line coverage, not path coverage: a new branch
# is caught, but a change in behaviour along an already-covered line that
# happens not to alter any probe's output is not. That residue is real and
# small, and is the price of not hashing source.

# FROZEN. These values are part of the algorithm digest's definition, so
# editing one moves the digest with no change in behaviour - a false positive
# on the axis that is supposed to mean "the tool scores differently".
#
# There is no way to make that impossible, so it is made loud instead: a test
# pins a hash of this table, and changing it fails the suite until someone
# updates the pin deliberately. The pin is hand-maintained, which is normally
# the thing to avoid, but its failure mode is a red suite rather than a silent
# wrong answer, and that is the difference that matters.
#
# Add a code here only when a probe needs one that does not exist yet.
_REFERENCE_ENTRIES: dict[str, Weight] = {
    "ref.heavy": Weight(weight=40, confidence=Confidence.HIGH),
    "ref.heavier": Weight(weight=45, confidence=Confidence.HIGH),
    # Deliberately outside ref.exclusive, so the cap probe can exceed
    # MAX_SCORE without the group cap clipping it first.
    "ref.bulk": Weight(weight=60, confidence=Confidence.HIGH),
    "ref.medium": Weight(weight=25, confidence=Confidence.MEDIUM),
    "ref.light": Weight(weight=15, confidence=Confidence.LOW),
    "ref.zero": Weight(weight=0, confidence=Confidence.HIGH),
    # Real per-area stakes, so the area-scaled confidence ceilings are
    # exercised by the probes rather than collapsing to "no cap".
    "dmarc.stake": Weight(weight=40, confidence=Confidence.HIGH),
    "dkim.stake": Weight(weight=20, confidence=Confidence.HIGH),
    "mx.stake": Weight(weight=15, confidence=Confidence.HIGH),
    "bimi.stake": Weight(weight=0, confidence=Confidence.HIGH),
    "dmarc.unreachable": Weight(weight=0, confidence=Confidence.LOW),
    "mx.unreachable": Weight(weight=0, confidence=Confidence.LOW),
}


def _reference_weights() -> Weights:
    """A fixed configuration, independent of weights.toml.

    Constructed directly rather than loaded, both to keep the algorithm digest
    independent of the shipped weights and to avoid recursing through
    load_weights while computing a digest for it.
    """
    return Weights(
        version="reference",
        schema_version=1,
        profile="reference",
        entries=dict(_REFERENCE_ENTRIES),
        risk_high=60,
        risk_medium=30,
        confidence_values={
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
        },
        label_high=0.8,
        label_medium=0.5,
        groups={"ref.exclusive": ["ref.heavy", "ref.medium", "ref.light"]},
    )


def _probe(*codes: str, posture: Posture = Posture.SENDING, **kwargs: Any) -> DomainResult:
    from .models import DkimResult, DmarcResult, ExtrasResult, SpfResult

    findings = [
        Finding(
            code=code,
            area="REF",
            severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            title=code,
        )
        for code in codes
    ]
    return DomainResult(
        domain="probe.invalid",
        resolver="reference",
        checked_at="1970-01-01T00:00:00+00:00",
        posture=posture,
        spf=SpfResult(findings=findings),
        dmarc=kwargs.get("dmarc", DmarcResult()),
        dkim=kwargs.get("dkim", DkimResult(selectors_tried=["a"])),
        extras=kwargs.get("extras", ExtrasResult()),
        error=kwargs.get("error"),
    )


def _build_probes() -> tuple[tuple[str, DomainResult], ...]:
    from .models import DkimResult, DmarcResult, ExtrasResult, QueryStatus, RecordProbe

    unreadable_dkim = DkimResult(
        selectors_tried=["a"], probe_failures=["a"], wildcard=False
    )
    return (
        ("sum", _probe("ref.heavy", "ref.medium")),
        # Must exceed MAX_SCORE or this probe does not exercise the cap at all.
        ("cap", _probe("ref.bulk", "ref.heavier")),
        ("duplicate", _probe("ref.heavy", "ref.heavy")),
        ("confidence-floor", _probe("ref.medium", "ref.light")),
        ("non-sending", _probe("ref.heavy", "ref.medium", posture=Posture.NON_SENDING)),
        ("errored", _probe("ref.heavy", error="the domain does not resolve")),
        # Nothing scored above zero, so the weighted mean has no denominator.
        ("no-contributing-findings", _probe("ref.zero")),
        ("unobserved-one", _probe("ref.heavy", dkim=unreadable_dkim)),
        # Each source of an unobserved area needs its own probe, or a change to
        # how that source is judged leaves every probe output identical and the
        # digest says "comparable" when the tool now scores differently.
        ("unobserved-wildcard", _probe("ref.heavy", dkim=DkimResult(wildcard=True))),
        (
            "unobserved-decisive-selector",
            _probe(
                "ref.heavy",
                dkim=DkimResult(
                    selectors_tried=["a", "b"],
                    probe_failures=["a"],
                    decisive_selectors=["a"],
                ),
            ),
        ),
        (
            "observed-partial-selector",
            _probe(
                "ref.heavy",
                dkim=DkimResult(
                    selectors_tried=["a", "b"],
                    probe_failures=["a"],
                    decisive_selectors=["a", "b"],
                ),
            ),
        ),
        ("unobserved-mx", _probe("ref.heavy", "mx.unreachable")),
        # Exclusive groups, all three arms:
        #   one member present, two present but within the cap because the
        #   heaviest member is absent, and two present that exceed it.
        ("group-single", _probe("ref.heavy", "ref.zero")),
        ("group-under-cap", _probe("ref.medium", "ref.light")),
        ("group-capped", _probe("ref.heavy", "ref.medium")),
        (
            "unobserved-supporting-record",
            _probe(
                "ref.heavy",
                extras=ExtrasResult(
                    tlsrpt=RecordProbe(name="_smtp._tls", status=QueryStatus.TIMEOUT)
                ),
            ),
        ),
        (
            "unobserved-two",
            _probe(
                "ref.heavy",
                "dmarc.unreachable",
                dkim=unreadable_dkim,
                dmarc=DmarcResult(),
            ),
        ),
    )


ALGORITHM_PROBES: tuple[tuple[str, DomainResult], ...] = _build_probes()


@cache
def algorithm_digest() -> str:
    """Fingerprint of scoring behaviour, derived by scoring fixed inputs."""
    reference = _reference_weights()
    material: list[str] = []
    for name, probe in ALGORITHM_PROBES:
        scored = score(probe, reference)
        material.append(
            f"{name}:{scored.score}:{scored.risk}:"
            f"{scored.confidence:.6f}:{scored.confidence_label}:"
            f"{scored.low_confidence_share:.6f}:"
            f"{','.join(scored.unobserved_areas)}"
        )
    joined = chr(10).join(material).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()[:ALGORITHM_DIGEST_LENGTH]


def _parse_entry(code: str, raw: Any, source: str) -> Weight:
    if not isinstance(raw, dict):
        raise WeightsError(f"{source}: entry for {code!r} is not a table")
    if "weight" not in raw:
        raise WeightsError(f"{source}: entry for {code!r} has no weight")
    try:
        weight = int(raw["weight"])
    except (TypeError, ValueError):
        raise WeightsError(f"{source}: weight for {code!r} is not a number") from None
    if weight < 0:
        raise WeightsError(f"{source}: weight for {code!r} is negative")

    confidence_raw = str(raw.get("confidence", "high")).lower()
    try:
        confidence = Confidence(confidence_raw)
    except ValueError:
        raise WeightsError(
            f"{source}: confidence for {code!r} is {confidence_raw!r}, "
            f"expected one of high, medium, low"
        ) from None

    return Weight(
        weight=weight,
        confidence=confidence,
        rationale=str(raw.get("rationale", "")).strip(),
    )


def load_weights(path: Path | None = None, profile: str = "default") -> Weights:
    """Load a weights file and resolve one profile over the base findings table."""
    path = path or DEFAULT_WEIGHTS_PATH
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise WeightsError(f"weights file not found: {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise WeightsError(f"{path} is not valid TOML: {exc}") from None

    schema_version = int(data.get("schema_version", 0))
    if schema_version != 1:
        raise WeightsError(
            f"{path} declares schema_version {schema_version}; this build "
            f"understands version 1"
        )

    base = data.get("findings")
    if not isinstance(base, dict) or not base:
        raise WeightsError(f"{path} has no [findings] table")

    entries = {code: _parse_entry(code, raw, str(path)) for code, raw in base.items()}

    version = str(data.get("weights_version", "unversioned"))
    description = ""

    if profile and profile != "default":
        profiles = data.get("profiles", {})
        if profile not in profiles:
            available = ", ".join(sorted(profiles)) or "none"
            raise WeightsError(
                f"unknown profile {profile!r}. Available profiles: {available}"
            )
        section = profiles[profile]
        description = str(section.get("description", "")).strip()
        overrides = section.get("findings", {})
        for code, raw in overrides.items():
            if code not in entries:
                raise WeightsError(
                    f"{path}: profile {profile!r} overrides {code!r}, which is not "
                    f"in the base [findings] table"
                )
            existing = entries[code]
            merged = dict(raw)
            merged.setdefault("confidence", str(existing.confidence))
            merged.setdefault("rationale", existing.rationale)
            entries[code] = _parse_entry(code, merged, f"{path} profile {profile}")
        version = f"{version}+{profile}"

    groups_raw = data.get("groups", {})
    groups: dict[str, list[str]] = {}
    for name, codes in groups_raw.items():
        members = [str(code) for code in codes]
        for code in members:
            if code not in entries:
                raise WeightsError(
                    f"{path}: group {name!r} names {code!r}, which is not in the "
                    f"base [findings] table"
                )
        groups[str(name)] = members

    risk = data.get("risk", {})
    confidence_table = data.get("confidence", {})
    confidence_values = {
        Confidence.HIGH: float(confidence_table.get("high", 1.0)),
        Confidence.MEDIUM: float(confidence_table.get("medium", 0.6)),
        Confidence.LOW: float(confidence_table.get("low", 0.3)),
    }
    risk_high = int(risk.get("high", 60))
    risk_medium = int(risk.get("medium", 30))
    labels = data.get("confidence_labels", {})
    label_high = float(labels.get("high", 0.8))
    label_medium = float(labels.get("medium", 0.5))

    algorithm = algorithm_digest()
    digest = content_digest(
        profile,
        entries,
        risk_high,
        risk_medium,
        confidence_values,
        label_high,
        label_medium,
        groups,
    )

    return Weights(
        version=f"{version}+{digest}.{algorithm}",
        schema_version=schema_version,
        profile=profile,
        entries=entries,
        risk_high=risk_high,
        risk_medium=risk_medium,
        confidence_values=confidence_values,
        label_high=label_high,
        label_medium=label_medium,
        groups=groups,
        config_digest=digest,
        algorithm_digest=algorithm,
        profile_description=description,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep the first finding per code.

    A check can legitimately raise the same code twice - two different SPF syntax
    errors, say - and both belong in the output. Only the first is scored, so a
    single underlying mistake cannot be charged for repeatedly.
    """
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.code in seen:
            continue
        seen.add(finding.code)
        unique.append(finding)
    return unique


def score(result: DomainResult, weights: Weights) -> DomainResult:
    """Score a checked domain, returning a copy with the score fields filled in.

    The confidence a finding is scored with comes from the finding itself when
    the check had a reason to lower it (an unreachable resolver, a provider whose
    selectors cannot be guessed), and from the config otherwise. The lower of the
    two always wins: configuration can never make a check more certain than the
    check itself was.
    """
    if result.error:
        return replace(
            result,
            scored=[],
            score=0,
            raw_score=0,
            risk="unknown",
            confidence=0.0,
            confidence_label=Confidence.LOW,
            low_confidence_share=0.0,
        )

    order = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
    scored: list[ScoredFinding] = []

    for finding in _dedupe(result.findings):
        entry = weights.get(finding.code)
        effective_confidence = min(
            finding.confidence, entry.confidence, key=lambda c: order[c]
        )
        scored.append(
            ScoredFinding(
                finding=replace(finding, confidence=effective_confidence),
                weight=entry.weight,
                rationale=entry.rationale,
            )
        )

    # Mutually exclusive groups: members all assert the same fact, so the
    # heaviest present member is charged and the rest are zeroed. They stay in
    # the list, at weight 0 with the reason recorded, so `explain` shows what was
    # observed and what it cost rather than quietly dropping findings.
    for name, members in weights.groups.items():
        present = [i for i in scored if i.finding.code in members and i.weight > 0]
        if len(present) < 2:
            continue
        cap = weights.group_cap(name)
        if sum(i.weight for i in present) <= cap:
            continue
        keeper = max(present, key=lambda i: i.weight)
        for index, item in enumerate(scored):
            if item in present and item is not keeper:
                scored[index] = replace(
                    item,
                    weight=0,
                    rationale=(
                        item.rationale
                        + " Not charged: capped by the "
                        + repr(name)
                        + " group, which is limited to the weight of its "
                        + "heaviest present member ("
                        + keeper.finding.code
                        + "). These codes all mean the same thing, so the "
                        + "domain is charged once for the fact rather than "
                        + "once per observation."
                    ).strip(),
                )

    raw_total = sum(item.weight for item in scored)
    total = min(MAX_SCORE, raw_total)

    # A non-sending domain is on its own track. Its gaps are real but they are
    # gaps in a lockdown, not in a live mail configuration. It gets no score at
    # all rather than a collapsed one: a number invites comparison with sending
    # domains, and that comparison is meaningless. raw_score still orders within
    # the track.
    display_total: int | None = total
    risk = weights.band(total)
    if result.posture == Posture.NON_SENDING:
        display_total = None
        risk = "non-sending"

    contributing = [item for item in scored if item.weight > 0]
    weighted_total = sum(item.weight for item in contributing)
    if weighted_total:
        confidence_value = (
            sum(
                item.weight * weights.confidence_values[item.finding.confidence]
                for item in contributing
            )
            / weighted_total
        )
        low_share = (
            sum(
                item.weight
                for item in contributing
                if item.finding.confidence == Confidence.LOW
            )
            / weighted_total
        )
    else:
        confidence_value = 1.0
        low_share = 0.0

    # Cap for anything this run could not observe. An unreachable finding is
    # weight 0, so it never reaches the weighted mean above and cannot lower the
    # figure on its own. Without this, a domain whose DMARC lookup timed out
    # reported the same confidence as one whose DMARC was read cleanly.
    #
    # Compounded per area rather than applied once: two unknowns are strictly
    # worse than one, and reading them identically would repeat the mistake this
    # cap exists to fix, one level up.
    if result.unobserved_areas:
        ceiling = 1.0
        for area in result.unobserved_areas:
            ceiling *= weights.area_ceiling(area)
        confidence_value = min(confidence_value, ceiling)

    label = weights.confidence_label(confidence_value)

    return replace(
        result,
        scored=sorted(scored, key=lambda item: item.weight, reverse=True),
        score=display_total,
        raw_score=raw_total,
        risk=risk,
        confidence=confidence_value,
        confidence_label=label,
        low_confidence_share=low_share,
    )


def explain(result: DomainResult) -> list[str]:
    """Render the score as an auditable line-by-line breakdown."""
    lines: list[str] = [f"{result.domain}: {result.score}/100 ({result.risk})"]
    running = 0
    for item in result.scored:
        if item.weight == 0:
            continue
        running += item.weight
        lines.append(
            f"  +{item.weight:<3} {item.finding.code:<34} "
            f"[{item.finding.confidence}] running total {min(running, MAX_SCORE)}"
        )
    if running > MAX_SCORE:
        lines.append(f"  capped at {MAX_SCORE} (raw total {running})")
    if result.posture == Posture.NON_SENDING:
        lines.append("  scored on the non-sending track: this domain receives no mail")
    lines.append(
        f"  aggregate confidence {result.confidence:.2f} "
        f"({result.confidence_label}), "
        f"{result.low_confidence_share:.0%} of the score is low confidence"
    )
    return lines
