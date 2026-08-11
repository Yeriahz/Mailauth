"""
tests/test_scoring.py - the weights loader, the score, and the confidence model.

The most valuable test here is test_every_emittable_code_is_weighted: it walks
the source for every finding code the checks can produce and asserts the shipped
weights file knows about all of them. That is what stops a new check silently
scoring zero.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from mailauth.engine import check_domain
from mailauth.models import (
    Confidence,
    DomainResult,
    Finding,
    Posture,
    Severity,
    SpfResult,
)
from mailauth.scoring import (
    MAX_SCORE,
    Weights,
    WeightsError,
    explain,
    load_weights,
    score,
)
from tests.conftest import FakeResolver

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "mailauth"


def make_result(*findings: Finding, posture: Posture = Posture.SENDING) -> DomainResult:
    """A minimal result carrying the given findings, for scoring in isolation."""
    return DomainResult(
        domain="x.test",
        resolver="fake",
        checked_at="2026-08-09T00:00:00+00:00",
        posture=posture,
        spf=SpfResult(findings=list(findings)),
    )


def finding(code: str, confidence: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        code=code,
        area="SPF",
        severity=Severity.WARNING,
        confidence=confidence,
        title=code,
    )


# ---------------------------------------------------------------------------
# the loader
# ---------------------------------------------------------------------------


def test_shipped_weights_file_loads(weights: Weights) -> None:
    assert weights.schema_version == 1
    assert weights.version
    assert weights.entries


def test_every_emittable_code_is_weighted(weights: Weights) -> None:
    """Every finding code in the source must have an entry in the weights file.

    Without this, adding a check and forgetting to weight it produces a finding
    worth zero points that nobody notices.
    """
    pattern = re.compile(
        r'"((?:spf|dmarc|dkim|mx|dns|tlsrpt|mtasts|bimi|dnssec|combo)\.[a-z0-9_]+)"'
    )
    # Only the modules that emit findings. scoring.py contains the algorithm
    # digest's reference fixtures, which are deliberately not real finding codes.
    sources = [*(PACKAGE_ROOT / "checks").glob("*.py"), PACKAGE_ROOT / "engine.py"]
    codes: set[str] = set()
    for path in sources:
        codes |= set(pattern.findall(path.read_text(encoding="utf-8")))

    assert codes, "no finding codes were discovered; the pattern is wrong"
    missing = sorted(codes - set(weights.entries))
    assert not missing, f"finding codes with no weight: {missing}"


def test_an_unknown_code_raises_rather_than_scoring_zero(weights: Weights) -> None:
    with pytest.raises(WeightsError, match="no entry in the weights file"):
        score(make_result(finding("spf.invented_code")), weights)


def test_missing_file_raises_a_clear_error() -> None:
    with pytest.raises(WeightsError, match="not found"):
        load_weights(Path("does-not-exist.toml"))


def test_malformed_weights_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "w.toml"
    path.write_text(
        'schema_version = 1\n[findings."spf.absent"]\nweight = "lots"\n',
        encoding="utf-8",
    )
    with pytest.raises(WeightsError, match="not a number"):
        load_weights(path)


def test_wrong_schema_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "w.toml"
    path.write_text(
        'schema_version = 99\n[findings."spf.absent"]\nweight = 1\n', encoding="utf-8"
    )
    with pytest.raises(WeightsError, match="schema_version"):
        load_weights(path)


def test_every_entry_has_a_rationale(weights: Weights) -> None:
    """Auditability: a weight with no stated reason cannot be explained to a client."""
    unexplained = [code for code, entry in weights.entries.items() if not entry.rationale]
    assert not unexplained, f"weights with no rationale: {unexplained}"


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------


def test_profile_overrides_apply() -> None:
    default = load_weights(profile="default")
    accounting = load_weights(profile="accounting")

    assert default.get("dmarc.absent").weight == 40
    assert accounting.get("dmarc.absent").weight == 45
    # Unmentioned codes keep the base value.
    assert accounting.get("spf.absent").weight == default.get("spf.absent").weight


def test_profile_version_records_the_profile() -> None:
    # The digest is appended after the profile name, so this is a containment
    # check rather than a suffix check.
    assert "+accounting+" in load_weights(profile="accounting").version


def test_unknown_profile_raises() -> None:
    with pytest.raises(WeightsError, match="unknown profile"):
        load_weights(profile="nonexistent")


def test_a_profile_cannot_invent_a_code(tmp_path: Path) -> None:
    path = tmp_path / "w.toml"
    path.write_text(
        "schema_version = 1\n"
        '[findings."spf.absent"]\nweight = 30\n'
        '[profiles.p.findings."spf.invented"]\nweight = 5\n',
        encoding="utf-8",
    )
    with pytest.raises(WeightsError, match="not in the base"):
        load_weights(path, profile="p")


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def test_score_is_the_sum_of_weights(weights: Weights) -> None:
    result = score(make_result(finding("spf.absent"), finding("dmarc.absent")), weights)
    assert result.score == 30 + 40
    assert result.risk == "high"


def test_score_is_capped(weights: Weights) -> None:
    result = score(
        make_result(
            finding("spf.absent"),
            finding("dmarc.absent"),
            finding("dkim.none_found"),
            finding("spf.lookup_limit_exceeded"),
            finding("combo.no_authentication_at_all"),
        ),
        weights,
    )
    assert result.score == MAX_SCORE


def test_duplicate_codes_are_scored_once(weights: Weights) -> None:
    """A check may legitimately raise the same code twice; it is charged once."""
    once = score(make_result(finding("spf.absent")), weights)
    twice = score(make_result(finding("spf.absent"), finding("spf.absent")), weights)
    assert once.score == twice.score


@pytest.mark.parametrize(
    "codes,expected",
    [
        ([], "low"),
        (["dmarc.policy_none"], "low"),
        (["dmarc.absent"], "medium"),
        (["dmarc.absent", "spf.absent"], "high"),
    ],
)
def test_risk_bands(codes: list[str], expected: str, weights: Weights) -> None:
    result = score(make_result(*[finding(c) for c in codes]), weights)
    assert result.risk == expected


def test_an_errored_domain_is_not_scored_zero(weights: Weights) -> None:
    """Zero would sort it with well-configured domains. It gets `unknown` instead."""
    errored = replace(make_result(), error="the domain does not resolve")
    result = score(errored, weights)
    assert result.risk == "unknown"
    assert result.score == 0


def test_non_sending_domains_score_on_a_separate_track(weights: Weights) -> None:
    """A parked domain must not outrank a live firm with no authentication."""
    gaps = [finding("spf.absent"), finding("dmarc.absent"), finding("dkim.none_found")]
    sending = score(make_result(*gaps, posture=Posture.SENDING), weights)
    parked = score(make_result(*gaps, posture=Posture.NON_SENDING), weights)

    assert sending.risk == "high"
    # The parked domain is off the scale entirely rather than low on it: a
    # number here would invite a comparison with sending domains that means
    # nothing. raw_score still orders it within its own track.
    assert parked.score is None
    assert parked.risk == "non-sending"
    assert parked.raw_score == sending.raw_score


# ---------------------------------------------------------------------------
# confidence
# ---------------------------------------------------------------------------


def test_confidence_is_high_when_every_finding_is_observed(weights: Weights) -> None:
    result = score(make_result(finding("dmarc.absent"), finding("spf.absent")), weights)
    assert result.confidence_label == Confidence.HIGH
    assert result.low_confidence_share == 0.0


def test_confidence_drops_when_the_score_rests_on_inference(weights: Weights) -> None:
    result = score(make_result(finding("dkim.none_found")), weights)
    assert result.confidence_label == Confidence.LOW
    assert result.low_confidence_share == 1.0


def test_two_equal_scores_can_be_sorted_by_confidence(weights: Weights) -> None:
    """The requirement from the brief, stated as a test."""
    observed = score(make_result(finding("dmarc.absent")), weights)
    inferred = score(
        make_result(
            finding("dkim.none_found"),
            finding("combo.no_authentication_at_all"),
            finding("mx.target_unresolvable"),
        ),
        weights,
    )
    assert observed.confidence > inferred.confidence


def test_config_cannot_make_a_check_more_confident_than_it_was(weights: Weights) -> None:
    """The weights file says dmarc.absent is high confidence.

    If a check reports it at low confidence - because the resolver was flaky, say
    - the lower value must win. Configuration describes the finding in general;
    the check describes this particular observation.
    """
    result = score(make_result(finding("dmarc.absent", confidence=Confidence.LOW)), weights)
    assert result.scored[0].finding.confidence == Confidence.LOW


def test_zero_weight_findings_do_not_affect_confidence(weights: Weights) -> None:
    with_info = score(make_result(finding("dmarc.absent"), finding("mx.no_ipv6")), weights)
    without = score(make_result(finding("dmarc.absent")), weights)
    assert with_info.confidence == without.confidence


# ---------------------------------------------------------------------------
# explanation
# ---------------------------------------------------------------------------


def test_explain_accounts_for_every_point(weights: Weights) -> None:
    result = score(make_result(finding("spf.absent"), finding("dmarc.absent")), weights)
    lines = explain(result)
    assert any("spf.absent" in line for line in lines)
    assert any("dmarc.absent" in line for line in lines)
    assert any("70" in line for line in lines)


def test_explain_notes_the_non_sending_track(weights: Weights) -> None:
    result = score(
        make_result(finding("dmarc.absent"), posture=Posture.NON_SENDING), weights
    )
    assert any("non-sending" in line for line in explain(result))


# ---------------------------------------------------------------------------
# end to end against fixture zones
# ---------------------------------------------------------------------------


def test_locked_domain_scores_low(clean_zone, weights: Weights) -> None:
    result = score(check_domain(FakeResolver(clean_zone), "locked.test"), weights)
    assert result.risk == "low"
    assert result.error is None
    assert result.posture == Posture.SENDING


def test_wideopen_domain_scores_high(wideopen_zone, weights: Weights) -> None:
    result = score(check_domain(FakeResolver(wideopen_zone), "wideopen.test"), weights)
    assert result.risk == "high"
    assert result.headline
    codes = {item.finding.code for item in result.scored}
    assert "dmarc.absent" in codes
    assert "spf.absent" in codes


def test_halfway_domain_scores_medium(halfway_zone, weights: Weights) -> None:
    result = score(check_domain(FakeResolver(halfway_zone), "halfway.test"), weights)
    assert result.risk == "medium"
    assert result.dmarc.policy == "none"
    assert result.mx.provider == "Microsoft 365"


def test_the_accounting_profile_ranks_dmarc_gaps_higher(wideopen_zone) -> None:
    checked = check_domain(FakeResolver(wideopen_zone), "wideopen.test")
    default = score(checked, load_weights(profile="default"))
    accounting = score(checked, load_weights(profile="accounting"))
    assert accounting.score >= default.score


# ---------------------------------------------------------------------------
# the DKIM ordering property
#
# dkim.revoked and dkim.unparseable both suppress dkim.none_found, so their
# weights only mean anything relative to it. Get that relationship wrong in one
# profile and a domain that published a broken key scores better than a domain
# that published nothing, despite both being equally unsigned.
#
# This asserts the property, not the numbers, so it survives future weight edits
# and fails if the inversion is reintroduced in any profile.
# ---------------------------------------------------------------------------

WEIGHTS_PATH = PACKAGE_ROOT / "weights.toml"


def all_profiles() -> list[str]:
    """Every profile in the shipped weights file, discovered rather than listed."""
    import tomllib

    with WEIGHTS_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    return ["default", *sorted(data.get("profiles", {}))]


def zero_usable_key_postures() -> dict[str, dict[tuple[str, str], list[str]]]:
    """Zones that differ only in how DKIM fails. Every one has no usable key."""
    from tests.test_dkim import BROKEN_QUOTED_KEY

    base = {
        ("x.test", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all"],
        ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 -all"],
        ("x.test", "MX"): ["0 x-test.mail.protection.outlook.com"],
        ("x-test.mail.protection.outlook.com", "A"): ["104.47.1.1"],
        ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@x.test"],
    }
    delegation = {
        ("selector1._domainkey.x.test", "CNAME"): ["s1-x._domainkey.tenant.onmicrosoft.com"]
    }
    return {
        "nothing published at all": base,
        "dangling delegation": {**base, **delegation},
        "unreadable key": {
            **base,
            ("default._domainkey.x.test", "TXT"): [BROKEN_QUOTED_KEY],
        },
        "revoked key": {
            **base,
            ("default._domainkey.x.test", "TXT"): ["v=DKIM1; k=rsa; p="],
        },
    }


@pytest.mark.parametrize("profile", all_profiles())
def test_no_dkim_state_scores_below_the_nothing_published_baseline(
    profile: str,
) -> None:
    """A domain that published a broken key must never outrank one with none.

    All four postures here are functionally identical: no receiver can verify a
    signature for any of them. Publishing something malformed must not be scored
    as better than publishing nothing.
    """
    loaded = load_weights(profile=profile)
    postures = zero_usable_key_postures()

    scores = {
        label: score(check_domain(FakeResolver(zone), "x.test"), loaded).score
        for label, zone in postures.items()
    }
    baseline = scores["nothing published at all"]

    for label, value in scores.items():
        assert value >= baseline, (
            f"profile {profile!r}: {label!r} scored {value}, below the "
            f"nothing-published baseline of {baseline}. A domain that published a "
            f"broken key must not outrank one that published nothing."
        )


@pytest.mark.parametrize("profile", all_profiles())
def test_zero_usable_key_states_stay_in_one_band(profile: str) -> None:
    """The four postures must stay close together, since the posture is the same.

    A generous band, because the point is to catch a state drifting away from the
    others, not to freeze the numbers.
    """
    loaded = load_weights(profile=profile)
    scores = [
        score(check_domain(FakeResolver(zone), "x.test"), loaded).score
        for zone in zero_usable_key_postures().values()
    ]
    assert max(scores) - min(scores) <= 10, (
        f"profile {profile!r}: zero-usable-key states span {max(scores) - min(scores)} "
        f"points ({sorted(scores)}), which is wider than one band"
    )


@pytest.mark.parametrize("profile", all_profiles())
def test_the_derived_dkim_relationships_hold_in_every_profile(profile: str) -> None:
    """The relationships the rationale comments claim, asserted as code.

    If someone edits dkim.none_found in a profile and does not move the two
    derived weights with it, this fails and names the profile.
    """
    loaded = load_weights(profile=profile)
    none_found = loaded.get("dkim.none_found").weight

    assert loaded.get("dkim.revoked").weight == none_found, (
        f"profile {profile!r}: dkim.revoked must equal dkim.none_found ({none_found})"
    )
    assert loaded.get("dkim.unparseable").weight == none_found + 5, (
        f"profile {profile!r}: dkim.unparseable must be dkim.none_found + 5 "
        f"({none_found + 5})"
    )
    # Flat by design: it does not suppress none_found, so it must not scale with it.
    assert loaded.get("dkim.delegation_without_key").weight == 2, (
        f"profile {profile!r}: dkim.delegation_without_key is flat at 2 by design"
    )


# ---------------------------------------------------------------------------
# the weights digest
#
# A hand-maintained version string fails in exactly the case it exists to catch:
# someone edits a number and forgets to bump it. The digest is derived from the
# scoring content so it cannot be forgotten.
# ---------------------------------------------------------------------------


def edited_weights(tmp_path: Path, old: str, new: str) -> Path:
    """Copy the shipped weights file with one textual substitution applied."""
    source = WEIGHTS_PATH.read_text(encoding="utf-8")
    assert old in source, f"anchor not found: {old!r}"
    target = tmp_path / "w.toml"
    target.write_text(source.replace(old, new, 1), encoding="utf-8")
    return target


def test_the_version_carries_a_digest() -> None:
    version = load_weights().version
    head, _, tail = version.rpartition("+")
    assert head, version
    config, _, algorithm = tail.partition(".")
    assert len(config) >= 6
    assert all(c in "0123456789abcdef" for c in config + algorithm), version


def test_the_profile_name_survives_in_the_version() -> None:
    assert "accounting" in load_weights(profile="accounting").version


def test_changing_a_weight_changes_the_digest(tmp_path: Path) -> None:
    before = load_weights().version
    after = load_weights(
        edited_weights(
            tmp_path,
            '[findings."dkim.none_found"]\nweight = 15',
            '[findings."dkim.none_found"]\nweight = 16',
        )
    ).version
    assert before != after


def test_changing_a_confidence_changes_the_digest(tmp_path: Path) -> None:
    before = load_weights().version
    after = load_weights(
        edited_weights(
            tmp_path,
            '[findings."dkim.revoked"]\nweight = 15\nconfidence = "high"',
            '[findings."dkim.revoked"]\nweight = 15\nconfidence = "medium"',
        )
    ).version
    assert before != after


def test_changing_a_profile_override_changes_the_digest(tmp_path: Path) -> None:
    path = edited_weights(
        tmp_path,
        '[profiles.accounting.findings."dmarc.absent"]\nweight = 45',
        '[profiles.accounting.findings."dmarc.absent"]\nweight = 46',
    )
    assert (
        load_weights(path, profile="accounting").version
        != load_weights(profile="accounting").version
    )
    # ...and the profile that does not use that override is unaffected.
    assert load_weights(path, profile="strict").version == (
        load_weights(profile="strict").version
    )


def test_changing_a_rationale_does_not_change_the_digest(tmp_path: Path) -> None:
    """Prose carries no scoring meaning, so it must not invalidate comparability."""
    path = edited_weights(
        tmp_path,
        "An empty p tag withdraws the key",
        "An empty p tag retires the key",
    )
    assert load_weights(path).version == load_weights().version


def test_adding_a_comment_does_not_change_the_digest(tmp_path: Path) -> None:
    path = edited_weights(
        tmp_path,
        "schema_version = 1",
        "# a passing remark that changes no score\nschema_version = 1",
    )
    assert load_weights(path).version == load_weights().version


def test_two_profiles_produce_different_digests() -> None:
    versions = {
        p: load_weights(profile=p).version for p in ("default", "accounting", "strict")
    }
    assert len(set(versions.values())) == 3, versions


def test_the_risk_thresholds_are_part_of_the_digest(tmp_path: Path) -> None:
    """Moving a band boundary changes which prospects read as high risk."""
    path = edited_weights(tmp_path, "[risk]\nhigh = 60", "[risk]\nhigh = 55")
    assert load_weights(path).version != load_weights().version


# ---------------------------------------------------------------------------
# the unobserved-area confidence ceiling
#
# Confidence is a weight-weighted mean over findings that scored above zero. An
# "unreachable" finding is weight 0 by design, so it contributes nothing and the
# remaining findings drag the figure up. The result was 96% confidence about a
# domain whose DKIM state is unknowable, and a domain whose DMARC lookup timed
# out reporting as though the record had been read cleanly.
# ---------------------------------------------------------------------------


def unobserved_zone(area: str) -> tuple[dict, set[tuple[str, str]]]:
    """A healthy domain with exactly one area made unobservable."""
    from mailauth.providers import selectors_for

    zone = {
        ("u.test", "TXT"): ["v=spf1 -all"],
        ("u.test", "MX"): ["10 mail.u.test"],
        ("mail.u.test", "A"): ["192.0.2.1"],
        ("_dmarc.u.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@u.test"],
    }
    fails = {
        "DMARC": {("_dmarc.u.test", "TXT")},
        "MX": {("u.test", "MX")},
        "DKIM": {
            (f"{s}._domainkey.u.test", t)
            for s in selectors_for(None)
            for t in ("TXT", "CNAME")
        },
        "none": set(),
    }
    return zone, fails[area]


@pytest.mark.parametrize("area", ["DMARC", "MX", "DKIM"])
def test_an_unobserved_area_caps_confidence(area: str, weights: Weights) -> None:
    zone, fail = unobserved_zone(area)
    result = score(check_domain(FakeResolver(zone, fail=fail), "u.test"), weights)

    assert area in result.unobserved_areas, result.unobserved_areas
    # Per-area: the ceiling scales with how much the area could have contributed.
    assert result.confidence <= weights.area_ceiling(area) + 1e-9, (
        f"{area} unobserved but confidence is {result.confidence}"
    )
    assert result.confidence_label != Confidence.HIGH


def test_a_fully_observed_domain_is_not_capped(weights: Weights) -> None:
    zone, _ = unobserved_zone("none")
    result = score(check_domain(FakeResolver(zone), "u.test"), weights)
    assert result.unobserved_areas == []
    assert result.confidence > weights.unobserved_ceiling


def test_unobserved_areas_compound(weights: Weights) -> None:
    """Two unknowns are strictly worse than one, and must read that way."""
    zone, dmarc_fail = unobserved_zone("DMARC")
    _, mx_fail = unobserved_zone("MX")

    one = score(check_domain(FakeResolver(zone, fail=dmarc_fail), "u.test"), weights)
    two = score(
        check_domain(FakeResolver(zone, fail=dmarc_fail | mx_fail), "u.test"), weights
    )

    assert len(two.unobserved_areas) > len(one.unobserved_areas)
    assert two.confidence < one.confidence


def test_the_ceiling_comes_from_configuration(tmp_path: Path) -> None:
    """Same rule as every other number: it lives in the config, via its derivation."""
    strict_ceiling = load_weights(edited_weights(tmp_path, "medium = 0.5", "medium = 0.2"))
    zone, fail = unobserved_zone("DMARC")
    result = score(check_domain(FakeResolver(zone, fail=fail), "u.test"), strict_ceiling)

    # DMARC is the heaviest area, so it takes the full ceiling.
    assert strict_ceiling.unobserved_ceiling == 0.2
    assert strict_ceiling.area_ceiling("DMARC") == pytest.approx(0.2)
    assert result.confidence <= 0.2 + 1e-9


def test_the_ceiling_cannot_be_pinned_independently() -> None:
    """It is a derived property, not a field, so no config key can decouple it."""
    from dataclasses import fields

    assert "unobserved_ceiling" not in {f.name for f in fields(load_weights())}


def test_unobserved_areas_are_persisted(weights: Weights) -> None:
    zone, fail = unobserved_zone("DMARC")
    payload = score(
        check_domain(FakeResolver(zone, fail=fail), "u.test"), weights
    ).to_dict()
    assert payload["unobserved_areas"] == ["DMARC"]


def test_confidence_labels_come_from_configuration(tmp_path: Path) -> None:
    """The label boundaries are scoring output, so they live in the config too."""
    relaxed = load_weights(edited_weights(tmp_path, "high = 0.8", "high = 0.4"))
    assert relaxed.label_high == 0.4
    assert load_weights().label_high == 0.8


def test_the_ceiling_is_derived_from_the_medium_threshold(tmp_path: Path) -> None:
    """One unobserved area must land at MEDIUM, whatever MEDIUM is set to."""
    base = load_weights()
    assert base.unobserved_ceiling == base.label_medium

    moved = load_weights(edited_weights(tmp_path, "medium = 0.5", "medium = 0.45"))
    assert moved.unobserved_ceiling == 0.45
    assert moved.unobserved_ceiling == moved.label_medium


def test_one_unobserved_area_lands_at_medium_after_moving_the_threshold(
    tmp_path: Path,
) -> None:
    moved = load_weights(edited_weights(tmp_path, "medium = 0.5", "medium = 0.45"))
    zone, fail = unobserved_zone("DMARC")
    result = score(check_domain(FakeResolver(zone, fail=fail), "u.test"), moved)

    assert result.confidence_label == Confidence.MEDIUM
    assert result.confidence <= 0.45 + 1e-9


def test_changing_a_label_threshold_changes_the_digest(tmp_path: Path) -> None:
    assert (
        load_weights(edited_weights(tmp_path, "medium = 0.5", "medium = 0.45")).version
        != load_weights().version
    )
    assert (
        load_weights(edited_weights(tmp_path, "high = 0.8", "high = 0.75")).version
        != load_weights().version
    )


# ---------------------------------------------------------------------------
# the scoring-algorithm digest
#
# The content digest covers the configuration. It cannot see a change to the
# algorithm that consumes it: adding a confidence ceiling, or an exclusive
# group, changes every score while leaving weights.toml untouched. Two runs
# either side of such a change would compare as though nothing had happened.
# ---------------------------------------------------------------------------


def test_the_version_carries_both_digests() -> None:
    version = load_weights().version
    tail = version.rsplit("+", 1)[1]
    config, _, algorithm = tail.partition(".")
    assert len(config) >= 6 and len(algorithm) >= 4, version
    assert config != algorithm


def test_the_algorithm_digest_is_stable_across_config_edits(tmp_path: Path) -> None:
    """Editing a weight must move the config digest and leave the algorithm alone."""
    edited = load_weights(
        edited_weights(
            tmp_path,
            '[findings."dkim.none_found"]\nweight = 15',
            '[findings."dkim.none_found"]\nweight = 16',
        )
    )
    base = load_weights()

    assert edited.algorithm_digest == base.algorithm_digest
    assert edited.config_digest != base.config_digest


def test_the_algorithm_digest_is_stable_across_profiles() -> None:
    """The algorithm does not change when the profile does."""
    digests = {load_weights(profile=p).algorithm_digest for p in ("default", "strict")}
    assert len(digests) == 1


def test_a_behaviour_change_moves_the_algorithm_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mutation test. A guard that cannot fail is not a guard.

    MAX_SCORE stands in for any scoring-shape change: it is behaviour that lives
    in the code rather than the config, which is exactly what this digest exists
    to catch.
    """
    from mailauth import scoring

    before = scoring.algorithm_digest()
    monkeypatch.setattr(scoring, "MAX_SCORE", 90)
    scoring.algorithm_digest.cache_clear()
    after = scoring.algorithm_digest()
    scoring.algorithm_digest.cache_clear()

    assert before != after


def test_the_probes_execute_every_line_of_the_scored_path() -> None:
    """The digest's only weakness, guarded by a derived check rather than a list.

    A behavioural fingerprint sees only what its probes touch. Comparing two
    hand-maintained lists would pass whenever someone forgets to update both,
    which is the failure mode the derived digest exists to avoid in the first
    place. So this traces execution instead.

    The traced scope is score() plus the two model derivations it reads whose
    output it cannot recompute: whether an area was observed, and whether a DKIM
    sweep learned anything. Those live in models.py, and a change to either
    alters real scoring behaviour. Deliberately NOT all of models.py: properties
    like usable_keys feed the report rather than the score, and requiring probe
    coverage of them would add probes that guard nothing.

    Line coverage, not path coverage. A new branch is caught; a behaviour change
    along an already-covered line that alters no probe output is not.
    """
    import inspect
    import sys

    from mailauth import scoring
    from mailauth.models import DkimResult, DomainResult
    from mailauth.scoring import ALGORITHM_PROBES, _reference_weights

    scored_path = (
        scoring.score,
        DomainResult.unobserved_areas.fget,
        DkimResult.observed.fget,
    )
    # Weights.area_ceiling is deliberately not traced: it carries a
    # divide-by-zero guard for a config with no weights at all, which no single
    # reference config can reach. Its behaviour is covered instead by the
    # unobserved-* probes, which now produce a distinct confidence per area, so a
    # change to the scaling still moves the digest.
    spans = []
    for func in scored_path:
        source_lines, first = inspect.getsourcelines(func)
        spans.append((func, source_lines, first, first + len(source_lines) - 1))

    files = {inspect.getsourcefile(func) for func in scored_path}
    executed: set[tuple[str, int]] = set()

    def tracer(frame, event, arg):  # type: ignore[no-untyped-def]
        if event == "line" and frame.f_code.co_filename in files:
            executed.add((frame.f_code.co_filename, frame.f_lineno))
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        reference = _reference_weights()
        for _, probe in ALGORITHM_PROBES:
            scoring.score(probe, reference)
    finally:
        sys.settrace(previous)

    missing: list[str] = []
    for func, source_lines, first, last in spans:
        path = inspect.getsourcefile(func)
        code = func.__code__
        executable = {
            entry[2] for entry in code.co_lines() if entry[2] and first < entry[2] <= last
        }
        for number in sorted(executable - {n for f, n in executed if f == path}):
            missing.append(
                f"{func.__qualname__} line {number}: {source_lines[number - first].strip()}"
            )

    assert not missing, (
        "these lines of the scored path are not reached by any algorithm probe, "
        "so a change to them would not move the algorithm digest: " + "; ".join(missing)
    )


def test_the_reference_config_is_frozen() -> None:
    """The reference config is part of the algorithm digest's definition.

    Editing it moves the digest with no behaviour change, which is a false
    positive on the axis that means "the tool scores differently". Nothing can
    make that impossible, so it is made loud: this pin fails until someone
    updates it deliberately, and updating it is the moment to ask whether the
    digest break is intended.

    If a probe needs a code that does not exist yet, add it and re-pin.
    """
    import hashlib

    from mailauth.scoring import _REFERENCE_ENTRIES, _reference_weights

    material = "|".join(
        f"{code}={entry.weight}:{entry.confidence}"
        for code, entry in sorted(_REFERENCE_ENTRIES.items())
    )
    # Groups are part of the reference too, so they are pinned with it.
    material += "||" + "|".join(
        f"{name}={','.join(codes)}"
        for name, codes in sorted(_reference_weights().groups.items())
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    assert digest == "25a3b7f4c851", (
        "the algorithm digest's reference config changed. If that was deliberate, "
        f"update this pin to {digest} and expect every stored run to compare as "
        "incomparable against runs made from here on."
    )


# ---------------------------------------------------------------------------
# per-area confidence ceilings
#
# A flat ceiling treats an unobserved BIMI lookup exactly like an unobserved
# DMARC lookup. BIMI's only finding is weight 0, so failing to read it costs the
# score nothing; DMARC drives the score. Scaling the ceiling by how much the
# area could have contributed is what makes the cap proportionate.
# ---------------------------------------------------------------------------


def test_area_ceilings_are_ordered_by_stake(weights: Weights) -> None:
    ceilings = {
        a: weights.area_ceiling(a)
        for a in ("DMARC", "DKIM", "MX", "MTA-STS", "TLS-RPT", "BIMI")
    }
    ordered = sorted(ceilings, key=lambda a: ceilings[a])
    assert ordered == ["DMARC", "DKIM", "MX", "MTA-STS", "TLS-RPT", "BIMI"], ceilings


def test_the_heaviest_area_gets_the_full_ceiling(weights: Weights) -> None:
    assert weights.area_ceiling("DMARC") == pytest.approx(weights.label_medium)


def test_a_weightless_area_is_not_capped_at_all(weights: Weights) -> None:
    """An unobserved BIMI costs the score nothing, so it must cost confidence nothing."""
    assert weights.area_ceiling("BIMI") == pytest.approx(1.0)


def test_an_unobserved_bimi_does_not_move_confidence(weights: Weights) -> None:
    from mailauth.models import ExtrasResult, QueryStatus, RecordProbe

    clean = make_result(finding("dmarc.absent"))
    blind_bimi = replace(
        clean,
        extras=ExtrasResult(
            bimi=RecordProbe(name="default._bimi", status=QueryStatus.TIMEOUT)
        ),
    )
    assert score(blind_bimi, weights).confidence == pytest.approx(
        score(clean, weights).confidence
    )
    assert score(blind_bimi, weights).unobserved_areas == ["BIMI"]


def test_an_unobserved_dmarc_still_caps_hard(weights: Weights) -> None:
    zone, fail = unobserved_zone("DMARC")
    result = score(check_domain(FakeResolver(zone, fail=fail), "u.test"), weights)
    assert result.confidence <= weights.label_medium + 1e-9


def test_ceilings_are_derived_from_the_weights(tmp_path: Path) -> None:
    """Give BIMI a real weight and its ceiling must tighten, with no code change."""
    heavier = load_weights(
        edited_weights(
            tmp_path,
            '[findings."bimi.no_logo"]\nweight = 0',
            '[findings."bimi.no_logo"]\nweight = 40',
        )
    )
    assert heavier.area_ceiling("BIMI") == pytest.approx(heavier.label_medium)
    assert load_weights().area_ceiling("BIMI") == pytest.approx(1.0)


def test_raw_score_is_recorded_before_clamping(weights: Weights) -> None:
    """The clamped score is what a client sees; the raw total is what ranks."""
    result = score(
        make_result(
            finding("spf.absent"),
            finding("dmarc.absent"),
            finding("dkim.none_found"),
            finding("spf.lookup_limit_exceeded"),
            finding("combo.no_authentication_at_all"),
        ),
        weights,
    )
    assert result.score == MAX_SCORE
    assert result.raw_score > MAX_SCORE


def test_raw_score_equals_score_when_under_the_cap(weights: Weights) -> None:
    result = score(make_result(finding("dmarc.absent")), weights)
    assert result.raw_score == result.score


def test_raw_score_separates_a_saturated_tie(weights: Weights) -> None:
    """Two domains both showing 100 must still be rankable."""
    worse = score(
        make_result(
            finding("dmarc.absent"),
            finding("spf.absent"),
            finding("dkim.none_found"),
            finding("combo.no_authentication_at_all"),
            finding("spf.lookup_limit_exceeded"),
        ),
        weights,
    )
    bad = score(
        make_result(
            finding("dmarc.absent"),
            finding("spf.absent"),
            finding("dkim.none_found"),
            finding("combo.no_authentication_at_all"),
        ),
        weights,
    )
    assert worse.score == bad.score == MAX_SCORE
    assert worse.raw_score > bad.raw_score


def test_raw_score_is_persisted(weights: Weights) -> None:
    result = score(make_result(finding("dmarc.absent")), weights)
    assert result.to_dict()["raw_score"] == result.raw_score


# ---------------------------------------------------------------------------
# mutually exclusive finding groups
#
# dkim.none_found, dkim.unparseable, dkim.revoked and dkim.delegation_without_key
# all assert the same underlying fact: no usable key. Summing them charges a
# domain three times for being unsigned once.
# ---------------------------------------------------------------------------


def test_the_group_cap_is_the_largest_member(weights: Weights) -> None:
    members = weights.groups["dkim_no_usable_key"]
    expected = max(weights.get(code).weight for code in members)
    assert weights.group_cap("dkim_no_usable_key") == expected


def test_group_members_do_not_sum_beyond_the_cap(weights: Weights) -> None:
    result = score(
        make_result(
            finding("dkim.unparseable"),
            finding("dkim.revoked"),
            finding("dkim.delegation_without_key"),
        ),
        weights,
    )
    cap = weights.group_cap("dkim_no_usable_key")
    charged = sum(
        item.weight
        for item in result.scored
        if item.finding.code in weights.groups["dkim_no_usable_key"]
    )
    assert charged == cap


def test_the_heaviest_member_keeps_its_weight(weights: Weights) -> None:
    """The worst state sets the price; the others are shown but not charged."""
    result = score(
        make_result(finding("dkim.unparseable"), finding("dkim.revoked")), weights
    )
    charged = {i.finding.code: i.weight for i in result.scored}
    assert charged["dkim.unparseable"] == weights.get("dkim.unparseable").weight
    assert charged["dkim.revoked"] == 0


def test_a_capped_member_says_why_in_its_rationale(weights: Weights) -> None:
    result = score(
        make_result(finding("dkim.unparseable"), finding("dkim.revoked")), weights
    )
    zeroed = next(i for i in result.scored if i.finding.code == "dkim.revoked")
    assert "group" in zeroed.rationale.lower()


def test_a_single_group_member_is_unaffected(weights: Weights) -> None:
    alone = score(make_result(finding("dkim.none_found")), weights)
    assert alone.score == weights.get("dkim.none_found").weight


def test_the_common_pairing_stays_below_the_cap(weights: Weights) -> None:
    """none_found plus a delegation is the ordinary case and must not be clipped."""
    result = score(
        make_result(finding("dkim.none_found"), finding("dkim.delegation_without_key")),
        weights,
    )
    expected = (
        weights.get("dkim.none_found").weight
        + weights.get("dkim.delegation_without_key").weight
    )
    assert result.score == min(expected, weights.group_cap("dkim_no_usable_key"))


def test_a_group_cannot_name_an_unknown_code(tmp_path: Path) -> None:
    path = edited_weights(
        tmp_path,
        "[groups]\ndkim_no_usable_key = [",
        '[groups]\ndkim_no_usable_key = [\n    "dkim.invented",',
    )
    with pytest.raises(WeightsError, match="not in the base"):
        load_weights(path)


def test_changing_a_group_changes_the_digest(tmp_path: Path) -> None:
    path = edited_weights(tmp_path, '    "dkim.revoked",\n', "")
    assert load_weights(path).version != load_weights().version


# ---------------------------------------------------------------------------
# the non-sending track
#
# A domain with no MX was collapsing to 29, which put it on the same scale as
# sending domains and invited a comparison that means nothing. The collapse is
# right for ranking; emitting a number that reads as cross-comparable is not.
# ---------------------------------------------------------------------------


def test_a_non_sending_domain_has_no_score(weights: Weights) -> None:
    result = score(
        make_result(finding("dmarc.absent"), posture=Posture.NON_SENDING), weights
    )
    assert result.score is None
    assert result.risk == "non-sending"


def test_a_non_sending_domain_keeps_its_raw_total(weights: Weights) -> None:
    """Raw is the sort key, and ordering within the track is still wanted."""
    result = score(
        make_result(
            finding("dmarc.absent"), finding("spf.absent"), posture=Posture.NON_SENDING
        ),
        weights,
    )
    assert (
        result.raw_score
        == weights.get("dmarc.absent").weight + weights.get("spf.absent").weight
    )


def test_non_sending_domains_still_order_among_themselves(weights: Weights) -> None:
    worse = score(
        make_result(
            finding("dmarc.absent"), finding("spf.absent"), posture=Posture.NON_SENDING
        ),
        weights,
    )
    milder = score(
        make_result(finding("dmarc.absent"), posture=Posture.NON_SENDING), weights
    )
    assert worse.raw_score > milder.raw_score


def test_a_sending_domain_still_has_a_score(weights: Weights) -> None:
    result = score(make_result(finding("dmarc.absent")), weights)
    assert result.score is not None
    assert result.risk in ("low", "medium", "high")
