"""
mailauth/models.py - the data model shared by every check, the scorer, the
store and the report renderer.

Everything here is a frozen dataclass with a to_dict() that produces plain JSON
types. Nothing in this module performs I/O or imports dnspython, which is what
lets the whole test suite run offline against constructed values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """How much a finding matters, independent of its numeric weight."""

    CRITICAL = "critical"
    WARNING = "warning"
    OK = "ok"
    INFO = "info"


class Confidence(StrEnum):
    """How certain we are that the finding reflects reality.

    Separate from weight on purpose. "No DMARC record" is HIGH: absence in DNS
    is absence. "No DKIM key on the selectors tried" is LOW: selectors cannot be
    enumerated from outside, so a miss is suggestive and never proof.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class QueryStatus(StrEnum):
    """Why a DNS query returned what it did.

    Distinguishing these matters: NXDOMAIN and EMPTY are answers that count
    toward the SPF void-lookup limit, while TIMEOUT and SERVFAIL are failures of
    our own vantage point and must never be scored as a finding about the
    domain.
    """

    OK = "ok"
    NXDOMAIN = "nxdomain"
    EMPTY = "empty"
    TIMEOUT = "timeout"
    SERVFAIL = "servfail"
    ERROR = "error"

    @property
    def is_void(self) -> bool:
        """True for the two statuses RFC 7208 counts as a void lookup."""
        return self in (QueryStatus.NXDOMAIN, QueryStatus.EMPTY)

    @property
    def is_our_fault(self) -> bool:
        """True when the query failed for reasons that say nothing about the domain."""
        return self in (QueryStatus.TIMEOUT, QueryStatus.SERVFAIL, QueryStatus.ERROR)


class Posture(StrEnum):
    """What kind of domain this is, which decides how it should be read.

    A parked domain with no MX and no SPF is a different conversation from a
    live firm with no authentication, even though both publish nothing. Keeping
    them apart stops parked domains crowding the top of a worklist.
    """

    SENDING = "sending"
    NON_SENDING = "non-sending"
    UNRESOLVED = "unresolved"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.OK: 2,
    Severity.INFO: 3,
}

SEVERITY_MARK: dict[Severity, str] = {
    Severity.CRITICAL: "[!!]",
    Severity.WARNING: "[! ]",
    Severity.OK: "[ok]",
    Severity.INFO: "[ i]",
}


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One observation about what a domain publishes.

    `code` is the stable identifier that ties a check to its weight in
    weights.toml, to its row in the store, and to its entry in a diff. Titles
    and details are prose and may be reworded freely; codes are versioned and
    only change alongside a CHANGELOG entry.
    """

    code: str
    area: str
    severity: Severity
    confidence: Confidence
    title: str
    detail: str = ""
    evidence: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "area": self.area,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "title": self.title,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


# ---------------------------------------------------------------------------
# per-check results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MxTarget:
    """One MX host and what public DNS says about it."""

    preference: int
    host: str
    resolves: bool = False
    is_cname: bool = False
    cname_target: str | None = None
    has_a: bool = False
    has_aaaa: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "preference": self.preference,
            "host": self.host,
            "resolves": self.resolves,
            "is_cname": self.is_cname,
            "cname_target": self.cname_target,
            "has_a": self.has_a,
            "has_aaaa": self.has_aaaa,
        }


@dataclass(frozen=True)
class MxResult:
    targets: list[MxTarget] = field(default_factory=list)
    provider: str | None = None
    null_mx: bool = False
    status: QueryStatus = QueryStatus.EMPTY
    findings: list[Finding] = field(default_factory=list)

    @property
    def hosts(self) -> list[str]:
        return [t.host for t in self.targets]

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": [t.to_dict() for t in self.targets],
            "provider": self.provider,
            "null_mx": self.null_mx,
            "status": str(self.status),
        }


@dataclass(frozen=True)
class SpfTerm:
    """One parsed term from an SPF record."""

    raw: str
    qualifier: str
    mechanism: str
    value: str
    cidr4: int | None = None
    cidr6: int | None = None
    is_modifier: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "qualifier": self.qualifier,
            "mechanism": self.mechanism,
            "value": self.value,
            "cidr4": self.cidr4,
            "cidr6": self.cidr6,
            "is_modifier": self.is_modifier,
        }


@dataclass(frozen=True)
class SpfResult:
    records: list[str] = field(default_factory=list)
    terms: list[SpfTerm] = field(default_factory=list)
    lookups: int = 0
    void_lookups: int = 0
    all_qualifier: str | None = None
    chain: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return len(self.records) == 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": list(self.records),
            "record_count": len(self.records),
            "terms": [t.to_dict() for t in self.terms],
            "dns_lookups": self.lookups,
            "void_lookups": self.void_lookups,
            "all_qualifier": self.all_qualifier,
            "include_chain": list(self.chain),
        }


@dataclass(frozen=True)
class ReportingAuthorization:
    """An external rua/ruf destination and whether it authorizes these reports.

    RFC 7489 section 7.1: when a DMARC report address is at a different domain,
    that domain must publish
    `<reporting-domain>._report._dmarc.<destination>` before any receiver will
    send reports there. Missing it is a silent, invisible failure - the policy
    looks configured and no report ever arrives.
    """

    uri: str
    destination: str
    authorized: bool | None = None
    record: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "destination": self.destination,
            "authorized": self.authorized,
            "record": self.record,
        }


@dataclass(frozen=True)
class DmarcResult:
    record: str | None = None
    record_count: int = 0
    tags: dict[str, str] = field(default_factory=dict)
    external: list[ReportingAuthorization] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def policy(self) -> str:
        return self.tags.get("p", "").lower()

    @property
    def policy_test_mode(self) -> bool:
        """Whether the record sets t=y, the RFC 9989 policy test mode tag.

        Case is folded and surrounding whitespace stripped at the read site, the
        way every other consumed tag value is handled: the parser preserves
        tag-value case, so a comparison against a bare "y" would miss t=Y.

        True only for exactly "y". Absent, empty, "n", "maybe" and near-misses
        such as "yes" are all False.
        """
        return self.tags.get("t", "").strip().lower() == "y"

    @property
    def subdomain_policy(self) -> str:
        return self.tags.get("sp", "").lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record,
            "record_count": self.record_count,
            "tags": dict(self.tags),
            "external_reporting": [e.to_dict() for e in self.external],
        }


@dataclass(frozen=True)
class DkimKey:
    """A DKIM key found on one selector.

    `bits` is the RSA modulus length recovered from the DER key. It is None for
    ed25519 keys, for CNAME delegations we did not follow, and for keys we could
    not parse.
    """

    selector: str
    source: str  # "txt" or "cname"
    record: str | None = None
    cname_target: str | None = None
    key_type: str = "rsa"
    bits: int | None = None
    testing: bool = False
    revoked: bool = False
    # The published p= value was missing its base64 padding and we restored
    # it. Recorded rather than normalised silently: the key is usable, but
    # the record is not what the standard describes.
    padding_repaired: bool = False
    parse_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "selector": self.selector,
            "source": self.source,
            "record": self.record,
            "cname_target": self.cname_target,
            "key_type": self.key_type,
            "bits": self.bits,
            "testing": self.testing,
            "revoked": self.revoked,
            "padding_repaired": self.padding_repaired,
            "parse_error": self.parse_error,
        }


@dataclass(frozen=True)
class DkimResult:
    """The outcome of probing a list of selectors.

    `selectors_tried` is recorded in full and surfaced in every rendering of
    this result. Selectors cannot be enumerated from outside a domain, so the
    only honest statement the tool can make is which selectors were tried and
    what each returned.
    """

    selectors_tried: list[str] = field(default_factory=list)
    keys: list[DkimKey] = field(default_factory=list)
    wildcard: bool = False
    findings: list[Finding] = field(default_factory=list)
    # Selectors whose probe failed rather than answering. NXDOMAIN is an answer
    # and does not appear here; a timeout or SERVFAIL does. Without this, a
    # resolver hiccup partway through a sweep is indistinguishable from a key
    # that was withdrawn, and a repeat scan reports a key as removed.
    probe_failures: list[str] = field(default_factory=list)
    # The detected provider's own default selectors, when a provider was
    # identified. These are the only selectors that can answer "does this domain
    # sign its own mail", so whether they answered decides whether the sweep
    # learned anything - see `observed`.
    decisive_selectors: list[str] = field(default_factory=list)

    @property
    def usable_keys(self) -> list[DkimKey]:
        """Keys a receiver could actually verify a signature against.

        This is the only list that may answer "does this domain have DKIM". A
        key that fails to parse and a delegation with nothing behind it are both
        real observations, and neither one is a key.
        """
        return [
            k
            for k in self.keys
            if k.bits is not None and not k.parse_error and not k.revoked
        ]

    @property
    def unreadable_keys(self) -> list[DkimKey]:
        """Key records that were retrieved but cannot be parsed by anyone.

        The domain published something at the selector; it is malformed. The
        common cause is quote characters or truncation introduced by a DNS
        control panel when the value was pasted in.
        """
        return [k for k in self.keys if k.record is not None and k.parse_error]

    @property
    def revoked_keys(self) -> list[DkimKey]:
        return [k for k in self.keys if k.revoked]

    @property
    def delegations_without_key(self) -> list[DkimKey]:
        """Selectors whose CNAME resolves but whose target publishes no key.

        The default Microsoft 365 state once a domain is added and DKIM is never
        enabled. Worth surfacing on its own, and emphatically not a key.
        """
        return [k for k in self.keys if k.record is None and k.cname_target]

    @property
    def published_something(self) -> bool:
        """True when a key record was retrieved, whatever state it was in.

        Distinct from `any_key_found`. Used to decide whether "no key was found"
        is a fair thing to say: a domain with a malformed or revoked key did
        publish one, and telling them otherwise would be wrong.
        """
        return bool(self.usable_keys or self.unreadable_keys or self.revoked_keys)

    @property
    def observed(self) -> bool:
        """Whether this run learned anything at all about the domain's DKIM.

        False in two cases: a wildcard zone, where every probe answers and none
        of the answers mean anything, and a sweep in which every probe failed.
        Both are the absence of an observation, and nothing may be scored or
        inferred from either. Distinct from `any_key_found`, which is False both
        when we looked and found nothing and when we never got to look.
        """
        if self.wildcard:
            return False
        failed = set(self.probe_failures)
        if not failed:
            return True
        # When the provider is known, its own selectors are the only ones that
        # could have found this domain's key. If every one of them went
        # unanswered the sweep is blind, however many generic selectors returned
        # a definitive NXDOMAIN - those were never going to find a Google key on
        # a Google domain. The fraction of failed probes is the wrong measure:
        # one failure out of twenty-three is the blind case here, and
        # twenty-two out of twenty-three is the informative one.
        if self.decisive_selectors:
            return not failed.issuperset(self.decisive_selectors)
        return not (bool(self.selectors_tried) and failed.issuperset(self.selectors_tried))

    @property
    def any_key_found(self) -> bool:
        """Whether this domain has a DKIM key a receiver could use."""
        return bool(self.usable_keys)

    def to_dict(self) -> dict[str, Any]:
        return {
            "selectors_tried": list(self.selectors_tried),
            "keys": [k.to_dict() for k in self.keys],
            "wildcard_domainkey": self.wildcard,
            # Counts are persisted so a stored run can be read back, and diffed,
            # without re-deriving the three-state split from the key list.
            "usable_key_count": len(self.usable_keys),
            "unreadable_key_count": len(self.unreadable_keys),
            "delegation_without_key_count": len(self.delegations_without_key),
            "probe_failed_selectors": list(self.probe_failures),
        }


@dataclass(frozen=True)
class RecordProbe:
    """A simple present/absent probe for a single TXT record type."""

    name: str
    present: bool = False
    record: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    status: QueryStatus = QueryStatus.EMPTY

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "present": self.present,
            "record": self.record,
            "tags": dict(self.tags),
            "status": str(self.status),
        }


@dataclass(frozen=True)
class MtaStsResult:
    """MTA-STS state.

    The DNS half is passive and always runs. `policy_fetched` is only ever True
    when --active was given, because fetching the policy file connects to a host
    the assessed domain operates.
    """

    dns: RecordProbe = field(default_factory=lambda: RecordProbe(name="_mta-sts"))
    policy_fetched: bool = False
    policy_mode: str | None = None
    policy_max_age: int | None = None
    policy_mx: list[str] = field(default_factory=list)
    policy_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "dns": self.dns.to_dict(),
            "policy_fetched": self.policy_fetched,
            "policy_mode": self.policy_mode,
            "policy_max_age": self.policy_max_age,
            "policy_mx": list(self.policy_mx),
            "policy_error": self.policy_error,
        }


@dataclass(frozen=True)
class ExtrasResult:
    tlsrpt: RecordProbe = field(default_factory=lambda: RecordProbe(name="_smtp._tls"))
    mtasts: MtaStsResult = field(default_factory=MtaStsResult)
    bimi: RecordProbe = field(default_factory=lambda: RecordProbe(name="default._bimi"))
    dnssec: bool | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tlsrpt": self.tlsrpt.to_dict(),
            "mta_sts": self.mtasts.to_dict(),
            "bimi": self.bimi.to_dict(),
            "dnssec_authenticated": self.dnssec,
        }


# ---------------------------------------------------------------------------
# domain result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoredFinding:
    """A finding paired with the weight the active config gave it.

    This is what makes a score explainable: every point in a total traces back
    to one of these, with the rationale the config author wrote.
    """

    finding: Finding
    weight: int
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = self.finding.to_dict()
        data["weight"] = self.weight
        data["rationale"] = self.rationale
        return data


@dataclass(frozen=True)
class DomainResult:
    """Everything known about one domain from one run."""

    domain: str
    resolver: str
    checked_at: str
    posture: Posture = Posture.SENDING
    mx: MxResult = field(default_factory=MxResult)
    spf: SpfResult = field(default_factory=SpfResult)
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    dkim: DkimResult = field(default_factory=DkimResult)
    extras: ExtrasResult = field(default_factory=ExtrasResult)
    combo: list[Finding] = field(default_factory=list)
    scored: list[ScoredFinding] = field(default_factory=list)
    # None for a non-sending domain. A number here reads as comparable with
    # every other domain in the list, and a parked domain is not on that
    # scale at all. raw_score stays populated and orders within the track.
    score: int | None = 0
    # The uncapped total. Three of 26 real domains exceeded 100, so the shown
    # score cannot rank the worst-configured prospects against each other - the
    # single question this tool exists to answer. The clamped score stays the
    # client-facing number and remains comparable to history; this ranks.
    raw_score: int = 0
    risk: str = "low"
    confidence: float = 1.0
    confidence_label: Confidence = Confidence.HIGH
    low_confidence_share: float = 0.0
    error: str | None = None
    passthrough: dict[str, str] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        """Every finding from every check, worst severity first."""
        collected = [
            *self.mx.findings,
            *self.spf.findings,
            *self.dmarc.findings,
            *self.dkim.findings,
            *self.extras.findings,
            *self.combo,
        ]
        return sorted(collected, key=lambda f: SEVERITY_RANK[f.severity])

    @property
    def unobserved_areas(self) -> list[str]:
        """Areas this run failed to get an answer about.

        An "unreachable" finding carries weight 0 on purpose, because a failure
        of our own vantage point is not a gap in the domain. But confidence is a
        weight-weighted mean over findings that scored above zero, so a weight-0
        finding is invisible to it, and a domain whose DMARC could not be read
        was reporting confidence as though it had been read cleanly. This is the
        list the scorer uses to cap that figure.
        """
        codes = {f.code for f in self.findings}
        areas: list[str] = []
        if not self.dkim.observed:
            areas.append("DKIM")
        if "dmarc.unreachable" in codes:
            areas.append("DMARC")
        if "mx.unreachable" in codes:
            areas.append("MX")
        for label, probe in (
            ("TLS-RPT", self.extras.tlsrpt),
            ("MTA-STS", self.extras.mtasts.dns),
            ("BIMI", self.extras.bimi),
        ):
            if probe.status.is_our_fault:
                areas.append(label)
        return areas

    @property
    def worst_severity(self) -> Severity:
        if self.error:
            return Severity.CRITICAL
        return min(
            (f.severity for f in self.findings),
            key=lambda s: SEVERITY_RANK[s],
            default=Severity.INFO,
        )

    @property
    def headline(self) -> str:
        """The single highest-weighted finding, for a one-line summary."""
        if self.error:
            return self.error
        ranked = sorted(self.scored, key=lambda s: s.weight, reverse=True)
        for item in ranked:
            if item.weight > 0:
                return item.finding.title
        return "no authentication gaps observed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "resolver": self.resolver,
            "checked_at": self.checked_at,
            "posture": str(self.posture),
            "error": self.error,
            "score": self.score,
            "raw_score": self.raw_score,
            "risk": self.risk,
            "confidence": round(self.confidence, 3),
            "confidence_label": str(self.confidence_label),
            "low_confidence_share": round(self.low_confidence_share, 3),
            "unobserved_areas": self.unobserved_areas,
            "worst_severity": str(self.worst_severity),
            "headline": self.headline,
            "mx": self.mx.to_dict(),
            "spf": self.spf.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "dkim": self.dkim.to_dict(),
            "extras": self.extras.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "scored_findings": [s.to_dict() for s in self.scored],
            "passthrough": dict(self.passthrough),
        }
