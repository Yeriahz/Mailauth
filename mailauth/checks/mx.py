"""
mailauth/checks/mx.py - MX records and the state of the hosts they point at.

Beyond "who handles this domain's mail", the checks here catch three things that
break mail quietly:
  - null MX (RFC 7505), which is a deliberate statement that a domain receives no
    mail, and which changes how everything else about the domain should be read
  - an MX target that is a CNAME, which RFC 2181 section 10.3 forbids and which
    some receivers refuse outright
  - an MX target that does not resolve at all
"""

from __future__ import annotations

from ..dns_client import Resolver
from ..models import Confidence, Finding, MxResult, MxTarget, QueryStatus, Severity
from ..providers import identify


def _finding(
    code: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    detail: str = "",
    **evidence: str,
) -> Finding:
    return Finding(
        code=code,
        area="MX",
        severity=severity,
        confidence=confidence,
        title=title,
        detail=detail,
        evidence={k: v for k, v in evidence.items() if v},
    )


def parse_mx_value(value: str) -> tuple[int, str]:
    """Split the "10 mail.example.com" form the DNS client normalises MX rdata to."""
    preference, _, host = value.partition(" ")
    try:
        return int(preference), host.strip().rstrip(".").lower()
    except ValueError:
        return 0, value.strip().rstrip(".").lower()


def check(resolver: Resolver, domain: str, inspect_targets: bool = True) -> MxResult:
    """Resolve MX for a domain and inspect each target host."""
    findings: list[Finding] = []
    response = resolver.mx(domain)

    if response.status.is_our_fault:
        findings.append(
            _finding(
                "mx.unreachable",
                Severity.INFO,
                Confidence.LOW,
                "MX records could not be read from this vantage point",
                "The query failed rather than returning an answer, so nothing can be "
                "said about this domain's inbound mail.",
                status=str(response.status),
            )
        )
        return MxResult(status=response.status, findings=findings)

    if not response.values:
        findings.append(
            _finding(
                "mx.absent",
                Severity.INFO,
                Confidence.HIGH,
                "No MX records are published",
                "This domain does not receive mail. If it is still used to send, or "
                "if it is simply parked, it can still be locked down so that nobody "
                "else can send as it.",
            )
        )
        return MxResult(status=response.status, findings=findings)

    parsed = sorted(parse_mx_value(value) for value in response.values)

    # RFC 7505: a single MX with preference 0 and a root target means "this
    # domain accepts no mail", stated deliberately.
    if len(parsed) == 1 and parsed[0][1] in ("", "."):
        findings.append(
            _finding(
                "mx.null",
                Severity.OK,
                Confidence.HIGH,
                "Null MX is published (RFC 7505)",
                "The domain states explicitly that it receives no mail, which is the "
                "correct configuration for a domain that only sends, or for one that "
                "does neither.",
            )
        )
        return MxResult(
            targets=[MxTarget(preference=0, host="")],
            null_mx=True,
            status=response.status,
            findings=findings,
        )

    targets: list[MxTarget] = []
    for preference, host in parsed:
        if not inspect_targets:
            targets.append(MxTarget(preference=preference, host=host))
            continue

        cname = resolver.cname(host)
        is_cname = cname.status == QueryStatus.OK and bool(cname.values)
        a_records = resolver.query(host, "A")
        aaaa_records = resolver.query(host, "AAAA")
        targets.append(
            MxTarget(
                preference=preference,
                host=host,
                resolves=bool(a_records.values or aaaa_records.values),
                is_cname=is_cname,
                cname_target=cname.values[0] if is_cname and cname.values else None,
                has_a=bool(a_records.values),
                has_aaaa=bool(aaaa_records.values),
            )
        )

    provider = identify([t.host for t in targets])

    findings.append(
        _finding(
            "mx.present",
            Severity.INFO,
            Confidence.HIGH,
            f"Mail is handled by {provider.name if provider else targets[0].host}",
            evidence_hosts=", ".join(f"{t.preference} {t.host}" for t in targets),
        )
    )

    if len(targets) == 1:
        findings.append(
            _finding(
                "mx.single",
                Severity.INFO,
                Confidence.HIGH,
                "Only one MX host is published",
                "Mail delivery depends on that single host being reachable. Most "
                "hosted providers publish several; a single host is common on "
                "self-hosted and small reseller setups.",
            )
        )

    cnamed = [t for t in targets if t.is_cname]
    if cnamed:
        findings.append(
            _finding(
                "mx.target_is_cname",
                Severity.WARNING,
                Confidence.HIGH,
                f"{len(cnamed)} MX target(s) are CNAMEs",
                "RFC 2181 section 10.3 states that an MX target must be a hostname "
                "with address records, not an alias. Some receivers reject this "
                "outright and others follow it, so delivery becomes inconsistent.",
                hosts=", ".join(t.host for t in cnamed),
            )
        )

    dead = [t for t in targets if not t.resolves]
    if dead and inspect_targets:
        severity = Severity.CRITICAL if len(dead) == len(targets) else Severity.WARNING
        findings.append(
            _finding(
                "mx.target_unresolvable",
                severity,
                Confidence.HIGH,
                f"{len(dead)} MX target(s) do not resolve to an address",
                "A published MX host with no A or AAAA record cannot receive mail. "
                "When every host is in this state the domain silently loses inbound "
                "mail.",
                hosts=", ".join(t.host for t in dead),
            )
        )

    if inspect_targets and targets and not any(t.has_aaaa for t in targets):
        findings.append(
            _finding(
                "mx.no_ipv6",
                Severity.INFO,
                Confidence.HIGH,
                "No MX target publishes an AAAA record",
                "Inbound mail is reachable over IPv4 only. This is common and not a "
                "problem on its own; it is recorded because IPv6-only senders are "
                "becoming less rare.",
            )
        )

    return MxResult(
        targets=targets,
        provider=provider.name if provider else None,
        status=response.status,
        findings=findings,
    )
