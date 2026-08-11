"""
mailauth/engine.py - runs every check against one domain and derives the
findings that only exist in the combination.

Not in the brief's module list, but the alternative was putting orchestration in
cli.py, which would make it unreachable from tests and from any future caller.

The interaction findings are the part worth reading. Individual checks cannot
see each other, so a per-check weight cannot express that `p=reject` published
by a domain whose outbound mail is unsigned is materially worse than either fact
alone. Each interaction finding inherits the confidence of its weakest input, so
a conclusion resting on a DKIM probe can never be stated more confidently than
that probe.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from .checks import dkim as dkim_check
from .checks import dmarc as dmarc_check
from .checks import extras as extras_check
from .checks import mx as mx_check
from .checks import spf as spf_check
from .dns_client import Resolver, normalise
from .models import (
    Confidence,
    DomainResult,
    Finding,
    Posture,
    QueryStatus,
    Severity,
)
from .providers import Provider, identify

CONFIDENCE_ORDER = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}


def weakest(*levels: Confidence) -> Confidence:
    """The least confident of the given levels."""
    return min(levels, key=lambda c: CONFIDENCE_ORDER[c])


def _combo(
    code: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    detail: str,
) -> Finding:
    return Finding(
        code=code,
        area="COMBINED",
        severity=severity,
        confidence=confidence,
        title=title,
        detail=detail,
    )


def interaction_findings(result: DomainResult) -> list[Finding]:
    """Findings that only exist when two checks are read together."""
    findings: list[Finding] = []
    policy = result.dmarc.policy
    enforcing = policy in ("quarantine", "reject")

    # A domain asking receivers to reject unauthenticated mail, whose own mail
    # carries no signature we can find, is one forwarding hop from dropping its
    # own invoices. SPF breaks across forwarding; DKIM is what survives it.
    if enforcing and not result.dkim.any_key_found and result.dkim.observed:
        findings.append(
            _combo(
                "combo.enforcing_without_dkim",
                Severity.CRITICAL,
                # Rests entirely on the DKIM probe, so it inherits that probe's
                # confidence and can never be stated more strongly than the
                # underlying "no key was found on the selectors tried".
                Confidence.LOW,
                f"DMARC is set to p={policy} while no DKIM key was found on the "
                f"selectors tried",
                "SPF does not survive mail forwarding: when a message is forwarded, "
                "the forwarding server becomes the sender and SPF no longer matches. "
                "DKIM is what keeps a forwarded message authenticated. If outbound "
                "mail really is unsigned, an enforcing DMARC policy risks the domain's "
                "own forwarded mail being rejected. Worth confirming before treating "
                "the enforcing policy as a finished deployment.",
            )
        )

    # A hard fail that never gets evaluated is not a hard fail. Over the lookup
    # limit the record is a permerror and the -all never applies.
    over_limit = any(f.code == "spf.lookup_limit_exceeded" for f in result.spf.findings)
    if over_limit and result.spf.all_qualifier == "-":
        findings.append(
            _combo(
                "combo.hardfail_never_evaluated",
                Severity.CRITICAL,
                Confidence.HIGH,
                "SPF ends in -all but exceeds the DNS lookup limit, so the hard fail "
                "never applies",
                "The record looks strict when read by eye. Because evaluation stops "
                "with a permanent error before reaching the end, receivers never apply "
                "the hard fail. The apparent strictness is not in effect.",
            )
        )

    # Reports are the input to every later decision. An enforcing policy with no
    # reporting means nobody can see what the policy is actually doing.
    if enforcing and not result.dmarc.tags.get("rua"):
        findings.append(
            _combo(
                "combo.enforcing_without_reporting",
                Severity.WARNING,
                Confidence.HIGH,
                f"DMARC is set to p={policy} with no reporting address",
                "Mail is being acted on by receivers and nobody is collecting the "
                "reports that would show which senders are affected. If a legitimate "
                "sender starts failing, the first signal will be a person saying their "
                "mail never arrived.",
            )
        )

    # Every unauthorized rua destination is a dashboard that will stay empty.
    unauthorized = [e for e in result.dmarc.external if e.authorized is False]
    if unauthorized and result.dmarc.tags.get("rua"):
        findings.append(
            _combo(
                "combo.reporting_never_arrives",
                Severity.WARNING,
                Confidence.HIGH,
                "The DMARC reporting address is configured but reports cannot be "
                "delivered to it",
                "The record names a destination at another domain that has not "
                "published the record authorizing these reports. Receivers check for "
                "it and, not finding it, send nothing. Everything looks configured and "
                "no report ever arrives.",
            )
        )

    # A sending domain with neither mechanism aligned has nothing for DMARC to
    # pass on, whatever the policy says.
    if (
        result.posture == Posture.SENDING
        and not result.spf.present
        and not result.dkim.any_key_found
        and result.dkim.observed
    ):
        findings.append(
            _combo(
                "combo.no_authentication_at_all",
                Severity.CRITICAL,
                weakest(Confidence.HIGH, Confidence.LOW),
                "Neither SPF nor a DKIM key was found for a domain that receives mail",
                "There is nothing published for a receiver to check a message against. "
                "Anyone can send mail claiming to be from this domain and it will "
                "authenticate exactly as well as the real thing, which is to say not "
                "at all.",
            )
        )

    return findings


def determine_posture(result: DomainResult) -> Posture:
    """Decide whether this domain sends mail, and should be read as such.

    A parked domain with no MX and no SPF is a different conversation from a
    live firm with no authentication. Scoring them on the same scale puts parked
    domains at the top of a worklist, which is where this tool was previously
    wrong.
    """
    if result.error:
        return Posture.UNRESOLVED
    if result.mx.null_mx:
        return Posture.NON_SENDING
    if not result.mx.targets and not result.spf.records:
        return Posture.NON_SENDING
    return Posture.SENDING


def check_domain(
    resolver: Resolver,
    domain: str,
    extra_selectors: list[str] | None = None,
    active: bool = False,
    inspect_mx_targets: bool = True,
    passthrough: dict[str, str] | None = None,
) -> DomainResult:
    """Run every check against one domain and return the assembled result.

    Scoring is not applied here; scoring.score() takes this result and a weights
    config. Keeping them apart is what lets the same run be re-scored under a
    different profile without re-querying anything.
    """
    domain = normalise(domain)
    now = datetime.now(UTC).isoformat(timespec="seconds")

    apex = resolver.txt(domain)
    if apex.status == QueryStatus.NXDOMAIN:
        return DomainResult(
            domain=domain,
            resolver=resolver.server,
            checked_at=now,
            posture=Posture.UNRESOLVED,
            error="the domain does not resolve",
            passthrough=dict(passthrough or {}),
        )
    if apex.status.is_our_fault:
        return DomainResult(
            domain=domain,
            resolver=resolver.server,
            checked_at=now,
            posture=Posture.UNRESOLVED,
            error=f"DNS query failed ({apex.status})",
            passthrough=dict(passthrough or {}),
        )

    mx_result = mx_check.check(resolver, domain, inspect_targets=inspect_mx_targets)
    provider: Provider | None = identify(mx_result.hosts)

    spf_result = spf_check.check(resolver, domain, apex.values)
    dmarc_result = dmarc_check.check(resolver, domain)
    dkim_result = dkim_check.check(resolver, domain, provider, extra_selectors)
    extras_result = extras_check.check(
        resolver, domain, has_mx=bool(mx_result.targets), active=active
    )

    result = DomainResult(
        domain=domain,
        resolver=resolver.server,
        checked_at=now,
        mx=mx_result,
        spf=spf_result,
        dmarc=dmarc_result,
        dkim=dkim_result,
        extras=extras_result,
        passthrough=dict(passthrough or {}),
    )

    # Posture first, because the interaction rules read it, then the interaction
    # findings, which need the assembled result to see across checks.
    result = replace(result, posture=determine_posture(result))
    return replace(result, combo=interaction_findings(result))
