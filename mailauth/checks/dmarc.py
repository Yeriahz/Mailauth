"""
mailauth/checks/dmarc.py - DMARC record parsing, every tag, plus the external
reporting authorization check.

The tag most worth reporting after `p` is `rua`, and the part of `rua` most
worth checking is whether it points somewhere that has agreed to receive the
reports. RFC 7489 section 7.1: if the report address is at a different domain,
that domain must publish

    <reporting-domain>._report._dmarc.<destination-domain>

before any receiver will send a report there. Without it the reports are simply
never delivered. The DMARC record looks correct, the dashboard stays empty, and
nothing anywhere reports an error. It is the most common invisible failure in
DMARC deployments and it is why this check exists.
"""

from __future__ import annotations

import re

from ..dns_client import Resolver, normalise, prefixed
from ..models import (
    Confidence,
    DmarcResult,
    Finding,
    ReportingAuthorization,
    Severity,
)

VALID_POLICIES = ("none", "quarantine", "reject")

# mailto:dmarc@example.com!10m  ->  the URI, with an optional size limit suffix
MAILTO_RE = re.compile(r"^mailto:([^!\s]+)(?:!(\d+[kmgt]?))?$", re.IGNORECASE)

# -- the p findings' copy ---------------------------------------------------
#
# An enforcing policy gets a second detail, used when and only when the record
# also sets t=y. The default text states what the record asks receivers to do,
# which on a t=y record is the opposite of what the record asks: t=y asks them
# not to apply it. Saying it plainly there would contradict dmarc.policy_test_mode
# on the same page, and the contradiction is not a matter of emphasis - one of
# the two sentences would be false.
#
# The test mode variants stay short on purpose. dmarc.policy_test_mode carries
# the full explanation of why the two receiver classes differ, and it is emitted
# on exactly the records these are selected for, so repeating it here would print
# the same paragraph twice on one page.
POLICY_QUARANTINE_DETAIL = (
    "Failing mail is asked to be treated as suspicious rather than delivered normally."
)
POLICY_QUARANTINE_TEST_MODE_DETAIL = (
    "The record requests that failing mail be treated as suspicious. It also sets "
    "t=y, which asks receivers not to apply that request, so this policy is "
    "published but not necessarily in effect."
)
# p=reject carries no detail outside test mode: the title says what the policy is
# and there is nothing further to add. The variant exists because t=y makes the
# published policy conditional, which the title alone cannot convey.
POLICY_REJECT_DETAIL = ""
POLICY_REJECT_TEST_MODE_DETAIL = (
    "The record requests that failing mail be rejected. It also sets t=y, which "
    "asks receivers not to apply that request, so this policy is published but "
    "not necessarily in effect."
)


def is_dmarc_record(text: str) -> bool:
    """True for a TXT record that declares itself DMARC version 1.

    Case-insensitive, and the version tag must come first per RFC 7489 6.3.
    """
    stripped = text.strip()
    lowered = stripped.lower()
    return lowered.startswith("v=dmarc1") and (len(stripped) == 8 or stripped[8] in "; \t")


def parse_tags(record: str) -> dict[str, str]:
    """Parse a DMARC record into its tag/value pairs, lower-casing tag names only."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key and key not in tags:
            tags[key] = value.strip()
    return tags


def report_destinations(uri_list: str) -> list[tuple[str, str]]:
    """Extract (uri, destination-domain) pairs from a rua or ruf tag value."""
    out: list[tuple[str, str]] = []
    for raw in uri_list.split(","):
        uri = raw.strip()
        if not uri:
            continue
        match = MAILTO_RE.match(uri)
        if not match:
            out.append((uri, ""))
            continue
        address = match.group(1)
        _, _, host = address.rpartition("@")
        out.append((uri, normalise(host)))
    return out


def is_same_organizational_domain(destination: str, domain: str) -> bool:
    """True when the destination needs no external authorization record.

    RFC 7489 requires the authorization record only when the destination is
    outside the DMARC record's own domain. A subdomain of the domain, or the
    domain itself, needs nothing.
    """
    destination = normalise(destination)
    domain = normalise(domain)
    return destination == domain or destination.endswith("." + domain)


def check_external_reporting(
    resolver: Resolver, domain: str, uri: str, destination: str
) -> ReportingAuthorization:
    """Look for the _report._dmarc authorization record at the destination."""
    if not destination:
        return ReportingAuthorization(uri=uri, destination="", authorized=None)
    if is_same_organizational_domain(destination, domain):
        return ReportingAuthorization(uri=uri, destination=destination, authorized=True)

    name = f"{normalise(domain)}._report._dmarc.{destination}"
    response = resolver.txt(name)
    if response.status.is_our_fault:
        return ReportingAuthorization(uri=uri, destination=destination, authorized=None)

    for value in response.values:
        if value.strip().lower().startswith("v=dmarc1"):
            return ReportingAuthorization(
                uri=uri, destination=destination, authorized=True, record=value
            )
    return ReportingAuthorization(uri=uri, destination=destination, authorized=False)


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
        area="DMARC",
        severity=severity,
        confidence=confidence,
        title=title,
        detail=detail,
        evidence={k: v for k, v in evidence.items() if v},
    )


def check(resolver: Resolver, domain: str) -> DmarcResult:
    """Read and evaluate the DMARC record for one domain."""
    findings: list[Finding] = []
    response = resolver.txt(prefixed("_dmarc", domain))

    if response.status.is_our_fault:
        findings.append(
            _finding(
                "dmarc.unreachable",
                Severity.INFO,
                Confidence.LOW,
                "The DMARC record could not be read from this vantage point",
                status=str(response.status),
            )
        )
        return DmarcResult(findings=findings)

    records = [v for v in response.values if is_dmarc_record(v)]

    if not records:
        findings.append(
            _finding(
                "dmarc.absent",
                Severity.CRITICAL,
                Confidence.HIGH,
                "No DMARC record is published",
                "Nothing tells Gmail, Outlook or any other receiver what to do with "
                "mail that claims to come from this domain and fails authentication. "
                "With no record the mail is delivered normally, and the domain owner "
                "receives no reports showing who is sending as them.",
            )
        )
        return DmarcResult(findings=findings)

    if len(records) > 1:
        findings.append(
            _finding(
                "dmarc.multiple_records",
                Severity.CRITICAL,
                Confidence.HIGH,
                f"{len(records)} DMARC records are published",
                "RFC 7489 requires exactly one. When a receiver finds several it "
                "applies none of them, so the domain is treated as having no policy.",
                records=" | ".join(records),
            )
        )

    record = records[0]
    tags = parse_tags(record)
    policy = tags.get("p", "").lower()
    # Read once, here, because two separate places below depend on it: which
    # detail the p finding carries, and whether dmarc.policy_test_mode is
    # emitted at all. A second predicate could drift from this one and put the
    # two findings back into contradiction, which is the failure being fixed.
    test_mode = DmarcResult(tags=tags).policy_test_mode

    # -- policy ------------------------------------------------------------
    if policy not in VALID_POLICIES:
        findings.append(
            _finding(
                "dmarc.invalid_policy",
                Severity.CRITICAL,
                Confidence.HIGH,
                "The DMARC record has no valid p tag",
                "A record without a policy of none, quarantine or reject is discarded "
                "by receivers, so the domain is treated as having no DMARC at all.",
                p=tags.get("p", "(absent)"),
            )
        )
    elif policy == "none":
        findings.append(
            _finding(
                "dmarc.policy_none",
                Severity.WARNING,
                Confidence.HIGH,
                "DMARC policy is p=none (monitor only)",
                "The record exists and reports can be collected, but no action is "
                "requested of receivers. Mail that fails authentication is still "
                "delivered normally. This is the correct first stage of a rollout and "
                "a gap if the domain has been sitting here for a long time.",
            )
        )
    elif policy == "quarantine":
        findings.append(
            _finding(
                "dmarc.policy_quarantine",
                Severity.OK,
                Confidence.HIGH,
                "DMARC policy is p=quarantine",
                POLICY_QUARANTINE_TEST_MODE_DETAIL
                if test_mode
                else POLICY_QUARANTINE_DETAIL,
            )
        )
    else:
        findings.append(
            _finding(
                "dmarc.policy_reject",
                Severity.OK,
                Confidence.HIGH,
                "DMARC policy is p=reject",
                POLICY_REJECT_TEST_MODE_DETAIL if test_mode else POLICY_REJECT_DETAIL,
            )
        )

    # -- policy test mode --------------------------------------------------
    # Restricted to an enforcing p, because that is the only case the copy below
    # is true for.
    #
    # On p=none both receiver classes take no action: one is asked not to apply a
    # policy that does nothing, the other applies a policy that does nothing. The
    # sentence about handling differing between receivers is therefore false
    # there, not merely unhelpful.
    #
    # On an absent, empty or invalid p there is no policy to name, and
    # dmarc.invalid_policy already carries the record.
    #
    # The gate lives here rather than on the model because it is a property of
    # what this copy asserts, not of the tag. DmarcResult.policy_test_mode reads
    # t alone and stays that way.
    if test_mode and policy in ("quarantine", "reject"):
        findings.append(
            _finding(
                "dmarc.policy_test_mode",
                Severity.WARNING,
                Confidence.HIGH,
                "DMARC record is in test mode (t=y)",
                f"This record publishes p={policy} and also sets t=y. Under RFC 9989 "
                f"that tag asks receivers not to apply the published policy while the "
                f"domain owner is testing. Receivers that have not implemented "
                f"RFC 9989 ignore tags they do not recognise and apply p={policy} as "
                f"published. How this domain's failing mail is actually handled "
                f"therefore differs between receivers, and cannot be determined from "
                f"DNS alone.",
                t=tags.get("t", ""),
            )
        )

    # -- pct ---------------------------------------------------------------
    pct_raw = tags.get("pct", "100")
    try:
        pct = int(pct_raw)
    except ValueError:
        pct = 100
        findings.append(
            _finding(
                "dmarc.invalid_pct",
                Severity.WARNING,
                Confidence.HIGH,
                f"The pct tag is not a number (pct={pct_raw})",
                "Receivers that cannot parse the tag fall back to applying the policy "
                "to all mail, but the record does not say what was intended.",
            )
        )
    if pct < 100 and policy in ("quarantine", "reject"):
        findings.append(
            _finding(
                "dmarc.pct_partial",
                Severity.WARNING,
                Confidence.HIGH,
                f"The policy applies to only {pct}% of mail (pct={pct})",
                f"Receivers apply p={policy} to {pct}% of failing messages and treat "
                f"the rest as p=none. The published policy overstates what is actually "
                f"enforced.",
                pct=str(pct),
            )
        )

    # -- subdomain policy --------------------------------------------------
    subdomain_policy = tags.get("sp", "").lower()
    if policy in ("quarantine", "reject") and not subdomain_policy:
        findings.append(
            _finding(
                "dmarc.sp_absent",
                Severity.INFO,
                Confidence.HIGH,
                "No subdomain policy (sp) is set",
                "Subdomains inherit the parent policy when sp is absent, which is "
                "usually what is wanted. Setting it explicitly removes the ambiguity, "
                "and matters most for domains that never send from subdomains.",
            )
        )
    elif subdomain_policy and subdomain_policy != policy:
        weaker = subdomain_policy == "none" or (
            subdomain_policy == "quarantine" and policy == "reject"
        )
        findings.append(
            _finding(
                "dmarc.sp_weaker" if weaker else "dmarc.sp_differs",
                Severity.WARNING if weaker else Severity.INFO,
                Confidence.HIGH,
                f"Subdomains use a different policy (sp={subdomain_policy})",
                "Mail sent from any subdomain is treated under the weaker policy, "
                "including subdomains nobody created deliberately."
                if weaker
                else "Subdomains are handled differently from the parent domain.",
                sp=subdomain_policy,
                p=policy,
            )
        )

    # -- reporting ---------------------------------------------------------
    external: list[ReportingAuthorization] = []
    rua = tags.get("rua", "")
    if not rua:
        findings.append(
            _finding(
                "dmarc.no_rua",
                Severity.WARNING,
                Confidence.HIGH,
                "No aggregate reporting address (rua) is set",
                "No aggregate reports are being collected, so there is no visibility "
                "into who is sending mail using this domain, legitimately or "
                "otherwise. Reports are what make it safe to tighten the policy later.",
            )
        )
    else:
        findings.append(
            _finding(
                "dmarc.rua_present",
                Severity.OK,
                Confidence.HIGH,
                "Aggregate reporting is configured",
                rua=rua,
            )
        )
        for uri, destination in report_destinations(rua):
            authorization = check_external_reporting(resolver, domain, uri, destination)
            external.append(authorization)
            if authorization.authorized is False:
                findings.append(
                    _finding(
                        "dmarc.rua_unauthorized",
                        Severity.WARNING,
                        Confidence.HIGH,
                        f"Reports are addressed to {authorization.destination}, which "
                        f"has not published the record authorizing them",
                        f"RFC 7489 requires {normalise(domain)}._report._dmarc."
                        f"{authorization.destination} to exist before receivers will "
                        f"send reports there. Without it the reports are never "
                        f"delivered and nothing signals the failure.",
                        uri=uri,
                    )
                )

    ruf = tags.get("ruf", "")
    if ruf:
        for uri, destination in report_destinations(ruf):
            authorization = check_external_reporting(resolver, domain, uri, destination)
            external.append(authorization)
            if authorization.authorized is False:
                findings.append(
                    _finding(
                        "dmarc.ruf_unauthorized",
                        Severity.INFO,
                        Confidence.HIGH,
                        f"Forensic reports are addressed to {authorization.destination}, "
                        f"which has not published the record authorizing them",
                        "Most large receivers do not send forensic reports at all, so "
                        "this matters less than the equivalent gap on rua.",
                        uri=uri,
                    )
                )

    # -- alignment ---------------------------------------------------------
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    strict = [name for name, mode in (("DKIM", adkim), ("SPF", aspf)) if mode == "s"]
    if strict:
        findings.append(
            _finding(
                "dmarc.strict_alignment",
                Severity.INFO,
                Confidence.HIGH,
                f"Strict alignment is required for {', '.join(strict)}",
                "Strict mode requires an exact domain match rather than an "
                "organizational one, so mail sent from a subdomain no longer aligns.",
                adkim=adkim,
                aspf=aspf,
            )
        )

    fo = tags.get("fo", "0")
    if fo and fo != "0" and not ruf:
        findings.append(
            _finding(
                "dmarc.fo_without_ruf",
                Severity.INFO,
                Confidence.HIGH,
                f"Failure reporting options are set (fo={fo}) with no ruf address",
                "The fo tag only affects forensic reports, which have nowhere to go "
                "without a ruf address.",
                fo=fo,
            )
        )

    ri = tags.get("ri", "")
    if ri:
        try:
            interval = int(ri)
            if interval != 86400:
                findings.append(
                    _finding(
                        "dmarc.nonstandard_ri",
                        Severity.INFO,
                        Confidence.HIGH,
                        f"A non-default report interval is requested (ri={interval})",
                        "Most receivers send aggregate reports once a day regardless "
                        "of this value.",
                        ri=str(interval),
                    )
                )
        except ValueError:
            pass

    return DmarcResult(
        record=record,
        record_count=len(records),
        tags=tags,
        external=external,
        findings=findings,
    )
