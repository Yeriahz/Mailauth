"""
mailauth/checks/extras.py - TLS-RPT, MTA-STS, BIMI and DNSSEC.

Everything here is a passive DNS read with exactly one exception, which is the
reason this module has an `active` parameter at all: the MTA-STS *policy file*
lives at

    https://mta-sts.<domain>/.well-known/mta-sts.txt

and fetching it opens a TLS connection to a web server the assessed domain
operates. That request lands in their logs with our source address. It is the
only thing this package can do that leaves a trace, and it stays off unless
explicitly enabled. The MTA-STS *DNS record* is an ordinary TXT lookup and is
always read.
"""

from __future__ import annotations

import urllib.error
import urllib.request

from ..dns_client import Resolver, prefixed
from ..models import (
    Confidence,
    ExtrasResult,
    Finding,
    MtaStsResult,
    RecordProbe,
    Severity,
)

# The policy file is a few hundred bytes. Anything beyond this is not a policy
# file and there is no reason to read it into memory.
MAX_POLICY_BYTES = 64 * 1024
POLICY_TIMEOUT = 10.0

USER_AGENT = "mailauth/2.0 (+passive email authentication review)"


def parse_semicolon_tags(record: str) -> dict[str, str]:
    """Parse the `v=X; k=v; k=v` shape shared by TLS-RPT, MTA-STS and BIMI."""
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


def _probe(resolver: Resolver, label: str, domain: str, version_prefix: str) -> RecordProbe:
    """Read a single underscore-prefixed TXT record and parse its tags."""
    name = prefixed(label, domain)
    response = resolver.txt(name)
    for value in response.values:
        if value.strip().lower().startswith(version_prefix):
            return RecordProbe(
                name=name,
                present=True,
                record=value,
                tags=parse_semicolon_tags(value),
                status=response.status,
            )
    return RecordProbe(name=name, present=False, status=response.status)


def parse_policy(text: str) -> dict[str, list[str]]:
    """Parse an MTA-STS policy file.

    The format is one `key: value` per line, with `mx` repeated once per host.
    """
    parsed: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        parsed.setdefault(key.strip().lower(), []).append(value.strip())
    return parsed


def fetch_policy(
    domain: str, timeout: float = POLICY_TIMEOUT
) -> tuple[str | None, str | None]:
    """Fetch the MTA-STS policy file. Returns (text, error).

    This is the one outbound connection in the package. It is only ever called
    when the caller passed active=True, which the CLI only sets from an explicit
    flag.
    """
    # The scheme is fixed in the format string and the host is derived from the
    # domain under review, so there is no path by which a caller can redirect
    # this at file: or any other scheme. RFC 8461 permits HTTPS only.
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            if response.status != 200:
                return None, f"HTTP {response.status}"
            body = response.read(MAX_POLICY_BYTES)
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"could not connect: {exc.reason}"
    except (TimeoutError, OSError) as exc:
        return None, f"could not connect: {exc}"
    return body.decode("utf-8", "replace"), None


def _finding(
    code: str,
    area: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    detail: str = "",
    **evidence: str,
) -> Finding:
    return Finding(
        code=code,
        area=area,
        severity=severity,
        confidence=confidence,
        title=title,
        detail=detail,
        evidence={k: v for k, v in evidence.items() if v},
    )


def check(
    resolver: Resolver,
    domain: str,
    has_mx: bool = True,
    active: bool = False,
) -> ExtrasResult:
    """Read the supporting records, and optionally fetch the MTA-STS policy."""
    findings: list[Finding] = []

    # -- TLS-RPT -----------------------------------------------------------
    tlsrpt = _probe(resolver, "_smtp._tls", domain, "v=tlsrptv1")
    if has_mx and not tlsrpt.present:
        findings.append(
            _finding(
                "tlsrpt.absent",
                "TLS-RPT",
                Severity.INFO,
                Confidence.HIGH,
                "No TLS-RPT record is published",
                "TLS-RPT asks sending servers to report failures to negotiate TLS when "
                "delivering here. Without it, a downgrade or certificate problem on "
                "inbound mail is invisible to the domain owner.",
            )
        )
    elif tlsrpt.present and not tlsrpt.tags.get("rua"):
        findings.append(
            _finding(
                "tlsrpt.no_rua",
                "TLS-RPT",
                Severity.INFO,
                Confidence.HIGH,
                "The TLS-RPT record has no rua destination",
                "The record is published but names nowhere to send the reports.",
            )
        )

    # -- MTA-STS -----------------------------------------------------------
    sts_dns = _probe(resolver, "_mta-sts", domain, "v=stsv1")
    mtasts = MtaStsResult(dns=sts_dns)

    if has_mx and not sts_dns.present:
        findings.append(
            _finding(
                "mtasts.absent",
                "MTA-STS",
                Severity.INFO,
                Confidence.HIGH,
                "No MTA-STS record is published",
                "MTA-STS lets a domain state that inbound mail must arrive over "
                "validated TLS. Without it, an attacker positioned between two mail "
                "servers can strip encryption and the mail is delivered in the clear.",
            )
        )
    elif sts_dns.present and not sts_dns.tags.get("id"):
        findings.append(
            _finding(
                "mtasts.no_id",
                "MTA-STS",
                Severity.WARNING,
                Confidence.HIGH,
                "The MTA-STS record has no id tag",
                "The id is what tells sending servers the policy has changed. Without "
                "it, caches are never refreshed.",
            )
        )

    if sts_dns.present and active:
        text, error = fetch_policy(domain)
        if error or text is None:
            mtasts = MtaStsResult(dns=sts_dns, policy_error=error)
            findings.append(
                _finding(
                    "mtasts.policy_unreachable",
                    "MTA-STS",
                    Severity.WARNING,
                    Confidence.HIGH,
                    "The MTA-STS DNS record is published but the policy file could "
                    "not be retrieved",
                    "Sending servers that honour MTA-STS fetch the policy from "
                    f"mta-sts.{domain} over HTTPS. When the record exists and the "
                    "policy does not, the feature does nothing.",
                    error=error or "unknown",
                )
            )
        else:
            policy = parse_policy(text)
            mode = (policy.get("mode") or [""])[0].lower()
            max_age_values = policy.get("max_age") or []
            try:
                max_age = int(max_age_values[0]) if max_age_values else None
            except ValueError:
                max_age = None
            mtasts = MtaStsResult(
                dns=sts_dns,
                policy_fetched=True,
                policy_mode=mode or None,
                policy_max_age=max_age,
                policy_mx=policy.get("mx", []),
            )
            if mode == "testing":
                findings.append(
                    _finding(
                        "mtasts.testing",
                        "MTA-STS",
                        Severity.INFO,
                        Confidence.HIGH,
                        "The MTA-STS policy is in testing mode",
                        "In testing mode senders report failures but still deliver, so "
                        "the policy is not yet enforced. This is the correct first "
                        "stage of a rollout.",
                    )
                )
            elif mode == "none":
                findings.append(
                    _finding(
                        "mtasts.mode_none",
                        "MTA-STS",
                        Severity.INFO,
                        Confidence.HIGH,
                        "The MTA-STS policy mode is none",
                        "Mode none withdraws a previously published policy.",
                    )
                )

    # -- BIMI --------------------------------------------------------------
    bimi = _probe(resolver, "default._bimi", domain, "v=bimi1")
    if bimi.present and not bimi.tags.get("l"):
        findings.append(
            _finding(
                "bimi.no_logo",
                "BIMI",
                Severity.INFO,
                Confidence.HIGH,
                "The BIMI record names no logo location",
                "A BIMI record with an empty l tag declines to display a logo.",
            )
        )

    # -- DNSSEC ------------------------------------------------------------
    soa = resolver.query(domain, "SOA")
    dnssec: bool | None
    if soa.status.is_our_fault:
        dnssec = None
    else:
        dnssec = soa.authenticated
        if not dnssec:
            findings.append(
                _finding(
                    "dnssec.unsigned",
                    "DNSSEC",
                    Severity.INFO,
                    # The AD flag depends on the recursive resolver validating and
                    # reporting it. A false here is good evidence, not certainty.
                    Confidence.MEDIUM,
                    "Responses for this domain are not DNSSEC authenticated",
                    "Without DNSSEC, the DNS answers that carry these mail records can "
                    "be tampered with in transit. This is the ordinary state of most "
                    "domains and is recorded for completeness rather than as a gap to "
                    "close first.",
                )
            )

    return ExtrasResult(
        tlsrpt=tlsrpt,
        mtasts=mtasts,
        bimi=bimi,
        dnssec=dnssec,
        findings=findings,
    )
