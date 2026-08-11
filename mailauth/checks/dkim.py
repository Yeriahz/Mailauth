"""
mailauth/checks/dkim.py - DKIM selector probing and key inspection.

DKIM itself is RFC 6376. The selector semantics, the key record tag syntax
(v, k, p, t), and the meaning of an empty p value all come from section 3.6.1
of that document. RFC 8301 supplies the key-length floor.

The governing constraint of this module: DKIM selectors cannot be enumerated
from outside a domain. There is no record that lists them. Probing a list of
likely selectors and finding nothing is evidence, not proof, and every string
this module produces says so. The list of selectors actually tried is recorded
and carried through to every rendering of the result.

Selector choice is derived from the MX fingerprint first - a domain on Microsoft
365 gets selector1/selector2 tried before anything else - then falls back to the
generic list.

Key inspection decodes the base64 `p=` value and walks the DER far enough to
recover the RSA modulus length. That is roughly forty lines of ASN.1 and it is
the only reason this package would otherwise need a compiled cryptography
dependency, so it is done by hand.
"""

from __future__ import annotations

import base64
import binascii
import secrets

from ..dns_client import Resolver
from ..models import Confidence, DkimKey, DkimResult, Finding, Severity
from ..providers import Provider, selectors_for

# Keys below this are considered weak. RFC 8301 sets 1024 as the floor for
# signing keys and recommends 2048.
WEAK_KEY_BITS = 1024
RECOMMENDED_KEY_BITS = 2048

# DER tags used by a SubjectPublicKeyInfo holding an RSA key.
_SEQUENCE = 0x30
_INTEGER = 0x02
_BIT_STRING = 0x03


# ---------------------------------------------------------------------------
# minimal DER walking
# ---------------------------------------------------------------------------


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value triple, returning (tag, value, next_pos)."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length encoding")
        if pos + count > len(data):
            raise ValueError("truncated DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("DER value runs past the end of the buffer")
    return tag, data[pos : pos + length], pos + length


def _modulus_bits(rsa_public_key: bytes) -> int:
    """Bit length of the modulus in a PKCS#1 RSAPublicKey SEQUENCE body."""
    tag, modulus, _ = _read_tlv(rsa_public_key, 0)
    if tag != _INTEGER:
        raise ValueError("first element of RSAPublicKey is not an INTEGER")
    return int.from_bytes(modulus, "big").bit_length()


def rsa_key_bits(der: bytes) -> int:
    """Recover the RSA modulus bit length from a DER key.

    Accepts both encodings seen in DKIM records: a full SubjectPublicKeyInfo,
    which is what every mainstream provider publishes, and a bare PKCS#1
    RSAPublicKey, which some appliances still emit.
    """
    tag, outer, _ = _read_tlv(der, 0)
    if tag != _SEQUENCE:
        raise ValueError("key does not start with a SEQUENCE")

    first_tag, _first_value, after_first = _read_tlv(outer, 0)

    if first_tag == _SEQUENCE:
        # SubjectPublicKeyInfo: AlgorithmIdentifier then a BIT STRING.
        bit_tag, bit_value, _ = _read_tlv(outer, after_first)
        if bit_tag != _BIT_STRING:
            raise ValueError("SubjectPublicKeyInfo has no BIT STRING")
        if not bit_value:
            raise ValueError("empty BIT STRING")
        # The first octet of a BIT STRING is the count of unused trailing bits.
        inner_tag, inner_value, _ = _read_tlv(bit_value[1:], 0)
        if inner_tag != _SEQUENCE:
            raise ValueError("BIT STRING does not contain an RSAPublicKey")
        return _modulus_bits(inner_value)

    if first_tag == _INTEGER:
        # Bare PKCS#1 RSAPublicKey.
        return _modulus_bits(outer)

    raise ValueError("unrecognised key structure")


# ---------------------------------------------------------------------------
# record parsing
# ---------------------------------------------------------------------------


def parse_key_record(selector: str, record: str) -> DkimKey:
    """Parse one DKIM key record into its parts.

    RFC 6376 section 3.6.1 defines these tags. A record with `p=` present but
    empty is a revoked key, which is meaningful: it means a key existed and was
    withdrawn, and any mail still signed with it now fails.
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key and key not in tags:
            tags[key] = value.strip()

    key_type = tags.get("k", "rsa").lower()
    flags = {f.strip().lower() for f in tags.get("t", "").split(":") if f.strip()}
    testing = "y" in flags

    if "p" not in tags:
        return DkimKey(
            selector=selector,
            source="txt",
            record=record,
            key_type=key_type,
            testing=testing,
            parse_error="record has no p tag",
        )

    encoded = "".join(tags["p"].split())
    if not encoded:
        return DkimKey(
            selector=selector,
            source="txt",
            record=record,
            key_type=key_type,
            testing=testing,
            revoked=True,
        )

    # A 1024- or 2048-bit RSA key encodes to a multiple of four characters and
    # needs no padding; 4096-bit RSA and ed25519 do. Publishers strip the
    # trailing "=" often enough that rejecting it misreports working keys.
    # Restoring it cannot mask corruption: a truncated value still decodes to
    # truncated DER, and the DER parser is the stricter check.
    padding_repaired = False
    if len(encoded) % 4:
        encoded += "=" * (-len(encoded) % 4)
        padding_repaired = True

    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return DkimKey(
            selector=selector,
            source="txt",
            record=record,
            key_type=key_type,
            testing=testing,
            parse_error="p value is not valid base64",
        )

    if key_type == "ed25519":
        # An ed25519 public key is 32 raw bytes with no structure to parse.
        return DkimKey(
            selector=selector,
            source="txt",
            record=record,
            key_type=key_type,
            bits=len(raw) * 8,
            testing=testing,
            padding_repaired=padding_repaired,
            parse_error=None if len(raw) == 32 else "ed25519 key is not 32 bytes",
        )

    try:
        bits = rsa_key_bits(raw)
    except ValueError as exc:
        return DkimKey(
            selector=selector,
            source="txt",
            record=record,
            key_type=key_type,
            testing=testing,
            parse_error=str(exc),
        )

    return DkimKey(
        selector=selector,
        source="txt",
        record=record,
        key_type=key_type,
        bits=bits,
        testing=testing,
        padding_repaired=padding_repaired,
    )


def is_key_record(text: str) -> bool:
    """True for a TXT record that looks like a DKIM key rather than something else."""
    lowered = text.strip().lower()
    return lowered.startswith("v=dkim1") or "p=" in lowered


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------


def has_wildcard_domainkey(
    resolver: Resolver, domain: str, label: str | None = None
) -> bool:
    """True when a selector that cannot exist still answers.

    A wildcard record under the domain makes every selector probe succeed.
    Without this guard the check reports keys that are not there, which is worse
    than reporting nothing.
    """
    label = label or ("zz" + secrets.token_hex(8) + "-nonexistent")
    name = f"{label}._domainkey.{domain}"
    if resolver.cname(name).values:
        return True
    return bool(resolver.txt(name).values)


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
        area="DKIM",
        severity=severity,
        confidence=confidence,
        title=title,
        detail=detail,
        evidence={k: v for k, v in evidence.items() if v},
    )


def check(
    resolver: Resolver,
    domain: str,
    provider: Provider | None = None,
    extra_selectors: list[str] | None = None,
) -> DkimResult:
    """Probe selectors for one domain and inspect whatever keys turn up."""
    findings: list[Finding] = []
    selectors = selectors_for(provider, extra_selectors)

    if has_wildcard_domainkey(resolver, domain):
        findings.append(
            _finding(
                "dkim.wildcard",
                Severity.WARNING,
                Confidence.HIGH,
                "A wildcard DNS record makes DKIM impossible to assess from outside",
                "A selector name that cannot exist still returns a record, so every "
                "probe answers and none of the answers mean anything. Nothing can be "
                "said about this domain's DKIM keys without access to its DNS.",
            )
        )
        findings.append(
            Finding(
                code="dns.wildcard",
                area="DNS",
                severity=Severity.WARNING,
                confidence=Confidence.HIGH,
                title="A wildcard record is published under this domain",
                detail=(
                    "Every name under the domain resolves, including ones nobody "
                    "created. Beyond making DKIM unreadable, this means typos and "
                    "invented subdomains all answer, which is worth addressing on its "
                    "own."
                ),
            )
        )
        return DkimResult(selectors_tried=selectors, wildcard=True, findings=findings)

    keys: list[DkimKey] = []
    probe_failures: list[str] = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"

        # Query TXT first: the resolver follows any CNAME chain, so a Microsoft
        # 365 style delegation still yields the key record at the far end.
        txt = resolver.txt(name)
        key_records = [v for v in txt.values if is_key_record(v)]

        cname = resolver.cname(name)
        cname_target = cname.values[0] if cname.values else None

        # A probe that failed tells us nothing about this selector. Record it so
        # nothing downstream mistakes it for a definitive absence: NXDOMAIN means
        # the name does not exist, a timeout means we did not get to ask.
        if txt.status.is_our_fault or cname.status.is_our_fault:
            probe_failures.append(selector)
            continue

        if key_records:
            key = parse_key_record(selector, key_records[0])
            if cname_target:
                key = DkimKey(
                    selector=key.selector,
                    source="cname",
                    record=key.record,
                    cname_target=cname_target,
                    key_type=key.key_type,
                    bits=key.bits,
                    testing=key.testing,
                    revoked=key.revoked,
                    parse_error=key.parse_error,
                )
            keys.append(key)
        elif cname_target:
            # A delegation exists but the target holds no readable key. Worth
            # recording: this is what a half-finished DKIM setup looks like.
            keys.append(
                DkimKey(
                    selector=selector,
                    source="cname",
                    cname_target=cname_target,
                    parse_error="the delegated name publishes no key record",
                )
            )

    selector_list = ", ".join(selectors)
    decisive = [s for s in (provider.selectors if provider else ()) if s in selectors]
    result = DkimResult(
        selectors_tried=selectors,
        keys=keys,
        findings=findings,
        probe_failures=probe_failures,
        decisive_selectors=decisive,
    )

    # A probe ends in one of three places, and they are not interchangeable. Only
    # a usable key answers "does this domain have DKIM"; a malformed record and a
    # delegation with nothing behind it are separate observations that a receiver
    # can do exactly as much with as it can do with nothing.
    usable = result.usable_keys
    unreadable = result.unreadable_keys
    delegations = result.delegations_without_key

    if not result.observed:
        # Every probe failed. We never got to ask, so there is nothing to say
        # about this domain's DKIM and nothing to score. Mirrors mx.unreachable
        # and dmarc.unreachable, which carry weight 0 for the same reason.
        findings.append(
            _finding(
                "dkim.unreachable",
                Severity.INFO,
                Confidence.LOW,
                f"DKIM could not be checked: all {len(selectors)} selector probes "
                f"failed to return an answer",
                "The queries did not fail to find a record, they failed to complete. "
                "That is a fact about this vantage point rather than about the "
                "domain, so nothing is concluded from it and nothing is scored.",
                selectors_tried=selector_list,
            )
        )
    elif not result.published_something:
        detail = (
            f"Selectors cannot be enumerated from DNS, so this is not proof that the "
            f"domain has no DKIM key. It means no key was found on the "
            f"{len(selectors)} selectors tried."
        )
        if provider and provider.selectors and not provider.selectors_unguessable:
            detail += (
                f" The default selectors for {provider.name} "
                f"({', '.join(provider.selectors)}) were among them, which makes a "
                f"real absence more likely for this domain."
            )
        elif provider and provider.selectors_unguessable:
            detail += (
                f" {provider.name} assigns selectors per tenant, so a miss here "
                f"carries very little information."
            )
        if delegations:
            detail += (
                f" {len(delegations)} selector(s) do have a delegation published, "
                f"but the name each one points at holds no key record."
            )
        # Some of the provider's own selectors went unanswered while others
        # replied. The sweep is not blind - `observed` covers that case - but it
        # is weaker than one where every decisive selector answered, and this is
        # the mechanism that already exists for saying so.
        decisive_unanswered = sorted(set(decisive) & set(probe_failures))
        if decisive_unanswered:
            detail += (
                f" The probe for {', '.join(decisive_unanswered)} did not return an "
                f"answer, so part of what would settle this went unchecked."
            )
        confidence = (
            Confidence.LOW
            if (not provider or provider.selectors_unguessable or decisive_unanswered)
            else Confidence.MEDIUM
        )
        findings.append(
            _finding(
                "dkim.none_found",
                Severity.WARNING,
                # Never HIGH. A miss is a miss, not an absence.
                confidence,
                f"No DKIM key found on the {len(selectors)} selectors tried",
                detail,
                selectors_tried=selector_list,
                probes_unanswered=", ".join(sorted(probe_failures)),
            )
        )

    if usable:
        extra = ""
        if unreadable or delegations:
            parts = []
            if unreadable:
                parts.append(f"{len(unreadable)} published a record that does not parse")
            if delegations:
                parts.append(f"{len(delegations)} delegate to a name with no key")
            extra = " Separately, " + " and ".join(parts) + "."
        findings.append(
            _finding(
                "dkim.key_found",
                Severity.OK,
                Confidence.HIGH,
                f"DKIM key published on {len(usable)} of the {len(selectors)} "
                f"selectors tried",
                extra.strip(),
                selectors_found=", ".join(k.selector for k in usable),
                selectors_tried=selector_list,
            )
        )

    live = usable

    for key in keys:
        if key.revoked:
            findings.append(
                _finding(
                    "dkim.revoked",
                    Severity.WARNING,
                    Confidence.HIGH,
                    f"Selector {key.selector} publishes a revoked key (empty p tag)",
                    "An empty p value withdraws the key, per RFC 6376 section "
                    "3.6.1. Any mail still signed with "
                    "it fails DKIM. This is normal immediately after a key rotation "
                    "and a problem if it is the only selector published.",
                    selector=key.selector,
                )
            )
        if key.testing:
            findings.append(
                _finding(
                    "dkim.testing_mode",
                    Severity.WARNING,
                    Confidence.HIGH,
                    f"Selector {key.selector} is in test mode (t=y)",
                    "RFC 6376 defines t=y as test mode: receivers are asked to treat "
                    "a signature failure as though the message were unsigned, so the "
                    "signature provides no protection. "
                    "This flag is meant to be removed once a key is verified working.",
                    selector=key.selector,
                )
            )
        if key.bits is not None and key.key_type == "rsa":
            if key.bits < WEAK_KEY_BITS:
                findings.append(
                    _finding(
                        "dkim.key_too_short",
                        Severity.WARNING,
                        Confidence.HIGH,
                        f"Selector {key.selector} publishes a {key.bits}-bit RSA key",
                        f"RFC 8301 sets {WEAK_KEY_BITS} bits as the floor for signing "
                        f"keys and recommends {RECOMMENDED_KEY_BITS}. Some receivers "
                        f"ignore signatures made with keys below the floor.",
                        selector=key.selector,
                        bits=str(key.bits),
                    )
                )
            elif key.bits < RECOMMENDED_KEY_BITS:
                findings.append(
                    _finding(
                        "dkim.key_1024",
                        Severity.INFO,
                        Confidence.HIGH,
                        f"Selector {key.selector} publishes a {key.bits}-bit RSA key",
                        f"Acceptable, but {RECOMMENDED_KEY_BITS} bits is the current "
                        f"recommendation.",
                        selector=key.selector,
                        bits=str(key.bits),
                    )
                )
        if key.padding_repaired:
            findings.append(
                _finding(
                    "dkim.padding_repaired",
                    Severity.INFO,
                    Confidence.HIGH,
                    f"Selector {key.selector} publishes a key whose base64 padding "
                    f"is missing",
                    "The key itself is valid and was read correctly once the "
                    "padding was restored, so this is a note rather than a fault. "
                    "Some strict parsers reject an unpadded value outright, so it "
                    "is worth republishing the record exactly as the mail provider "
                    "supplied it, trailing = characters included.",
                    selector=key.selector,
                )
            )
        if key.parse_error and not key.revoked:
            if key.record is not None:
                # Broken: something is published and no receiver can read it.
                # Directly observed - we retrieved the record and inspected it -
                # so this is stated with full confidence, unlike anything that
                # rests on a selector guess.
                findings.append(
                    _finding(
                        "dkim.unparseable",
                        Severity.WARNING,
                        Confidence.HIGH,
                        f"Selector {key.selector} publishes a key record that cannot "
                        f"be read",
                        f"A record is published at this selector, so DKIM was set up "
                        f"at some point, but the key in it cannot be parsed: "
                        f"{key.parse_error}. A receiver reaching this record gets "
                        f"nothing it can verify a signature against, so mail signed "
                        f"with this selector authenticates no better than unsigned "
                        f"mail. The usual cause is the value being altered when it "
                        f"was pasted into a DNS control panel.",
                        selector=key.selector,
                    )
                )
            else:
                # Absent: the delegation resolves, the target holds no key. The
                # default Microsoft 365 state when a domain is added and DKIM is
                # never switched on. Its own code, because it is a different
                # conversation from a malformed record and needs to be
                # distinguishable in the run history and in a diff.
                findings.append(
                    _finding(
                        "dkim.delegation_without_key",
                        Severity.WARNING,
                        Confidence.HIGH,
                        f"Selector {key.selector} delegates to a name that publishes "
                        f"no key",
                        f"The CNAME at this selector resolves to "
                        f"{key.cname_target}, and that name holds no key record. "
                        f"This is what a half-finished DKIM setup looks like: the "
                        f"delegation was created and the key was never generated at "
                        f"the other end. Nothing is signing mail for this domain "
                        f"through this selector.",
                        selector=key.selector,
                    )
                )

    # Microsoft 365 signs as the tenant unless DKIM is enabled for the custom
    # domain. The selector exists either way, so presence alone is misleading.
    if provider and provider.key == "microsoft365" and live:
        targets = " ".join(k.cname_target or "" for k in live).lower()
        if "onmicrosoft.com" in targets and domain.lower() not in targets:
            findings.append(
                _finding(
                    "dkim.m365_tenant_signing",
                    Severity.WARNING,
                    Confidence.MEDIUM,
                    "DKIM selectors point at the tenant rather than this domain",
                    "Outbound mail may be signed as the onmicrosoft.com tenant instead "
                    "of this domain. A signature that does not carry this domain does "
                    "not align for DMARC, so DMARC would still fail on DKIM. Worth "
                    "confirming in the Microsoft 365 admin center.",
                    targets=targets.strip(),
                )
            )

    return DkimResult(
        selectors_tried=selectors,
        keys=keys,
        findings=findings,
        probe_failures=probe_failures,
        decisive_selectors=decisive,
    )
