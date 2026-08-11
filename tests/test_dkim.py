"""
tests/test_dkim.py - selector derivation, key parsing, and the wildcard guard.

The most important assertions in this file are the ones about language and
confidence: nothing this module produces may claim a domain has no DKIM, and
nothing it produces about a missing key may be high confidence.
"""

from __future__ import annotations

import base64

import pytest

from mailauth.checks import dkim
from mailauth.models import Confidence
from mailauth.providers import PROVIDERS_BY_KEY
from tests.conftest import (
    RSA_512_P,
    RSA_1024_P,
    RSA_2048_P,
    FakeResolver,
    make_dkim_p,
    make_rsa_spki,
)

# ---------------------------------------------------------------------------
# key parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bits", [512, 1024, 2048, 4096])
def test_rsa_modulus_length_is_recovered(bits: int) -> None:
    assert dkim.rsa_key_bits(make_rsa_spki(bits)) == bits


def test_bare_pkcs1_key_is_also_accepted() -> None:
    """Some appliances publish an RSAPublicKey rather than a SubjectPublicKeyInfo."""
    from tests.conftest import _der, _der_integer

    modulus = bytearray(b"\xcd" * 128)
    modulus[0] |= 0x80
    pkcs1 = _der(0x30, _der_integer(bytes(modulus)) + _der_integer(b"\x01\x00\x01"))
    assert dkim.rsa_key_bits(pkcs1) == 1024


def test_truncated_der_raises_rather_than_guessing() -> None:
    with pytest.raises(ValueError):
        dkim.rsa_key_bits(make_rsa_spki(2048)[:40])


def test_key_record_reports_algorithm_and_size() -> None:
    key = dkim.parse_key_record("s1", f"v=DKIM1; k=rsa; p={RSA_2048_P}")
    assert key.key_type == "rsa"
    assert key.bits == 2048
    assert not key.revoked
    assert not key.testing
    assert key.parse_error is None


def test_empty_p_is_a_revoked_key_not_a_parse_failure() -> None:
    key = dkim.parse_key_record("s1", "v=DKIM1; k=rsa; p=")
    assert key.revoked
    assert key.parse_error is None
    assert key.bits is None


def test_test_mode_flag_is_read() -> None:
    key = dkim.parse_key_record("s1", f"v=DKIM1; k=rsa; t=y; p={RSA_2048_P}")
    assert key.testing


def test_test_mode_among_several_flags_is_read() -> None:
    key = dkim.parse_key_record("s1", f"v=DKIM1; k=rsa; t=s:y; p={RSA_2048_P}")
    assert key.testing


def test_ed25519_key_needs_no_der_parsing() -> None:
    raw = base64.b64encode(b"\x11" * 32).decode("ascii")
    key = dkim.parse_key_record("s1", f"v=DKIM1; k=ed25519; p={raw}")
    assert key.key_type == "ed25519"
    assert key.bits == 256
    assert key.parse_error is None


def test_invalid_base64_is_reported_not_raised() -> None:
    key = dkim.parse_key_record("s1", "v=DKIM1; k=rsa; p=not!valid!base64!")
    assert key.parse_error is not None
    assert key.bits is None


def test_whitespace_inside_p_is_stripped() -> None:
    """DNS panels wrap long values, and the wrapping ends up inside the record."""
    wrapped = RSA_2048_P[:40] + " " + RSA_2048_P[40:]
    key = dkim.parse_key_record("s1", f"v=DKIM1; k=rsa; p={wrapped}")
    assert key.bits == 2048


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------


def test_key_found_on_a_provider_selector() -> None:
    zone = {("google._domainkey.g.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]}
    result = dkim.check(FakeResolver(zone), "g.test", PROVIDERS_BY_KEY["google"])

    assert result.any_key_found
    assert result.keys[0].selector == "google"
    assert result.keys[0].bits == 2048
    assert "dkim.key_found" in {f.code for f in result.findings}


def test_provider_selectors_are_tried_first() -> None:
    result = dkim.check(FakeResolver({}), "m.test", PROVIDERS_BY_KEY["microsoft365"])
    assert result.selectors_tried[:2] == ["selector1", "selector2"]


def test_extra_selectors_are_tried_before_everything_else() -> None:
    result = dkim.check(
        FakeResolver({}), "e.test", None, extra_selectors=["custom1", "custom2"]
    )
    assert result.selectors_tried[:2] == ["custom1", "custom2"]


def test_selectors_tried_are_always_recorded() -> None:
    result = dkim.check(FakeResolver({}), "n.test", None)
    assert len(result.selectors_tried) > 10
    finding = next(f for f in result.findings if f.code == "dkim.none_found")
    assert "selectors_tried" in finding.evidence


def test_a_miss_is_never_stated_as_absence() -> None:
    """The core language constraint.

    "No DKIM key found on the 23 selectors tried" is correct. A bare "no DKIM"
    is not. The rule this asserts is that every sentence making the claim also
    carries its qualification, so no sentence can be quoted out of the report and
    become an overstatement.
    """
    result = dkim.check(FakeResolver({}), "n.test", None)
    finding = next(f for f in result.findings if f.code == "dkim.none_found")

    text = f"{finding.title}. {finding.detail}".lower()
    assert "selectors tried" in text
    assert "not proof" in text

    for sentence in (s.strip() for s in text.split(".") if "no dkim" in s):
        qualified = "selector" in sentence or "not proof" in sentence
        assert qualified, f"unqualified DKIM absence claim: {sentence!r}"


def test_a_miss_is_never_high_confidence() -> None:
    for provider_key in (None, "google", "microsoft365", "proofpoint"):
        provider = PROVIDERS_BY_KEY[provider_key] if provider_key else None
        result = dkim.check(FakeResolver({}), "n.test", provider)
        finding = next(f for f in result.findings if f.code == "dkim.none_found")
        assert finding.confidence != Confidence.HIGH, provider_key


def test_unguessable_provider_lowers_confidence_further() -> None:
    """Proofpoint assigns selectors per tenant, so a miss says almost nothing."""
    known = dkim.check(FakeResolver({}), "n.test", PROVIDERS_BY_KEY["google"])
    unguessable = dkim.check(FakeResolver({}), "n.test", PROVIDERS_BY_KEY["proofpoint"])

    known_finding = next(f for f in known.findings if f.code == "dkim.none_found")
    unguessable_finding = next(
        f for f in unguessable.findings if f.code == "dkim.none_found"
    )
    assert known_finding.confidence == Confidence.MEDIUM
    assert unguessable_finding.confidence == Confidence.LOW


# ---------------------------------------------------------------------------
# wildcard guard
# ---------------------------------------------------------------------------


class WildcardResolver(FakeResolver):
    """Answers every _domainkey query, as a wildcard zone would."""

    def query(self, name: str, rdtype: str):  # type: ignore[no-untyped-def]
        if "_domainkey" in name and rdtype == "TXT":
            return super().query("wildcard.hit", "TXT")
        return super().query(name, rdtype)


def test_wildcard_is_detected_and_stops_the_probe() -> None:
    resolver = WildcardResolver(
        {("wildcard.hit", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]}
    )
    result = dkim.check(resolver, "wild.test", None)

    assert result.wildcard
    assert not result.keys
    codes = {f.code for f in result.findings}
    assert "dkim.wildcard" in codes
    assert "dns.wildcard" in codes
    # No key may be claimed on a wildcard zone, however many probes answered.
    assert "dkim.key_found" not in codes


def test_a_clean_zone_produces_no_false_wildcard() -> None:
    assert not dkim.has_wildcard_domainkey(FakeResolver({}), "clean.test")


def test_wildcard_detection_does_not_depend_on_the_label_chosen() -> None:
    resolver = WildcardResolver({("wildcard.hit", "TXT"): ["anything"]})
    assert dkim.has_wildcard_domainkey(resolver, "w.test", label="fixed-label")
    assert dkim.has_wildcard_domainkey(resolver, "w.test")


# ---------------------------------------------------------------------------
# key quality
# ---------------------------------------------------------------------------


def test_short_key_is_flagged() -> None:
    zone = {("default._domainkey.s.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_512_P}"]}
    result = dkim.check(FakeResolver(zone), "s.test", None)
    assert "dkim.key_too_short" in {f.code for f in result.findings}


def test_1024_bit_key_is_noted_but_not_flagged_as_too_short() -> None:
    zone = {("default._domainkey.k.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_1024_P}"]}
    result = dkim.check(FakeResolver(zone), "k.test", None)
    codes = {f.code for f in result.findings}
    assert "dkim.key_1024" in codes
    assert "dkim.key_too_short" not in codes


def test_2048_bit_key_raises_no_size_finding() -> None:
    zone = {("default._domainkey.g.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]}
    result = dkim.check(FakeResolver(zone), "g.test", None)
    codes = {f.code for f in result.findings}
    assert "dkim.key_1024" not in codes
    assert "dkim.key_too_short" not in codes


def test_revoked_key_is_flagged() -> None:
    zone = {("default._domainkey.r.test", "TXT"): ["v=DKIM1; k=rsa; p="]}
    result = dkim.check(FakeResolver(zone), "r.test", None)
    assert "dkim.revoked" in {f.code for f in result.findings}


def test_testing_mode_is_flagged() -> None:
    zone = {("default._domainkey.t.test", "TXT"): [f"v=DKIM1; k=rsa; t=y; p={RSA_2048_P}"]}
    result = dkim.check(FakeResolver(zone), "t.test", None)
    assert "dkim.testing_mode" in {f.code for f in result.findings}


def test_microsoft_tenant_signing_is_flagged() -> None:
    """Selectors exist but point at the tenant, so DKIM does not align for DMARC."""
    zone = {
        ("selector1._domainkey.m.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"],
        ("selector1._domainkey.m.test", "CNAME"): [
            "selector1-m-test._domainkey.contoso.onmicrosoft.com"
        ],
    }
    result = dkim.check(FakeResolver(zone), "m.test", PROVIDERS_BY_KEY["microsoft365"])
    assert "dkim.m365_tenant_signing" in {f.code for f in result.findings}


def test_cname_delegation_with_no_key_behind_it_is_recorded() -> None:
    zone = {
        ("selector1._domainkey.h.test", "CNAME"): ["nowhere.example.test"],
    }
    result = dkim.check(FakeResolver(zone), "h.test", PROVIDERS_BY_KEY["microsoft365"])
    assert result.keys[0].cname_target == "nowhere.example.test"
    # A delegation with nothing behind it is its own code, not "unparseable":
    # there is no record here to have failed to parse.
    assert "dkim.delegation_without_key" in {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# the three key states
#
# A selector probe can end in three materially different places, and conflating
# them is what let a Microsoft 365 domain with dangling CNAMEs be reported as
# having DKIM:
#
#   usable       a key record was retrieved and parsed
#   broken       a key record was retrieved and cannot be parsed by anyone
#   absent       a delegation resolved but nothing is published behind it
# ---------------------------------------------------------------------------


def m365_delegation_only_zone(domain: str) -> dict[tuple[str, str], list[str]]:
    """The default Microsoft 365 state: CNAMEs added, DKIM never enabled."""
    dashed = domain.replace(".", "-")
    return {
        (f"selector1._domainkey.{domain}", "CNAME"): [
            f"selector1-{dashed}._domainkey.tenant.onmicrosoft.com"
        ],
        (f"selector2._domainkey.{domain}", "CNAME"): [
            f"selector2-{dashed}._domainkey.tenant.onmicrosoft.com"
        ],
    }


# The quoted-key shape: whoever entered the record pasted quote characters
# into the DNS panel, so the published p= value is not decodable by any
# receiver. Observed in the wild on a live domain; reproduced here under a
# reserved name because the defect is what matters, not who exhibited it.
BROKEN_QUOTED_KEY = f'v=DKIM1; k=rsa; p={RSA_2048_P[:120]}" "{RSA_2048_P[120:]}'


def test_delegation_without_a_key_is_not_a_usable_key() -> None:
    result = dkim.check(
        FakeResolver(m365_delegation_only_zone("h.test")),
        "h.test",
        PROVIDERS_BY_KEY["microsoft365"],
    )
    assert result.usable_keys == []
    assert not result.any_key_found
    assert len(result.delegations_without_key) == 2


def test_delegation_only_never_claims_a_key_was_published() -> None:
    """The bug this section exists for: 'DKIM key published on 2 selectors'."""
    result = dkim.check(
        FakeResolver(m365_delegation_only_zone("h.test")),
        "h.test",
        PROVIDERS_BY_KEY["microsoft365"],
    )
    assert "dkim.key_found" not in {f.code for f in result.findings}


def test_the_dangling_delegation_is_still_surfaced() -> None:
    """It is not a key, but it is a finding, and it must not be dropped."""
    result = dkim.check(
        FakeResolver(m365_delegation_only_zone("h.test")),
        "h.test",
        PROVIDERS_BY_KEY["microsoft365"],
    )
    assert "dkim.delegation_without_key" in {f.code for f in result.findings}
    assert [k.cname_target for k in result.delegations_without_key] == [
        "selector1-h-test._domainkey.tenant.onmicrosoft.com",
        "selector2-h-test._domainkey.tenant.onmicrosoft.com",
    ]


def test_a_broken_key_is_not_usable_but_is_published() -> None:
    zone = {("default._domainkey.b.test", "TXT"): [BROKEN_QUOTED_KEY]}
    result = dkim.check(FakeResolver(zone), "b.test", None)

    assert result.usable_keys == []
    assert not result.any_key_found
    assert len(result.unreadable_keys) == 1
    assert result.unreadable_keys[0].parse_error is not None


def test_a_broken_key_does_not_produce_a_none_found_claim() -> None:
    """They published something. Telling them they published nothing is wrong."""
    zone = {("default._domainkey.b.test", "TXT"): [BROKEN_QUOTED_KEY]}
    result = dkim.check(FakeResolver(zone), "b.test", None)
    codes = {f.code for f in result.findings}

    assert "dkim.none_found" not in codes
    assert "dkim.unparseable" in codes
    assert "dkim.key_found" not in codes


def test_the_broken_finding_says_the_record_cannot_be_read() -> None:
    zone = {("default._domainkey.b.test", "TXT"): [BROKEN_QUOTED_KEY]}
    result = dkim.check(FakeResolver(zone), "b.test", None)
    finding = next(f for f in result.findings if f.code == "dkim.unparseable")

    text = f"{finding.title} {finding.detail}".lower()
    assert "published" in text
    assert "read" in text or "parse" in text
    # We retrieved and inspected the record. That is observation, not inference.
    assert finding.confidence == Confidence.HIGH


def test_a_revoked_key_is_not_usable() -> None:
    zone = {("default._domainkey.r.test", "TXT"): ["v=DKIM1; k=rsa; p="]}
    result = dkim.check(FakeResolver(zone), "r.test", None)

    assert result.usable_keys == []
    assert not result.any_key_found
    assert "dkim.none_found" not in {f.code for f in result.findings}


def test_none_found_still_fires_when_nothing_at_all_was_published() -> None:
    result = dkim.check(FakeResolver({}), "n.test", None)
    assert "dkim.none_found" in {f.code for f in result.findings}


def test_a_mixed_domain_counts_only_the_usable_key() -> None:
    zone = dict(m365_delegation_only_zone("m.test"))
    zone[("default._domainkey.m.test", "TXT")] = [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]
    result = dkim.check(FakeResolver(zone), "m.test", PROVIDERS_BY_KEY["microsoft365"])

    assert len(result.usable_keys) == 1
    assert len(result.delegations_without_key) == 2
    finding = next(f for f in result.findings if f.code == "dkim.key_found")
    assert "1 of the" in finding.title, finding.title
    assert "3 of the" not in finding.title


# ---------------------------------------------------------------------------
# each state gets its own finding code
#
# Sharing a code means sharing a weight and a confidence, and being
# indistinguishable in the run history and in `diff`. These are three different
# conversations with a client, so they are three codes.
# ---------------------------------------------------------------------------


def test_a_malformed_record_emits_only_the_unparseable_code() -> None:
    zone = {("default._domainkey.u.test", "TXT"): [BROKEN_QUOTED_KEY]}
    codes = {f.code for f in dkim.check(FakeResolver(zone), "u.test", None).findings}

    assert "dkim.unparseable" in codes
    assert "dkim.delegation_without_key" not in codes
    assert "dkim.revoked" not in codes


def test_a_dangling_delegation_emits_only_the_delegation_code() -> None:
    result = dkim.check(
        FakeResolver(m365_delegation_only_zone("d.test")),
        "d.test",
        PROVIDERS_BY_KEY["microsoft365"],
    )
    codes = {f.code for f in result.findings}

    assert "dkim.delegation_without_key" in codes
    assert "dkim.unparseable" not in codes
    assert "dkim.revoked" not in codes


def test_a_revoked_key_emits_only_the_revoked_code() -> None:
    zone = {("default._domainkey.v.test", "TXT"): ["v=DKIM1; k=rsa; p="]}
    codes = {f.code for f in dkim.check(FakeResolver(zone), "v.test", None).findings}

    assert "dkim.revoked" in codes
    assert "dkim.unparseable" not in codes
    assert "dkim.delegation_without_key" not in codes


def test_all_three_states_on_one_domain_stay_distinct() -> None:
    zone = dict(m365_delegation_only_zone("all.test"))
    zone[("default._domainkey.all.test", "TXT")] = [BROKEN_QUOTED_KEY]
    zone[("dkim._domainkey.all.test", "TXT")] = ["v=DKIM1; k=rsa; p="]
    result = dkim.check(FakeResolver(zone), "all.test", PROVIDERS_BY_KEY["microsoft365"])
    codes = {f.code for f in result.findings}

    assert {"dkim.unparseable", "dkim.revoked", "dkim.delegation_without_key"} <= codes
    assert len(result.unreadable_keys) == 1
    assert len(result.revoked_keys) == 1
    assert len(result.delegations_without_key) == 2
    assert result.usable_keys == []


def test_the_delegation_finding_names_the_target() -> None:
    result = dkim.check(
        FakeResolver(m365_delegation_only_zone("d.test")),
        "d.test",
        PROVIDERS_BY_KEY["microsoft365"],
    )
    finding = next(f for f in result.findings if f.code == "dkim.delegation_without_key")
    assert "onmicrosoft.com" in f"{finding.title} {finding.detail}"
    assert finding.confidence == Confidence.HIGH


def test_all_three_observed_states_are_high_confidence() -> None:
    """None of these is a selector guess: we retrieved or resolved every one."""
    zone = dict(m365_delegation_only_zone("all.test"))
    zone[("default._domainkey.all.test", "TXT")] = [BROKEN_QUOTED_KEY]
    zone[("dkim._domainkey.all.test", "TXT")] = ["v=DKIM1; k=rsa; p="]
    result = dkim.check(FakeResolver(zone), "all.test", PROVIDERS_BY_KEY["microsoft365"])

    for code in ("dkim.unparseable", "dkim.revoked", "dkim.delegation_without_key"):
        finding = next(f for f in result.findings if f.code == code)
        assert finding.confidence == Confidence.HIGH, code


def test_a_revoked_only_domain_is_not_told_it_published_nothing() -> None:
    zone = {("default._domainkey.v.test", "TXT"): ["v=DKIM1; k=rsa; p="]}
    result = dkim.check(FakeResolver(zone), "v.test", None)

    assert result.usable_keys == []
    assert not result.any_key_found
    assert result.published_something
    assert "dkim.none_found" not in {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# a failed selector probe is not an absent key
#
# NXDOMAIN is a definitive answer: the name does not exist. SERVFAIL and a
# timeout are the absence of an answer. The resolver distinguishes them; this
# module used to read only `.values` and throw the distinction away, so a
# resolver hiccup mid-sweep looked exactly like a key that had been withdrawn.
# ---------------------------------------------------------------------------


def all_selector_probes(domain: str) -> set[tuple[str, str]]:
    from mailauth.providers import selectors_for

    return {
        (f"{s}._domainkey.{domain}", t)
        for s in selectors_for(None)
        for t in ("TXT", "CNAME")
    }


def test_a_failed_selector_probe_is_recorded_not_silently_dropped() -> None:
    zone = {("google._domainkey.p.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]}
    resolver = FakeResolver(zone, fail=all_selector_probes("p.test"))
    result = dkim.check(resolver, "p.test", None)

    assert result.probe_failures, "a timed-out probe must be recorded"
    assert "google" in result.probe_failures


def test_nxdomain_on_a_selector_is_not_recorded_as_a_failure() -> None:
    """A definitive 'this name does not exist' is an answer, not a failure."""
    result = dkim.check(FakeResolver({}), "n.test", None)
    assert result.probe_failures == []


def test_probe_failures_survive_serialisation() -> None:
    resolver = FakeResolver({}, fail=all_selector_probes("p.test"))
    payload = dkim.check(resolver, "p.test", None).to_dict()
    assert payload["probe_failed_selectors"]


def test_a_total_probe_failure_does_not_claim_no_key_was_found() -> None:
    """We did not get to ask. That is not the same as asking and finding nothing."""
    resolver = FakeResolver({}, fail=all_selector_probes("p.test"))
    result = dkim.check(resolver, "p.test", None)
    codes = {f.code for f in result.findings}

    assert "dkim.unreachable" in codes
    assert "dkim.none_found" not in codes


def test_the_unreachable_finding_is_low_confidence() -> None:
    resolver = FakeResolver({}, fail=all_selector_probes("p.test"))
    result = dkim.check(resolver, "p.test", None)
    finding = next(f for f in result.findings if f.code == "dkim.unreachable")
    assert finding.confidence == Confidence.LOW


def test_dkim_is_marked_unobserved_when_every_probe_failed() -> None:
    resolver = FakeResolver({}, fail=all_selector_probes("p.test"))
    assert not dkim.check(resolver, "p.test", None).observed


def test_dkim_is_observed_on_a_normal_sweep() -> None:
    assert dkim.check(FakeResolver({}), "n.test", None).observed


def test_a_wildcard_zone_is_also_unobserved() -> None:
    resolver = WildcardResolver({("wildcard.hit", "TXT"): ["v=DKIM1; k=rsa; p=x"]})
    assert not dkim.check(resolver, "w.test", None).observed


# ---------------------------------------------------------------------------
# provider selectors decide whether a sweep learned anything
#
# The fraction of failed probes is the wrong measure. On a Google Workspace
# domain, one unanswered probe (google) is the blind case and twenty-two
# unanswered generic probes with google answering is the informative one. What
# matters is whether the provider's own selectors answered.
# ---------------------------------------------------------------------------


GOOGLE_ZONE = {
    ("g.test", "MX"): ["1 aspmx.l.google.com"],
    ("aspmx.l.google.com", "A"): ["142.250.1.26"],
}
M365_ZONE = {
    ("m.test", "MX"): ["0 m-test.mail.protection.outlook.com"],
    ("m-test.mail.protection.outlook.com", "A"): ["104.47.1.1"],
}


def test_a_failed_provider_selector_means_the_sweep_learned_nothing() -> None:
    """One unanswered probe out of 23, and it is the only one that mattered."""
    fail = {("google._domainkey.g.test", t) for t in ("TXT", "CNAME")}
    result = dkim.check(
        FakeResolver(GOOGLE_ZONE, fail=fail), "g.test", PROVIDERS_BY_KEY["google"]
    )

    assert not result.observed
    codes = {f.code for f in result.findings}
    assert "dkim.unreachable" in codes
    assert "dkim.none_found" not in codes


def test_failed_generic_selectors_do_not_blind_the_sweep() -> None:
    """Twenty-two unanswered probes, and the decisive one answered."""
    from mailauth.providers import selectors_for

    fail = {
        (f"{s}._domainkey.g.test", t)
        for s in selectors_for(PROVIDERS_BY_KEY["google"])
        if s != "google"
        for t in ("TXT", "CNAME")
    }
    result = dkim.check(
        FakeResolver(GOOGLE_ZONE, fail=fail), "g.test", PROVIDERS_BY_KEY["google"]
    )

    assert result.observed
    assert "dkim.none_found" in {f.code for f in result.findings}


def test_one_of_two_provider_selectors_failing_lowers_confidence() -> None:
    """Microsoft publishes two. One answered, so the sweep is not blind."""
    fail = {("selector1._domainkey.m.test", t) for t in ("TXT", "CNAME")}
    result = dkim.check(
        FakeResolver(M365_ZONE, fail=fail), "m.test", PROVIDERS_BY_KEY["microsoft365"]
    )

    assert result.observed
    finding = next(f for f in result.findings if f.code == "dkim.none_found")
    assert finding.confidence == Confidence.LOW


def test_both_provider_selectors_failing_blinds_the_sweep() -> None:
    fail = {
        (f"{s}._domainkey.m.test", t)
        for s in ("selector1", "selector2")
        for t in ("TXT", "CNAME")
    }
    result = dkim.check(
        FakeResolver(M365_ZONE, fail=fail), "m.test", PROVIDERS_BY_KEY["microsoft365"]
    )
    assert not result.observed


def test_an_unidentified_provider_keeps_the_all_probes_rule() -> None:
    """With no provider there is no decisive selector, so only a total failure blinds."""
    fail = {("default._domainkey.n.test", t) for t in ("TXT", "CNAME")}
    result = dkim.check(FakeResolver({}, fail=fail), "n.test", None)
    assert result.observed


# ---------------------------------------------------------------------------
# adversarial DER
#
# Every one of these must produce a parse_error string. An unhandled exception
# here aborts a batch run partway through a prospect list, losing every domain
# after the malformed one.
# ---------------------------------------------------------------------------


def der(tag: int, value: bytes) -> bytes:
    from tests.conftest import _der

    return _der(tag, value)


def as_p(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@pytest.mark.parametrize("cut", [1, 5, 20, 40, 100, 293])
def test_truncated_spki_at_any_offset_reports_rather_than_raises(cut: int) -> None:
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(make_rsa_spki(2048)[:cut])}")
    assert key.parse_error is not None
    assert key.bits is None


def test_a_long_form_length_claiming_gigabytes_is_rejected() -> None:
    """The buffer is 9 bytes and the header claims 4GB."""
    blob = bytes([0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]) + b"\x02\x01\x01"
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
    assert key.parse_error is not None


def test_a_length_field_wider_than_four_bytes_is_rejected() -> None:
    blob = bytes([0x30, 0x85]) + b"\xff" * 5 + b"\x02\x01\x01"
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
    assert key.parse_error == "unsupported DER length encoding"


def test_indefinite_length_encoding_is_rejected() -> None:
    """Legal in BER, forbidden in DER, and a parser that accepted it could hang."""
    blob = bytes([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00])
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
    assert key.parse_error == "unsupported DER length encoding"


def test_an_ed25519_spki_mislabelled_as_rsa_is_rejected() -> None:
    """k=rsa with an ed25519 key behind it. The structure does not match."""
    algorithm = bytes.fromhex("300506032b6570")
    blob = der(0x30, algorithm + der(0x03, b"\x00" + b"\x11" * 32))
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
    assert key.parse_error is not None
    assert key.bits is None


def test_an_ec_p256_spki_is_rejected_rather_than_misread() -> None:
    algorithm = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    blob = der(0x30, algorithm + der(0x03, b"\x00\x04" + b"\x22" * 64))
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
    assert key.parse_error is not None
    assert key.bits is None


def test_a_modulus_with_the_high_bit_clear_reports_its_true_bit_length() -> None:
    """A real RSA modulus always has the top bit set.

    One that does not is malformed, and the honest report is the actual integer
    width rather than the size it was probably meant to be.
    """
    from tests.conftest import _der_integer

    modulus = bytes([0x7F]) + b"\xab" * 255
    rsa_key = der(0x30, _der_integer(modulus) + _der_integer(b"\x01\x00\x01"))
    algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
    blob = der(0x30, algorithm + der(0x03, b"\x00" + rsa_key))

    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
    assert key.parse_error is None
    assert key.bits == 2047


def test_valid_base64_of_random_bytes_is_rejected() -> None:
    # Bytes hoisted out of the f-string: escape sequences inside an f-string
    # expression are 3.12+ syntax and this project's floor is 3.11.
    noise = b"\xde\xad\xbe\xef" * 8
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(noise)}")
    assert key.parse_error is not None


def test_no_adversarial_input_raises() -> None:
    """The property that matters: a malformed key must never abort a run."""
    from tests.conftest import _der_integer

    blobs = [
        make_rsa_spki(2048)[:40],
        bytes([0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]),
        bytes([0x30, 0x80, 0x00, 0x00]),
        der(0x30, bytes.fromhex("300506032b6570") + der(0x03, b"\x00" + b"\x11" * 32)),
        der(0x02, _der_integer(b"\x01")),
        b"",
        b"\x30",
        b"\x05\x00",
    ]
    for blob in blobs:
        key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={as_p(blob)}")
        assert isinstance(key.parse_error, str) or key.revoked, blob.hex()


# ---------------------------------------------------------------------------
# missing base64 padding
#
# 1024- and 2048-bit RSA keys encode to a length divisible by four and need no
# padding at all. 4096-bit RSA and ed25519 do, so a publisher who stripped the
# trailing '=' was being reported as malformed when the key was fine.
# ---------------------------------------------------------------------------


def test_an_unpadded_4096_bit_rsa_key_parses() -> None:
    padded = make_dkim_p(4096)
    assert padded.endswith("="), "this size must need padding or the test proves nothing"
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={padded.rstrip('=')}")

    assert key.parse_error is None
    assert key.bits == 4096


def test_an_unpadded_ed25519_key_parses() -> None:
    padded = base64.b64encode(b"\x11" * 32).decode("ascii")
    assert padded.endswith("=")
    key = dkim.parse_key_record("s", f"v=DKIM1; k=ed25519; p={padded.rstrip('=')}")

    assert key.parse_error is None
    assert key.bits == 256


def test_restoring_padding_cannot_mask_a_truncated_key() -> None:
    """The reservation this change had to answer.

    Tolerating missing padding must not let corruption through. A truncated key
    with padding restored still decodes to truncated DER, and the DER layer -
    which is stricter - still rejects it.
    """
    truncated = make_rsa_spki(2048)[:150]
    encoded = base64.b64encode(truncated).decode("ascii").rstrip("=")
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={encoded}")

    assert key.parse_error is not None
    assert key.bits is None


def test_missing_padding_is_recorded_rather_than_silently_normalised() -> None:
    padded = make_dkim_p(4096)
    key = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={padded.rstrip('=')}")
    assert key.padding_repaired is True

    intact = dkim.parse_key_record("s", f"v=DKIM1; k=rsa; p={padded}")
    assert intact.padding_repaired is False


def test_a_repaired_key_produces_its_own_finding() -> None:
    padded = make_dkim_p(4096)
    zone = {
        ("default._domainkey.r.test", "TXT"): [f"v=DKIM1; k=rsa; p={padded.rstrip('=')}"]
    }
    result = dkim.check(FakeResolver(zone), "r.test", None)
    codes = {f.code for f in result.findings}

    assert "dkim.padding_repaired" in codes
    # It is a note, not a defect: the key is usable and must still count.
    assert "dkim.unparseable" not in codes
    assert len(result.usable_keys) == 1


def test_a_well_formed_key_produces_no_padding_finding() -> None:
    zone = {("default._domainkey.g.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]}
    result = dkim.check(FakeResolver(zone), "g.test", None)
    assert "dkim.padding_repaired" not in {f.code for f in result.findings}
