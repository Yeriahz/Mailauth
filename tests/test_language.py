"""
tests/test_language.py - mechanical enforcement of the output language rules.

Two constraints from the brief are easy to honour in a CSV column and easy to
violate in a paragraph of generated prose. Rather than trust the author to keep
honouring them, they are asserted here against every finding every check can
produce and against every section of a rendered report.

  1. The tool describes what is published in DNS. It does not characterise
     anyone as being in violation of anything and does not name a statute.
  2. Nothing about DKIM may be phrased as proof of absence.

If a legitimate string trips one of these, the fix is to reword the string. The
word list is meant to be added to.
"""

from __future__ import annotations

import re

import pytest

from mailauth.checks import dkim, dmarc, extras, mx, spf
from mailauth.engine import check_domain
from mailauth.report import render_html, render_markdown
from mailauth.scoring import Weights, load_weights, score
from tests.conftest import RSA_512_P, FakeResolver

# Phrasings that assert a legal conclusion, name a statute, or characterise the
# domain owner rather than the DNS records.
FORBIDDEN = [
    "violation",
    "violates",
    "non-compliant",
    "noncompliant",
    "not compliant",
    "illegal",
    "in breach",
    "breach of",
    "unlawful",
    "liable",
    "liability",
    "negligent",
    "negligence",
    "required by law",
    "legally required",
    "mandated by",
    "must comply",
    "ftc",
    "glba",
    "gramm-leach",
    "irs pub",
    "safeguards rule",
    "wisp",
    "hipaa",
    "pci dss",
    "sox ",
    "fined",
    "penalty",
    "penalties",
]

# Claims about DKIM absence. These are not banned outright: "no DKIM key was
# found" is the correct phrasing, and "this is not proof that the domain has no
# DKIM key" explicitly denies the claim. What is banned is making the claim in a
# sentence that does not also carry its qualification, because such a sentence
# can be quoted out of the report and become an overstatement on its own.
DKIM_CLAIMS = [
    "no dkim",
    "dkim is not configured",
    "dkim is absent",
    "does not use dkim",
    "dkim is missing",
    "without dkim",
    "unsigned",
]

# Any one of these in the same sentence makes the claim honest.
DKIM_QUALIFIERS = [
    "selector",
    "not proof",
    "not conclusive",
    "cannot be enumerated",
    "cannot be listed",
    "cannot be assessed",
    "found on",
    "if outbound mail really is",
    "may be signed",
]


def assert_clean(text: str, where: str) -> None:
    """Assert no forbidden phrase appears as a whole word.

    Whole-word matching matters: "unreliable" contains "liable", and banning the
    substring would forbid a correct sentence about the ptr mechanism.
    """
    lowered = text.lower()
    for phrase in FORBIDDEN:
        pattern = r"\b" + re.escape(phrase.strip()) + r"\b"
        assert not re.search(pattern, lowered), f"{where}: forbidden phrase {phrase!r}"


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n", text) if s.strip()]


def assert_no_dkim_overstatement(text: str, where: str) -> None:
    for sentence in sentences(text.lower()):
        if not any(claim in sentence for claim in DKIM_CLAIMS):
            continue
        assert any(q in sentence for q in DKIM_QUALIFIERS), (
            f"{where}: unqualified claim about DKIM absence: {sentence!r}"
        )


# ---------------------------------------------------------------------------
# every finding a check can produce
# ---------------------------------------------------------------------------


def all_findings():
    """Drive every check hard enough to emit as much of its vocabulary as possible."""
    collected = []

    zones: list[tuple[str, dict]] = [
        ("nothing.test", {("nothing.test", "TXT"): ["x=y"]}),
        (
            "bad.test",
            {
                ("bad.test", "MX"): ["10 dead.test", "10 alias.test"],
                ("alias.test", "CNAME"): ["elsewhere.test"],
                ("bad.test", "TXT"): [
                    "v=spf1 ptr include:gone1.test include:gone2.test "
                    "include:gone3.test include:dup.test include:dup.test "
                    "exists:%{i}.x.test ~all ip4:1.2.3.0/24 -all "
                    "redirect=other.test badterm!",
                    "v=spf1 -all",
                ],
                ("dup.test", "TXT"): ["v=spf1 ip4:1.2.3.0/24 -all"],
                ("_dmarc.bad.test", "TXT"): [
                    "v=DMARC1; p=reject; sp=none; pct=20; adkim=s; aspf=s; "
                    "fo=1; ri=3600; rua=mailto:r@vendor.test; ruf=mailto:f@vendor.test"
                ],
                ("default._domainkey.bad.test", "TXT"): [
                    f"v=DKIM1; k=rsa; t=y; p={RSA_512_P}"
                ],
                ("dkim._domainkey.bad.test", "TXT"): ["v=DKIM1; k=rsa; p="],
            },
        ),
        (
            "weird.test",
            {
                ("weird.test", "MX"): ["0 ."],
                ("weird.test", "TXT"): ["v=spf1 +all"],
                ("_dmarc.weird.test", "TXT"): ["v=DMARC1; p=bogus", "v=DMARC1; p=none"],
                ("_mta-sts.weird.test", "TXT"): ["v=STSv1"],
                ("default._bimi.weird.test", "TXT"): ["v=BIMI1; l="],
                ("_smtp._tls.weird.test", "TXT"): ["v=TLSRPTv1"],
            },
        ),
        (
            "neutral.test",
            {
                ("neutral.test", "MX"): ["10 mail.neutral.test"],
                ("mail.neutral.test", "A"): ["192.0.2.1"],
                ("neutral.test", "TXT"): ["v=spf1 ?all"],
                ("_dmarc.neutral.test", "TXT"): ["v=DMARC1; p=quarantine"],
            },
        ),
    ]

    for domain, zone in zones:
        result = check_domain(FakeResolver(zone), domain)
        for finding in result.findings:
            collected.append((domain, finding))

    # Direct calls for paths the orchestrator does not reach.
    collected += [
        ("direct", f)
        for f in spf.check(FakeResolver({}), "d.test", ["v=spf1 a mx"]).findings
    ]
    collected += [("direct", f) for f in mx.check(FakeResolver({}), "d.test").findings]
    collected += [("direct", f) for f in dmarc.check(FakeResolver({}), "d.test").findings]
    collected += [("direct", f) for f in dkim.check(FakeResolver({}), "d.test").findings]
    collected += [("direct", f) for f in extras.check(FakeResolver({}), "d.test").findings]
    return collected


FINDINGS = all_findings()


def test_the_fixtures_exercise_a_wide_vocabulary() -> None:
    """Guard against the language tests passing because nothing was rendered."""
    codes = {finding.code for _, finding in FINDINGS}
    assert len(codes) >= 30, f"only {len(codes)} codes exercised: {sorted(codes)}"


def test_no_finding_asserts_a_legal_conclusion() -> None:
    for where, finding in FINDINGS:
        assert_clean(f"{finding.title} {finding.detail}", f"{where}/{finding.code}")


def test_no_finding_overstates_dkim_absence() -> None:
    for where, finding in FINDINGS:
        assert_no_dkim_overstatement(
            f"{finding.title} {finding.detail}", f"{where}/{finding.code}"
        )


def test_every_finding_has_a_title() -> None:
    for where, finding in FINDINGS:
        assert finding.title.strip(), f"{where}/{finding.code} has an empty title"


def test_no_finding_title_ends_with_a_full_stop() -> None:
    """Titles are labels, not sentences; details carry the prose."""
    for where, finding in FINDINGS:
        assert not finding.title.rstrip().endswith("."), (
            f"{where}/{finding.code}: title ends with a full stop"
        )


# ---------------------------------------------------------------------------
# the weights file
# ---------------------------------------------------------------------------


def test_rationales_carry_no_legal_conclusions(weights: Weights) -> None:
    """Rationales are quoted to clients when explaining a score."""
    for code, entry in weights.entries.items():
        assert_clean(entry.rationale, f"weights/{code}")


# ---------------------------------------------------------------------------
# rendered reports
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rendered() -> list[tuple[str, str]]:
    weights = load_weights()
    out: list[tuple[str, str]] = []
    zones = {
        "wideopen.test": {
            ("wideopen.test", "MX"): ["10 mail.secureserver.net"],
            ("mail.secureserver.net", "A"): ["97.74.1.1"],
            ("wideopen.test", "TXT"): ["x=y"],
        },
        "halfway.test": {
            ("halfway.test", "MX"): ["0 h.mail.protection.outlook.com"],
            ("h.mail.protection.outlook.com", "A"): ["104.47.1.1"],
            ("halfway.test", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all"],
            ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 -all"],
            ("_dmarc.halfway.test", "TXT"): ["v=DMARC1; p=none"],
        },
        "quarantined.test": {
            ("quarantined.test", "MX"): ["10 aspmx.l.google.com"],
            ("aspmx.l.google.com", "A"): ["142.250.1.26"],
            ("quarantined.test", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
            ("_spf.google.com", "TXT"): ["v=spf1 ip4:35.190.0.0/16 ~all"],
            ("_dmarc.quarantined.test", "TXT"): [
                "v=DMARC1; p=quarantine; rua=mailto:d@quarantined.test"
            ],
        },
        "parked.test": {("parked.test", "TXT"): ["x=y"]},
    }
    for domain, zone in zones.items():
        result = score(check_domain(FakeResolver(zone), domain), weights)
        out.append((domain, render_markdown(result)))
        out.append((f"{domain} (html)", render_html(result)))
    return out


def test_reports_assert_no_legal_conclusions(rendered) -> None:
    for where, text in rendered:
        assert_clean(text, f"report/{where}")


def test_reports_do_not_overstate_dkim_absence(rendered) -> None:
    for where, text in rendered:
        assert_no_dkim_overstatement(text, f"report/{where}")


def test_reports_state_the_method_is_passive(rendered) -> None:
    for where, text in rendered:
        lowered = text.lower()
        assert "public dns" in lowered, where


def test_reports_never_recommend_jumping_straight_to_reject(rendered) -> None:
    """The staging rule. p=reject may appear, but never as the only step.

    Telling a small firm to publish p=reject on day one breaks their mail, and
    the person who pays for that is the client.
    """
    for where, text in rendered:
        if "p=reject" not in text:
            continue
        assert "p=none" in text or "p=quarantine" in text, (
            f"{where}: recommends p=reject with no earlier stage"
        )


def test_reports_show_selectors_tried_when_no_key_was_found(rendered) -> None:
    for where, text in rendered:
        lowered = text.lower()
        if "no dkim" in lowered or "no dkim signing key" in lowered:
            assert "selector" in lowered, f"{where}: claims absence without the caveat"


def test_generated_records_are_syntactically_plausible(rendered) -> None:
    """Every generated DMARC value must start with the version tag and set a policy."""
    for where, text in rendered:
        for value in re.findall(r"v=DMARC1[^\n<`]*", text):
            assert value.startswith("v=DMARC1;"), f"{where}: {value!r}"
            assert "p=" in value, f"{where}: {value!r}"


def test_html_render_is_self_contained(rendered) -> None:
    for where, text in rendered:
        if "(html)" not in where:
            continue
        assert text.startswith("<!doctype html>")
        assert "<style>" in text
        # No external resources: the page must render offline.
        assert "http://" not in text.replace("http://www.w3.org", "")
        assert "<script" not in text
