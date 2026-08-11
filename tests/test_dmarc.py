"""
tests/test_dmarc.py - DMARC tag parsing and the external reporting
authorization check.
"""

from __future__ import annotations

import pytest

from mailauth.checks import dmarc
from tests.conftest import FakeResolver

# ---------------------------------------------------------------------------
# record detection and tag parsing
# ---------------------------------------------------------------------------


def test_version_detection_is_exact() -> None:
    assert dmarc.is_dmarc_record("v=DMARC1; p=none")
    assert dmarc.is_dmarc_record("V=dmarc1;p=reject")
    assert dmarc.is_dmarc_record("v=DMARC1")
    assert not dmarc.is_dmarc_record("v=DMARC10; p=none")
    assert not dmarc.is_dmarc_record("v=spf1 -all")


def test_every_tag_is_parsed() -> None:
    tags = dmarc.parse_tags(
        "v=DMARC1; p=quarantine; sp=none; pct=50; adkim=s; aspf=s; "
        "fo=1; ri=3600; rua=mailto:a@b.test; ruf=mailto:f@b.test"
    )
    assert tags["p"] == "quarantine"
    assert tags["sp"] == "none"
    assert tags["pct"] == "50"
    assert tags["adkim"] == "s"
    assert tags["aspf"] == "s"
    assert tags["fo"] == "1"
    assert tags["ri"] == "3600"
    assert tags["rua"] == "mailto:a@b.test"
    assert tags["ruf"] == "mailto:f@b.test"


def test_tag_names_lowercase_but_values_keep_their_case() -> None:
    """rua addresses are handed to receivers verbatim, so case must survive."""
    tags = dmarc.parse_tags("v=DMARC1; P=reject; RUA=mailto:DMARC-Reports@Example.test")
    assert tags["p"] == "reject"
    assert tags["rua"] == "mailto:DMARC-Reports@Example.test"


def test_duplicate_tags_keep_the_first() -> None:
    tags = dmarc.parse_tags("v=DMARC1; p=none; p=reject")
    assert tags["p"] == "none"


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "record,expected",
    [
        ("v=DMARC1; p=none", "dmarc.policy_none"),
        ("v=DMARC1; p=quarantine", "dmarc.policy_quarantine"),
        ("v=DMARC1; p=reject", "dmarc.policy_reject"),
        ("v=DMARC1; rua=mailto:x@y.test", "dmarc.invalid_policy"),
        ("v=DMARC1; p=block", "dmarc.invalid_policy"),
    ],
)
def test_policy_classification(record: str, expected: str) -> None:
    zone = {("_dmarc.x.test", "TXT"): [record]}
    result = dmarc.check(FakeResolver(zone), "x.test")
    assert expected in {f.code for f in result.findings}


def test_absent_record() -> None:
    result = dmarc.check(FakeResolver({}), "none.test")
    assert result.record is None
    assert "dmarc.absent" in {f.code for f in result.findings}


def test_two_records_are_reported() -> None:
    zone = {
        ("_dmarc.two.test", "TXT"): ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
    }
    result = dmarc.check(FakeResolver(zone), "two.test")
    assert result.record_count == 2
    assert "dmarc.multiple_records" in {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# pct and sp
# ---------------------------------------------------------------------------


def test_partial_pct_under_an_enforcing_policy_is_flagged() -> None:
    zone = {("_dmarc.p.test", "TXT"): ["v=DMARC1; p=reject; pct=20; rua=mailto:a@p.test"]}
    result = dmarc.check(FakeResolver(zone), "p.test")
    assert "dmarc.pct_partial" in {f.code for f in result.findings}


def test_pct_under_p_none_is_not_flagged() -> None:
    """pct only modifies an enforcing policy; under p=none it changes nothing."""
    zone = {("_dmarc.p2.test", "TXT"): ["v=DMARC1; p=none; pct=20; rua=mailto:a@p2.test"]}
    result = dmarc.check(FakeResolver(zone), "p2.test")
    assert "dmarc.pct_partial" not in {f.code for f in result.findings}


def test_pct_100_is_not_flagged() -> None:
    zone = {
        ("_dmarc.p3.test", "TXT"): ["v=DMARC1; p=reject; pct=100; rua=mailto:a@p3.test"]
    }
    result = dmarc.check(FakeResolver(zone), "p3.test")
    assert "dmarc.pct_partial" not in {f.code for f in result.findings}


def test_missing_sp_under_an_enforcing_policy_is_noted() -> None:
    zone = {("_dmarc.s.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@s.test"]}
    result = dmarc.check(FakeResolver(zone), "s.test")
    assert "dmarc.sp_absent" in {f.code for f in result.findings}


def test_weaker_subdomain_policy_is_flagged_as_weaker() -> None:
    zone = {("_dmarc.w.test", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:a@w.test"]}
    result = dmarc.check(FakeResolver(zone), "w.test")
    codes = {f.code for f in result.findings}
    assert "dmarc.sp_weaker" in codes
    assert "dmarc.sp_differs" not in codes


def test_stronger_subdomain_policy_is_not_flagged_as_weaker() -> None:
    zone = {
        ("_dmarc.v.test", "TXT"): ["v=DMARC1; p=quarantine; sp=reject; rua=mailto:a@v.test"]
    }
    result = dmarc.check(FakeResolver(zone), "v.test")
    codes = {f.code for f in result.findings}
    assert "dmarc.sp_differs" in codes
    assert "dmarc.sp_weaker" not in codes


# ---------------------------------------------------------------------------
# external reporting authorization
# ---------------------------------------------------------------------------


def test_report_destinations_are_extracted() -> None:
    pairs = dmarc.report_destinations("mailto:a@reports.test, mailto:b@other.test!10m")
    assert pairs == [
        ("mailto:a@reports.test", "reports.test"),
        ("mailto:b@other.test!10m", "other.test"),
    ]


def test_same_domain_reporting_needs_no_authorization_record() -> None:
    zone = {("_dmarc.self.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@self.test"]}
    resolver = FakeResolver(zone)
    result = dmarc.check(resolver, "self.test")

    assert result.external[0].authorized is True
    assert "dmarc.rua_unauthorized" not in {f.code for f in result.findings}
    # No _report._dmarc query should have been made at all.
    assert not any("_report._dmarc" in name for name, _ in resolver.queries)


def test_subdomain_reporting_needs_no_authorization_record() -> None:
    zone = {("_dmarc.sub.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@mail.sub.test"]}
    result = dmarc.check(FakeResolver(zone), "sub.test")
    assert result.external[0].authorized is True


def test_external_reporting_without_the_authorization_record_is_flagged() -> None:
    """The invisible failure: configured, looks right, receives nothing."""
    zone = {
        ("_dmarc.client.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:reports@vendor.test"]
    }
    result = dmarc.check(FakeResolver(zone), "client.test")

    assert result.external[0].authorized is False
    assert "dmarc.rua_unauthorized" in {f.code for f in result.findings}


def test_external_reporting_with_the_authorization_record_passes() -> None:
    zone = {
        ("_dmarc.client.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:reports@vendor.test"],
        ("client.test._report._dmarc.vendor.test", "TXT"): ["v=DMARC1"],
    }
    result = dmarc.check(FakeResolver(zone), "client.test")

    assert result.external[0].authorized is True
    assert "dmarc.rua_unauthorized" not in {f.code for f in result.findings}


def test_authorization_check_is_inconclusive_when_the_query_fails() -> None:
    """A timeout must not be reported as a missing authorization record."""
    zone = {("_dmarc.c2.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:r@vendor.test"]}
    resolver = FakeResolver(zone, fail={("c2.test._report._dmarc.vendor.test", "TXT")})
    result = dmarc.check(resolver, "c2.test")

    assert result.external[0].authorized is None
    assert "dmarc.rua_unauthorized" not in {f.code for f in result.findings}


def test_ruf_authorization_is_checked_at_lower_severity() -> None:
    zone = {
        ("_dmarc.f.test", "TXT"): [
            "v=DMARC1; p=none; rua=mailto:r@f.test; ruf=mailto:f@vendor.test"
        ]
    }
    result = dmarc.check(FakeResolver(zone), "f.test")
    assert "dmarc.ruf_unauthorized" in {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# other tags
# ---------------------------------------------------------------------------


def test_no_rua_is_flagged() -> None:
    zone = {("_dmarc.n.test", "TXT"): ["v=DMARC1; p=none"]}
    result = dmarc.check(FakeResolver(zone), "n.test")
    assert "dmarc.no_rua" in {f.code for f in result.findings}


def test_strict_alignment_is_reported() -> None:
    zone = {
        ("_dmarc.a.test", "TXT"): [
            "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:a@a.test"
        ]
    }
    result = dmarc.check(FakeResolver(zone), "a.test")
    assert "dmarc.strict_alignment" in {f.code for f in result.findings}


def test_fo_without_ruf_is_reported() -> None:
    zone = {("_dmarc.o.test", "TXT"): ["v=DMARC1; p=none; fo=1; rua=mailto:a@o.test"]}
    result = dmarc.check(FakeResolver(zone), "o.test")
    assert "dmarc.fo_without_ruf" in {f.code for f in result.findings}


def test_a_resolver_failure_produces_no_absence_finding() -> None:
    resolver = FakeResolver({}, fail={("_dmarc.t.test", "TXT")})
    result = dmarc.check(resolver, "t.test")
    codes = {f.code for f in result.findings}
    assert "dmarc.unreachable" in codes
    assert "dmarc.absent" not in codes
