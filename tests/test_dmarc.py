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


# ---------------------------------------------------------------------------
# the t tag: RFC 9989 policy test mode
#
# t=y asks receivers not to apply the published policy while the owner tests
# (RFC 9989 section 4.7). A receiver still on RFC 7489 treats t as an unknown
# tag and MUST ignore it (section 6.3), applying the policy as published. The
# tool records that the tag is present; it does not compute an effective policy,
# because the text defines an owner expectation rather than a receiver rule.
# ---------------------------------------------------------------------------

MUST_FIRE = [
    ("quarantine, lowercase", "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com"),
    ("quarantine, uppercase", "v=DMARC1; p=quarantine; t=Y; rua=mailto:r@example.com"),
    ("reject, no rua", "v=DMARC1; p=reject; t=y"),
    ("p capitalised", "v=DMARC1; p=Quarantine; t=y; rua=mailto:r@example.com"),
    ("p uppercase", "v=DMARC1; p=REJECT; t=y; rua=mailto:r@example.com"),
]

MUST_STAY_SILENT = [
    ("t=n", "v=DMARC1; p=reject; t=n; rua=mailto:r@example.com"),
    ("t=N", "v=DMARC1; p=reject; t=N; rua=mailto:r@example.com"),
    ("t=maybe", "v=DMARC1; p=reject; t=maybe; rua=mailto:r@example.com"),
    ("t empty", "v=DMARC1; p=reject; t=; rua=mailto:r@example.com"),
    ("t absent", "v=DMARC1; p=reject; rua=mailto:r@example.com"),
    ("t=yes", "v=DMARC1; p=reject; t=yes; rua=mailto:r@example.com"),
    ("t=y:s", "v=DMARC1; p=reject; t=y:s; rua=mailto:r@example.com"),
    # The gate: the finding's copy speaks only about p, and is only true when p
    # is enforcing. See the comment at the emit site in checks/dmarc.py.
    ("p=none", "v=DMARC1; p=none; t=y; rua=mailto:r@example.com"),
    ("p absent", "v=DMARC1; t=y; rua=mailto:r@example.com"),
    ("p empty", "v=DMARC1; p=; t=y; rua=mailto:r@example.com"),
    ("p invalid", "v=DMARC1; p=foo; t=y; rua=mailto:r@example.com"),
    ("p absent, no rua", "v=DMARC1; t=y"),
]


def dmarc_codes(record: str) -> set[str]:
    resolver = FakeResolver({("_dmarc.t.test", "TXT"): [record]})
    return {f.code for f in dmarc.check(resolver, "t.test").findings}


@pytest.mark.parametrize("label,record", MUST_FIRE, ids=[m[0] for m in MUST_FIRE])
def test_policy_test_mode_fires(label: str, record: str) -> None:
    assert "dmarc.policy_test_mode" in dmarc_codes(record), label


@pytest.mark.parametrize(
    "label,record", MUST_STAY_SILENT, ids=[m[0] for m in MUST_STAY_SILENT]
)
def test_policy_test_mode_stays_silent(label: str, record: str) -> None:
    assert "dmarc.policy_test_mode" not in dmarc_codes(record), label


# The property reads t alone and knows nothing about p. The gate lives at the
# emit site, so these lists are deliberately separate from MUST_FIRE and
# MUST_STAY_SILENT above: a record can set t=y (property True) and still emit no
# finding (gated on p).
PROPERTY_TRUE = [
    ("lowercase", "v=DMARC1; p=quarantine; t=y"),
    ("uppercase", "v=DMARC1; p=quarantine; t=Y"),
    ("p=none still sets the tag", "v=DMARC1; p=none; t=y"),
    ("p absent still sets the tag", "v=DMARC1; t=y"),
]
PROPERTY_FALSE = [
    ("t=n", "v=DMARC1; p=reject; t=n"),
    ("t=N", "v=DMARC1; p=reject; t=N"),
    ("t=maybe", "v=DMARC1; p=reject; t=maybe"),
    ("t empty", "v=DMARC1; p=reject; t="),
    ("t absent", "v=DMARC1; p=reject"),
    ("t=yes", "v=DMARC1; p=reject; t=yes"),
    ("t=y:s", "v=DMARC1; p=reject; t=y:s"),
]


@pytest.mark.parametrize("label,record", PROPERTY_TRUE, ids=[m[0] for m in PROPERTY_TRUE])
def test_the_property_reads_the_t_tag_alone(label: str, record: str) -> None:
    from mailauth.models import DmarcResult

    assert DmarcResult(tags=dmarc.parse_tags(record)).policy_test_mode, label


@pytest.mark.parametrize("label,record", PROPERTY_FALSE, ids=[m[0] for m in PROPERTY_FALSE])
def test_the_property_is_false_for_everything_else(label: str, record: str) -> None:
    from mailauth.models import DmarcResult

    assert not DmarcResult(tags=dmarc.parse_tags(record)).policy_test_mode, label


def test_the_property_strips_whitespace_when_tags_bypass_the_parser() -> None:
    """Reaches the property's own .strip(), which parse_tags otherwise pre-empts.

    parse_tags strips values, so a padded tag routed through it can never
    exercise this. Tags also reach DmarcResult from the stored run history, so
    the strip is real defence and needs a test that actually gets to it.
    """
    from mailauth.models import DmarcResult

    assert DmarcResult(tags={"t": " y "}).policy_test_mode is True
    assert DmarcResult(tags={"t": "\ty\n"}).policy_test_mode is True
    assert DmarcResult(tags={"t": " n "}).policy_test_mode is False


def test_the_finding_names_the_published_policy() -> None:
    result = dmarc.check(
        FakeResolver({("_dmarc.t.test", "TXT"): ["v=DMARC1; p=quarantine; t=y"]}),
        "t.test",
    )
    finding = next(f for f in result.findings if f.code == "dmarc.policy_test_mode")
    assert finding.title == "DMARC record is in test mode (t=y)"
    assert "p=quarantine" in finding.detail
    assert "RFC 9989" in finding.detail
    assert str(finding.severity) == "warning"
    assert str(finding.confidence) == "high"


def test_the_finding_carries_no_weight(weights) -> None:
    """Weight 0 on purpose: this records an observable, it does not price it."""
    assert weights.get("dmarc.policy_test_mode").weight == 0


def test_a_dkim_key_in_test_mode_does_not_trip_the_dmarc_guard() -> None:
    """t=y in a DKIM key record is a different tags mapping with a different meaning.

    checks/dkim.py:134 reads t from a DKIM key, where it marks the key as being
    in test mode. That must not leak into the DMARC assessment, and the DMARC
    tag must not change the DKIM reading.
    """
    from mailauth.checks import dkim as dkim_check
    from mailauth.engine import check_domain
    from tests.conftest import RSA_2048_P

    zone = {
        ("k.test", "TXT"): ["v=spf1 -all"],
        ("k.test", "MX"): ["10 mail.k.test"],
        ("mail.k.test", "A"): ["192.0.2.1"],
        # DMARC record with NO t tag.
        ("_dmarc.k.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:r@k.test"],
        # DKIM key record WITH t=y.
        ("default._domainkey.k.test", "TXT"): [f"v=DKIM1; k=rsa; t=y; p={RSA_2048_P}"],
    }
    result = check_domain(FakeResolver(zone), "k.test")
    codes = {f.code for f in result.findings}

    assert "dmarc.policy_test_mode" not in codes
    assert not result.dmarc.policy_test_mode
    # The DKIM side is unchanged: the key is still read as being in test mode.
    assert "dkim.testing_mode" in codes
    assert dkim_check.parse_key_record(
        "default", f"v=DKIM1; k=rsa; t=y; p={RSA_2048_P}"
    ).testing


def test_sp_enforcing_under_p_none_is_a_known_suppression() -> None:
    """A record in real test mode for its subdomains, which we do not report.

    RFC 9989 section 4.7 names "sp" and "np" alongside "p": the t tag signals
    whether the owner wants the policy declared in any of the three applied.
    This record publishes p=none with sp=reject, so it is in meaningful test
    mode for its subdomains - a receiver implementing RFC 9989 is asked not to
    apply that sp=reject, and a receiver still on RFC 7489 applies it.

    The gate suppresses it deliberately. dmarc.policy_test_mode's copy speaks
    only about p, and on p=none that copy is false. Covering the sp and np case
    needs a separate finding with its own copy, which does not exist yet. This
    test exists so the gap is recorded as a gap rather than read as correctness.
    """
    record = "v=DMARC1; p=none; sp=reject; t=y; rua=mailto:r@example.com"
    resolver = FakeResolver({("_dmarc.t.test", "TXT"): [record]})
    result = dmarc.check(resolver, "t.test")

    assert "dmarc.policy_test_mode" not in {f.code for f in result.findings}
    # The tag is set and the model still says so; only the finding is withheld.
    assert result.policy_test_mode
    assert result.tags["sp"] == "reject"
