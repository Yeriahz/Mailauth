"""
tests/test_mx_extras.py - MX target inspection, TLS-RPT, MTA-STS, BIMI, DNSSEC.

The MTA-STS tests assert the constraint that matters most in this package: the
policy fetch never happens unless it was explicitly enabled. That is enforced
here by giving the check a fetcher that fails the test if it is ever called.
"""

from __future__ import annotations

import pytest

from mailauth.checks import extras, mx
from mailauth.providers import identify
from tests.conftest import FakeResolver

# ---------------------------------------------------------------------------
# MX
# ---------------------------------------------------------------------------


def test_mx_value_parsing() -> None:
    assert mx.parse_mx_value("10 mail.example.com") == (10, "mail.example.com")
    assert mx.parse_mx_value("0 MAIL.Example.COM.") == (0, "mail.example.com")


def test_null_mx_is_recognised() -> None:
    zone = {("null.test", "MX"): ["0 ."]}
    result = mx.check(FakeResolver(zone), "null.test")
    assert result.null_mx
    assert "mx.null" in {f.code for f in result.findings}


def test_no_mx_is_informational_not_a_gap() -> None:
    """A domain with no MX does not receive mail. That is not a finding to score."""
    result = mx.check(FakeResolver({}), "parked.test")
    assert not result.targets
    assert "mx.absent" in {f.code for f in result.findings}


def test_cname_mx_target_is_flagged() -> None:
    zone = {
        ("c.test", "MX"): ["10 mail.c.test"],
        ("mail.c.test", "CNAME"): ["real.example.net"],
        ("mail.c.test", "A"): ["192.0.2.1"],
    }
    result = mx.check(FakeResolver(zone), "c.test")
    assert result.targets[0].is_cname
    assert "mx.target_is_cname" in {f.code for f in result.findings}


def test_unresolvable_mx_target_is_flagged() -> None:
    zone = {("d.test", "MX"): ["10 dead.example.net"]}
    result = mx.check(FakeResolver(zone), "d.test")
    assert not result.targets[0].resolves
    assert "mx.target_unresolvable" in {f.code for f in result.findings}


def test_aaaa_records_are_recorded() -> None:
    zone = {
        ("v6.test", "MX"): ["10 mail.v6.test"],
        ("mail.v6.test", "A"): ["192.0.2.1"],
        ("mail.v6.test", "AAAA"): ["2001:db8::1"],
    }
    result = mx.check(FakeResolver(zone), "v6.test")
    assert result.targets[0].has_aaaa
    assert "mx.no_ipv6" not in {f.code for f in result.findings}


def test_ipv4_only_is_noted() -> None:
    zone = {("v4.test", "MX"): ["10 mail.v4.test"], ("mail.v4.test", "A"): ["192.0.2.1"]}
    result = mx.check(FakeResolver(zone), "v4.test")
    assert "mx.no_ipv6" in {f.code for f in result.findings}


def test_single_mx_is_noted() -> None:
    zone = {("s.test", "MX"): ["10 mail.s.test"], ("mail.s.test", "A"): ["192.0.2.1"]}
    result = mx.check(FakeResolver(zone), "s.test")
    assert "mx.single" in {f.code for f in result.findings}


def test_two_mx_hosts_produce_no_single_host_finding() -> None:
    zone = {
        ("m.test", "MX"): ["10 a.m.test", "20 b.m.test"],
        ("a.m.test", "A"): ["192.0.2.1"],
        ("b.m.test", "A"): ["192.0.2.2"],
    }
    result = mx.check(FakeResolver(zone), "m.test")
    assert "mx.single" not in {f.code for f in result.findings}


@pytest.mark.parametrize(
    "host,expected",
    [
        ("example-com.mail.protection.outlook.com", "Microsoft 365"),
        ("aspmx.l.google.com", "Google Workspace"),
        ("mx.zoho.com", "Zoho Mail"),
        ("in1-smtp.messagingengine.com", "Fastmail"),
        ("mailstore1.secureserver.net", "GoDaddy"),
        ("mx1.emailsrvr.com", "Rackspace Email"),
        ("mx.selfhosted.example", None),
    ],
)
def test_provider_fingerprinting(host: str, expected: str | None) -> None:
    provider = identify([host])
    assert (provider.name if provider else None) == expected


def test_a_resolver_failure_produces_no_absence_finding() -> None:
    resolver = FakeResolver({}, fail={("t.test", "MX")})
    result = mx.check(resolver, "t.test")
    codes = {f.code for f in result.findings}
    assert "mx.unreachable" in codes
    assert "mx.absent" not in codes


# ---------------------------------------------------------------------------
# supporting records
# ---------------------------------------------------------------------------


def test_tlsrpt_present_and_absent() -> None:
    zone = {("_smtp._tls.t.test", "TXT"): ["v=TLSRPTv1; rua=mailto:t@t.test"]}
    present = extras.check(FakeResolver(zone), "t.test")
    assert present.tlsrpt.present
    assert present.tlsrpt.tags["rua"] == "mailto:t@t.test"
    assert "tlsrpt.absent" not in {f.code for f in present.findings}

    absent = extras.check(FakeResolver({}), "t2.test")
    assert not absent.tlsrpt.present
    assert "tlsrpt.absent" in {f.code for f in absent.findings}


def test_tlsrpt_absent_is_not_raised_for_a_non_receiving_domain() -> None:
    result = extras.check(FakeResolver({}), "parked.test", has_mx=False)
    assert "tlsrpt.absent" not in {f.code for f in result.findings}
    assert "mtasts.absent" not in {f.code for f in result.findings}


def test_mta_sts_dns_record_is_read_passively() -> None:
    zone = {("_mta-sts.m.test", "TXT"): ["v=STSv1; id=20260101000000Z"]}
    result = extras.check(FakeResolver(zone), "m.test")
    assert result.mtasts.dns.present
    assert result.mtasts.dns.tags["id"] == "20260101000000Z"
    # Passive by default: no policy was fetched.
    assert not result.mtasts.policy_fetched


def test_mta_sts_policy_is_never_fetched_without_the_active_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The constraint that matters: no outbound connection under default settings."""

    def explode(domain: str, timeout: float = 10.0) -> tuple[str | None, str | None]:
        raise AssertionError(
            "fetch_policy was called without --active, which would connect to a "
            "host the assessed domain operates"
        )

    monkeypatch.setattr(extras, "fetch_policy", explode)
    zone = {("_mta-sts.m.test", "TXT"): ["v=STSv1; id=1"]}
    result = extras.check(FakeResolver(zone), "m.test", active=False)
    assert result.mtasts.dns.present


def test_mta_sts_policy_is_fetched_only_when_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_fetch(domain: str, timeout: float = 10.0) -> tuple[str | None, str | None]:
        calls.append(domain)
        return ("version: STSv1\nmode: enforce\nmx: mail.m.test\nmax_age: 604800\n", None)

    monkeypatch.setattr(extras, "fetch_policy", fake_fetch)
    zone = {("_mta-sts.m.test", "TXT"): ["v=STSv1; id=1"]}
    result = extras.check(FakeResolver(zone), "m.test", active=True)

    assert calls == ["m.test"]
    assert result.mtasts.policy_fetched
    assert result.mtasts.policy_mode == "enforce"
    assert result.mtasts.policy_max_age == 604800
    assert result.mtasts.policy_mx == ["mail.m.test"]


def test_mta_sts_policy_is_not_fetched_when_no_dns_record_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with --active, there is no reason to connect if nothing advertises a policy."""

    def explode(domain: str, timeout: float = 10.0) -> tuple[str | None, str | None]:
        raise AssertionError("fetched a policy for a domain with no MTA-STS record")

    monkeypatch.setattr(extras, "fetch_policy", explode)
    extras.check(FakeResolver({}), "nopolicy.test", active=True)


def test_unreachable_policy_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extras, "fetch_policy", lambda d, timeout=10.0: (None, "HTTP 404"))
    zone = {("_mta-sts.m.test", "TXT"): ["v=STSv1; id=1"]}
    result = extras.check(FakeResolver(zone), "m.test", active=True)
    assert "mtasts.policy_unreachable" in {f.code for f in result.findings}


def test_policy_file_parsing() -> None:
    parsed = extras.parse_policy(
        "version: STSv1\nmode: testing\nmx: a.test\nmx: b.test\nmax_age: 86400\n"
    )
    assert parsed["mode"] == ["testing"]
    assert parsed["mx"] == ["a.test", "b.test"]


def test_bimi_is_read() -> None:
    zone = {("default._bimi.b.test", "TXT"): ["v=BIMI1; l=https://b.test/logo.svg"]}
    result = extras.check(FakeResolver(zone), "b.test")
    assert result.bimi.present
    assert result.bimi.tags["l"] == "https://b.test/logo.svg"


def test_bimi_without_a_logo_is_noted() -> None:
    zone = {("default._bimi.b.test", "TXT"): ["v=BIMI1; l="]}
    result = extras.check(FakeResolver(zone), "b.test")
    assert "bimi.no_logo" in {f.code for f in result.findings}


def test_dnssec_authenticated_flag_is_reported() -> None:
    zone = {("d.test", "SOA"): ["ns1.d.test. host.d.test. 1 2 3 4 5"]}
    signed = extras.check(FakeResolver(zone, authenticated=True), "d.test")
    assert signed.dnssec is True
    assert "dnssec.unsigned" not in {f.code for f in signed.findings}

    unsigned = extras.check(FakeResolver(zone, authenticated=False), "d.test")
    assert unsigned.dnssec is False
    assert "dnssec.unsigned" in {f.code for f in unsigned.findings}


def test_dnssec_is_unknown_when_the_query_fails() -> None:
    resolver = FakeResolver({}, fail={("d.test", "SOA")})
    result = extras.check(resolver, "d.test")
    assert result.dnssec is None
    assert "dnssec.unsigned" not in {f.code for f in result.findings}
