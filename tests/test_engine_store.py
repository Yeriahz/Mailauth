"""
tests/test_engine_store.py - orchestration, interaction findings, persistence,
the TTL cache, and diffing.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mailauth.dns_client import DnsResponse, clamp_ttl
from mailauth.engine import check_domain, interaction_findings
from mailauth.models import Confidence, Posture, QueryStatus
from mailauth.scoring import Weights, load_weights, score
from mailauth.store import Store, diff_domain, diff_runs
from tests.conftest import RSA_2048_P, FakeResolver

# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


def test_nxdomain_produces_an_error_not_a_score(weights: Weights) -> None:
    result = score(check_domain(FakeResolver({}), "nothing.test"), weights)
    assert result.error == "the domain does not resolve"
    assert result.posture == Posture.UNRESOLVED
    assert result.risk == "unknown"


def test_a_resolver_failure_is_distinguished_from_nxdomain() -> None:
    resolver = FakeResolver({}, fail={("slow.test", "TXT")})
    result = check_domain(resolver, "slow.test")
    assert result.error is not None
    assert "does not resolve" not in result.error


def test_posture_is_non_sending_for_a_parked_domain() -> None:
    zone = {("parked.test", "SOA"): ["ns1.parked.test. h.parked.test. 1 2 3 4 5"]}
    zone[("parked.test", "TXT")] = ["google-site-verification=x"]
    result = check_domain(FakeResolver(zone), "parked.test")
    assert result.posture == Posture.NON_SENDING


def test_posture_is_non_sending_for_null_mx() -> None:
    zone = {
        ("nomail.test", "TXT"): ["v=spf1 -all"],
        ("nomail.test", "MX"): ["0 ."],
    }
    result = check_domain(FakeResolver(zone), "nomail.test")
    assert result.posture == Posture.NON_SENDING


def test_posture_is_sending_when_mx_exists(halfway_zone) -> None:
    result = check_domain(FakeResolver(halfway_zone), "halfway.test")
    assert result.posture == Posture.SENDING


def test_domain_is_normalised_before_checking() -> None:
    resolver = FakeResolver({})
    result = check_domain(resolver, "  Example.TEST.  ")
    assert result.domain == "example.test"


def test_passthrough_columns_survive() -> None:
    result = check_domain(
        FakeResolver({}), "x.test", passthrough={"firm": "Example LLC", "tier": "a"}
    )
    assert result.passthrough["firm"] == "Example LLC"


# ---------------------------------------------------------------------------
# interaction findings
# ---------------------------------------------------------------------------


def test_enforcing_policy_without_dkim_is_flagged() -> None:
    zone = {
        ("e.test", "MX"): ["10 mail.e.test"],
        ("mail.e.test", "A"): ["192.0.2.1"],
        ("e.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("_dmarc.e.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@e.test"],
    }
    result = check_domain(FakeResolver(zone), "e.test")
    assert "combo.enforcing_without_dkim" in {f.code for f in result.combo}


def test_that_finding_is_never_high_confidence() -> None:
    """It rests on a selector probe, so it inherits that probe's uncertainty."""
    zone = {
        ("e.test", "MX"): ["10 mail.e.test"],
        ("mail.e.test", "A"): ["192.0.2.1"],
        ("e.test", "TXT"): ["v=spf1 -all"],
        ("_dmarc.e.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@e.test"],
    }
    result = check_domain(FakeResolver(zone), "e.test")
    combo = next(f for f in result.combo if f.code == "combo.enforcing_without_dkim")
    assert combo.confidence == Confidence.LOW


def test_enforcing_policy_with_dkim_is_not_flagged() -> None:
    zone = {
        ("e2.test", "MX"): ["10 aspmx.l.google.com"],
        ("aspmx.l.google.com", "A"): ["142.250.1.26"],
        ("e2.test", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_spf.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 -all"],
        ("_dmarc.e2.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@e2.test"],
        ("google._domainkey.e2.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"],
    }
    result = check_domain(FakeResolver(zone), "e2.test")
    assert "combo.enforcing_without_dkim" not in {f.code for f in result.combo}


def test_hardfail_that_never_evaluates_is_flagged() -> None:
    includes = " ".join(f"include:s{i}.test" for i in range(12))
    zone: dict[tuple[str, str], list[str]] = {
        ("h.test", "MX"): ["10 mail.h.test"],
        ("mail.h.test", "A"): ["192.0.2.1"],
        ("h.test", "TXT"): [f"v=spf1 {includes} -all"],
        ("_dmarc.h.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@h.test"],
    }
    for i in range(12):
        zone[(f"s{i}.test", "TXT")] = ["v=spf1 ip4:192.0.2.0/24 -all"]

    result = check_domain(FakeResolver(zone), "h.test")
    assert "combo.hardfail_never_evaluated" in {f.code for f in result.combo}


def test_enforcing_without_reporting_is_flagged() -> None:
    zone = {
        ("r.test", "MX"): ["10 mail.r.test"],
        ("mail.r.test", "A"): ["192.0.2.1"],
        ("r.test", "TXT"): ["v=spf1 -all"],
        ("_dmarc.r.test", "TXT"): ["v=DMARC1; p=quarantine"],
    }
    result = check_domain(FakeResolver(zone), "r.test")
    assert "combo.enforcing_without_reporting" in {f.code for f in result.combo}


def test_no_authentication_at_all_is_flagged_for_a_sending_domain(
    wideopen_zone,
) -> None:
    result = check_domain(FakeResolver(wideopen_zone), "wideopen.test")
    assert "combo.no_authentication_at_all" in {f.code for f in result.combo}


def test_no_authentication_is_not_flagged_for_a_parked_domain() -> None:
    zone = {("parked.test", "TXT"): ["x=y"]}
    result = check_domain(FakeResolver(zone), "parked.test")
    assert "combo.no_authentication_at_all" not in {f.code for f in result.combo}


def test_wildcard_suppresses_dkim_based_interactions() -> None:
    """With a wildcard zone the DKIM probe is meaningless, so nothing may rest on it."""
    from mailauth.models import DkimResult, DmarcResult, DomainResult, MxResult

    result = DomainResult(
        domain="w.test",
        resolver="fake",
        checked_at="now",
        posture=Posture.SENDING,
        mx=MxResult(),
        dmarc=DmarcResult(record="v=DMARC1; p=reject", tags={"p": "reject"}),
        dkim=DkimResult(wildcard=True),
    )
    codes = {f.code for f in interaction_findings(result)}
    assert "combo.enforcing_without_dkim" not in codes


# ---------------------------------------------------------------------------
# TTL cache
# ---------------------------------------------------------------------------


def test_ttl_is_clamped_at_both_ends() -> None:
    assert clamp_ttl(5) == 60
    assert clamp_ttl(3600) == 3600
    assert clamp_ttl(30 * 86400) == 86400


def test_cache_round_trips_through_the_store(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    response = DnsResponse("x.test", "TXT", QueryStatus.OK, ["v=spf1 -all"], ttl=3600)
    now = time.time()
    store.save_cache("1.1.1.1", [("x.test", "TXT", response, now + 3600)], now)

    cache, expiry = store.load_cache("1.1.1.1", now)
    assert cache[("x.test", "TXT")].values == ["v=spf1 -all"]
    assert expiry[("x.test", "TXT")] > now
    store.close()


def test_expired_cache_rows_are_not_returned(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    response = DnsResponse("x.test", "TXT", QueryStatus.OK, ["v=spf1 -all"], ttl=60)
    now = time.time()
    store.save_cache("1.1.1.1", [("x.test", "TXT", response, now - 10)], now - 100)

    cache, _ = store.load_cache("1.1.1.1", now)
    assert not cache
    store.close()


def test_cache_is_keyed_by_resolver(tmp_path: Path) -> None:
    """Two resolvers can legitimately disagree; their answers must not mix."""
    store = Store(tmp_path / "t.db")
    now = time.time()
    store.save_cache(
        "1.1.1.1",
        [("x.test", "TXT", DnsResponse("x.test", "TXT", QueryStatus.OK, ["a"]), now + 60)],
        now,
    )
    cache, _ = store.load_cache("8.8.8.8", now)
    assert not cache
    store.close()


# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------


def test_a_run_round_trips(tmp_path: Path, weights: Weights, halfway_zone) -> None:
    store = Store(tmp_path / "t.db")
    run_id = store.start_run("1.0.0", weights.version, "default", "1.1.1.1")
    result = score(check_domain(FakeResolver(halfway_zone), "halfway.test"), weights)
    store.save_result(run_id, result)
    store.finish_run(run_id, 1)

    payloads = store.run_payloads(run_id)
    assert payloads["halfway.test"]["score"] == result.score
    assert payloads["halfway.test"]["dmarc"]["tags"]["p"] == "none"

    run = store.resolve_run(str(run_id))
    assert run is not None and run.domain_count == 1
    store.close()


def test_run_references(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    first = store.start_run("1.0.0", "w", "default", "1.1.1.1")
    second = store.start_run("1.0.0", "w", "default", "1.1.1.1")

    assert store.resolve_run("latest").id == second
    assert store.resolve_run("latest~1").id == first
    assert store.resolve_run(str(first)).id == first
    assert store.resolve_run("nope") is None
    store.close()


def test_run_metadata_is_recorded(tmp_path: Path) -> None:
    """A score is not comparable across weights versions, so the version is stored."""
    store = Store(tmp_path / "t.db")
    run_id = store.start_run(
        "1.0.0", "2026.08.1+accounting", "accounting", "9.9.9.9", active_checks=True
    )
    run = store.resolve_run(str(run_id))
    assert run is not None
    assert run.weights_version == "2026.08.1+accounting"
    assert run.profile == "accounting"
    assert run.active_checks is True
    store.close()


# ---------------------------------------------------------------------------
# diffing
# ---------------------------------------------------------------------------


def payload(**overrides: object) -> dict:
    base = {
        "domain": "x.test",
        "score": 50,
        "spf": {"records": [], "all_qualifier": None, "dns_lookups": 0},
        "dmarc": {"record": None, "tags": {}},
        "dkim": {"keys": []},
        "mx": {"targets": []},
        "extras": {
            "tlsrpt": {"present": False},
            "mta_sts": {"dns": {"present": False}},
            "bimi": {"present": False},
        },
    }
    base.update(overrides)
    return base


def test_publishing_dmarc_is_reported() -> None:
    before = payload()
    after = payload(score=10, dmarc={"record": "v=DMARC1; p=none", "tags": {"p": "none"}})
    result = diff_domain("x.test", before, after)
    assert result.status == "changed"
    assert result.score_delta == -40
    assert any("DMARC record published" in c for c in result.changes)


def test_tightening_a_policy_is_described_as_tightening() -> None:
    before = payload(dmarc={"record": "r", "tags": {"p": "none"}})
    after = payload(dmarc={"record": "r", "tags": {"p": "reject"}})
    changes = diff_domain("x.test", before, after).changes
    assert any("tightened" in c for c in changes)


def test_loosening_a_policy_is_described_as_loosening() -> None:
    before = payload(dmarc={"record": "r", "tags": {"p": "reject"}})
    after = payload(dmarc={"record": "r", "tags": {"p": "none"}})
    changes = diff_domain("x.test", before, after).changes
    assert any("loosened" in c for c in changes)


def test_spf_terminal_mechanism_movement_is_described() -> None:
    before = payload(spf={"records": ["v=spf1 ~all"], "all_qualifier": "~"})
    after = payload(spf={"records": ["v=spf1 -all"], "all_qualifier": "-"})
    changes = diff_domain("x.test", before, after).changes
    assert any("tightened" in c and "all" in c for c in changes)


def test_a_new_dkim_key_is_reported() -> None:
    before = payload()
    after = payload(dkim={"keys": [{"selector": "google"}]})
    changes = diff_domain("x.test", before, after).changes
    assert any("DKIM key now found on: google" in c for c in changes)


def test_supporting_records_appearing_are_reported() -> None:
    before = payload()
    after = payload(
        extras={
            "tlsrpt": {"present": True},
            "mta_sts": {"dns": {"present": True}},
            "bimi": {"present": False},
        }
    )
    changes = diff_domain("x.test", before, after).changes
    assert any("TLS-RPT record published" in c for c in changes)
    assert any("MTA-STS record published" in c for c in changes)


def test_an_unchanged_domain_reports_unchanged() -> None:
    assert diff_domain("x.test", payload(), payload()).status == "unchanged"


def test_domains_present_in_only_one_run_are_handled() -> None:
    diffs = diff_runs({"gone.test": payload()}, {"new.test": payload()})
    by_domain = {d.domain: d for d in diffs}

    assert by_domain["gone.test"].status == "removed"
    assert by_domain["gone.test"].score_delta is None
    assert by_domain["new.test"].status == "added"
    assert by_domain["new.test"].score_delta is None


def test_diff_covers_the_union_of_both_runs() -> None:
    diffs = diff_runs(
        {"a.test": payload(), "b.test": payload()},
        {"b.test": payload(), "c.test": payload()},
    )
    assert {d.domain for d in diffs} == {"a.test", "b.test", "c.test"}


# ---------------------------------------------------------------------------
# DKIM key states and the enforcing-without-DKIM gate
#
# The finding gates on zero *usable* keys. A broken key and a dangling
# delegation both count as zero, because a receiver cannot verify a signature it
# cannot parse, and cannot verify one that was never published. Before this was
# split out, both states counted as "has DKIM" and silently suppressed the
# finding on exactly the domains it exists to catch.
# ---------------------------------------------------------------------------


def m365_dangling_zone() -> dict[tuple[str, str], list[str]]:
    """Microsoft 365, selector CNAMEs published, DKIM never enabled, p=reject."""
    return {
        ("t.test", "MX"): ["0 t-test.mail.protection.outlook.com"],
        ("t-test.mail.protection.outlook.com", "A"): ["104.47.1.1"],
        ("t.test", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all"],
        ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 -all"],
        ("_dmarc.t.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@t.test"],
        ("selector1._domainkey.t.test", "CNAME"): [
            "selector1-t-test._domainkey.tenant.onmicrosoft.com"
        ],
        ("selector2._domainkey.t.test", "CNAME"): [
            "selector2-t-test._domainkey.tenant.onmicrosoft.com"
        ],
    }


def test_dangling_delegations_do_not_count_as_dkim() -> None:
    result = check_domain(FakeResolver(m365_dangling_zone()), "t.test")
    assert result.dkim.usable_keys == []
    assert not result.dkim.any_key_found


def test_enforcing_without_dkim_fires_on_dangling_delegations() -> None:
    """The regression that matters. p=reject plus no verifiable signature."""
    result = check_domain(FakeResolver(m365_dangling_zone()), "t.test")
    assert "combo.enforcing_without_dkim" in {f.code for f in result.combo}


def test_enforcing_without_dkim_fires_on_a_broken_key() -> None:
    """A key nobody can parse protects nothing, so the interaction still holds."""
    from tests.test_dkim import BROKEN_QUOTED_KEY

    zone = dict(m365_dangling_zone())
    del zone[("selector1._domainkey.t.test", "CNAME")]
    del zone[("selector2._domainkey.t.test", "CNAME")]
    zone[("default._domainkey.t.test", "TXT")] = [BROKEN_QUOTED_KEY]

    result = check_domain(FakeResolver(zone), "t.test")
    codes = {f.code for f in result.combo}
    assert "combo.enforcing_without_dkim" in codes
    assert "dkim.none_found" not in {f.code for f in result.dkim.findings}


def test_enforcing_with_a_real_key_still_does_not_fire() -> None:
    zone = dict(m365_dangling_zone())
    zone[("selector1._domainkey.t.test", "TXT")] = [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]
    result = check_domain(FakeResolver(zone), "t.test")

    assert len(result.dkim.usable_keys) == 1
    assert "combo.enforcing_without_dkim" not in {f.code for f in result.combo}


# ---------------------------------------------------------------------------
# diff: an unreadable observation is not an absent record
#
# The check layer distinguishes a failed lookup from a definitive "no record"
# and scores them differently. The diff layer has to carry that distinction
# through, or a repeat scan reports that a prospect dropped their DMARC record
# when the truth is that a query timed out.
# ---------------------------------------------------------------------------


def diff_payload(**overrides: object) -> dict:
    base: dict = {
        "domain": "x.test",
        "score": 50,
        "error": None,
        "spf": {"records": [], "all_qualifier": None, "dns_lookups": 0},
        "dmarc": {"record": None, "tags": {}},
        "dkim": {"keys": []},
        "mx": {"targets": [], "status": "empty"},
        "extras": {
            "tlsrpt": {"present": False, "status": "empty"},
            "mta_sts": {"dns": {"present": False, "status": "empty"}},
            "bimi": {"present": False, "status": "empty"},
        },
        "findings": [],
    }
    base.update(overrides)
    return base


def with_dmarc(policy: str = "none") -> dict:
    return diff_payload(dmarc={"record": f"v=DMARC1; p={policy}", "tags": {"p": policy}})


def dmarc_unreachable() -> dict:
    """What the store holds when the _dmarc query timed out."""
    return diff_payload(
        findings=[{"code": "dmarc.unreachable", "area": "DMARC", "title": "x"}]
    )


def test_a_timed_out_dmarc_lookup_is_not_reported_as_removed() -> None:
    """A timed-out DMARC lookup between two runs. The record never went anywhere."""
    result = diff_domain("x.test", with_dmarc("none"), dmarc_unreachable())

    joined = " ".join(result.changes).lower()
    assert "removed" not in joined, result.changes
    assert "could not be read" in joined or "not be checked" in joined


def test_a_dmarc_record_appearing_after_a_timeout_is_not_reported_as_published() -> None:
    result = diff_domain("x.test", dmarc_unreachable(), with_dmarc("none"))
    joined = " ".join(result.changes).lower()
    assert "published" not in joined, result.changes


def test_a_genuinely_removed_dmarc_record_is_still_reported() -> None:
    """The fix must not blunt the real signal."""
    result = diff_domain("x.test", with_dmarc("reject"), diff_payload())
    assert any("removed" in c.lower() for c in result.changes), result.changes


def test_a_timed_out_mx_lookup_is_not_reported_as_a_change() -> None:
    before = diff_payload(mx={"targets": [{"host": "mail.x.test"}], "status": "ok"})
    after = diff_payload(mx={"targets": [], "status": "timeout"})
    joined = " ".join(diff_domain("x.test", before, after).changes).lower()

    assert "-> none" not in joined, joined
    assert "could not be read" in joined or "not be checked" in joined


def test_a_domain_that_errored_does_not_report_every_record_as_removed() -> None:
    """A domain-level timeout between two runs: one failure, four bogus
    'removed' lines before this was fixed."""
    before = diff_payload(
        spf={"records": ["v=spf1 -all"], "all_qualifier": "-", "dns_lookups": 1},
        mx={"targets": [{"host": "mail.x.test"}], "status": "ok"},
        dmarc={"record": "v=DMARC1; p=none", "tags": {"p": "none"}},
    )
    after = diff_payload(score=0, error="DNS query failed (timeout)")
    result = diff_domain("x.test", before, after)

    joined = " ".join(result.changes).lower()
    assert "removed" not in joined, result.changes
    assert "could not be" in joined


@pytest.mark.parametrize(
    "label,path",
    [
        ("TLS-RPT", ("tlsrpt",)),
        ("BIMI", ("bimi",)),
    ],
)
def test_a_timed_out_supporting_record_is_not_reported_as_removed(
    label: str, path: tuple[str, ...]
) -> None:
    key = path[0]
    before = diff_payload(
        extras={
            "tlsrpt": {"present": key == "tlsrpt", "status": "ok"},
            "mta_sts": {"dns": {"present": False, "status": "empty"}},
            "bimi": {"present": key == "bimi", "status": "ok"},
        }
    )
    after = diff_payload(
        extras={
            "tlsrpt": {"present": False, "status": "timeout"},
            "mta_sts": {"dns": {"present": False, "status": "empty"}},
            "bimi": {"present": False, "status": "timeout"},
        }
    )
    joined = " ".join(diff_domain("x.test", before, after).changes).lower()
    assert "removed" not in joined, joined


# ---------------------------------------------------------------------------
# diff: score movement is a change
# ---------------------------------------------------------------------------


def test_a_score_only_move_is_not_classified_as_unchanged() -> None:
    """Run 4 to 5: the store held seven movements and diff reported one."""
    before = with_dmarc("none")
    after = dict(with_dmarc("none"))
    after["score"] = 46

    result = diff_domain("x.test", before, after)
    assert result.status == "changed"
    assert result.score_delta == -4


def test_a_score_only_move_says_the_records_did_not_change() -> None:
    before = with_dmarc("none")
    after = dict(with_dmarc("none"))
    after["score"] = 46
    joined = " ".join(diff_domain("x.test", before, after).changes).lower()

    assert "score" in joined
    assert "no change" in joined or "without" in joined


def test_a_score_only_move_survives_diff_runs() -> None:
    """The filter that dropped these lives in the caller, so test end to end."""
    before = {"x.test": with_dmarc("none")}
    after = {"x.test": dict(with_dmarc("none"), score=46)}

    diffs = {d.domain: d for d in diff_runs(before, after)}
    assert diffs["x.test"].status == "changed"


def test_an_identical_run_is_still_unchanged() -> None:
    assert diff_domain("x.test", with_dmarc("none"), with_dmarc("none")).status == (
        "unchanged"
    )


def test_a_failed_selector_sweep_is_not_reported_as_a_lost_dkim_key() -> None:
    """The failure mode: a resolver hiccup reading as 'DKIM key removed'."""
    before = diff_payload(
        dkim={"keys": [{"selector": "google"}], "probe_failed_selectors": []}
    )
    after = diff_payload(dkim={"keys": [], "probe_failed_selectors": ["google"]})

    joined = " ".join(diff_domain("x.test", before, after).changes).lower()
    assert "no longer found" not in joined, joined
    assert "could not be" in joined


def test_a_genuinely_withdrawn_dkim_key_is_still_reported() -> None:
    before = diff_payload(
        dkim={"keys": [{"selector": "google"}], "probe_failed_selectors": []}
    )
    after = diff_payload(dkim={"keys": [], "probe_failed_selectors": []})

    joined = " ".join(diff_domain("x.test", before, after).changes).lower()
    assert "no longer found" in joined, joined


def test_a_key_appearing_where_the_earlier_probe_failed_is_not_claimed_as_new() -> None:
    before = diff_payload(dkim={"keys": [], "probe_failed_selectors": ["google"]})
    after = diff_payload(
        dkim={"keys": [{"selector": "google"}], "probe_failed_selectors": []}
    )

    joined = " ".join(diff_domain("x.test", before, after).changes).lower()
    assert "now found on" not in joined, joined


def test_a_total_probe_failure_does_not_score_as_a_dkim_gap() -> None:
    """A failed sweep is a fact about our vantage point, not about the domain."""
    from mailauth.providers import selectors_for

    zone = {
        ("u.test", "TXT"): ["v=spf1 -all"],
        ("u.test", "MX"): ["10 mail.u.test"],
        ("mail.u.test", "A"): ["192.0.2.1"],
        ("_dmarc.u.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@u.test"],
    }
    fail = {
        (f"{s}._domainkey.u.test", t) for s in selectors_for(None) for t in ("TXT", "CNAME")
    }
    healthy = score(check_domain(FakeResolver(zone), "u.test"), load_weights())
    broken = score(check_domain(FakeResolver(zone, fail=fail), "u.test"), load_weights())

    codes = {f.code for f in broken.findings}
    assert "dkim.unreachable" in codes
    assert "dkim.none_found" not in codes
    # An unobservable sweep must not fire the enforcing interaction either: it
    # rests entirely on knowing there is no key.
    assert "combo.enforcing_without_dkim" not in codes
    assert broken.score < healthy.score


# ---------------------------------------------------------------------------
# crossing the sending / non-sending boundary
# ---------------------------------------------------------------------------


def non_sending_payload() -> dict:
    return diff_payload(score=None, raw_score=93, posture="non-sending")


def sending_payload() -> dict:
    return diff_payload(
        score=93,
        raw_score=93,
        posture="sending",
        mx={"targets": [{"host": "mail.x.test"}], "status": "ok"},
    )


def test_a_domain_becoming_reachable_is_reported_prominently() -> None:
    """The transition I would act on: a prospect that now receives mail."""
    result = diff_domain("x.test", non_sending_payload(), sending_payload())

    assert result.status == "changed"
    assert result.changes, "a track crossing must not be silent"
    first = result.changes[0].lower()
    assert "receives mail" in first or "receiving mail" in first
    assert "93" not in result.changes[0], "the crossing is not a number moving"


def test_a_domain_that_stops_receiving_mail_is_reported_prominently() -> None:
    result = diff_domain("x.test", sending_payload(), non_sending_payload())
    first = result.changes[0].lower()
    assert "no longer" in first or "stopped" in first


def test_a_track_crossing_reports_no_score_delta() -> None:
    """One side has no score, so any delta would be meaningless."""
    result = diff_domain("x.test", non_sending_payload(), sending_payload())
    assert result.score_delta is None


def test_a_domain_staying_non_sending_is_not_reported_as_crossing() -> None:
    result = diff_domain("x.test", non_sending_payload(), non_sending_payload())
    assert result.status == "unchanged"
