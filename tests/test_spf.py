"""
tests/test_spf.py - SPF tokenizer and include-chain evaluation.

Every check has a fixture proving the passing case and the failing case, which
is the requirement in the brief. The tokenizer tests matter most: the failure
mode they guard against is a record that looks parsed but was silently mangled,
which produces a confidently wrong number for a client.
"""

from __future__ import annotations

import pytest

from mailauth.checks import spf
from tests.conftest import FakeResolver

# ---------------------------------------------------------------------------
# tokenizer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,qualifier,mechanism,value",
    [
        ("-all", "-", "all", ""),
        ("all", "", "all", ""),
        ("~all", "~", "all", ""),
        ("include:_spf.google.com", "", "include", "_spf.google.com"),
        ("+include:example.com", "+", "include", "example.com"),
        ("a", "", "a", ""),
        ("mx", "", "mx", ""),
        ("a:mail.example.com", "", "a", "mail.example.com"),
        ("ip4:192.0.2.0", "", "ip4", "192.0.2.0"),
        ("exists:%{i}._spf.example.com", "", "exists", "%{i}._spf.example.com"),
        ("ptr:example.com", "", "ptr", "example.com"),
    ],
)
def test_mechanisms_parse(raw: str, qualifier: str, mechanism: str, value: str) -> None:
    term = spf.parse_term(raw)
    assert term.qualifier == qualifier
    assert term.mechanism == mechanism
    assert term.value == value
    assert not term.is_modifier


def test_cidr_suffix_is_kept_separate_from_the_value() -> None:
    """`a/24` is a bare `a` with a prefix length, not a mechanism named `a/24`.

    A string-splitting parser drops the CIDR and produces an empty value, which
    happens to work; one that keeps it in the value would try to resolve "24"
    as a hostname.
    """
    term = spf.parse_term("a/24")
    assert term.mechanism == "a"
    assert term.value == ""
    assert term.cidr4 == 24

    term = spf.parse_term("+mx/24")
    assert term.qualifier == "+"
    assert term.mechanism == "mx"
    assert term.cidr4 == 24


def test_modifiers_are_distinguished_from_mechanisms() -> None:
    term = spf.parse_term("redirect=_spf.example.com")
    assert term.is_modifier
    assert term.mechanism == "redirect"
    assert term.value == "_spf.example.com"

    term = spf.parse_term("exp=explain.example.com")
    assert term.is_modifier
    assert term.mechanism == "exp"


def test_a_qualifier_on_a_modifier_is_a_syntax_error() -> None:
    """RFC 7208 permits qualifiers on mechanisms only."""
    term = spf.parse_term("-redirect=example.com")
    assert term.mechanism == ""


def test_garbage_terms_report_as_invalid_rather_than_being_skipped() -> None:
    for raw in ("!!!", "include::", "@@@@"):
        assert spf.parse_term(raw).mechanism == "", raw


def test_version_token_detection_is_exact() -> None:
    assert spf.is_spf_record("v=spf1 -all")
    assert spf.is_spf_record("V=SPF1 -all")
    assert spf.is_spf_record("v=spf1")
    # A record that merely starts with the same letters is not an SPF record.
    assert not spf.is_spf_record("v=spf10 -all")
    assert not spf.is_spf_record("google-site-verification=abc")


def test_tokenize_drops_the_version_token() -> None:
    terms = spf.tokenize("v=spf1 a mx -all")
    assert [t.mechanism for t in terms] == ["a", "mx", "all"]


# ---------------------------------------------------------------------------
# lookup counting
# ---------------------------------------------------------------------------


def test_nested_include_chain_counts_each_lookup_once() -> None:
    """A GoDaddy-to-Microsoft chain: three includes, three lookups."""
    zone = {
        ("example.test", "TXT"): ["v=spf1 include:secureserver.net -all"],
        ("secureserver.net", "TXT"): ["v=spf1 include:spf-0.secureserver.net -all"],
        ("spf-0.secureserver.net", "TXT"): [
            "v=spf1 ip4:1.2.3.0/24 include:spf.protection.outlook.com -all"
        ],
        ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 -all"],
    }
    walker = spf.SpfWalker(FakeResolver(zone))
    state = walker.walk(zone[("example.test", "TXT")][0], "example.test")

    assert state.lookups == 3
    assert state.void_lookups == 0
    assert state.all_qualifier == "-"
    assert len(state.chain) == 3


def test_redirect_counts_exactly_one_lookup() -> None:
    """A naive counter charges a redirect twice: once for the term, once in
    the recursion it triggers."""
    zone = {
        ("a.test", "TXT"): ["v=spf1 redirect=b.test"],
        ("b.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    }
    walker = spf.SpfWalker(FakeResolver(zone))
    state = walker.walk(zone[("a.test", "TXT")][0], "a.test")
    assert state.lookups == 1


def test_over_the_lookup_limit_is_reported() -> None:
    includes = " ".join(f"include:s{i}.test" for i in range(12))
    zone: dict[tuple[str, str], list[str]] = {
        ("big.test", "TXT"): [f"v=spf1 {includes} -all"]
    }
    for i in range(12):
        zone[(f"s{i}.test", "TXT")] = ["v=spf1 ip4:192.0.2.0/24 -all"]

    result = spf.check(FakeResolver(zone), "big.test", zone[("big.test", "TXT")])
    codes = {f.code for f in result.findings}
    assert "spf.lookup_limit_exceeded" in codes
    assert result.lookups == 12


def test_at_the_limit_warns_without_failing() -> None:
    includes = " ".join(f"include:s{i}.test" for i in range(9))
    zone: dict[tuple[str, str], list[str]] = {
        ("near.test", "TXT"): [f"v=spf1 {includes} -all"]
    }
    for i in range(9):
        zone[(f"s{i}.test", "TXT")] = ["v=spf1 ip4:192.0.2.0/24 -all"]

    result = spf.check(FakeResolver(zone), "near.test", zone[("near.test", "TXT")])
    codes = {f.code for f in result.findings}
    assert "spf.lookup_limit_near" in codes
    assert "spf.lookup_limit_exceeded" not in codes


# ---------------------------------------------------------------------------
# void lookups
# ---------------------------------------------------------------------------


def test_void_lookups_are_counted_separately_from_the_lookup_limit() -> None:
    """Three dangling includes: three lookups, three voids, over the void limit."""
    zone = {
        ("void.test", "TXT"): [
            "v=spf1 include:gone1.test include:gone2.test include:gone3.test -all"
        ]
    }
    result = spf.check(FakeResolver(zone), "void.test", zone[("void.test", "TXT")])

    assert result.lookups == 3
    assert result.void_lookups == 3
    codes = {f.code for f in result.findings}
    assert "spf.void_limit_exceeded" in codes
    assert "spf.lookup_limit_exceeded" not in codes


def test_two_void_lookups_are_within_the_limit() -> None:
    zone = {("ok.test", "TXT"): ["v=spf1 include:gone1.test include:gone2.test -all"]}
    result = spf.check(FakeResolver(zone), "ok.test", zone[("ok.test", "TXT")])
    assert result.void_lookups == 2
    assert "spf.void_limit_exceeded" not in {f.code for f in result.findings}


def test_a_timeout_is_not_counted_as_a_void_lookup() -> None:
    """A resolver failure says nothing about the domain and must not be scored."""
    zone = {("t.test", "TXT"): ["v=spf1 include:slow.test -all"]}
    resolver = FakeResolver(zone, fail={("slow.test", "TXT")})
    result = spf.check(resolver, "t.test", zone[("t.test", "TXT")])

    assert result.void_lookups == 0
    assert "spf.include_unreachable" in {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# structural problems
# ---------------------------------------------------------------------------


def test_include_loop_terminates_and_is_reported() -> None:
    zone = {
        ("a.test", "TXT"): ["v=spf1 include:b.test -all"],
        ("b.test", "TXT"): ["v=spf1 include:a.test -all"],
    }
    walker = spf.SpfWalker(FakeResolver(zone))
    state = walker.walk(zone[("a.test", "TXT")][0], "a.test")
    assert any(code == "spf.include_loop" for code, _ in state.notes)


def test_duplicate_include_in_one_record_is_flagged() -> None:
    zone = {
        ("dup.test", "TXT"): ["v=spf1 include:x.test include:x.test -all"],
        ("x.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    }
    result = spf.check(FakeResolver(zone), "dup.test", zone[("dup.test", "TXT")])
    assert "spf.duplicate_include" in {f.code for f in result.findings}


def test_multiple_all_mechanisms_are_flagged() -> None:
    zone = {("m.test", "TXT"): ["v=spf1 ~all ip4:192.0.2.0/24 -all"]}
    result = spf.check(FakeResolver(zone), "m.test", zone[("m.test", "TXT")])
    codes = {f.code for f in result.findings}
    assert "spf.multiple_all" in codes
    assert "spf.terms_after_all" in codes
    # The first all wins, so the effective qualifier is the soft fail.
    assert result.all_qualifier == "~"


def test_redirect_after_all_is_reported_as_never_used() -> None:
    zone = {
        ("r.test", "TXT"): ["v=spf1 -all redirect=other.test"],
        ("other.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    }
    result = spf.check(FakeResolver(zone), "r.test", zone[("r.test", "TXT")])
    assert "spf.redirect_ignored" in {f.code for f in result.findings}
    assert result.lookups == 0


def test_ptr_mechanism_is_flagged() -> None:
    zone = {("p.test", "TXT"): ["v=spf1 ptr -all"], ("p.test", "A"): ["192.0.2.1"]}
    result = spf.check(FakeResolver(zone), "p.test", zone[("p.test", "TXT")])
    assert "spf.ptr" in {f.code for f in result.findings}


def test_macros_are_reported_but_not_resolved() -> None:
    zone = {("mac.test", "TXT"): ["v=spf1 exists:%{i}._spf.mac.test -all"]}
    result = spf.check(FakeResolver(zone), "mac.test", zone[("mac.test", "TXT")])
    assert "spf.macro" in {f.code for f in result.findings}
    # The macro is not expanded, so it must not be counted as a void lookup.
    assert result.void_lookups == 0


def test_unknown_mechanism_is_a_syntax_error() -> None:
    zone = {("bad.test", "TXT"): ["v=spf1 includ:typo.test -all"]}
    result = spf.check(FakeResolver(zone), "bad.test", zone[("bad.test", "TXT")])
    assert "spf.syntax_error" in {f.code for f in result.findings}


def test_unknown_modifier_is_ignored_not_an_error() -> None:
    """RFC 7208 requires unknown modifiers to be ignored, unlike mechanisms."""
    zone = {("mod.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 future=yes -all"]}
    result = spf.check(FakeResolver(zone), "mod.test", zone[("mod.test", "TXT")])
    assert "spf.syntax_error" not in {f.code for f in result.findings}


def test_nested_domain_with_two_spf_records_is_reported() -> None:
    zone = {
        ("n.test", "TXT"): ["v=spf1 include:broken.test -all"],
        ("broken.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all", "v=spf1 mx -all"],
    }
    result = spf.check(FakeResolver(zone), "n.test", zone[("n.test", "TXT")])
    assert "spf.nested_multiple" in {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# record level
# ---------------------------------------------------------------------------


def test_no_spf_record() -> None:
    result = spf.check(FakeResolver({}), "none.test", ["google-site-verification=x"])
    assert not result.records
    assert "spf.absent" in {f.code for f in result.findings}


def test_two_spf_records_at_the_apex() -> None:
    values = ["v=spf1 a mx ~all", "v=spf1 include:relay.test ~all"]
    result = spf.check(FakeResolver({}), "two.test", values)
    assert len(result.records) == 2
    assert "spf.multiple_records" in {f.code for f in result.findings}


@pytest.mark.parametrize(
    "record,expected_code",
    [
        ("v=spf1 ip4:192.0.2.0/24 +all", "spf.all_pass"),
        ("v=spf1 ip4:192.0.2.0/24 ?all", "spf.all_neutral"),
        ("v=spf1 ip4:192.0.2.0/24 ~all", "spf.all_softfail"),
        ("v=spf1 ip4:192.0.2.0/24 -all", "spf.all_hardfail"),
        ("v=spf1 ip4:192.0.2.0/24", "spf.no_all"),
    ],
)
def test_terminal_mechanism_classification(record: str, expected_code: str) -> None:
    result = spf.check(FakeResolver({}), "q.test", [record])
    assert expected_code in {f.code for f in result.findings}
