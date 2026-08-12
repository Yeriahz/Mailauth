"""
tests/test_input_validation.py - rejecting input that cannot be a domain name.

A CSV row passed to --file was being reported as `the domain does not resolve`,
which is a claim about the outside world made on the strength of a query that
could never have succeeded. Input that cannot be a domain is a fact about the
input, and it is reported as such: no score, no risk band, no severity, and no
DNS query.
"""

from __future__ import annotations

import pytest

from mailauth.cli import domain_rejection, normalise_domain

INVALID = [
    ("csv row", "example firm,example.com,henderson,new"),
    ("bom header", "﻿firm,domain,tier,status"),
    ("over-long label", "a" * 67 + ".com"),
    ("empty", ""),
    ("contains @", "user@example.com"),
]

VALID = [
    ("leading and trailing space", "  example.com  "),
    ("trailing dot", "example.com."),
    ("uppercase", "EXAMPLE.COM"),
    ("control", "example.com"),
]


@pytest.mark.parametrize("label,raw", INVALID, ids=[i[0] for i in INVALID])
def test_invalid_input_is_rejected(label: str, raw: str) -> None:
    reason = domain_rejection(normalise_domain(raw))
    assert reason is not None, f"{label}: accepted {raw!r}"
    assert isinstance(reason, str) and reason


@pytest.mark.parametrize("label,raw", VALID, ids=[i[0] for i in VALID])
def test_valid_input_is_accepted(label: str, raw: str) -> None:
    assert domain_rejection(normalise_domain(raw)) is None, label


def test_a_rejection_never_says_the_domain_does_not_resolve() -> None:
    """The whole point: a rejection is not a claim about DNS."""
    for _, raw in INVALID:
        reason = domain_rejection(normalise_domain(raw))
        assert reason is not None
        assert "does not resolve" not in reason.lower()
        assert "nxdomain" not in reason.lower()


def test_the_awkward_valid_forms_all_normalise_to_one_domain() -> None:
    assert {normalise_domain(raw) for _, raw in VALID} == {"example.com"}


@pytest.mark.parametrize(
    "raw",
    [
        "a" * 63 + ".com",
        "x.co",
        "sub.domain.example.com",
        "xn--bcher-kva.example",
        "a-b.example.com",
        "_dmarc.example.com",
    ],
)
def test_legitimate_shapes_are_not_rejected(raw: str) -> None:
    assert domain_rejection(raw) is None, raw


@pytest.mark.parametrize(
    "raw",
    [
        "example..com",
        ".example.com",
        "-example.com",
        "example-.com",
        "exa mple.com",
        "example.com/path",
        "singlelabel",
        "a" * 250 + ".example.com",
    ],
)
def test_malformed_shapes_are_rejected(raw: str) -> None:
    assert domain_rejection(raw) is not None, raw


def test_rejected_input_issues_no_dns_query(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing may reach the resolver on the strength of invalid input."""
    from mailauth import cli
    from tests.conftest import FakeResolver

    resolver = FakeResolver({})

    def fake_client(args, store):  # type: ignore[no-untyped-def]
        return resolver

    monkeypatch.setattr(cli, "build_client", fake_client)
    monkeypatch.setattr(cli, "flush_cache", lambda *a, **k: None)

    with pytest.raises(SystemExit):
        cli.main(["check", "example firm,example.com,henderson,new", "--no-db"])
    assert resolver.queries == []


def test_a_rejected_input_is_not_scored_or_stored(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mailauth import cli
    from mailauth.store import Store
    from tests.conftest import FakeResolver

    zone = {
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("example.com", "SOA"): ["ns.example.com. h.example.com. 1 2 3 4 5"],
    }
    monkeypatch.setattr(cli, "build_client", lambda args, store: FakeResolver(zone))
    monkeypatch.setattr(cli, "flush_cache", lambda *a, **k: None)

    db = tmp_path / "t.db"
    cli.main(["check", "user@example.com", "example.com", "--db", str(db)])
    out = capsys.readouterr()

    store = Store(db)
    stored = set(store.run_payloads(1))
    store.close()

    assert stored == {"example.com"}, stored
    assert "user@example.com" in out.err
    assert "does not resolve" not in out.err


def test_every_target_invalid_exits_without_checking_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mailauth import cli
    from tests.conftest import FakeResolver

    monkeypatch.setattr(cli, "build_client", lambda args, store: FakeResolver({}))
    monkeypatch.setattr(cli, "flush_cache", lambda *a, **k: None)
    with pytest.raises(SystemExit):
        cli.main(["check", "a,b,c", "user@x.test", "--no-db"])


def test_a_bom_on_the_first_line_of_a_target_file_is_stripped(
    tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mailauth import cli
    from tests.conftest import FakeResolver

    listing = tmp_path / "targets.txt"
    listing.write_bytes("﻿example.com\n".encode())

    zone = {
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("example.com", "SOA"): ["ns.example.com. h.example.com. 1 2 3 4 5"],
    }
    monkeypatch.setattr(cli, "build_client", lambda args, store: FakeResolver(zone))
    monkeypatch.setattr(cli, "flush_cache", lambda *a, **k: None)

    cli.main(["check", "--file", str(listing), "--no-db"])
    out = capsys.readouterr().out
    assert "example.com" in out
    assert "﻿" not in out
    assert "does not resolve" not in out
