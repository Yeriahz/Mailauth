"""
tests/test_cli.py - argument handling, CSV round-tripping, and the compatibility
shim.

These tests never reach the network: the DNS client is replaced with the fake
resolver at the point the CLI builds it.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from mailauth import __version__, cli
from tests.conftest import FakeResolver

ZONE = {
    ("wideopen.test", "MX"): ["10 mail.secureserver.net"],
    ("mail.secureserver.net", "A"): ["97.74.1.1"],
    ("wideopen.test", "TXT"): ["x=y"],
    ("locked.test", "MX"): ["1 aspmx.l.google.com"],
    ("aspmx.l.google.com", "A"): ["142.250.1.26"],
    ("aspmx.l.google.com", "AAAA"): ["2607:f8b0::1"],
    ("locked.test", "TXT"): ["v=spf1 include:_spf.google.com -all"],
    ("_spf.google.com", "TXT"): ["v=spf1 ip4:35.190.0.0/16 -all"],
    ("_dmarc.locked.test", "TXT"): [
        "v=DMARC1; p=reject; sp=reject; rua=mailto:d@locked.test"
    ],
}


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV fully and close the handle.

    Worth a helper rather than inlining: the suite runs with warnings as errors,
    so a leaked file handle fails the test that leaked it.
    """
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the real DNS client everywhere the CLI would build one."""

    def fake_client(args, store):  # type: ignore[no-untyped-def]
        return FakeResolver(ZONE, server=getattr(args, "resolver", "fake"))

    monkeypatch.setattr(cli, "build_client", fake_client)
    monkeypatch.setattr(cli, "flush_cache", lambda *a, **k: None)


# ---------------------------------------------------------------------------
# domain normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("www.example.com", "example.com"),
        ("https://example.com", "example.com"),
        ("http://www.example.com/contact", "example.com"),
        ("example.com.", "example.com"),
    ],
)
def test_domain_normalisation(raw: str, expected: str) -> None:
    assert cli.normalise_domain(raw) == expected


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_prints_a_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check", "wideopen.test", "--db", str(tmp_path / "t.db")])
    out = capsys.readouterr().out
    assert code == 0
    assert "wideopen.test" in out
    assert "No DMARC record is published" in out


def test_check_writes_json(tmp_path: Path) -> None:
    target = tmp_path / "results.json"
    cli.main(["check", "locked.test", "--json", str(target), "--no-db"])
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data[0]["domain"] == "locked.test"
    assert data[0]["dmarc"]["tags"]["p"] == "reject"


def test_check_reads_a_domain_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listing = tmp_path / "targets.txt"
    listing.write_text("# a comment\nwideopen.test\n\nlocked.test\n", encoding="utf-8")
    cli.main(["check", "--file", str(listing), "--no-db"])
    out = capsys.readouterr().out
    assert "wideopen.test" in out
    assert "locked.test" in out


def test_check_with_no_domains_errors() -> None:
    with pytest.raises(SystemExit):
        cli.main(["check", "--no-db"])


def test_unresolvable_domain_exits_nonzero(tmp_path: Path) -> None:
    assert cli.main(["check", "nothing.test", "--no-db"]) == 1


def test_verbose_shows_the_score_breakdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["-v", "check", "wideopen.test", "--no-db"])
    out = capsys.readouterr().out
    assert "score breakdown" in out
    assert "running total" in out


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------


@pytest.fixture
def prospects(tmp_path: Path) -> Path:
    path = tmp_path / "targets.csv"
    path.write_text(
        "firm,domain,tier,status\n"
        "Wide Open LLC,wideopen.test,henderson,new\n"
        "Locked Down CPA,https://www.locked.test,lasvegas,new\n",
        encoding="utf-8",
    )
    return path


def test_batch_writes_a_sorted_csv(prospects: Path, tmp_path: Path) -> None:
    out = tmp_path / "results.csv"
    cli.main(["batch", str(prospects), "-o", str(out), "--db", str(tmp_path / "t.db")])

    rows = read_csv(out)
    assert [r["domain"] for r in rows] == ["wideopen.test", "locked.test"]
    assert int(rows[0]["score"]) > int(rows[1]["score"])


def test_batch_carries_input_columns_through(prospects: Path, tmp_path: Path) -> None:
    out = tmp_path / "results.csv"
    cli.main(["batch", str(prospects), "-o", str(out), "--no-db"])

    rows = read_csv(out)
    assert rows[0]["firm"] == "Wide Open LLC"
    assert rows[0]["tier"] == "henderson"
    assert rows[0]["status"] == "new"


def test_batch_normalises_urls_in_the_domain_column(
    prospects: Path, tmp_path: Path
) -> None:
    out = tmp_path / "results.csv"
    cli.main(["batch", str(prospects), "-o", str(out), "--no-db"])
    rows = read_csv(out)
    assert "locked.test" in [r["domain"] for r in rows]


def test_batch_output_carries_confidence_columns(prospects: Path, tmp_path: Path) -> None:
    out = tmp_path / "results.csv"
    cli.main(["batch", str(prospects), "-o", str(out), "--no-db"])
    rows = read_csv(out)
    assert "confidence" in rows[0]
    assert "confidence_label" in rows[0]
    assert "posture" in rows[0]


def test_batch_rejects_a_csv_with_no_domain_column(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("firm,website\nExample,example.com\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="domain"):
        cli.main(["batch", str(path), "-o", str(tmp_path / "o.csv"), "--no-db"])


def test_batch_records_a_run(prospects: Path, tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    cli.main(["batch", str(prospects), "-o", str(tmp_path / "o.csv"), "--db", str(db)])

    from mailauth.store import Store

    store = Store(db)
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0].domain_count == 2
    store.close()


# ---------------------------------------------------------------------------
# report, diff, runs
# ---------------------------------------------------------------------------


def test_report_generates_one_pagers_from_a_run(prospects: Path, tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    outdir = tmp_path / "reports"
    cli.main(["batch", str(prospects), "-o", str(tmp_path / "o.csv"), "--db", str(db)])
    cli.main(["report", "latest", "--db", str(db), "--outdir", str(outdir), "--html"])

    assert (outdir / "wideopen.test.md").exists()
    assert (outdir / "wideopen.test.html").exists()
    text = (outdir / "wideopen.test.md").read_text(encoding="utf-8")
    assert "Wide Open LLC" in text
    assert "p=none" in text


def test_report_can_target_one_domain(prospects: Path, tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    outdir = tmp_path / "reports"
    cli.main(["batch", str(prospects), "-o", str(tmp_path / "o.csv"), "--db", str(db)])
    cli.main(
        [
            "report",
            "latest",
            "--domain",
            "locked.test",
            "--db",
            str(db),
            "--outdir",
            str(outdir),
        ]
    )
    assert (outdir / "locked.test.md").exists()
    assert not (outdir / "wideopen.test.md").exists()


def test_report_from_a_json_file(tmp_path: Path) -> None:
    payload = tmp_path / "results.json"
    cli.main(["check", "wideopen.test", "--json", str(payload), "--no-db"])
    outdir = tmp_path / "reports"
    cli.main(["report", str(payload), "--outdir", str(outdir)])
    assert (outdir / "wideopen.test.md").exists()


def test_report_on_an_unknown_run_errors(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="no run matching"):
        cli.main(["report", "9999", "--db", str(tmp_path / "t.db")])


def test_diff_reports_what_changed(prospects: Path, tmp_path: Path, capsys) -> None:
    db = tmp_path / "t.db"
    cli.main(["batch", str(prospects), "-o", str(tmp_path / "o.csv"), "--db", str(db)])
    cli.main(["batch", str(prospects), "-o", str(tmp_path / "o.csv"), "--db", str(db)])

    capsys.readouterr()
    code = cli.main(["diff", "1", "2", "--db", str(db)])
    out = capsys.readouterr().out
    assert code == 0
    assert "nothing changed" in out


def test_runs_lists_stored_runs(prospects: Path, tmp_path: Path, capsys) -> None:
    db = tmp_path / "t.db"
    cli.main(["batch", str(prospects), "-o", str(tmp_path / "o.csv"), "--db", str(db)])
    capsys.readouterr()
    cli.main(["runs", "--db", str(db)])
    assert "default" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# the active flag
# ---------------------------------------------------------------------------


def test_active_prints_a_notice(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["check", "locked.test", "--active", "--no-db"])
    err = capsys.readouterr().err
    assert "NOTICE" in err
    assert "--active" in err
    assert "authorization" in err.lower()


def test_no_notice_without_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli.main(["check", "locked.test", "--no-db"])
    assert "NOTICE" not in capsys.readouterr().err


def test_active_defaults_to_off() -> None:
    args = cli.build_parser().parse_args(["check", "x.test"])
    assert args.active is False


# ---------------------------------------------------------------------------
# version and profiles
# ---------------------------------------------------------------------------


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_unknown_profile_exits_cleanly(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="unknown profile"):
        cli.main(["check", "locked.test", "--profile", "nope", "--no-db"])


def test_profile_changes_the_score(prospects: Path, tmp_path: Path) -> None:
    default_out = tmp_path / "d.csv"
    accounting_out = tmp_path / "a.csv"
    cli.main(["batch", str(prospects), "-o", str(default_out), "--no-db"])
    cli.main(
        [
            "batch",
            str(prospects),
            "-o",
            str(accounting_out),
            "--profile",
            "accounting",
            "--no-db",
        ]
    )

    default_rows = read_csv(default_out)
    accounting_rows = read_csv(accounting_out)
    assert int(accounting_rows[0]["score"]) >= int(default_rows[0]["score"])


# ---------------------------------------------------------------------------
# the weights-mismatch warning
# ---------------------------------------------------------------------------


def test_diff_warns_when_a_numbers_only_weight_edit_changed_the_scoring(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case the digest exists for.

    Editing a weight without touching weights_version used to leave both runs
    labelled identically, so the mismatch warning could not fire and six score
    movements looked like domain changes.
    """
    from mailauth.scoring import load_weights
    from mailauth.store import Store

    db = tmp_path / "t.db"
    baseline = load_weights()

    edited_path = tmp_path / "edited.toml"
    source = (Path("mailauth") / "weights.toml").read_text(encoding="utf-8")
    edited_path.write_text(
        source.replace(
            '[findings."dkim.none_found"]\nweight = 15',
            '[findings."dkim.none_found"]\nweight = 16',
            1,
        ),
        encoding="utf-8",
    )
    edited = load_weights(edited_path)

    # The human-readable part is untouched; only the digest moves.
    assert edited.version.rsplit("+", 1)[0] == baseline.version.rsplit("+", 1)[0]
    assert edited.version != baseline.version

    store = Store(db)
    store.finish_run(store.start_run("1", baseline.version, "default", "1.1.1.1"), 0)
    store.finish_run(store.start_run("1", edited.version, "default", "1.1.1.1"), 0)
    store.close()

    capsys.readouterr()
    cli.main(["diff", "1", "2", "--db", str(db)])
    err = capsys.readouterr().err
    # It must name which axis moved: a weight edit is a different conversation
    # from the tool scoring differently.
    assert "the weights changed" in err
    assert "scoring algorithm" not in err


def test_batch_ranks_by_raw_score_not_the_clamped_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two saturated domains both show 100; the worse one must still sort first."""
    path = tmp_path / "p.csv"
    path.write_text("domain\nwideopen.test\nlocked.test\n", encoding="utf-8")
    out = tmp_path / "r.csv"
    cli.main(["batch", str(path), "-o", str(out), "--no-db"])
    rows = read_csv(out)

    assert "raw_score" in rows[0]
    raws = [int(r["raw_score"]) for r in rows]
    assert raws == sorted(raws, reverse=True), raws
    for row in rows:
        assert int(row["raw_score"]) >= int(row["score"])


def test_diff_names_a_package_version_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The check layer sits outside both digests; the package version marks it."""
    from mailauth.scoring import load_weights
    from mailauth.store import Store

    db = tmp_path / "t.db"
    weights = load_weights()
    store = Store(db)
    store.finish_run(store.start_run("1.0.0", weights.version, "default", "1.1.1.1"), 0)
    store.finish_run(store.start_run("1.1.0", weights.version, "default", "1.1.1.1"), 0)
    store.close()

    capsys.readouterr()
    cli.main(["diff", "1", "2", "--db", str(db)])
    err = capsys.readouterr().err
    assert "different versions of mailauth" in err
    assert "1.0.0" in err and "1.1.0" in err
    # The weights are identical, so it must not claim they changed.
    assert "the weights changed" not in err
