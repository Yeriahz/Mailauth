"""
mailauth/store.py - SQLite persistence, run diffing, and the TTL-aware DNS cache.

Every run is recorded with enough context to reproduce and to interpret it later:
tool version, weights version, profile, resolver, and whether the active check
was enabled. A score is not comparable across weights versions, and a diff that
silently compared two different scoring configs would be worse than no diff.

Threading note: no connection is shared across threads. The DNS cache is read
into memory before a batch starts and written back after it finishes. At the
scale this tool runs at, mid-run persistence saves nothing and the class of bug
it invites is real.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .dns_client import DnsResponse
from .models import DomainResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid       TEXT    NOT NULL UNIQUE,
    started_at     TEXT    NOT NULL,
    finished_at    TEXT,
    tool_version   TEXT    NOT NULL,
    weights_version TEXT   NOT NULL,
    profile        TEXT    NOT NULL,
    resolver       TEXT    NOT NULL,
    active_checks  INTEGER NOT NULL DEFAULT 0,
    input_path     TEXT,
    domain_count   INTEGER NOT NULL DEFAULT 0,
    note           TEXT
);

CREATE TABLE IF NOT EXISTS domain_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain        TEXT    NOT NULL,
    score         INTEGER,
    risk          TEXT    NOT NULL,
    posture       TEXT    NOT NULL,
    confidence    REAL    NOT NULL,
    confidence_label TEXT NOT NULL,
    low_confidence_share REAL NOT NULL,
    error         TEXT,
    payload_json  TEXT    NOT NULL,
    UNIQUE (run_id, domain)
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    domain     TEXT    NOT NULL,
    code       TEXT    NOT NULL,
    area       TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    confidence TEXT    NOT NULL,
    weight     INTEGER NOT NULL,
    title      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_findings_run_domain ON findings (run_id, domain);
CREATE INDEX IF NOT EXISTS ix_results_domain ON domain_results (domain);

CREATE TABLE IF NOT EXISTS dns_cache (
    name       TEXT NOT NULL,
    rdtype     TEXT NOT NULL,
    resolver   TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (name, rdtype, resolver)
);
"""


@dataclass(frozen=True)
class RunInfo:
    id: int
    run_uuid: str
    started_at: str
    finished_at: str | None
    tool_version: str
    weights_version: str
    profile: str
    resolver: str
    active_checks: bool
    input_path: str | None
    domain_count: int

    @property
    def label(self) -> str:
        return f"run {self.id} ({self.started_at}, weights {self.weights_version})"


class Store:
    """SQLite-backed run history and DNS cache."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA)
        self._allow_null_scores()
        self.connection.commit()

    def _allow_null_scores(self) -> None:
        """Drop the NOT NULL constraint on domain_results.score if present.

        A non-sending domain has no score, and SQLite cannot relax a constraint
        in place, so the table is rebuilt. Runs made before this change stored a
        collapsed number; they keep it, and the digest already marks them as
        scored under a different algorithm.
        """
        columns = self.connection.execute("PRAGMA table_info(domain_results)").fetchall()
        if not any(c["name"] == "score" and c["notnull"] for c in columns):
            return
        self.connection.executescript(
            """
            PRAGMA foreign_keys = OFF;
            ALTER TABLE domain_results RENAME TO domain_results_old;
            """
        )
        self.connection.executescript(SCHEMA)
        # Columns listed literally rather than assembled from PRAGMA output, so
        # this is a constant statement with no query construction in it.
        self.connection.execute(
            "INSERT INTO domain_results "
            "(id, run_id, domain, score, risk, posture, confidence, "
            " confidence_label, low_confidence_share, error, payload_json) "
            "SELECT id, run_id, domain, score, risk, posture, confidence, "
            "       confidence_label, low_confidence_share, error, payload_json "
            "FROM domain_results_old"
        )
        self.connection.executescript(
            """
            DROP TABLE domain_results_old;
            PRAGMA foreign_keys = ON;
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- runs --------------------------------------------------------------

    def start_run(
        self,
        tool_version: str,
        weights_version: str,
        profile: str,
        resolver: str,
        active_checks: bool = False,
        input_path: str | None = None,
        note: str | None = None,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO runs (run_uuid, started_at, tool_version, weights_version, "
            "profile, resolver, active_checks, input_path, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                datetime.now(UTC).isoformat(timespec="seconds"),
                tool_version,
                weights_version,
                profile,
                resolver,
                int(active_checks),
                input_path,
                note,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid or 0)

    def finish_run(self, run_id: int, domain_count: int) -> None:
        self.connection.execute(
            "UPDATE runs SET finished_at = ?, domain_count = ? WHERE id = ?",
            (
                datetime.now(UTC).isoformat(timespec="seconds"),
                domain_count,
                run_id,
            ),
        )
        self.connection.commit()

    def save_result(self, run_id: int, result: DomainResult) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO domain_results "
            "(run_id, domain, score, risk, posture, confidence, confidence_label, "
            " low_confidence_share, error, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                result.domain,
                result.score,
                result.risk,
                str(result.posture),
                result.confidence,
                str(result.confidence_label),
                result.low_confidence_share,
                result.error,
                json.dumps(result.to_dict(), separators=(",", ":")),
            ),
        )
        self.connection.executemany(
            "INSERT INTO findings (run_id, domain, code, area, severity, confidence, "
            "weight, title) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    result.domain,
                    item.finding.code,
                    item.finding.area,
                    str(item.finding.severity),
                    str(item.finding.confidence),
                    item.weight,
                    item.finding.title,
                )
                for item in result.scored
            ],
        )
        self.connection.commit()

    def resolve_run(self, reference: str) -> RunInfo | None:
        """Accept an integer id, a run uuid, `latest`, or `latest~N`."""
        reference = reference.strip()
        if reference.startswith("latest"):
            offset = 0
            if "~" in reference:
                try:
                    offset = int(reference.split("~", 1)[1])
                except ValueError:
                    return None
            row = self.connection.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT 1 OFFSET ?", (offset,)
            ).fetchone()
        elif reference.isdigit():
            row = self.connection.execute(
                "SELECT * FROM runs WHERE id = ?", (int(reference),)
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT * FROM runs WHERE run_uuid = ?", (reference,)
            ).fetchone()
        return _row_to_run(row) if row else None

    def list_runs(self, limit: int = 20) -> list[RunInfo]:
        rows = self.connection.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_run(row) for row in rows]

    def run_payloads(self, run_id: int) -> dict[str, dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT domain, payload_json FROM domain_results WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return {row["domain"]: json.loads(row["payload_json"]) for row in rows}

    # -- DNS cache ---------------------------------------------------------

    def load_cache(
        self, resolver: str, now: float
    ) -> tuple[dict[tuple[str, str], DnsResponse], dict[tuple[str, str], float]]:
        """Load unexpired cache rows for one resolver."""
        rows = self.connection.execute(
            "SELECT name, rdtype, payload_json, expires_at FROM dns_cache "
            "WHERE resolver = ? AND expires_at > ?",
            (resolver, now),
        ).fetchall()
        cache: dict[tuple[str, str], DnsResponse] = {}
        expiry: dict[tuple[str, str], float] = {}
        for row in rows:
            key = (row["name"], row["rdtype"])
            cache[key] = DnsResponse.from_dict(json.loads(row["payload_json"]))
            expiry[key] = float(row["expires_at"])
        return cache, expiry

    def save_cache(
        self,
        resolver: str,
        entries: list[tuple[str, str, DnsResponse, float]],
        now: float,
    ) -> None:
        self.connection.executemany(
            "INSERT OR REPLACE INTO dns_cache "
            "(name, rdtype, resolver, payload_json, fetched_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    name,
                    rdtype,
                    resolver,
                    json.dumps(response.to_dict(), separators=(",", ":")),
                    now,
                    expires_at,
                )
                for name, rdtype, response, expires_at in entries
            ],
        )
        self.connection.execute("DELETE FROM dns_cache WHERE expires_at < ?", (now,))
        self.connection.commit()

    def clear_cache(self) -> int:
        cursor = self.connection.execute("DELETE FROM dns_cache")
        self.connection.commit()
        return cursor.rowcount


def _row_to_run(row: sqlite3.Row) -> RunInfo:
    return RunInfo(
        id=int(row["id"]),
        run_uuid=str(row["run_uuid"]),
        started_at=str(row["started_at"]),
        finished_at=row["finished_at"],
        tool_version=str(row["tool_version"]),
        weights_version=str(row["weights_version"]),
        profile=str(row["profile"]),
        resolver=str(row["resolver"]),
        active_checks=bool(row["active_checks"]),
        input_path=row["input_path"],
        domain_count=int(row["domain_count"]),
    )


# ---------------------------------------------------------------------------
# diffing
# ---------------------------------------------------------------------------

# Policy strength ordering, so a diff can say "tightened" or "loosened" rather
# than just "changed".
POLICY_RANK = {"": 0, "none": 1, "quarantine": 2, "reject": 3}
ALL_RANK = {"": 0, "+": 1, "?": 2, "~": 3, "-": 4}


@dataclass(frozen=True)
class DomainDiff:
    """What changed for one domain between two runs."""

    domain: str
    status: str  # "changed", "unchanged", "added", "removed"
    score_before: int | None = None
    score_after: int | None = None
    changes: list[str] = field(default_factory=list)

    @property
    def score_delta(self) -> int | None:
        if self.score_before is None or self.score_after is None:
            return None
        return self.score_after - self.score_before


def _get(payload: dict[str, Any], *path: str) -> Any:
    node: Any = payload
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


# Query statuses that mean "we failed to get an answer", as opposed to "the
# answer was that no record exists". Mirrors QueryStatus.is_our_fault, restated
# here because the diff works from stored JSON rather than from live objects.
_UNRELIABLE_STATUSES = frozenset({"timeout", "servfail", "error"})

# Areas the diff reports on, and how to tell whether the observation for each one
# can be trusted in a given run.
AREAS = ("SPF", "DMARC", "DKIM", "MX", "TLS-RPT", "MTA-STS", "BIMI")


def observation_reliable(payload: dict[str, Any], area: str) -> bool:
    """True when this run got a definitive answer about `area` for this domain.

    An unreliable observation is not evidence of anything, and must never be
    differenced against a reliable one. Comparing them is how "the query timed
    out" becomes "the prospect removed their DMARC record", which is a thing you
    would put in an email and be wrong about.
    """
    # A domain-level error means the apex lookup failed, so nothing below it was
    # ever queried. Every area is unreliable.
    if payload.get("error"):
        return False

    codes = {
        str(f.get("code", ""))
        for f in (payload.get("findings") or [])
        if isinstance(f, dict)
    }

    if area == "MX":
        status = str(_get(payload, "mx", "status") or "")
        return status not in _UNRELIABLE_STATUSES and "mx.unreachable" not in codes
    if area == "DMARC":
        return "dmarc.unreachable" not in codes
    if area == "TLS-RPT":
        return (
            str(_get(payload, "extras", "tlsrpt", "status") or "")
            not in _UNRELIABLE_STATUSES
        )
    if area == "MTA-STS":
        return (
            str(_get(payload, "extras", "mta_sts", "dns", "status") or "")
            not in _UNRELIABLE_STATUSES
        )
    if area == "BIMI":
        return (
            str(_get(payload, "extras", "bimi", "status") or "") not in _UNRELIABLE_STATUSES
        )
    # SPF and DKIM have no independent failure mode: SPF is read from the apex
    # TXT set, which is covered by the domain-level error above, and a DKIM
    # selector probe that fails is indistinguishable from one that finds nothing.
    return True


def _comparable(
    before: dict[str, Any], after: dict[str, Any], area: str, changes: list[str]
) -> bool:
    """Decide whether `area` can be differenced, recording a note when it cannot."""
    ok_before = observation_reliable(before, area)
    ok_after = observation_reliable(after, area)
    if ok_before and ok_after:
        return True
    if not ok_before and not ok_after:
        note = f"{area} could not be read in either run, so no comparison was made"
    elif not ok_after:
        note = (
            f"{area} could not be read in the later run, so it is not known whether "
            f"it changed"
        )
    else:
        note = (
            f"{area} could not be read in the earlier run, so it is not known whether "
            f"it changed"
        )
    if note not in changes:
        changes.append(note)
    return False


def diff_domain(domain: str, before: dict[str, Any], after: dict[str, Any]) -> DomainDiff:
    """Describe what changed for one domain between two stored results."""
    changes: list[str] = []

    # A domain-level error makes every area unreliable at once. Say that once,
    # rather than repeating the same caveat for all seven record types.
    error_before = str(before.get("error") or "")
    error_after = str(after.get("error") or "")
    if error_before or error_after:
        if error_before and error_after:
            note = (
                f"the domain could not be checked in either run "
                f"({error_after}), so nothing was compared"
            )
        elif error_after:
            note = (
                f"the domain could not be checked in the later run ({error_after}), "
                f"so it is not known whether anything changed"
            )
        else:
            note = (
                f"the domain could not be checked in the earlier run "
                f"({error_before}), so it is not known whether anything changed"
            )
        score_before = _get(before, "score")
        score_after = _get(after, "score")
        return DomainDiff(
            domain=domain,
            status="changed",
            score_before=score_before if isinstance(score_before, int) else None,
            score_after=score_after if isinstance(score_after, int) else None,
            changes=[note],
        )

    # A domain crossing between the sending and non-sending tracks is one of the
    # few changes worth acting on, and under the track split it is a score
    # appearing or disappearing rather than a number moving. Say it first, and in
    # words: "score went from nothing to 93" is not a sentence anyone can use.
    posture_before = str(before.get("posture") or "")
    posture_after = str(after.get("posture") or "")
    if posture_before and posture_after and posture_before != posture_after:
        if posture_after == "sending":
            changes.append(
                "this domain now receives mail - it publishes MX records where it "
                "previously published none, so its mail authentication is now "
                "worth assessing"
            )
        elif posture_before == "sending":
            changes.append(
                "this domain no longer receives mail - the MX records it "
                "previously published are gone"
            )
        else:
            changes.append(f"posture changed from {posture_before} to {posture_after}")

    compare_dmarc = _comparable(before, after, "DMARC", changes)
    compare_spf = _comparable(before, after, "SPF", changes)
    compare_dkim = _comparable(before, after, "DKIM", changes)
    compare_mx = _comparable(before, after, "MX", changes)

    if compare_dmarc:
        # -- DMARC -------------------------------------------------------------
        p_before = str(_get(before, "dmarc", "tags", "p") or "").lower()
        p_after = str(_get(after, "dmarc", "tags", "p") or "").lower()
        had_dmarc = bool(_get(before, "dmarc", "record"))
        has_dmarc = bool(_get(after, "dmarc", "record"))

        if not had_dmarc and has_dmarc:
            changes.append(f"DMARC record published (p={p_after or 'unset'})")
        elif had_dmarc and not has_dmarc:
            changes.append("DMARC record removed")
        elif p_before != p_after:
            direction = (
                "tightened"
                if POLICY_RANK.get(p_after, 0) > POLICY_RANK.get(p_before, 0)
                else "loosened"
            )
            changes.append(
                f"DMARC policy {direction}: p={p_before or 'unset'} -> p={p_after or 'unset'}"
            )

        rua_before = str(_get(before, "dmarc", "tags", "rua") or "")
        rua_after = str(_get(after, "dmarc", "tags", "rua") or "")
        if rua_before != rua_after:
            if not rua_before:
                changes.append("DMARC reporting address added")
            elif not rua_after:
                changes.append("DMARC reporting address removed")
            else:
                changes.append("DMARC reporting address changed")

        pct_before = str(_get(before, "dmarc", "tags", "pct") or "100")
        pct_after = str(_get(after, "dmarc", "tags", "pct") or "100")
        if pct_before != pct_after:
            changes.append(f"DMARC pct changed: {pct_before} -> {pct_after}")

        sp_before = str(_get(before, "dmarc", "tags", "sp") or "")
        sp_after = str(_get(after, "dmarc", "tags", "sp") or "")
        if sp_before != sp_after:
            changes.append(
                f"DMARC subdomain policy changed: sp={sp_before or 'unset'} -> sp={sp_after or 'unset'}"
            )

    if compare_spf:
        # -- SPF ---------------------------------------------------------------
        spf_before = list(_get(before, "spf", "records") or [])
        spf_after = list(_get(after, "spf", "records") or [])
        if not spf_before and spf_after:
            changes.append("SPF record published")
        elif spf_before and not spf_after:
            changes.append("SPF record removed")
        elif spf_before != spf_after:
            changes.append("SPF record edited")

        all_before = str(_get(before, "spf", "all_qualifier") or "")
        all_after = str(_get(after, "spf", "all_qualifier") or "")
        if all_before != all_after:
            direction = (
                "tightened"
                if ALL_RANK.get(all_after, 0) > ALL_RANK.get(all_before, 0)
                else "loosened"
            )
            changes.append(
                f"SPF terminal mechanism {direction}: "
                f"{all_before or 'none'}all -> {all_after or 'none'}all"
            )

        lookups_before = _get(before, "spf", "dns_lookups")
        lookups_after = _get(after, "spf", "dns_lookups")
        if (
            isinstance(lookups_before, int)
            and isinstance(lookups_after, int)
            and lookups_before != lookups_after
        ):
            changes.append(f"SPF lookup count: {lookups_before} -> {lookups_after}")

    if compare_dkim:
        # -- DKIM --------------------------------------------------------------
        keys_before = {k["selector"] for k in (_get(before, "dkim", "keys") or [])}
        keys_after = {k["selector"] for k in (_get(after, "dkim", "keys") or [])}
        # A selector whose probe failed is unknown, not empty. Comparing it
        # against a run where it answered turns a resolver hiccup into "DKIM key
        # removed" on a domain that never changed anything.
        failed_before = set(_get(before, "dkim", "probe_failed_selectors") or [])
        failed_after = set(_get(after, "dkim", "probe_failed_selectors") or [])

        gained = sorted(keys_after - keys_before - failed_before)
        lost = sorted(keys_before - keys_after - failed_after)
        unknown = sorted((failed_before | failed_after) & (keys_before | keys_after))

        if gained:
            changes.append(f"DKIM key now found on: {', '.join(gained)}")
        if lost:
            changes.append(f"DKIM key no longer found on: {', '.join(lost)}")
        if unknown:
            changes.append(
                f"DKIM selector(s) {', '.join(unknown)} could not be probed in one of "
                f"the runs, so it is not known whether they changed"
            )

    # -- MX and supporting records ----------------------------------------
    if compare_mx:
        mx_before = [t["host"] for t in (_get(before, "mx", "targets") or [])]
        mx_after = [t["host"] for t in (_get(after, "mx", "targets") or [])]
        if mx_before != mx_after:
            changes.append(
                f"MX changed: {', '.join(mx_before) or 'none'} -> "
                f"{', '.join(mx_after) or 'none'}"
            )

    for label, path in (
        ("TLS-RPT", ("extras", "tlsrpt", "present")),
        ("MTA-STS", ("extras", "mta_sts", "dns", "present")),
        ("BIMI", ("extras", "bimi", "present")),
    ):
        if not _comparable(before, after, label, changes):
            continue
        was = bool(_get(before, *path))
        now = bool(_get(after, *path))
        if was != now:
            changes.append(f"{label} record {'published' if now else 'removed'}")

    score_before = _get(before, "score")
    score_after = _get(after, "score")
    moved = (
        isinstance(score_before, int)
        and isinstance(score_after, int)
        and score_before != score_after
    )

    # A score that moved while every published record stayed put is a change, and
    # a specific one: it means the tool changed, not the domain. Silently
    # classifying it as unchanged hid six of seven movements in one run.
    if moved and not changes:
        changes.append(
            f"score moved {score_before} -> {score_after} with no change to any "
            f"published record, which points at a change in the tool or its "
            f"weights rather than at the domain"
        )

    return DomainDiff(
        domain=domain,
        status="changed" if changes or moved else "unchanged",
        score_before=score_before if isinstance(score_before, int) else None,
        score_after=score_after if isinstance(score_after, int) else None,
        changes=changes,
    )


def diff_runs(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[DomainDiff]:
    """Compare two runs, handling domains present in only one of them."""
    diffs: list[DomainDiff] = []
    for domain in sorted(set(before) | set(after)):
        in_before = domain in before
        in_after = domain in after
        if in_before and in_after:
            diffs.append(diff_domain(domain, before[domain], after[domain]))
        elif in_after:
            score = after[domain].get("score")
            diffs.append(
                DomainDiff(
                    domain=domain,
                    status="added",
                    score_after=score if isinstance(score, int) else None,
                    changes=["not present in the earlier run"],
                )
            )
        else:
            score = before[domain].get("score")
            diffs.append(
                DomainDiff(
                    domain=domain,
                    status="removed",
                    score_before=score if isinstance(score, int) else None,
                    changes=["not present in the later run"],
                )
            )
    return diffs
