"""
mailauth/cli.py - the command line interface.

    mailauth check <domain>...      one or more domains, rendered to the terminal
    mailauth batch <input.csv>      a prospect list, scored and written to CSV
    mailauth report <results>       the client-facing one-pager
    mailauth diff <run-a> <run-b>   what changed between two stored runs
    mailauth runs                   list stored runs
    mailauth selftest               run the offline test suite

Quiet by default. -v reports progress, -vv reports every DNS query.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import logging
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import __version__
from .dns_client import DnsClient
from .engine import check_domain
from .models import SEVERITY_MARK, DomainResult, Posture, Severity
from .report import render_html, render_markdown
from .scoring import Weights, WeightsError, explain, load_weights, score
from .store import Store, diff_runs

LOG = logging.getLogger("mailauth")

DEFAULT_RESOLVER = "1.1.1.1"
DEFAULT_DB = Path("out") / "mailauth.db"

# Columns written by `batch`, after any passthrough columns from the input.
OUTPUT_FIELDS = [
    "score",
    "raw_score",
    "risk",
    "confidence",
    "confidence_label",
    "posture",
    "headline",
    "mx_provider",
    "mx_count",
    "spf_present",
    "spf_all",
    "spf_lookups",
    "dmarc_present",
    "dmarc_policy",
    "dmarc_rua",
    "dkim_keys_found",
    "dkim_keys_unreadable",
    "dkim_delegations_without_key",
    "dkim_selectors_tried",
    "tlsrpt",
    "mtasts",
    "dnssec",
    "all_findings",
    "error",
]


# ---------------------------------------------------------------------------
# shared plumbing
# ---------------------------------------------------------------------------


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr, force=True)


def load_weights_or_exit(path: str | None, profile: str) -> Weights:
    try:
        return load_weights(Path(path) if path else None, profile)
    except WeightsError as exc:
        raise SystemExit(f"weights: {exc}") from None


def build_client(args: argparse.Namespace, store: Store | None) -> DnsClient:
    """Construct the DNS client, seeding it from the persistent cache if enabled."""
    cache: dict[tuple[str, str], Any] = {}
    expiry: dict[tuple[str, str], float] = {}
    use_cache = not getattr(args, "no_cache", False)
    if store is not None and use_cache and not getattr(args, "refresh", False):
        cache, expiry = store.load_cache(args.resolver, time.time())
        if cache:
            LOG.info("loaded %d cached DNS answers", len(cache))
    return DnsClient(
        nameservers=[args.resolver] if args.resolver else None,
        timeout=args.timeout,
        retries=args.retries,
        cache=cache,
        expiry=expiry,
        cache_enabled=use_cache,
    )


def notice_if_active(args: argparse.Namespace) -> None:
    """Print the one-line notice the active flag requires."""
    if getattr(args, "active", False):
        print(
            "NOTICE: --active is on. The MTA-STS policy fetch will connect to "
            "https://mta-sts.<domain>/.well-known/mta-sts.txt for each domain that "
            "publishes an MTA-STS record. This is the only check that contacts a "
            "host the assessed domain operates, and it will appear in their web "
            "server logs. Use it only where you have authorization.",
            file=sys.stderr,
        )


def normalise_domain(raw: str) -> str:
    """Accept a bare domain, a URL, or a www-prefixed host and return the domain."""
    domain = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split("/", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.rstrip(".")


# Longest a DNS name and a single label may be, per RFC 1035 section 2.3.4.
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63

# A hostname label is letters, digits and hyphens. Underscore is admitted
# because the names this tool handles routinely carry it: _dmarc, _domainkey,
# _smtp._tls. Anything else - a comma, a space, an @ - means the input is not a
# domain name, and saying so is a statement about the input rather than a claim
# about what DNS holds.
_ALLOWED_CHARS = re.compile(r"[a-z0-9._-]")


def domain_rejection(domain: str) -> str | None:
    """Why `domain` cannot be a domain name, or None if it could be.

    Called before anything reaches the resolver. Reporting a CSV row as "the
    domain does not resolve" is a claim about the outside world made on the
    strength of a query that could never have succeeded, and it is
    indistinguishable in the output from a real domain that has been let lapse.

    Checks run cheapest and most specific first, so the reason given names the
    actual problem: a stray comma is reported as a stray comma rather than as
    the missing dot it also causes.
    """
    if not domain:
        return "the input is empty"
    if len(domain) > MAX_DOMAIN_LENGTH:
        return (
            f"the input is {len(domain)} characters, longer than the "
            f"{MAX_DOMAIN_LENGTH} a domain name may be"
        )

    illegal = sorted({c for c in domain if not _ALLOWED_CHARS.match(c)})
    if illegal:
        shown = ", ".join(repr(c) for c in illegal[:4])
        more = f" and {len(illegal) - 4} more" if len(illegal) > 4 else ""
        return f"the input contains {shown}{more}, which cannot appear in a domain name"

    if "." not in domain:
        return "the input has no dot, so it is a single label rather than a domain name"

    for label in domain.split("."):
        if not label:
            return "the input has an empty label, from a leading, trailing or doubled dot"
        if len(label) > MAX_LABEL_LENGTH:
            return (
                f"the label {label[:20]}... is {len(label)} characters, longer than "
                f"the {MAX_LABEL_LENGTH} a single label may be"
            )
        if label.startswith("-") or label.endswith("-"):
            return f"the label {label!r} starts or ends with a hyphen"
    return None


def partition_targets(raw_targets: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split inputs into checkable domains and rejections, preserving order."""
    valid: list[str] = []
    rejected: list[tuple[str, str]] = []
    for target in raw_targets:
        reason = domain_rejection(target)
        if reason is None:
            valid.append(target)
        else:
            rejected.append((target, reason))
    return valid, rejected


def report_rejections(rejected: list[tuple[str, str]]) -> None:
    """Print rejections to stderr, kept out of the results entirely.

    Deliberately not a finding: no score, no risk band, no severity. A rejected
    input was never assessed, so it has nothing to report about a domain.
    """
    for target, reason in rejected:
        shown = target if len(target) <= 60 else target[:57] + "..."
        print(f"not a domain name, skipped: {shown!r} - {reason}", file=sys.stderr)


def run_checks(
    args: argparse.Namespace,
    client: DnsClient,
    weights: Weights,
    rows: list[dict[str, str]],
) -> list[DomainResult]:
    """Check every row, in parallel when there is more than one."""
    selectors = (
        [s.strip() for s in args.selectors.split(",") if s.strip()]
        if getattr(args, "selectors", None)
        else None
    )

    def work(row: dict[str, str]) -> DomainResult:
        domain = row["domain"]
        passthrough = {k: v for k, v in row.items() if k != "domain"}
        result = score(
            check_domain(
                client,
                domain,
                extra_selectors=selectors,
                active=getattr(args, "active", False),
                passthrough=passthrough,
            ),
            weights,
        )
        LOG.info(
            "%3d %-6s %-38s %s",
            result.score if result.score is not None else -1,
            result.risk,
            result.domain,
            result.headline,
        )
        return result

    workers = max(1, int(getattr(args, "workers", 1)))
    if workers == 1 or len(rows) == 1:
        return [work(row) for row in rows]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(work, rows))


def flush_cache(store: Store | None, client: DnsClient, resolver: str) -> None:
    if store is None:
        return
    entries = client.export_cache()
    if entries:
        store.save_cache(resolver, entries, time.time())
        LOG.info(
            "%d DNS queries made, %d served from cache",
            client.queries_made,
            client.cache_hits,
        )


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def render_terminal(result: DomainResult, verbose: bool = False) -> str:
    width = 74
    out: list[str] = [
        "=" * width,
        f"{result.domain}   (via {result.resolver})",
        "=" * width,
    ]

    if result.error:
        out.append(f"  {SEVERITY_MARK[Severity.CRITICAL]} {result.error}")
        return "\n".join(out)

    out.append(
        (
            f"  no score - {result.risk} track  "
            if result.score is None
            else f"  score {result.score}/100  {result.risk}  "
        )
        + (
            f"confidence {result.confidence:.0%} ({result.confidence_label})  "
            f"posture {result.posture}"
        )
    )
    out.append("")

    for finding in result.findings:
        out.append(f"{SEVERITY_MARK[finding.severity]} {finding.area:<9} {finding.title}")
        if finding.detail:
            for line in _wrap(finding.detail, 62):
                out.append("             " + line)

    if verbose:
        out.append("")
        out.append("  raw records")
        for record in result.spf.records:
            out.append("    SPF   " + record)
        if result.dmarc.record:
            out.append("    DMARC " + result.dmarc.record)
        for target in result.mx.targets:
            out.append(f"    MX    {target.preference:<4} {target.host}")
        for key in result.dkim.keys:
            detail = key.cname_target or (
                f"{key.bits} bit {key.key_type}" if key.bits else "key"
            )
            out.append(f"    DKIM  {key.selector:<12} {detail}")
        if result.spf.chain:
            out.append("")
            out.append(f"  SPF include chain ({result.spf.lookups} lookups)")
            for entry in result.spf.chain:
                out.append("    " + entry)
        out.append("")
        out.append("  score breakdown")
        for line in explain(result):
            out.append("  " + line)

    return "\n".join(out)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def cmd_check(args: argparse.Namespace) -> int:
    weights = load_weights_or_exit(args.weights, args.profile)
    notice_if_active(args)

    targets = [normalise_domain(d) for d in args.domains]
    if args.file:
        # utf-8-sig so a byte order mark on the first line is consumed rather
        # than becoming part of the first domain. Editors on Windows add one
        # without saying so, and it is invisible in the resulting error.
        with Path(args.file).open(encoding="utf-8-sig") as handle:
            targets += [
                normalise_domain(line)
                for line in handle
                if line.strip() and not line.lstrip().startswith("#")
            ]
    if not targets:
        raise SystemExit("give at least one domain, or use --file")

    # Reject what cannot be a domain before the resolver sees it. A rejection is
    # a statement about the input and carries no score, risk band or severity.
    targets, rejected = partition_targets(targets)
    report_rejections(rejected)
    if not targets:
        raise SystemExit(
            f"nothing left to check: all {len(rejected)} input(s) were rejected as "
            f"not being domain names"
        )

    store = None if args.no_db else Store(Path(args.db))
    client = build_client(args, store)
    results = run_checks(args, client, weights, [{"domain": t} for t in targets])

    for result in results:
        print(render_terminal(result, args.verbose >= 1))
        print("")

    if store is not None:
        run_id = store.start_run(
            __version__, weights.version, args.profile, client.server, args.active
        )
        for result in results:
            store.save_result(run_id, result)
        store.finish_run(run_id, len(results))
        flush_cache(store, client, args.resolver)
        LOG.info("stored as run %d", run_id)
        store.close()

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        with Path(args.json).open("w", encoding="utf-8") as handle:
            json.dump([r.to_dict() for r in results], handle, indent=2)
        print(f"wrote {args.json}", file=sys.stderr)

    return 0 if all(r.error is None for r in results) else 1


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------


def read_input_rows(path: str) -> list[dict[str, str]]:
    """Read the prospect CSV, keeping every column for passthrough."""
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "domain" not in reader.fieldnames:
            raise SystemExit(f"{path} has no 'domain' column. Found: {reader.fieldnames}")
        rows: list[dict[str, str]] = []
        for row in reader:
            domain = normalise_domain(row.get("domain") or "")
            if not domain:
                continue
            cleaned = {k: (v or "") for k, v in row.items() if k}
            cleaned["domain"] = domain
            rows.append(cleaned)
        return rows


def result_to_row(result: DomainResult) -> dict[str, str]:
    """Flatten a result into the CSV columns."""
    findings = "; ".join(item.finding.title for item in result.scored if item.weight > 0)
    return {
        # Blank for a non-sending domain: the column reads as cross-comparable
        # and that comparison is meaningless. raw_score carries the ordering.
        "score": "" if result.score is None else str(result.score),
        "raw_score": str(result.raw_score),
        "risk": result.risk,
        "confidence": f"{result.confidence:.2f}",
        "confidence_label": str(result.confidence_label),
        "posture": str(result.posture),
        "headline": result.headline,
        "mx_provider": result.mx.provider or "",
        "mx_count": str(len(result.mx.targets)),
        "spf_present": (
            "no"
            if not result.spf.records
            else ("multiple" if len(result.spf.records) > 1 else "yes")
        ),
        "spf_all": f"{result.spf.all_qualifier}all" if result.spf.all_qualifier else "",
        "spf_lookups": str(result.spf.lookups),
        "dmarc_present": "yes" if result.dmarc.record else "no",
        "dmarc_policy": result.dmarc.policy,
        "dmarc_rua": "yes" if result.dmarc.tags.get("rua") else "no",
        # Usable keys only. This column answers "does this domain have DKIM", and
        # a malformed record or an empty delegation is not a yes.
        "dkim_keys_found": ",".join(k.selector for k in result.dkim.usable_keys),
        "dkim_keys_unreadable": str(len(result.dkim.unreadable_keys)),
        "dkim_delegations_without_key": str(len(result.dkim.delegations_without_key)),
        "dkim_selectors_tried": str(len(result.dkim.selectors_tried)),
        "tlsrpt": "yes" if result.extras.tlsrpt.present else "no",
        "mtasts": "yes" if result.extras.mtasts.dns.present else "no",
        "dnssec": (
            ""
            if result.extras.dnssec is None
            else ("yes" if result.extras.dnssec else "no")
        ),
        "all_findings": findings or "none",
        "error": result.error or "",
    }


def cmd_batch(args: argparse.Namespace) -> int:
    weights = load_weights_or_exit(args.weights, args.profile)
    notice_if_active(args)

    rows = read_input_rows(args.infile)
    if not rows:
        raise SystemExit(f"{args.infile} contains no usable domains")

    kept: list[dict[str, str]] = []
    rejected: list[tuple[str, str]] = []
    for row in rows:
        reason = domain_rejection(row["domain"])
        if reason is None:
            kept.append(row)
        else:
            rejected.append((row["domain"], reason))
    report_rejections(rejected)
    rows = kept
    if not rows:
        raise SystemExit(
            f"nothing left to check: all {len(rejected)} row(s) were rejected as not "
            f"being domain names"
        )
    passthrough_fields = list(rows[0].keys())

    store = None if args.no_db else Store(Path(args.db))
    client = build_client(args, store)

    LOG.info("screening %d domains with %d workers", len(rows), args.workers)
    results = run_checks(args, client, weights, rows)
    # Sort by the uncapped total. Domains that clamp all display 100 and would
    # otherwise tie at the top of the worklist, which is exactly where the
    # ordering matters most.
    results.sort(key=lambda r: (-r.raw_score, r.domain))

    outfile = Path(args.outfile)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    fields = passthrough_fields + [f for f in OUTPUT_FIELDS if f not in passthrough_fields]
    with outfile.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            row = dict(result.passthrough)
            row["domain"] = result.domain
            row.update(result_to_row(result))
            writer.writerow(row)

    if store is not None:
        run_id = store.start_run(
            __version__,
            weights.version,
            args.profile,
            client.server,
            args.active,
            input_path=str(args.infile),
        )
        for result in results:
            store.save_result(run_id, result)
        store.finish_run(run_id, len(results))
        flush_cache(store, client, args.resolver)
        store.close()
        print(f"stored as run {run_id}", file=sys.stderr)

    high = sum(1 for r in results if r.risk == "high")
    medium = sum(1 for r in results if r.risk == "medium")
    non_sending = sum(1 for r in results if r.risk == "non-sending")
    errored = sum(1 for r in results if r.error)
    print(
        f"wrote {outfile}: {high} high, {medium} medium, "
        f"{len(results) - high - medium - errored - non_sending} low, "
        f"{non_sending} non-sending, {errored} unresolved",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def load_results_file(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return [data]
    return [item for item in data if isinstance(item, dict)]


def cmd_report(args: argparse.Namespace) -> int:
    """Generate the client-facing one-pager from a stored run or a JSON file."""
    payloads: dict[str, dict[str, Any]]

    source = Path(args.source)
    if source.exists() and source.suffix.lower() == ".json":
        payloads = {str(item.get("domain", "")): item for item in load_results_file(source)}
    else:
        store = Store(Path(args.db))
        run = store.resolve_run(args.source)
        if run is None:
            store.close()
            raise SystemExit(
                f"no run matching {args.source!r}. Use `mailauth runs` to list them, "
                f"or pass a path to a results JSON file."
            )
        payloads = store.run_payloads(run.id)
        store.close()

    if args.domain:
        wanted = normalise_domain(args.domain)
        payloads = {d: p for d, p in payloads.items() if d == wanted}
        if not payloads:
            raise SystemExit(f"{wanted} is not in that run")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for domain, payload in sorted(payloads.items()):
        result = _result_from_payload(payload)
        firm = payload.get("passthrough", {}).get("firm") or None
        markdown = render_markdown(result, firm)
        md_path = outdir / f"{domain}.md"
        md_path.write_text(markdown, encoding="utf-8", newline="\n")
        written.append(md_path)
        if args.html:
            html_path = outdir / f"{domain}.html"
            html_path.write_text(render_html(result, firm), encoding="utf-8", newline="\n")
            written.append(html_path)

    for path in written:
        print(path)
    return 0


def _result_from_payload(payload: dict[str, Any]) -> DomainResult:
    """Rebuild enough of a DomainResult from stored JSON to render a report.

    The report only reads parsed state and scored findings, so this rebuilds
    those rather than every field. Findings are reconstructed from the stored
    scored_findings list, which is what carries the weights.
    """
    from .models import (
        Confidence,
        DkimKey,
        DkimResult,
        DmarcResult,
        ExtrasResult,
        Finding,
        MtaStsResult,
        MxResult,
        MxTarget,
        RecordProbe,
        ScoredFinding,
        SpfResult,
    )

    def probe(data: dict[str, Any] | None, name: str) -> RecordProbe:
        data = data or {}
        return RecordProbe(
            name=str(data.get("name", name)),
            present=bool(data.get("present", False)),
            record=data.get("record"),
            tags={str(k): str(v) for k, v in (data.get("tags") or {}).items()},
        )

    mx_data = payload.get("mx") or {}
    dkim_data = payload.get("dkim") or {}
    spf_data = payload.get("spf") or {}
    dmarc_data = payload.get("dmarc") or {}
    extras_data = payload.get("extras") or {}

    scored: list[ScoredFinding] = []
    for item in payload.get("scored_findings") or []:
        scored.append(
            ScoredFinding(
                finding=Finding(
                    code=str(item.get("code", "")),
                    area=str(item.get("area", "")),
                    severity=Severity(item.get("severity", "info")),
                    confidence=Confidence(item.get("confidence", "high")),
                    title=str(item.get("title", "")),
                    detail=str(item.get("detail", "")),
                ),
                weight=int(item.get("weight", 0)),
                rationale=str(item.get("rationale", "")),
            )
        )

    return DomainResult(
        domain=str(payload.get("domain", "")),
        resolver=str(payload.get("resolver", "")),
        checked_at=str(payload.get("checked_at", "")),
        posture=Posture(payload.get("posture", "sending")),
        mx=MxResult(
            targets=[
                MxTarget(
                    preference=int(t.get("preference", 0)),
                    host=str(t.get("host", "")),
                    resolves=bool(t.get("resolves", False)),
                    is_cname=bool(t.get("is_cname", False)),
                    has_aaaa=bool(t.get("has_aaaa", False)),
                )
                for t in mx_data.get("targets") or []
            ],
            provider=mx_data.get("provider"),
            null_mx=bool(mx_data.get("null_mx", False)),
        ),
        spf=SpfResult(
            records=[str(r) for r in spf_data.get("records") or []],
            lookups=int(spf_data.get("dns_lookups", 0)),
            void_lookups=int(spf_data.get("void_lookups", 0)),
            all_qualifier=spf_data.get("all_qualifier"),
        ),
        dmarc=DmarcResult(
            record=dmarc_data.get("record"),
            record_count=int(dmarc_data.get("record_count", 0)),
            tags={str(k): str(v) for k, v in (dmarc_data.get("tags") or {}).items()},
        ),
        dkim=DkimResult(
            selectors_tried=[str(s) for s in dkim_data.get("selectors_tried") or []],
            keys=[
                DkimKey(
                    selector=str(k.get("selector", "")),
                    source=str(k.get("source", "txt")),
                    cname_target=k.get("cname_target"),
                    key_type=str(k.get("key_type", "rsa")),
                    bits=k.get("bits"),
                    testing=bool(k.get("testing", False)),
                    revoked=bool(k.get("revoked", False)),
                )
                for k in dkim_data.get("keys") or []
            ],
            wildcard=bool(dkim_data.get("wildcard_domainkey", False)),
        ),
        extras=ExtrasResult(
            tlsrpt=probe(extras_data.get("tlsrpt"), "_smtp._tls"),
            mtasts=MtaStsResult(
                dns=probe((extras_data.get("mta_sts") or {}).get("dns"), "_mta-sts")
            ),
            bimi=probe(extras_data.get("bimi"), "default._bimi"),
            dnssec=extras_data.get("dnssec_authenticated"),
        ),
        scored=scored,
        score=int(payload.get("score", 0)),
        risk=str(payload.get("risk", "low")),
        confidence=float(payload.get("confidence", 1.0)),
        confidence_label=Confidence(payload.get("confidence_label", "high")),
        low_confidence_share=float(payload.get("low_confidence_share", 0.0)),
        error=payload.get("error"),
        passthrough={str(k): str(v) for k, v in (payload.get("passthrough") or {}).items()},
    )


# ---------------------------------------------------------------------------
# diff and runs
# ---------------------------------------------------------------------------


def cmd_diff(args: argparse.Namespace) -> int:
    store = Store(Path(args.db))
    before = store.resolve_run(args.run_a)
    after = store.resolve_run(args.run_b)
    if before is None or after is None:
        store.close()
        missing = args.run_a if before is None else args.run_b
        raise SystemExit(f"no run matching {missing!r}. Try `mailauth runs`.")

    # The two digests cover the scoring config and the scorer. Neither sees the
    # check layer that produces the findings in the first place: change what
    # `dkim.unparseable` fires on and every score moves with both digests
    # unchanged. The package version is the existing marker for that, and it is
    # already recorded per run - it just was never surfaced.
    if before.tool_version != after.tool_version:
        print(
            f"note: these runs were made by different versions of mailauth "
            f"({before.tool_version} and {after.tool_version}), so the checks "
            f"themselves may differ, not only the weights.",
            file=sys.stderr,
        )

    if before.weights_version != after.weights_version:
        # The version carries two independent digests, `config.algorithm`. Saying
        # which one moved is the difference between "you changed a weight" and
        # "the tool scores differently now", and they call for different reading.
        def digests(version: str) -> tuple[str, str]:
            tail = version.rsplit("+", 1)[-1]
            config, _, algorithm = tail.partition(".")
            return config, algorithm

        config_before, algorithm_before = digests(before.weights_version)
        config_after, algorithm_after = digests(after.weights_version)
        moved = []
        if config_before != config_after:
            moved.append("the weights")
        if algorithm_before != algorithm_after:
            moved.append("the scoring algorithm itself")
        print(
            f"note: {' and '.join(moved) or 'the scoring configuration'} changed "
            f"between these runs ({before.weights_version} and "
            f"{after.weights_version}), so score movement reflects both the domains "
            f"and that change.",
            file=sys.stderr,
        )

    diffs = diff_runs(store.run_payloads(before.id), store.run_payloads(after.id))
    store.close()

    print(f"comparing {before.label}")
    print(f"     with {after.label}")
    print("")

    changed = [d for d in diffs if d.status != "unchanged"]
    if not changed:
        print("nothing changed for any domain in both runs.")
        return 0

    for item in sorted(changed, key=lambda d: (d.score_delta or 0, d.domain)):
        delta = item.score_delta
        if delta is None:
            movement = f"({item.status})"
        elif delta == 0:
            movement = f"score {item.score_after} (unchanged)"
        else:
            movement = f"score {item.score_before} -> {item.score_after} ({delta:+d})"
        print(f"{item.domain}  {movement}")
        for change in item.changes:
            print(f"    {change}")
        print("")

    improved = [d for d in changed if (d.score_delta or 0) < 0]
    worsened = [d for d in changed if (d.score_delta or 0) > 0]
    print(
        f"{len(improved)} improved, {len(worsened)} regressed, "
        f"{len(diffs) - len(changed)} unchanged"
    )
    if not args.quiet and improved:
        print("improved: " + ", ".join(d.domain for d in improved))
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    store = Store(Path(args.db))
    runs = store.list_runs(args.limit)
    store.close()
    if not runs:
        print("no runs recorded yet")
        return 0
    print(f"{'id':>4}  {'started':<20} {'domains':>7}  {'profile':<12} {'weights'}")
    for run in runs:
        print(
            f"{run.id:>4}  {run.started_at:<20} {run.domain_count:>7}  "
            f"{run.profile:<12} {run.weights_version}"
            + ("  [active]" if run.active_checks else "")
        )
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Run the offline test suite.

    A thin wrapper around pytest rather than a hand-rolled assertion runner. If
    pytest is not installed it says so and exits, rather than reporting success
    for tests that never ran.
    """
    # find_spec rather than an import: we only need to know whether pytest is
    # installed, and importing it here would drag the whole test framework into
    # the import graph of an ordinary CLI run.
    if importlib.util.find_spec("pytest") is None:
        print(
            "pytest is not installed, so the test suite cannot run.\n"
            "  python -m pip install -e .[dev]",
            file=sys.stderr,
        )
        return 2
    command = [sys.executable, "-m", "pytest", "-q"]
    if args.verbose:
        command.append("-v")
    LOG.info("running: %s", " ".join(command))
    return subprocess.call(command)


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


def add_shared_dns_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--resolver",
        default=DEFAULT_RESOLVER,
        help=f"DNS server to query (default {DEFAULT_RESOLVER})",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="per-query timeout")
    parser.add_argument(
        "--retries", type=int, default=1, help="retries for a timed-out query"
    )
    parser.add_argument("--selectors", help="extra DKIM selectors to try, comma separated")
    parser.add_argument(
        "--active",
        action="store_true",
        help="enable the MTA-STS policy fetch, which connects to a host the "
        "assessed domain operates. Off by default. Requires authorization.",
    )
    parser.add_argument("--weights", help="path to a weights TOML file")
    parser.add_argument(
        "--profile", default="default", help="scoring profile from the weights file"
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    parser.add_argument(
        "--no-db", action="store_true", help="do not record this run or use the cache"
    )
    parser.add_argument("--no-cache", action="store_true", help="ignore cached DNS answers")
    parser.add_argument(
        "--refresh", action="store_true", help="re-query everything and rewrite the cache"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailauth",
        description="Passive email authentication review over public DNS.",
        epilog="Reads public DNS. Contacts no host the assessed domain operates "
        "unless --active is given.",
    )
    parser.add_argument("--version", action="version", version=f"mailauth {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v for progress, -vv for every query",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="review one or more domains")
    check.add_argument("domains", nargs="*", help="domains to review")
    check.add_argument("--file", help="file with one domain per line")
    check.add_argument("--json", help="also write full results as JSON")
    add_shared_dns_arguments(check)
    check.set_defaults(func=cmd_check, workers=1)

    batch = subparsers.add_parser("batch", help="screen a CSV of prospects")
    batch.add_argument("infile", help="input CSV with a 'domain' column")
    batch.add_argument("-o", "--outfile", default="out/results.csv", help="output CSV path")
    batch.add_argument("--workers", type=int, default=8, help="parallel lookups")
    add_shared_dns_arguments(batch)
    batch.set_defaults(func=cmd_batch)

    report = subparsers.add_parser("report", help="generate client-facing one-pagers")
    report.add_argument(
        "source",
        nargs="?",
        default="latest",
        help="a run id, run uuid, `latest`, `latest~1`, or a results JSON path",
    )
    report.add_argument("--domain", help="only this domain")
    report.add_argument("--outdir", default="out/reports", help="where to write")
    report.add_argument("--html", action="store_true", help="also render HTML")
    report.add_argument("--db", default=str(DEFAULT_DB))
    report.set_defaults(func=cmd_report)

    diff = subparsers.add_parser("diff", help="compare two stored runs")
    diff.add_argument("run_a", help="the earlier run")
    diff.add_argument("run_b", nargs="?", default="latest", help="the later run")
    diff.add_argument("--db", default=str(DEFAULT_DB))
    diff.add_argument("--quiet", action="store_true")
    diff.set_defaults(func=cmd_diff)

    runs = subparsers.add_parser("runs", help="list stored runs")
    runs.add_argument("--limit", type=int, default=20)
    runs.add_argument("--db", default=str(DEFAULT_DB))
    runs.set_defaults(func=cmd_runs)

    selftest = subparsers.add_parser("selftest", help="run the offline test suite")
    selftest.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        result: int = args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return result


if __name__ == "__main__":
    sys.exit(main())
