"""
mailauth/checks/spf.py - RFC 7208 SPF parsing and include-chain evaluation.

The parser is a real tokenizer rather than string splitting, because the failure
modes worth reporting are exactly the ones string splitting misses: a macro in a
mechanism value, a CIDR suffix on a bare `a`, a `redirect=` that is silently
ignored because an `all` mechanism precedes it, or a term that is simply not
valid syntax and makes the whole record a permerror.

Two counters matter and are tracked separately, because RFC 7208 section 4.6.4
imposes two different limits and both are failure modes:
  - DNS-querying terms, limit 10
  - void lookups (NXDOMAIN or empty answer), limit 2
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..dns_client import Resolver
from ..models import Confidence, Finding, Severity, SpfResult, SpfTerm

# RFC 7208 section 4.6.4
LOOKUP_LIMIT = 10
VOID_LIMIT = 2

# Guard against pathological nesting. RFC 7208 sets no explicit depth limit
# beyond the lookup limit, but a cycle-free chain 10 deep already exceeds it.
MAX_DEPTH = 10

# Mechanisms that cost one DNS lookup each.
LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})

# Every mechanism RFC 7208 defines. Anything else makes the record a permerror.
KNOWN_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})

# Modifiers. Unknown modifiers are legal and must be ignored, unlike unknown
# mechanisms, which are a syntax error.
KNOWN_MODIFIERS = frozenset({"redirect", "exp"})

QUALIFIERS = "+-~?"

# Macro expansions such as %{i} or %{ir}. Legal, but they make a record hard to
# reason about and are worth surfacing.
MACRO_RE = re.compile(r"%\{[a-zA-Z]")

TERM_RE = re.compile(
    r"""^
    (?P<qualifier>[+\-~?])?
    (?P<name>[A-Za-z][A-Za-z0-9_.\-]*)
    (?:
        (?P<sep>[:=])(?P<value>.*?)
    )?
    (?:/(?P<cidr4>\d+))?
    (?:(?://)(?P<cidr6>\d+))?
    $""",
    re.VERBOSE,
)


def is_spf_record(text: str) -> bool:
    """True for a TXT record that declares itself an SPF version 1 record.

    The version token is case-insensitive and must be followed by a space or be
    the whole record; `v=spf10` is not an SPF record.
    """
    lowered = text.strip().lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def records_from(txt_values: list[str]) -> list[str]:
    return [t for t in txt_values if is_spf_record(t)]


# Mechanisms whose domain-spec argument is mandatory, per RFC 7208 section 5.
REQUIRE_DOMAIN = frozenset({"include", "exists"})

# A domain-spec is either a macro expansion or an ordinary domain name. This is
# deliberately permissive about what constitutes a name - `include:localhost` is
# odd but syntactically legal - and strict about characters, which is what
# catches the real-world mistakes: a stray colon, a URL pasted in, a space.
DOMAIN_SPEC_RE = re.compile(r"^[A-Za-z0-9._\-]+$")


def valid_domain_spec(value: str) -> bool:
    """True when a mechanism's argument could be a domain name or a macro."""
    if not value:
        return False
    if MACRO_RE.search(value):
        return True
    return bool(DOMAIN_SPEC_RE.match(value))


def parse_term(raw: str) -> SpfTerm:
    """Parse one whitespace-delimited SPF term.

    Returns a term whose mechanism is "" when the token is not valid syntax, so
    the caller can report a permerror rather than silently skipping it.
    """
    match = TERM_RE.match(raw)
    if not match:
        return SpfTerm(raw=raw, qualifier="", mechanism="", value="")

    name = (match.group("name") or "").lower()
    separator = match.group("sep") or ""
    value = match.group("value") or ""
    cidr4 = int(match.group("cidr4")) if match.group("cidr4") else None
    cidr6 = int(match.group("cidr6")) if match.group("cidr6") else None
    qualifier = match.group("qualifier") or ""

    # A modifier is `name=value`; a mechanism is `name` or `name:value`.
    is_modifier = separator == "="

    if is_modifier and qualifier:
        # Qualifiers are not permitted on modifiers.
        return SpfTerm(raw=raw, qualifier=qualifier, mechanism="", value=value)

    # A mechanism that requires a domain and was given something that cannot be
    # one is a syntax error, not a mechanism with an odd argument. Catching it
    # here keeps the walker from trying to resolve it as a name.
    if name in REQUIRE_DOMAIN and not valid_domain_spec(value):
        return SpfTerm(raw=raw, qualifier=qualifier, mechanism="", value=value)
    if name == "redirect" and is_modifier and not valid_domain_spec(value):
        return SpfTerm(raw=raw, qualifier=qualifier, mechanism="", value=value)

    return SpfTerm(
        raw=raw,
        qualifier=qualifier,
        mechanism=name,
        value=value,
        cidr4=cidr4,
        cidr6=cidr6,
        is_modifier=is_modifier,
    )


def tokenize(record: str) -> list[SpfTerm]:
    """Split a record into terms, dropping the leading version token."""
    tokens = record.split()
    if tokens and tokens[0].lower() == "v=spf1":
        tokens = tokens[1:]
    return [parse_term(token) for token in tokens]


@dataclass
class _WalkState:
    """Mutable accumulator for one full evaluation of a record and its includes."""

    lookups: int = 0
    void_lookups: int = 0
    chain: list[str] = field(default_factory=list)
    top_terms: list[SpfTerm] = field(default_factory=list)
    all_qualifier: str | None = None
    notes: list[tuple[str, str]] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)

    def note(self, code: str, text: str) -> None:
        if (code, text) not in self.notes:
            self.notes.append((code, text))


class SpfWalker:
    """Evaluates a record and everything it includes, counting as it goes."""

    def __init__(self, resolver: Resolver) -> None:
        self.resolver = resolver
        self.state = _WalkState()

    def walk(self, record: str, domain: str, depth: int = 0) -> _WalkState:
        if depth > MAX_DEPTH:
            self.state.note(
                "spf.depth_exceeded",
                f"include nesting goes deeper than {MAX_DEPTH} levels",
            )
            return self.state

        terms = tokenize(record)
        if depth == 0:
            self.state.top_terms = terms

        seen_includes: set[str] = set()
        redirect_target: str | None = None
        all_seen = False
        all_count = 0

        for term in terms:
            if not term.mechanism:
                self.state.note(
                    "spf.syntax_error",
                    f"term `{term.raw}` is not valid SPF syntax, which makes the "
                    f"whole record fail to evaluate",
                )
                continue

            if term.is_modifier:
                if term.mechanism == "redirect":
                    if redirect_target is not None:
                        self.state.note(
                            "spf.syntax_error",
                            "more than one redirect modifier is present",
                        )
                    redirect_target = term.value
                elif term.mechanism == "exp":
                    # exp is fetched only when explaining a failure and does not
                    # count against the lookup limit.
                    pass
                # Unknown modifiers are legal and ignored, per RFC 7208 6.
                continue

            if term.mechanism not in KNOWN_MECHANISMS:
                self.state.note(
                    "spf.syntax_error",
                    f"`{term.raw}` is not a mechanism RFC 7208 defines, which makes "
                    f"the whole record fail to evaluate",
                )
                continue

            if MACRO_RE.search(term.value):
                self.state.note(
                    "spf.macro",
                    f"`{term.raw}` uses macro expansion, which is legal but makes "
                    f"the record hard to verify by reading it",
                )

            if term.mechanism == "all":
                all_count += 1
                all_seen = True
                if depth == 0 and self.state.all_qualifier is None:
                    self.state.all_qualifier = term.qualifier or "+"
                continue

            if all_seen and depth == 0:
                self.state.note(
                    "spf.terms_after_all",
                    f"`{term.raw}` appears after the all mechanism, so it is never "
                    f"evaluated",
                )

            if term.mechanism == "ptr":
                self.state.note(
                    "spf.ptr",
                    "uses the ptr mechanism, which RFC 7208 deprecates and some "
                    "receivers ignore entirely",
                )

            if term.mechanism in LOOKUP_MECHANISMS:
                self.state.lookups += 1

            if term.mechanism in ("a", "mx"):
                self._probe(term.value or domain, "A" if term.mechanism == "a" else "MX")
            elif term.mechanism == "exists":
                if not MACRO_RE.search(term.value):
                    self._probe(term.value, "A")
            elif term.mechanism == "include":
                if not term.value:
                    self.state.note("spf.syntax_error", "an include has no domain")
                    continue
                target = term.value.lower().rstrip(".")
                if target in seen_includes:
                    self.state.note(
                        "spf.duplicate_include",
                        f"include:{target} appears more than once in the same record, "
                        f"which spends a DNS lookup for no additional senders",
                    )
                seen_includes.add(target)
                self._descend(target, depth, "include")

        if all_count > 1:
            self.state.note(
                "spf.multiple_all",
                f"the record has {all_count} all mechanisms; only the first is used",
            )

        if redirect_target:
            if all_seen:
                self.state.note(
                    "spf.redirect_ignored",
                    "a redirect modifier is present but an all mechanism precedes "
                    "it, so the redirect is never used",
                )
            else:
                self.state.lookups += 1
                self._descend(redirect_target.lower().rstrip("."), depth, "redirect")

        return self.state

    def _probe(self, name: str, rdtype: str) -> None:
        """Resolve a name purely to see whether it is a void lookup."""
        if not name:
            return
        response = self.resolver.query(name, rdtype)
        if response.status.is_void:
            self.state.void_lookups += 1

    def _descend(self, target: str, depth: int, kind: str) -> None:
        if not target:
            return
        self.state.chain.append(f"{'  ' * depth}{kind} {target}")

        if target in self.state.seen:
            self.state.note(
                "spf.include_loop",
                f"the include chain loops back to {target}, so it can never finish "
                f"evaluating",
            )
            return
        self.state.seen.add(target)

        response = self.resolver.txt(target)
        if response.status.is_void:
            self.state.void_lookups += 1
            self.state.note(
                "spf.unresolved_include",
                f"{kind}:{target} does not publish an SPF record, usually a service "
                f"that was decommissioned without removing the reference",
            )
            return
        if response.status.is_our_fault:
            self.state.note(
                "spf.include_unreachable",
                f"{kind}:{target} could not be resolved from here, so the chain "
                f"below it was not counted",
            )
            return

        nested = records_from(response.values)
        if len(nested) > 1:
            self.state.note(
                "spf.nested_multiple",
                f"{target} publishes {len(nested)} SPF records, which makes every "
                f"record that includes it fail to evaluate",
            )
        if nested:
            self.walk(nested[0], target, depth + 1)


def _finding(
    code: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    detail: str = "",
    **evidence: str,
) -> Finding:
    return Finding(
        code=code,
        area="SPF",
        severity=severity,
        confidence=confidence,
        title=title,
        detail=detail,
        evidence={k: v for k, v in evidence.items() if v},
    )


def check(resolver: Resolver, domain: str, txt_values: list[str]) -> SpfResult:
    """Evaluate SPF for one domain.

    `txt_values` is passed in rather than re-queried because the caller already
    fetched the apex TXT set to decide whether the domain resolves at all.
    """
    findings: list[Finding] = []
    records = records_from(txt_values)

    if not records:
        findings.append(
            _finding(
                "spf.absent",
                Severity.CRITICAL,
                Confidence.HIGH,
                "No SPF record is published",
                "Nothing in DNS tells receiving servers which hosts are allowed to "
                "send mail using this domain, so SPF cannot contribute to DMARC "
                "alignment.",
            )
        )
        return SpfResult(findings=findings)

    if len(records) > 1:
        findings.append(
            _finding(
                "spf.multiple_records",
                Severity.CRITICAL,
                Confidence.HIGH,
                f"{len(records)} SPF records are published",
                "RFC 7208 allows exactly one. A receiver that finds more than one "
                "returns permerror instead of choosing between them, so SPF is not "
                "evaluated at all for this domain right now.",
                records=" | ".join(records),
            )
        )

    walker = SpfWalker(resolver)
    state = walker.walk(records[0], domain)

    # -- lookup budget -----------------------------------------------------
    if state.lookups > LOOKUP_LIMIT:
        findings.append(
            _finding(
                "spf.lookup_limit_exceeded",
                Severity.CRITICAL,
                Confidence.HIGH,
                f"SPF needs {state.lookups} DNS lookups, above the limit of {LOOKUP_LIMIT}",
                "Receivers stop evaluating and return permerror once the limit is "
                "passed. In practice the record behaves as though it were not there.",
                lookups=str(state.lookups),
            )
        )
    elif state.lookups >= LOOKUP_LIMIT - 2:
        findings.append(
            _finding(
                "spf.lookup_limit_near",
                Severity.WARNING,
                Confidence.HIGH,
                f"SPF uses {state.lookups} of the {LOOKUP_LIMIT} available DNS lookups",
                "Adding one more sending service would push this over the limit, at "
                "which point the record stops evaluating.",
                lookups=str(state.lookups),
            )
        )
    else:
        findings.append(
            _finding(
                "spf.lookup_limit_ok",
                Severity.OK,
                Confidence.HIGH,
                f"SPF lookup count is within limits ({state.lookups} of {LOOKUP_LIMIT})",
            )
        )

    if state.void_lookups > VOID_LIMIT:
        findings.append(
            _finding(
                "spf.void_limit_exceeded",
                Severity.WARNING,
                Confidence.HIGH,
                f"SPF has {state.void_lookups} void lookups, above the limit of {VOID_LIMIT}",
                "Void lookups are references to names that hold no records. RFC 7208 "
                "caps them at two, separately from the ten-lookup limit, and passing "
                "the cap is its own permerror.",
                void_lookups=str(state.void_lookups),
            )
        )

    # -- terminal mechanism ------------------------------------------------
    qualifier = state.all_qualifier
    if qualifier is None:
        findings.append(
            _finding(
                "spf.no_all",
                Severity.WARNING,
                Confidence.HIGH,
                "SPF has no terminal all mechanism",
                "Without one the default result is neutral, which for unlisted "
                "senders is the same outcome as publishing no SPF record.",
            )
        )
    elif qualifier == "+":
        findings.append(
            _finding(
                "spf.all_pass",
                Severity.CRITICAL,
                Confidence.HIGH,
                "SPF ends in +all",
                "This states that every host on the internet is an authorised sender "
                "for this domain.",
            )
        )
    elif qualifier == "?":
        findings.append(
            _finding(
                "spf.all_neutral",
                Severity.WARNING,
                Confidence.HIGH,
                "SPF ends in ?all (neutral)",
                "Unlisted senders receive no verdict, so SPF contributes nothing.",
            )
        )
    elif qualifier == "~":
        findings.append(
            _finding(
                "spf.all_softfail",
                Severity.INFO,
                Confidence.HIGH,
                "SPF ends in ~all (soft fail)",
                "Appropriate while DMARC reports are still being reviewed. It can be "
                "tightened to -all once the reports confirm no legitimate sender is "
                "failing.",
            )
        )
    else:
        findings.append(
            _finding(
                "spf.all_hardfail",
                Severity.OK,
                Confidence.HIGH,
                "SPF ends in -all (hard fail)",
            )
        )

    # -- notes raised during the walk --------------------------------------
    note_severity = {
        "spf.syntax_error": Severity.CRITICAL,
        "spf.include_loop": Severity.CRITICAL,
        "spf.nested_multiple": Severity.CRITICAL,
        "spf.ptr": Severity.WARNING,
        "spf.unresolved_include": Severity.WARNING,
        "spf.duplicate_include": Severity.WARNING,
        "spf.multiple_all": Severity.WARNING,
        "spf.terms_after_all": Severity.WARNING,
        "spf.redirect_ignored": Severity.WARNING,
        "spf.depth_exceeded": Severity.WARNING,
        "spf.macro": Severity.INFO,
        "spf.include_unreachable": Severity.INFO,
    }
    for code, text in state.notes:
        title = text[0].upper() + text[1:] if text else code
        findings.append(
            _finding(
                code,
                note_severity.get(code, Severity.WARNING),
                # An unreachable include is a fact about our vantage point, not
                # about the domain, so it can never be stated with confidence.
                Confidence.LOW if code == "spf.include_unreachable" else Confidence.HIGH,
                title,
            )
        )

    return SpfResult(
        records=records,
        terms=state.top_terms,
        lookups=state.lookups,
        void_lookups=state.void_lookups,
        all_qualifier=state.all_qualifier,
        chain=state.chain,
        findings=findings,
    )
