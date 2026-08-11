"""
mailauth/report.py - the client-facing one-pager.

This is the artifact that gets handed to a firm, so two rules govern every
string in this module:

  1. It describes what is published in DNS. It does not characterise anyone as
     being in violation of anything, does not name a statute, and does not
     assert consequences it cannot observe. tests/test_language.py enforces this
     mechanically against a forbidden-word list rather than trusting the author.

  2. The records it generates must be correct and copy-pasteable, and the DMARC
     rollout must be staged. Telling a five-person accounting firm to publish
     p=reject on day one will break their mail, and the person who pays for that
     is the client. Stage one is always p=none with a reporting address.
"""

from __future__ import annotations

import html
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import Confidence, DomainResult, Posture, Severity
from .providers import Provider, dns_host_guidance, identify
from .scoring import DEFAULT_WEIGHTS_PATH


@dataclass(frozen=True)
class Rollout:
    """How the report stages a DMARC deployment. Loaded from configuration."""

    monitor_weeks: int = 2
    quarantine_weeks: int = 2
    pct_ladder: tuple[int, ...] = (25, 100)


def load_rollout(path: Path | None = None) -> Rollout:
    """Read the rollout staging from the config file.

    Lives alongside the weights because that is where this tool's numbers live,
    but it is not scoring: it changes what the report advises, never what a
    domain scores, which is why it is not part of the weights digest.
    """
    path = path or DEFAULT_WEIGHTS_PATH
    try:
        with path.open("rb") as handle:
            section = tomllib.load(handle).get("rollout", {})
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        return Rollout()
    ladder = tuple(int(v) for v in section.get("pct_ladder", (25, 100)))
    return Rollout(
        monitor_weeks=int(section.get("monitor_weeks", 2)),
        quarantine_weeks=int(section.get("quarantine_weeks", 2)),
        pct_ladder=ladder or (100,),
    )


@dataclass(frozen=True)
class RecordSuggestion:
    """One DNS record to publish, in the three fields every DNS panel asks for."""

    host: str
    rtype: str
    value: str
    note: str = ""
    stage: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "host": self.host,
            "type": self.rtype,
            "value": self.value,
            "note": self.note,
            "stage": self.stage,
        }


def dmarc_rollout(domain: str, result: DomainResult) -> list[RecordSuggestion]:
    """Build the staged DMARC rollout appropriate to where this domain already is.

    A domain already at p=quarantine does not need to be told to go back to
    p=none. The rollout starts from the current state and describes the next
    step, then the one after.
    """
    rollout = load_rollout()
    policy = result.dmarc.policy
    has_rua = bool(result.dmarc.tags.get("rua"))
    reporting = f"rua=mailto:dmarc@{domain}"

    suggestions: list[RecordSuggestion] = []

    if policy not in ("none", "quarantine", "reject"):
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=none; {reporting}; fo=1;",
                stage=f"Stage 1 - now, then leave for {rollout.monitor_weeks} weeks",
                note=(
                    "p=none changes nothing about how mail is delivered. Its only job "
                    "is to start the flow of aggregate reports, which show every "
                    "service currently sending as this domain. Publishing an enforcing "
                    "policy before reading those reports is what breaks mail, because "
                    "there is almost always a sender nobody remembered."
                ),
            )
        )
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=quarantine; sp=quarantine; pct={rollout.pct_ladder[0]}; {reporting}; fo=1;",
                stage=f"Stage 2 - after {rollout.monitor_weeks} weeks of clean reports",
                note=(
                    "Move here only once the reports show every legitimate sender "
                    "passing. Failing mail is then treated as suspicious rather than "
                    "delivered normally."
                ),
            )
        )
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=reject; sp=reject; pct={rollout.pct_ladder[-1]}; {reporting}; fo=1;",
                stage=f"Stage 3 - after a further {rollout.quarantine_weeks} weeks",
                note=(
                    "The end state. Mail that fails authentication is refused rather "
                    "than delivered."
                ),
            )
        )
        return suggestions

    if policy == "none":
        if not has_rua:
            suggestions.append(
                RecordSuggestion(
                    host="_dmarc",
                    rtype="TXT",
                    value=f"v=DMARC1; p=none; {reporting}; fo=1;",
                    stage="Do this first",
                    note=(
                        "The existing record has no reporting address, so no data is "
                        "being collected. Adding one changes nothing about delivery "
                        "and is what makes every later step safe."
                    ),
                )
            )
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=quarantine; sp=quarantine; pct={rollout.pct_ladder[0]}; {reporting}; fo=1;",
                stage=f"Next - after {rollout.monitor_weeks} weeks of clean reports",
                note=(
                    "Move here once the aggregate reports show every legitimate sender "
                    "passing. If a sender is still failing, fix that sender first."
                ),
            )
        )
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=reject; sp=reject; pct={rollout.pct_ladder[-1]}; {reporting}; fo=1;",
                stage=f"Then - after a further {rollout.quarantine_weeks} weeks",
            )
        )
        return suggestions

    if policy == "quarantine":
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=reject; sp=reject; pct={rollout.pct_ladder[-1]}; {reporting}; fo=1;",
                stage=f"Next - after {rollout.quarantine_weeks} weeks of clean reports",
                note=(
                    "The remaining step. Quarantine already moves failing mail out of "
                    "the inbox; reject stops it being accepted at all."
                ),
            )
        )
        return suggestions

    # Already at reject: the only suggestions left are repairs to the tags.
    tags = result.dmarc.tags
    if not has_rua:
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=reject; sp=reject; pct={rollout.pct_ladder[-1]}; {reporting}; fo=1;",
                stage="Repair",
                note=(
                    "The policy is already at its end state but no reports are being "
                    "collected, so there is no visibility into what it is refusing."
                ),
            )
        )
    elif tags.get("pct", "100") != "100":
        existing_rua = tags.get("rua", f"mailto:dmarc@{domain}")
        suggestions.append(
            RecordSuggestion(
                host="_dmarc",
                rtype="TXT",
                value=f"v=DMARC1; p=reject; sp=reject; pct={rollout.pct_ladder[-1]}; rua={existing_rua}; fo=1;",
                stage="Repair",
                note=(
                    f"The record reads as p=reject but pct={tags.get('pct')} applies it "
                    f"to only part of the mail stream. Setting pct={rollout.pct_ladder[-1]} "
                    f"makes the "
                    f"published policy and the enforced policy the same thing."
                ),
            )
        )
    return suggestions


def spf_suggestion(
    domain: str, result: DomainResult, provider: Provider | None
) -> list[RecordSuggestion]:
    """Suggest an SPF record, using the detected provider's documented include."""
    suggestions: list[RecordSuggestion] = []

    if not result.spf.records:
        if provider and provider.spf_record:
            suggestions.append(
                RecordSuggestion(
                    host="@",
                    rtype="TXT",
                    value=provider.spf_record,
                    note=(
                        f"Built for {provider.name}, which is what the MX records point "
                        f"at. If any other service sends mail as this domain - a "
                        f"payroll provider, a marketing platform, tax software - its "
                        f"include goes in before the -all. Start with ~all instead of "
                        f"-all if there is any doubt about the full list of senders."
                    ),
                )
            )
        else:
            suggestions.append(
                RecordSuggestion(
                    host="@",
                    rtype="TXT",
                    value="v=spf1 -all",
                    note=(
                        "This domain has no detected mail provider. If it sends no mail "
                        "at all, this record is complete as written and states that "
                        "nobody is authorised to send as it. If it does send, each "
                        "sending service's include goes in before the -all."
                    ),
                )
            )
        return suggestions

    if len(result.spf.records) > 1:
        suggestions.append(
            RecordSuggestion(
                host="@",
                rtype="TXT",
                value=result.spf.records[0],
                note=(
                    f"There are currently {len(result.spf.records)} SPF records. Only "
                    f"one may exist. Merge the mechanisms from all of them into a "
                    f"single record and delete the others; the value shown here is the "
                    f"first one as a starting point, not a merged result."
                ),
            )
        )

    if result.spf.all_qualifier == "+":
        merged = result.spf.records[0].rsplit("+all", 1)[0].strip() + " -all"
        suggestions.append(
            RecordSuggestion(
                host="@",
                rtype="TXT",
                value=merged,
                note=(
                    "The current record ends in +all, which states that any host may "
                    "send as this domain. The value shown is the existing record with "
                    "that changed to -all."
                ),
            )
        )

    return suggestions


def dkim_suggestion(result: DomainResult, provider: Provider | None) -> list[str]:
    """Return prose instructions for DKIM, never a generated record.

    A DKIM record cannot be generated from outside: the key is produced by the
    mail provider. The only honest output is where to go and press the button.
    """
    if result.dkim.wildcard:
        return [
            "A wildcard DNS record under this domain makes it impossible to tell from "
            "outside whether DKIM is set up, because every name asked for returns an "
            "answer. Checking this needs access to the domain's DNS."
        ]
    if result.dkim.any_key_found:
        found = ", ".join(k.selector for k in result.dkim.usable_keys)
        return [f"A DKIM key is already published on: {found}."]

    lines: list[str] = []
    if result.dkim.revoked_keys:
        selectors = ", ".join(k.selector for k in result.dkim.revoked_keys)
        lines.append(
            f"The key at {selectors} has been revoked, so nothing is signing mail "
            f"through it. If a key rotation was started and not finished, completing "
            f"it at the mail provider restores signing. If the sender behind this "
            f"selector was retired on purpose, the record can be removed."
        )
    elif result.dkim.unreadable_keys:
        selectors = ", ".join(k.selector for k in result.dkim.unreadable_keys)
        lines.append(
            f"A key record is published at {selectors} but cannot be read, so it "
            f"needs replacing rather than adding. Generate a fresh key at the mail "
            f"provider and paste the value in as a single unbroken string, without "
            f"quotation marks around it - the panel adds those itself."
        )
    elif result.dkim.delegations_without_key:
        selectors = ", ".join(k.selector for k in result.dkim.delegations_without_key)
        lines.append(
            f"The DNS side of DKIM is already in place at {selectors}, pointing at "
            f"the mail provider. What is missing is the key at the other end, which "
            f"is switched on in the provider's admin area. No DNS change is needed "
            f"for this step."
        )
    else:
        lines.append(
            f"No DKIM key was found on the {len(result.dkim.selectors_tried)} "
            f"selectors tried. Selectors cannot be listed from outside a domain, so "
            f"this is not proof that no key exists - it means none was found at the "
            f"names checked."
        )
    if provider and provider.dkim_setup:
        if provider.setup_verified:
            lines.append(f"For {provider.name}: {provider.dkim_setup}")
        else:
            # Not checked against current vendor documentation, so it is offered
            # as a description of where this lived rather than as a step to
            # follow. A wrong menu path under our name costs more than silence.
            lines.append(
                f"For {provider.name}, this was last documented as: "
                f"{provider.dkim_setup} Vendor admin areas change, so confirm the "
                f"current location rather than following this verbatim."
            )
    else:
        lines.append(
            "DKIM keys are generated by whichever service sends the mail, then "
            "published in DNS. The setting is usually under a heading like "
            "authentication, DKIM, or email signing in that service's admin area."
        )
    lines.append("Selectors tried: " + ", ".join(result.dkim.selectors_tried) + ".")
    return lines


def supporting_suggestions(domain: str, result: DomainResult) -> list[RecordSuggestion]:
    """Records worth adding once DMARC, SPF and DKIM are in order."""
    suggestions: list[RecordSuggestion] = []
    if result.posture != Posture.SENDING:
        return suggestions
    if not result.extras.tlsrpt.present:
        suggestions.append(
            RecordSuggestion(
                host="_smtp._tls",
                rtype="TXT",
                value=f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}",
                note=(
                    "Asks sending servers to report failures to negotiate TLS when "
                    "delivering here. Optional, and worth doing after the three above."
                ),
            )
        )
    return suggestions


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _plain_state(result: DomainResult) -> list[str]:
    """Describe what is currently published, in ordinary language."""
    lines: list[str] = []

    if result.mx.null_mx:
        lines.append(
            "This domain publishes a null MX record, which states that it receives no mail."
        )
    elif result.mx.targets:
        provider = result.mx.provider or result.mx.targets[0].host
        lines.append(f"Mail for this domain is handled by {provider}.")
    else:
        lines.append("This domain publishes no MX records, so it does not receive mail.")

    if not result.spf.records:
        lines.append(
            "There is no SPF record, so nothing states which servers are allowed to send mail using this domain."
        )
    elif len(result.spf.records) > 1:
        lines.append(
            f"There are {len(result.spf.records)} SPF records. Only one is allowed, and "
            f"a receiving server that finds several stops evaluating SPF for this "
            f"domain entirely."
        )
    else:
        ending = {
            "-": "It ends in -all, which asks receivers to reject mail from anywhere else.",
            "~": "It ends in ~all, which asks receivers to treat mail from anywhere else as suspicious.",
            "?": "It ends in ?all, which asks nothing of receivers for mail from anywhere else.",
            "+": "It ends in +all, which states that any server on the internet may send as this domain.",
        }.get(
            result.spf.all_qualifier or "",
            "It has no terminal all mechanism, so the result for anywhere else is neutral.",
        )
        lines.append(
            f"There is an SPF record listing the authorised senders. {ending} "
            f"It uses {result.spf.lookups} of the 10 DNS lookups a record is allowed."
        )

    if not result.dmarc.record:
        lines.append(
            "There is no DMARC record. Nothing tells receiving servers what to do with "
            "mail that claims to be from this domain and fails the checks above, and "
            "no reports are collected showing who is sending as this domain."
        )
    else:
        policy_text = {
            "none": "monitor only - failing mail is still delivered normally",
            "quarantine": "quarantine - failing mail is treated as suspicious",
            "reject": "reject - failing mail is refused",
        }.get(result.dmarc.policy, "no valid policy setting")
        reporting = (
            f"Reports are sent to {result.dmarc.tags['rua']}."
            if result.dmarc.tags.get("rua")
            else "No reporting address is set, so no reports are collected."
        )
        lines.append(f"There is a DMARC record set to {policy_text}. {reporting}")

    if result.dkim.wildcard:
        lines.append(
            "DKIM cannot be assessed from outside this domain, because a wildcard DNS "
            "record makes every name asked for return an answer."
        )
    else:
        lines.extend(_dkim_state_lines(result))

    return lines


def _dkim_state_lines(result: DomainResult) -> list[str]:
    """Describe DKIM in plain language, keeping the three states apart.

    A usable key, a published record nobody can read, and a delegation with
    nothing behind it are three different conversations with a client. Folding
    the last two into the first is how a firm gets told they have DKIM when
    nothing is signing their mail.
    """
    dkim = result.dkim
    usable = dkim.usable_keys
    unreadable = dkim.unreadable_keys
    revoked = dkim.revoked_keys
    delegations = dkim.delegations_without_key
    lines: list[str] = []

    if usable:
        found = ", ".join(k.selector for k in usable)
        bits = [str(k.bits) for k in usable if k.bits]
        size = f" The key is {bits[0]} bits." if bits else ""
        plural = "keys are" if len(usable) > 1 else "key is"
        lines.append(f"A DKIM signing {plural} published on the selector {found}.{size}")
    elif not dkim.published_something:
        # Only say nothing was found when nothing was in fact retrieved. A
        # malformed or withdrawn key is something, and saying otherwise here
        # would contradict the findings section directly below it.
        lines.append(
            f"No DKIM signing key was found on the {len(dkim.selectors_tried)} "
            f"selector names checked. Selector names cannot be listed from outside a "
            f"domain, so this does not prove that no key exists."
        )

    if revoked:
        selectors = ", ".join(k.selector for k in revoked)
        has = "have" if len(revoked) > 1 else "has"
        plural = "records" if len(revoked) > 1 else "record"
        lines.append(
            f"The key {plural} at the selector {selectors} {has} been withdrawn: the "
            f"record is still published, but the key value in it is empty, which tells "
            f"receiving servers the key is no longer valid. Mail signed with it fails. "
            f"This is the expected state for a short period during a key rotation, and "
            f"a gap if it stays this way."
        )

    if unreadable:
        selectors = ", ".join(k.selector for k in unreadable)
        plural = "records are" if len(unreadable) > 1 else "record is"
        lines.append(
            f"A key {plural} published at the selector {selectors}, but it cannot be "
            f"read: the key value in it is malformed. A receiving server that looks "
            f"there gets nothing it can check a signature against, so this selector "
            f"protects nothing at present."
        )

    if delegations:
        selectors = ", ".join(k.selector for k in delegations)
        count = len(delegations)
        plural = "selectors" if count > 1 else "selector"
        lines.append(
            f"{count} {plural} ({selectors}) point at another name using a CNAME "
            f"record, but no key is published at the far end. This is the state a "
            f"domain is left in when the DKIM records are added and the key is never "
            f"generated at the mail provider."
        )

    return lines


def _observations(result: DomainResult) -> list[tuple[str, str]]:
    """The gaps, phrased as observations, worst first."""
    out: list[tuple[str, str]] = []
    for item in result.scored:
        if item.weight <= 0:
            continue
        if item.finding.severity == Severity.OK:
            continue
        suffix = ""
        if item.finding.confidence == Confidence.LOW:
            suffix = " (this one is inferred rather than directly observed)"
        out.append((item.finding.title + suffix, item.finding.detail))
    return out


def render_markdown(result: DomainResult, firm_name: str | None = None) -> str:
    """Render the per-domain one-pager as Markdown."""
    provider = identify(result.mx.hosts)
    title = firm_name or result.domain
    lines: list[str] = []

    lines.append(f"# Email authentication review: {title}")
    lines.append("")
    lines.append(f"**Domain:** {result.domain}  ")
    lines.append(f"**Reviewed:** {result.checked_at}  ")
    lines.append("**Method:** public DNS records only  ")
    lines.append("")

    if result.error:
        lines.append(f"This domain could not be reviewed: {result.error}.")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "Everything below was read from this domain's public DNS records. Nothing "
        "was sent to, or requested from, any server this domain operates."
    )
    lines.append("")

    lines.append("## What is published today")
    lines.append("")
    for line in _plain_state(result):
        lines.append(f"- {line}")
    lines.append("")

    observations = _observations(result)
    lines.append("## What is missing or incomplete")
    lines.append("")
    if not observations:
        lines.append(
            "Nothing stands out. SPF, DKIM and DMARC are all published and the "
            "settings are consistent with each other."
        )
        lines.append("")
    else:
        for title_text, detail in observations:
            lines.append(f"**{title_text}**")
            lines.append("")
            if detail:
                lines.append(detail)
                lines.append("")

    # -- the records ------------------------------------------------------
    lines.append("## The records to publish")
    lines.append("")

    spf_records = spf_suggestion(result.domain, result, provider)
    dmarc_records = dmarc_rollout(result.domain, result)
    supporting = supporting_suggestions(result.domain, result)

    if spf_records:
        lines.append("### SPF")
        lines.append("")
        for suggestion in spf_records:
            lines.extend(_render_record(suggestion))
    if dmarc_records:
        lines.append("### DMARC")
        lines.append("")
        lines.append(
            "DMARC is published in stages. Each stage stays in place long enough for "
            "the reports to show what it would have affected before the next one is "
            "applied. Skipping to the final stage is how legitimate mail gets lost, "
            "because there is almost always a sending service nobody remembered."
        )
        lines.append("")
        for suggestion in dmarc_records:
            lines.extend(_render_record(suggestion))

    lines.append("### DKIM")
    lines.append("")
    for line in dkim_suggestion(result, provider):
        lines.append(line)
        lines.append("")

    if supporting:
        lines.append("### Optional, once the above are in place")
        lines.append("")
        for suggestion in supporting:
            lines.extend(_render_record(suggestion))

    # -- where to put them -------------------------------------------------
    lines.append("## Where these go")
    lines.append("")
    host_keys = [provider.key] if provider else []
    for guidance in dns_host_guidance(host_keys):
        lines.append(f"- {guidance}")
    lines.append("")
    lines.append(
        "TXT record values must be pasted exactly, including the semicolons. Most "
        "panels add the domain to the host field automatically, so entering the full "
        "name produces `_dmarc.example.com.example.com` - if a record does not seem "
        "to take effect, that is the first thing to check."
    )
    lines.append("")

    lines.append("## How this was assessed")
    lines.append("")
    if result.score is None:
        # No number for a domain that receives no mail. A score here would be
        # read against other firms' scores, and the comparison is meaningless:
        # the findings above describe a domain nobody sends mail to.
        lines.append(
            f"This domain publishes no MX records, so it does not receive mail. It "
            f"is therefore not scored on the same scale as a domain that does - a "
            f"number here would invite a comparison that does not hold. The "
            f"observations above still stand, and the records suggested below still "
            f"stop anyone sending mail that claims to come from this domain. "
            f"Aggregate confidence in what was read is {result.confidence:.0%}."
        )
    else:
        lines.append(
            f"Score {result.score} of 100 ({result.risk}), with an aggregate "
            f"confidence of {result.confidence:.0%}. The score is the sum of the "
            f"weights of the observations above, capped at 100. Confidence is "
            f"tracked separately because some observations are read directly from "
            f"DNS and some are inferred."
        )
    lines.append("")
    if result.low_confidence_share > 0:
        lines.append(
            f"{result.low_confidence_share:.0%} of this score comes from observations "
            f"that are inferred rather than directly observed - in practice, the DKIM "
            f"selector check, which cannot be conclusive from outside."
        )
        lines.append("")

    return "\n".join(lines)


def _render_record(suggestion: RecordSuggestion) -> list[str]:
    lines: list[str] = []
    if suggestion.stage:
        lines.append(f"**{suggestion.stage}**")
        lines.append("")
    lines.append("```")
    lines.append(f"Host:  {suggestion.host}")
    lines.append(f"Type:  {suggestion.rtype}")
    lines.append(f"Value: {suggestion.value}")
    lines.append("```")
    lines.append("")
    if suggestion.note:
        lines.append(suggestion.note)
        lines.append("")
    return lines


HTML_STYLE = """
:root { color-scheme: light dark; }
body { max-width: 46rem; margin: 3rem auto; padding: 0 1.25rem;
       font: 16px/1.6 -apple-system, Segoe UI, Roboto, sans-serif; }
h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.2rem; margin-top: 2.5rem;
     border-bottom: 1px solid rgba(128,128,128,0.3); padding-bottom: 0.3rem; }
h3 { font-size: 1rem; margin-top: 1.75rem; }
pre { background: rgba(128,128,128,0.12); padding: 0.9rem 1rem;
      border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
code { font-family: Consolas, Menlo, monospace; }
"""


def render_html(result: DomainResult, firm_name: str | None = None) -> str:
    """Render the one-pager as a self-contained HTML page.

    Deliberately a minimal Markdown-to-HTML pass rather than a dependency: the
    document only ever uses headings, paragraphs, bullets, bold and fenced code.
    """
    markdown = render_markdown(result, firm_name)
    body: list[str] = []
    in_code = False
    in_list = False

    for line in markdown.splitlines():
        if line.startswith("```"):
            if in_code:
                body.append("</pre>")
            else:
                body.append("<pre>")
            in_code = not in_code
            continue
        if in_code:
            body.append(html.escape(line))
            continue

        if line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{_inline(line[2:])}</li>")
            continue
        if in_list:
            body.append("</ul>")
            in_list = False

        if line.startswith("### "):
            body.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            body.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.strip():
            body.append(f"<p>{_inline(line)}</p>")

    if in_list:
        body.append("</ul>")
    if in_code:
        body.append("</pre>")

    title = html.escape(firm_name or result.domain)
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Email authentication review: {title}</title>\n"
        f"<style>{HTML_STYLE}</style>\n</head>\n<body>\n"
        + "\n".join(body)
        + "\n</body>\n</html>\n"
    )


def _inline(text: str) -> str:
    """Escape a line and apply the two inline markers the document uses."""
    escaped = html.escape(text)
    parts = escaped.split("**")
    out: list[str] = []
    for index, part in enumerate(parts):
        out.append(f"<strong>{part}</strong>" if index % 2 else part)
    rendered = "".join(out)
    segments = rendered.split("`")
    out = []
    for index, segment in enumerate(segments):
        out.append(f"<code>{segment}</code>" if index % 2 else segment)
    return "".join(out).replace("  \n", "<br>")
