"""
tests/test_report.py - the client-facing one-pager.

The generated records are the part of this tool a client actually acts on, so
the tests here are about correctness of those records and about the staging of
the DMARC rollout. A wrong record here costs a real firm their mail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mailauth.engine import check_domain
from mailauth.models import DmarcResult, DomainResult, Posture, SpfResult
from mailauth.providers import PROVIDERS_BY_KEY
from mailauth.report import (
    dmarc_rollout,
    render_html,
    render_markdown,
    spf_suggestion,
    strip_test_mode_tag,
)
from mailauth.scoring import Weights, score
from tests.conftest import RSA_2048_P, FakeResolver


def result_with(**kwargs: object) -> DomainResult:
    base = {
        "domain": "x.test",
        "resolver": "fake",
        "checked_at": "2026-08-09T00:00:00+00:00",
        "posture": Posture.SENDING,
    }
    base.update(kwargs)
    return DomainResult(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# DMARC rollout staging
# ---------------------------------------------------------------------------


def test_a_domain_with_no_dmarc_is_staged_from_none() -> None:
    """The rule that protects the client: never reject on day one."""
    suggestions = dmarc_rollout("x.test", result_with())

    assert len(suggestions) == 3
    assert "p=none" in suggestions[0].value
    assert "p=quarantine" in suggestions[1].value
    assert "p=reject" in suggestions[2].value
    # The first stage must carry a reporting address, or the later stages are blind.
    assert "rua=mailto:" in suggestions[0].value


def test_the_first_stage_explains_why_it_changes_nothing() -> None:
    first = dmarc_rollout("x.test", result_with())[0]
    assert "changes nothing" in first.note.lower()


def test_a_domain_at_p_none_is_not_told_to_start_over() -> None:
    result = result_with(
        dmarc=DmarcResult(
            record="v=DMARC1; p=none; rua=mailto:d@x.test",
            tags={"p": "none", "rua": "mailto:d@x.test"},
        )
    )
    suggestions = dmarc_rollout("x.test", result)
    assert all("p=none" not in s.value for s in suggestions)
    assert "p=quarantine" in suggestions[0].value


def test_a_domain_at_p_none_without_reporting_is_told_to_add_it_first() -> None:
    result = result_with(dmarc=DmarcResult(record="v=DMARC1; p=none", tags={"p": "none"}))
    suggestions = dmarc_rollout("x.test", result)
    assert "p=none" in suggestions[0].value
    assert "rua=" in suggestions[0].value
    assert suggestions[0].stage == "Do this first"


def test_a_domain_at_quarantine_gets_only_the_remaining_step() -> None:
    result = result_with(
        dmarc=DmarcResult(
            record="v=DMARC1; p=quarantine; rua=mailto:d@x.test",
            tags={"p": "quarantine", "rua": "mailto:d@x.test"},
        )
    )
    suggestions = dmarc_rollout("x.test", result)
    assert len(suggestions) == 1
    assert "p=reject" in suggestions[0].value


def test_a_domain_at_reject_with_partial_pct_gets_a_repair() -> None:
    result = result_with(
        dmarc=DmarcResult(
            record="v=DMARC1; p=reject; pct=20; rua=mailto:d@x.test",
            tags={"p": "reject", "pct": "20", "rua": "mailto:d@x.test"},
        )
    )
    suggestions = dmarc_rollout("x.test", result)
    assert len(suggestions) == 1
    # The repair removes the tag rather than setting it to 100: the current
    # standard removed pct, so a conforming receiver ignores any value.
    assert "pct" not in suggestions[0].value
    assert "removes the tag" in suggestions[0].note
    # The existing reporting address must be preserved, not replaced.
    assert "mailto:d@x.test" in suggestions[0].value


def test_a_fully_configured_domain_gets_no_dmarc_suggestions() -> None:
    result = result_with(
        dmarc=DmarcResult(
            record="v=DMARC1; p=reject; pct=100; rua=mailto:d@x.test",
            tags={"p": "reject", "pct": "100", "rua": "mailto:d@x.test"},
        )
    )
    assert dmarc_rollout("x.test", result) == []


def test_every_generated_dmarc_record_is_well_formed() -> None:
    for result in (
        result_with(),
        result_with(dmarc=DmarcResult(record="v=DMARC1; p=none", tags={"p": "none"})),
        result_with(
            dmarc=DmarcResult(
                record="v=DMARC1; p=quarantine; rua=mailto:d@x.test",
                tags={"p": "quarantine", "rua": "mailto:d@x.test"},
            )
        ),
    ):
        for suggestion in dmarc_rollout("x.test", result):
            assert suggestion.host == "_dmarc"
            assert suggestion.rtype == "TXT"
            assert suggestion.value.startswith("v=DMARC1;")
            assert "p=" in suggestion.value


# ---------------------------------------------------------------------------
# SPF generation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "provider_key,expected_include",
    [
        ("google", "include:_spf.google.com"),
        ("microsoft365", "include:spf.protection.outlook.com"),
        ("zoho", "include:zoho.com"),
        ("fastmail", "include:spf.messagingengine.com"),
    ],
)
def test_spf_is_generated_for_the_detected_provider(
    provider_key: str, expected_include: str
) -> None:
    suggestions = spf_suggestion("x.test", result_with(), PROVIDERS_BY_KEY[provider_key])
    assert expected_include in suggestions[0].value
    assert suggestions[0].value.endswith("-all")


def test_spf_for_an_unknown_provider_is_a_lockdown_with_a_caveat() -> None:
    suggestions = spf_suggestion("x.test", result_with(), None)
    assert suggestions[0].value == "v=spf1 -all"
    assert "if it does send" in suggestions[0].note.lower()


def test_plus_all_is_rewritten_to_hard_fail_keeping_the_mechanisms() -> None:
    result = result_with(
        spf=SpfResult(records=["v=spf1 ip4:192.0.2.0/24 +all"], all_qualifier="+")
    )
    suggestions = spf_suggestion("x.test", result, None)
    rewritten = suggestions[-1].value
    assert rewritten == "v=spf1 ip4:192.0.2.0/24 -all"


def test_two_spf_records_are_not_silently_merged() -> None:
    """A merge would need to be correct; the tool says merge them rather than guessing."""
    result = result_with(
        spf=SpfResult(records=["v=spf1 a -all", "v=spf1 mx -all"], all_qualifier="-")
    )
    note = spf_suggestion("x.test", result, None)[0].note.lower()
    assert "merge" in note
    assert "not a merged result" in note


def test_a_domain_with_good_spf_gets_no_spf_suggestion() -> None:
    result = result_with(
        spf=SpfResult(records=["v=spf1 include:_spf.google.com -all"], all_qualifier="-")
    )
    assert spf_suggestion("x.test", result, PROVIDERS_BY_KEY["google"]) == []


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


@pytest.fixture
def wideopen_report(wideopen_zone, weights: Weights) -> str:
    result = score(check_domain(FakeResolver(wideopen_zone), "wideopen.test"), weights)
    return render_markdown(result, firm_name="Example Bookkeeping LLC")


def test_report_carries_the_firm_name_when_given(wideopen_report: str) -> None:
    assert "Example Bookkeeping LLC" in wideopen_report


def test_report_has_the_expected_sections(wideopen_report: str) -> None:
    for heading in (
        "## What is published today",
        "## What is missing or incomplete",
        "## The records to publish",
        "## Where these go",
        "## How this was assessed",
    ):
        assert heading in wideopen_report, heading


def test_report_states_nothing_was_sent_to_the_domain(wideopen_report: str) -> None:
    assert "Nothing was sent to" in wideopen_report


def test_report_includes_provider_specific_dns_guidance(wideopen_report: str) -> None:
    # wideopen.test is on GoDaddy MX, so the GoDaddy panel note must appear.
    assert "GoDaddy" in wideopen_report


def test_report_warns_about_the_host_field_trap(wideopen_report: str) -> None:
    """The most common reason a correctly generated record does not take effect."""
    assert "_dmarc.example.com.example.com" in wideopen_report


def test_low_confidence_share_is_disclosed(wideopen_report: str) -> None:
    assert "inferred rather than directly observed" in wideopen_report


def test_a_clean_domain_report_says_so(clean_zone, weights: Weights) -> None:
    """A domain with genuinely nothing to report gets told that plainly.

    The resolver is set to report DNSSEC authentication here, because without it
    the domain has one real observation left and the branch under test would not
    be the correct output.
    """
    result = score(
        check_domain(FakeResolver(clean_zone, authenticated=True), "locked.test"),
        weights,
    )
    assert result.score == 0
    assert "Nothing stands out" in render_markdown(result)


def test_an_errored_domain_renders_without_raising(weights: Weights) -> None:
    result = score(check_domain(FakeResolver({}), "gone.test"), weights)
    markdown = render_markdown(result)
    assert "could not be reviewed" in markdown


def test_html_escapes_content(weights: Weights) -> None:
    zone = {
        ("evil.test", "TXT"): ["v=spf1 include:<script>alert(1)</script> -all"],
        ("evil.test", "MX"): ["10 mail.evil.test"],
        ("mail.evil.test", "A"): ["192.0.2.1"],
    }
    result = score(check_domain(FakeResolver(zone), "evil.test"), weights)
    rendered = render_html(result)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_html_and_markdown_carry_the_same_records(clean_zone, weights: Weights) -> None:
    result = score(check_domain(FakeResolver(clean_zone), "locked.test"), weights)
    markdown = render_markdown(result)
    rendered = render_html(result)
    for line in markdown.splitlines():
        if line.startswith("Value: "):
            assert line[7:].replace("&", "&amp;") in rendered


# ---------------------------------------------------------------------------
# key-state counts in the client-facing report
# ---------------------------------------------------------------------------


def test_report_counts_only_usable_keys(weights: Weights) -> None:
    """One real key plus two dangling delegations must read as one, not three."""
    from tests.test_dkim import m365_delegation_only_zone

    zone = dict(m365_delegation_only_zone("m.test"))
    zone[("default._domainkey.m.test", "TXT")] = [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]
    zone[("m.test", "TXT")] = ["v=spf1 include:spf.protection.outlook.com -all"]
    zone[("spf.protection.outlook.com", "TXT")] = ["v=spf1 ip4:40.92.0.0/15 -all"]
    zone[("m.test", "MX")] = ["0 m-test.mail.protection.outlook.com"]
    zone[("m-test.mail.protection.outlook.com", "A")] = ["104.47.1.1"]

    result = score(check_domain(FakeResolver(zone), "m.test"), weights)
    markdown = render_markdown(result)

    assert "on 3 " not in markdown
    assert "selector default" in markdown or "on the selector default" in markdown


def test_report_states_delegation_count_separately(weights: Weights) -> None:
    from tests.test_dkim import m365_delegation_only_zone

    zone = dict(m365_delegation_only_zone("d.test"))
    zone[("d.test", "TXT")] = ["v=spf1 include:spf.protection.outlook.com -all"]
    zone[("spf.protection.outlook.com", "TXT")] = ["v=spf1 ip4:40.92.0.0/15 -all"]
    zone[("d.test", "MX")] = ["0 d-test.mail.protection.outlook.com"]
    zone[("d-test.mail.protection.outlook.com", "A")] = ["104.47.1.1"]

    result = score(check_domain(FakeResolver(zone), "d.test"), weights)
    markdown = render_markdown(result).lower()

    # It must not claim a key is published, and must explain the delegation.
    assert "a dkim signing key is published" not in markdown
    assert "2 selector" in markdown or "two selector" in markdown


def test_report_describes_a_broken_key_as_published_but_unreadable(
    weights: Weights,
) -> None:
    from tests.test_dkim import BROKEN_QUOTED_KEY

    zone = {
        ("b.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("b.test", "MX"): ["10 mail.b.test"],
        ("mail.b.test", "A"): ["192.0.2.1"],
        ("default._domainkey.b.test", "TXT"): [BROKEN_QUOTED_KEY],
    }
    result = score(check_domain(FakeResolver(zone), "b.test"), weights)
    markdown = render_markdown(result).lower()

    # Not "no key" - they published one. Not "a key is published" either, with
    # no qualification, because no receiver can actually read it.
    assert "no dkim signing key was found" not in markdown
    assert "a dkim signing key is published on the selector" not in markdown
    assert "cannot be read" in markdown or "could not be read" in markdown


def revoked_only_zone() -> dict[tuple[str, str], list[str]]:
    """A domain whose only key record was withdrawn with an empty p= value."""
    return {
        ("rev.test", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_spf.google.com", "TXT"): ["v=spf1 ip4:35.190.0.0/16 -all"],
        ("rev.test", "MX"): ["1 aspmx.l.google.com"],
        ("aspmx.l.google.com", "A"): ["142.250.1.26"],
        ("_dmarc.rev.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@rev.test"],
        ("google._domainkey.rev.test", "TXT"): ["v=DKIM1; k=rsa; p="],
    }


def test_a_revoked_only_domain_is_not_told_no_key_was_found(weights: Weights) -> None:
    """The report must not contradict its own findings section.

    Saying "no key was found" in the summary while the findings below say
    "selector google publishes a revoked key" is the kind of inconsistency a
    client notices and a competitor points at.
    """
    result = score(check_domain(FakeResolver(revoked_only_zone()), "rev.test"), weights)
    markdown = render_markdown(result).lower()

    assert "no dkim signing key was found" not in markdown
    assert "withdraw" in markdown or "revoked" in markdown


def test_a_revoked_only_domain_gets_actionable_dkim_guidance(weights: Weights) -> None:
    result = score(check_domain(FakeResolver(revoked_only_zone()), "rev.test"), weights)
    section = render_markdown(result).lower().split("### dkim")[1]

    assert "no dkim key was found on the" not in section
    assert "revoked" in section or "withdrawn" in section


# ---------------------------------------------------------------------------
# the rollout is configuration, not literals in the renderer
# ---------------------------------------------------------------------------


def test_the_rollout_defaults_to_two_weeks_per_stage() -> None:
    from mailauth.report import load_rollout

    rollout = load_rollout()
    assert rollout.monitor_weeks == 2
    assert rollout.quarantine_weeks == 2


def test_the_ladder_has_three_rungs_and_no_percentage() -> None:
    """pct was removed from DMARC, so the ladder is none -> quarantine -> reject.

    The graduated exposure pct was meant to give now comes from the time spent
    at quarantine, which is what monitor_weeks and quarantine_weeks control.
    """
    from mailauth.report import Rollout, load_rollout

    rollout = load_rollout()
    assert not hasattr(rollout, "pct_ladder")
    assert set(Rollout.__dataclass_fields__) == {"monitor_weeks", "quarantine_weeks"}

    policies = [
        s.value.split("p=", 1)[1].split(";", 1)[0]
        for s in dmarc_rollout("x.test", result_with())
    ]
    assert policies == ["none", "quarantine", "reject"], policies


def test_the_generated_rollout_uses_the_configured_interval() -> None:
    from mailauth.report import load_rollout

    weeks = load_rollout().monitor_weeks
    stages = " ".join(s.stage for s in dmarc_rollout("x.test", result_with()))
    assert f"{weeks} weeks" in stages


def test_no_generated_record_carries_a_pct_tag() -> None:
    """A record meaning the same thing to a 7489 and a 9989 receiver."""
    from mailauth.models import DmarcResult

    states = [
        result_with(),
        result_with(dmarc=DmarcResult(record="v=DMARC1; p=none", tags={"p": "none"})),
        result_with(
            dmarc=DmarcResult(
                record="v=DMARC1; p=quarantine; rua=mailto:d@x.test",
                tags={"p": "quarantine", "rua": "mailto:d@x.test"},
            )
        ),
        result_with(
            dmarc=DmarcResult(
                record="v=DMARC1; p=reject; pct=20; rua=mailto:d@x.test",
                tags={"p": "reject", "pct": "20", "rua": "mailto:d@x.test"},
            )
        ),
    ]
    for state in states:
        for suggestion in dmarc_rollout("x.test", state):
            assert "pct" not in suggestion.value, suggestion.value


def test_the_intervals_come_from_the_config_file(tmp_path: Path) -> None:
    from mailauth.report import load_rollout

    source = (Path("mailauth") / "weights.toml").read_text(encoding="utf-8")
    edited = tmp_path / "w.toml"
    edited.write_text(
        source.replace("monitor_weeks = 2", "monitor_weeks = 6", 1), encoding="utf-8"
    )
    assert load_rollout(edited).monitor_weeks == 6


def test_no_generated_record_template_carries_pct() -> None:
    """pct=100 was once hardcoded in seven places. Now it is in none of them.

    The tag may still be named in the repair prose, which explains why it is
    being removed, but it must not appear inside a v=DMARC1 record template.
    """
    source = (Path("mailauth") / "report.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if "v=DMARC1" in line:
            assert "pct" not in line, line.strip()


# ---------------------------------------------------------------------------
# the DKIM precondition on the enforcing rungs
#
# Both rungs are gated, not only the last one. `enforcing` at engine.py:66 is
# policy in ("quarantine", "reject"), so a domain reaching stage 2 without a
# usable key is already in the state combo.enforcing_without_dkim calls
# critical, and it sits there for the whole quarantine period.
# ---------------------------------------------------------------------------

SIGNING_PRECONDITION = "only once DKIM is signing"


def rollout_for(**dkim_kwargs: object) -> list:
    from mailauth.models import DkimResult

    return dmarc_rollout(
        "x.test",
        result_with(dkim=DkimResult(**dkim_kwargs)),  # type: ignore[arg-type]
    )


def enforcing_rungs(suggestions: list) -> list:
    return [s for s in suggestions if "p=quarantine" in s.value or "p=reject" in s.value]


def test_both_enforcing_rungs_are_gated_when_no_usable_key_was_found() -> None:
    rungs = enforcing_rungs(rollout_for(selectors_tried=["a"]))
    assert len(rungs) == 2, [s.stage for s in rungs]
    for rung in rungs:
        assert SIGNING_PRECONDITION in rung.stage, rung.stage
        assert "does not survive forwarding" in rung.note


def test_a_delegation_with_an_empty_target_is_gated_like_no_key() -> None:
    """Mail is unsigned either way, so the advice must be the same either way."""
    from mailauth.models import DkimKey

    rungs = enforcing_rungs(
        rollout_for(
            selectors_tried=["selector1"],
            keys=[
                DkimKey(
                    selector="selector1",
                    source="cname",
                    cname_target="s1._domainkey.tenant.onmicrosoft.com",
                    parse_error="the delegated name publishes no key record",
                )
            ],
        )
    )
    assert rungs
    for rung in rungs:
        assert SIGNING_PRECONDITION in rung.stage, rung.stage


def test_an_unobserved_wildcard_zone_is_gated() -> None:
    """Nothing can be established either way, so the caveat stands."""
    rungs = enforcing_rungs(rollout_for(selectors_tried=["a"], wildcard=True))
    assert rungs
    for rung in rungs:
        assert SIGNING_PRECONDITION in rung.stage, rung.stage


def test_a_usable_key_leaves_the_ladder_untouched() -> None:
    from mailauth.models import DkimKey

    rungs = enforcing_rungs(
        rollout_for(
            selectors_tried=["selector1"],
            keys=[DkimKey(selector="selector1", source="txt", record="v=DKIM1", bits=2048)],
        )
    )
    assert len(rungs) == 2
    for rung in rungs:
        assert SIGNING_PRECONDITION not in rung.stage, rung.stage
        assert "does not survive forwarding" not in rung.note


def test_the_gate_reads_usable_keys_rather_than_key_records() -> None:
    """The predicate must match engine.py:71, which uses any_key_found.

    A delegation produces a DkimKey with no usable key behind it. Gating on
    `keys` rather than `usable_keys` would wave that domain through.
    """
    from mailauth.models import DkimKey, DkimResult

    delegation = DkimResult(
        selectors_tried=["selector1"],
        keys=[
            DkimKey(
                selector="selector1",
                source="cname",
                cname_target="s1._domainkey.tenant.onmicrosoft.com",
                parse_error="the delegated name publishes no key record",
            )
        ],
    )
    assert delegation.keys, "the fixture must carry a key record"
    assert not delegation.usable_keys, "and no usable key"
    assert not delegation.any_key_found


def test_the_prerequisite_step_appears_before_stage_two(weights: Weights) -> None:
    """A client reading top to bottom must meet DKIM before the enforcing records."""
    from mailauth.engine import check_domain

    zone = {
        ("x.test", "TXT"): ["v=spf1 -all"],
        ("x.test", "MX"): ["10 mail.x.test"],
        ("mail.x.test", "A"): ["192.0.2.1"],
    }
    markdown = render_markdown(score(check_domain(FakeResolver(zone), "x.test"), weights))

    step = markdown.index("**Before stage 2 - set up DKIM**")
    quarantine = markdown.index("p=quarantine")
    reject = markdown.index("p=reject")
    assert step < quarantine < reject


def test_the_prerequisite_step_is_absent_when_a_key_is_present(
    weights: Weights,
) -> None:
    from mailauth.engine import check_domain

    zone = {
        ("x.test", "TXT"): ["v=spf1 -all"],
        ("x.test", "MX"): ["10 mail.x.test"],
        ("mail.x.test", "A"): ["192.0.2.1"],
        ("default._domainkey.x.test", "TXT"): [f"v=DKIM1; k=rsa; p={RSA_2048_P}"],
    }
    markdown = render_markdown(score(check_domain(FakeResolver(zone), "x.test"), weights))
    assert "**Before stage 2 - set up DKIM**" not in markdown


# ---------------------------------------------------------------------------
# the published-policy line under RFC 9989 test mode
#
# render_markdown drops findings with severity OK and findings with weight 0,
# which removes both dmarc.policy_quarantine and dmarc.policy_test_mode. The
# one-pager therefore never carried the qualification those two findings carry
# between them, and described an enforcing policy the record asks receivers not
# to apply as though it were being applied.
#
# These assert on the rendered page rather than on findings, because the page is
# the layer the claim is made at and the only layer a client reads.
# ---------------------------------------------------------------------------

QUARANTINE_LINE = (
    "There is a DMARC record set to quarantine - failing mail is treated as suspicious."
)
REJECT_LINE = "There is a DMARC record set to reject - failing mail is refused."
QUARANTINE_TEST_MODE_LINE = (
    "There is a DMARC record set to quarantine, test mode - failing mail is to be "
    "treated as suspicious, but t=y asks receivers not to act on that yet."
)
REJECT_TEST_MODE_LINE = (
    "There is a DMARC record set to reject, test mode - failing mail is to be "
    "refused, but t=y asks receivers not to act on that yet."
)

# Every unqualified claim that the published policy is being applied, as found by
# reading the rendered page. Two of them, on different sections: the "What is
# published today" line, and the quarantine rung's note in the rollout ladder,
# which says the existing policy "already moves" mail out of the inbox. Neither
# may survive on a t=y page.
ENFORCEMENT_ASSERTIONS = [
    "quarantine - failing mail is treated as suspicious",
    "reject - failing mail is refused",
    "Quarantine already moves failing mail out of the inbox",
]


def one_pager(record: str, weights: Weights) -> str:
    """Render the client one-pager for a domain publishing `record`."""
    zone = {
        ("x.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("x.test", "MX"): ["10 mail.x.test"],
        ("mail.x.test", "A"): ["192.0.2.1"],
        ("_dmarc.x.test", "TXT"): [record],
    }
    return render_markdown(score(check_domain(FakeResolver(zone), "x.test"), weights))


@pytest.mark.parametrize(
    "record,expected",
    [
        (
            "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
            QUARANTINE_TEST_MODE_LINE,
        ),
        ("v=DMARC1; p=reject; t=y; rua=mailto:r@example.com", REJECT_TEST_MODE_LINE),
    ],
    ids=["quarantine", "reject"],
)
def test_test_mode_qualifies_the_published_policy_line(
    record: str, expected: str, weights: Weights
) -> None:
    assert expected in one_pager(record, weights)


@pytest.mark.parametrize(
    "record,expected",
    [
        ("v=DMARC1; p=quarantine; rua=mailto:r@example.com", QUARANTINE_LINE),
        ("v=DMARC1; p=quarantine; t=n; rua=mailto:r@example.com", QUARANTINE_LINE),
        ("v=DMARC1; p=quarantine; t=maybe; rua=mailto:r@example.com", QUARANTINE_LINE),
        ("v=DMARC1; p=reject; rua=mailto:r@example.com", REJECT_LINE),
        ("v=DMARC1; p=reject; t=n; rua=mailto:r@example.com", REJECT_LINE),
        ("v=DMARC1; p=reject; t=maybe; rua=mailto:r@example.com", REJECT_LINE),
    ],
    ids=[
        "quarantine, no t",
        "quarantine, t=n",
        "quarantine, t=maybe",
        "reject, no t",
        "reject, t=n",
        "reject, t=maybe",
    ],
)
def test_without_test_mode_the_published_policy_line_is_unchanged(
    record: str, expected: str, weights: Weights
) -> None:
    assert expected in one_pager(record, weights)


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com",
    ],
    ids=["quarantine", "reject"],
)
def test_a_test_mode_page_asserts_no_enforcement_anywhere(
    record: str, weights: Weights
) -> None:
    """The page-level guard, covering both sections, not just the state list."""
    page = one_pager(record, weights)
    found = [phrase for phrase in ENFORCEMENT_ASSERTIONS if phrase in page]
    assert found == [], found


def test_the_rollout_note_still_asserts_enforcement_outside_test_mode() -> None:
    """The other half of the guard: the original wording is not simply deleted.

    Without this, removing the assertion from every page would pass the guard
    above, and the ladder would stop telling a client at p=quarantine what their
    current policy is doing.
    """
    result = result_with(
        dmarc=DmarcResult(record="v=DMARC1; p=quarantine", tags={"p": "quarantine"})
    )
    note = dmarc_rollout("x.test", result)[0].note
    assert "Quarantine already moves failing mail out of the inbox" in note


def test_p_none_in_test_mode_keeps_the_monitor_only_line(weights: Weights) -> None:
    """policy_test_mode reads t alone, so it is True here; the line must not change.

    Test mode is suppressed at p=none in the findings, and the same suppression
    has to hold on the page: p=none asks receivers for nothing, so there is
    nothing for t=y to withhold and nothing to qualify.
    """
    page = one_pager("v=DMARC1; p=none; t=y; rua=mailto:r@example.com", weights)
    assert "monitor only - failing mail is still delivered normally" in page


# ---------------------------------------------------------------------------
# the remove-t=y rung
#
# Measured before this rung existed: a p=reject; t=y domain produced no rollout
# suggestions at all, because the ladder reads p and rua and concluded the
# deployment was finished, and a p=quarantine; t=y domain was told to move to
# p=reject while still not enforcing quarantine - handed a replacement record
# with the t tag silently absent. Removing t=y is the action that turns
# enforcement on, and nothing in the ladder named it.
#
# The generated value is the domain's own record minus one tag. A regenerated
# canonical record would drop whatever else the domain publishes, and the client
# pastes what is printed.
# ---------------------------------------------------------------------------

REMOVE_T_STAGE = "**First - remove the t=y tag"
SIGNING_CAVEAT_LABEL = "**First - remove the t=y tag, and only once DKIM is signing**"
NOT_YET_STAGE = "**Not yet - keep the t=y tag until DKIM is signing**"

# Several tags, deliberately out of the order a generator would emit them in,
# with a size limit and mixed case in a value that has to survive untouched.
MULTITAG_RECORD = (
    "v=DMARC1; fo=1; adkim=s; t=y; rua=mailto:DMARC-Reports@x.test!10m; "
    "sp=quarantine; p=reject; aspf=s; ri=3600"
)


def ladder_page(record: str, weights: Weights, dkim: bool = True) -> str:
    """Render the one-pager for a domain publishing `record`.

    `dkim` puts a usable 2048-bit key on the default selector, which is the
    predicate the enforcing rungs are gated on.
    """
    zone = {
        ("x.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("x.test", "MX"): ["10 mail.x.test"],
        ("mail.x.test", "A"): ["192.0.2.1"],
        ("_dmarc.x.test", "TXT"): [record],
    }
    if dkim:
        zone[("default._domainkey.x.test", "TXT")] = [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]
    return render_markdown(score(check_domain(FakeResolver(zone), "x.test"), weights))


@pytest.mark.parametrize(
    "record,expected_value",
    [
        (
            "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
            "v=DMARC1; p=quarantine; rua=mailto:r@example.com",
        ),
        (
            "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com",
            "v=DMARC1; p=reject; rua=mailto:r@example.com",
        ),
    ],
    ids=["quarantine", "reject"],
)
def test_a_test_mode_domain_is_told_to_remove_the_tag(
    record: str, expected_value: str, weights: Weights
) -> None:
    page = ladder_page(record, weights)
    assert REMOVE_T_STAGE in page
    assert f"Value: {expected_value}" in page


def test_the_remove_t_rung_comes_before_the_escalation_rung(weights: Weights) -> None:
    """A client reading top to bottom enforces quarantine before moving to reject."""
    page = ladder_page("v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com", weights)

    remove = page.index(REMOVE_T_STAGE)
    escalate = page.index("**Next - after 2 weeks of clean reports**")
    assert remove < escalate
    # The existing rung is untouched: same label, same record, same note.
    assert "Value: v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@x.test; fo=1;" in page


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=quarantine; rua=mailto:r@example.com",
        "v=DMARC1; p=quarantine; t=n; rua=mailto:r@example.com",
        "v=DMARC1; p=quarantine; t=maybe; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=n; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=maybe; rua=mailto:r@example.com",
    ],
    ids=[
        "quarantine, no t",
        "quarantine, t=n",
        "quarantine, t=maybe",
        "reject, no t",
        "reject, t=n",
        "reject, t=maybe",
    ],
)
def test_a_domain_not_in_test_mode_gets_no_remove_t_rung(
    record: str, weights: Weights
) -> None:
    assert REMOVE_T_STAGE not in ladder_page(record, weights)


def test_p_none_in_test_mode_gets_no_remove_t_rung(weights: Weights) -> None:
    """t=y at p=none withholds nothing, so there is no enforcement to turn on.

    The rung would tell a monitoring domain to take an action that changes
    nothing about delivery, ahead of the two rungs that do.
    """
    page = ladder_page("v=DMARC1; p=none; t=y; rua=mailto:r@example.com", weights)
    assert REMOVE_T_STAGE not in page
    # The ordinary p=none ladder is still there and still starts at quarantine.
    assert (
        "Value: v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:dmarc@x.test; fo=1;"
        in page
    )


def test_the_generated_record_is_the_domains_own_minus_only_the_t_tag(
    weights: Weights,
) -> None:
    """Every other tag survives byte for byte, in the order it was published."""
    expected = (
        "v=DMARC1; fo=1; adkim=s; rua=mailto:DMARC-Reports@x.test!10m; "
        "sp=quarantine; p=reject; aspf=s; ri=3600"
    )
    # The difference between what was published and what is suggested is exactly
    # the t tag and its separator - nothing reordered, nothing re-cased, the
    # !10m size limit and the capitals in the mailbox intact.
    assert MULTITAG_RECORD.replace("; t=y", "") == expected

    page = ladder_page(MULTITAG_RECORD, weights)
    assert f"Value: {expected}" in page
    assert "t=y" not in page.split("Value: ")[1].splitlines()[0]


def test_without_a_key_the_step_is_inverted_rather_than_caveated(
    weights: Weights,
) -> None:
    """Replaces an earlier test that pinned the caveat-don't-suppress behaviour.

    That behaviour was the bug: a caveated "remove the tag" step is still a step
    whose record removes the tag, and a client who follows the page's first
    instruction publishes it. On an unsigned domain the instruction inverts, so
    the caveated label must be gone rather than merely softened.
    """
    page = ladder_page(
        "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com", weights, dkim=False
    )
    assert NOT_YET_STAGE in page
    assert SIGNING_CAVEAT_LABEL not in page
    assert REMOVE_T_STAGE not in page


def test_the_escalation_rungs_still_qualify_rather_than_suppress(
    weights: Weights,
) -> None:
    """The inversion is confined to the test mode step.

    Whether the escalation rungs should also be withheld from an unsigned domain
    is a live question - the structural sweep below records that they hand over
    enforcing records today - but it is not settled here, and this pins that
    nothing about them moved.
    """
    page = ladder_page(
        "v=DMARC1; p=quarantine; rua=mailto:r@example.com", weights, dkim=False
    )
    assert (
        "**Next - after 2 weeks of clean reports, and only once DKIM is signing**" in page
    )
    assert "Value: v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@x.test; fo=1;" in page
    assert "Do not publish this until the DKIM step below is done" in page


def test_without_a_key_the_not_yet_step_sits_behind_the_dkim_prerequisite(
    weights: Weights,
) -> None:
    """The prerequisite step already fires on any suggested p=quarantine record.

    The "not yet" value on a quarantine domain is the domain's own p=quarantine
    record, so the existing prerequisite block still picks it up and stands in
    front of it. Nothing was added to make that happen; this pins that it does.
    """
    page = ladder_page(
        "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com", weights, dkim=False
    )
    prerequisite = page.index("**Before stage 2 - set up DKIM**")
    not_yet = page.index(NOT_YET_STAGE)
    assert prerequisite < not_yet


# ---------------------------------------------------------------------------
# the inverted step, and the structural guard behind it
#
# Measured before this change: on p=reject; t=y with no key, the page's FIRST
# instruction was to publish the domain's own record minus the t tag. t=y is the
# only thing withholding enforcement on an unsigned domain, so the page was
# telling a client to take the brake off. combo.enforcing_without_dkim did not
# catch it, and cannot: `enforcing` at engine.py:66 reads p alone, so the finding
# already fires on the test mode record and there is no absent-to-present
# transition to detect. The score does not move either - dmarc.policy_test_mode
# carries weight 0. The guard below therefore states the claim structurally.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "record,policy",
    [
        ("v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com", "quarantine"),
        ("v=DMARC1; p=reject; t=y; rua=mailto:r@example.com", "reject"),
    ],
    ids=["quarantine", "reject"],
)
def test_without_a_key_the_page_says_keep_the_tag(
    record: str, policy: str, weights: Weights
) -> None:
    page = ladder_page(record, weights, dkim=False)

    assert NOT_YET_STAGE in page
    assert f"which asks receivers not to apply p={policy}" in page
    assert "leave it as it is until outbound mail is signed" in page
    # The step shows the record already published, so pasting it changes nothing.
    assert f"Value: {record}" in page


@pytest.mark.parametrize(
    "record,policy",
    [
        ("v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com", "quarantine"),
        ("v=DMARC1; p=reject; t=y; rua=mailto:r@example.com", "reject"),
    ],
    ids=["quarantine", "reject"],
)
def test_the_keep_the_tag_step_says_legacy_receivers_enforce_already(
    record: str, policy: str, weights: Weights
) -> None:
    """The positive half of the guard below, which only pins an absence.

    Telling a client to leave t=y alone without saying that a receiver which
    does not implement RFC 9989 enforces the policy regardless invites the
    reading that the tag is holding the line everywhere. It is not, and
    combo.enforcing_without_dkim fires at critical on the same page saying so.
    """
    page = ladder_page(record, weights, dkim=False)

    assert "Receivers that have not implemented RFC 9989 ignore that tag" in page
    assert f"apply p={policy} as published" in page
    assert "some forwarded mail may already be refused" in page


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com",
    ],
    ids=["quarantine", "reject"],
)
def test_without_a_key_no_suggested_record_drops_the_tag(
    record: str, weights: Weights
) -> None:
    """The claim in its strongest form: nowhere on the page, not just in one rung.

    A client copies from anywhere on the page, so it is not enough that the first
    step no longer removes the tag - no suggested value anywhere may be this
    domain's record with the tag gone.
    """
    page = ladder_page(record, weights, dkim=False)
    stripped = strip_test_mode_tag(record)
    values = [
        line[len("Value: ") :] for line in page.splitlines() if line.startswith("Value: ")
    ]
    assert stripped not in values, values


@pytest.mark.parametrize(
    "record,expected_value,policy",
    [
        (
            "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
            "v=DMARC1; p=quarantine; rua=mailto:r@example.com",
            "quarantine",
        ),
        (
            "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com",
            "v=DMARC1; p=reject; rua=mailto:r@example.com",
            "reject",
        ),
    ],
    ids=["quarantine", "reject"],
)
def test_with_a_key_the_remove_t_rung_is_unchanged(
    record: str, expected_value: str, policy: str, weights: Weights
) -> None:
    """The with-a-key form is exactly what it was before the inversion."""
    page = ladder_page(record, weights, dkim=True)
    assert REMOVE_T_STAGE in page
    assert NOT_YET_STAGE not in page
    assert f"Value: {expected_value}" in page
    # The rung's note, which nothing pinned until a mutation swapping the two
    # notes passed the whole suite. Putting the "Not yet" copy here would tell a
    # domain that is already signing to wait until it is signing, and the page
    # would still render, still order correctly, and still carry the right
    # record - so only the note itself catches it.
    assert f"Removing that tag is the step that puts p={policy} into effect" in page
    assert "leave it as it is until outbound mail is signed" not in page
    assert "Receivers that have not implemented RFC 9989" not in page


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=quarantine; rua=mailto:r@example.com",
        "v=DMARC1; p=quarantine; t=n; rua=mailto:r@example.com",
        "v=DMARC1; p=quarantine; t=maybe; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=n; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=maybe; rua=mailto:r@example.com",
        "v=DMARC1; p=none; t=y; rua=mailto:r@example.com",
    ],
    ids=[
        "quarantine, no t",
        "quarantine, t=n",
        "quarantine, t=maybe",
        "reject, no t",
        "reject, t=n",
        "reject, t=maybe",
        "p=none, t=y",
    ],
)
@pytest.mark.parametrize("dkim", [True, False], ids=["with key", "no key"])
def test_neither_step_appears_outside_enforcing_test_mode(
    record: str, dkim: bool, weights: Weights
) -> None:
    page = ladder_page(record, weights, dkim=dkim)
    assert REMOVE_T_STAGE not in page
    assert NOT_YET_STAGE not in page


# -- the structural guard ---------------------------------------------------
#
# Not about t. For a domain state the ladder emits a rung for, publishing that
# rung's record and re-running the assessment must not introduce
# combo.enforcing_without_dkim where it was absent. Driven from the ladder's own
# output, so a rung added later is covered without anyone extending a list.
#
# SCOPE, stated rather than assumed. The sweep was run across every ladder state
# before this change and ten rung/context pairs already violate it, all of them
# escalation rungs handing an enforcing record to an unsigned domain:
#
#   no DMARC record   / no key / Stage 2 (p=quarantine) and Stage 3 (p=reject)
#   invalid p         / no key / Stage 2 (p=quarantine) and Stage 3 (p=reject)
#   p=none, no rua    / no key / Next (p=quarantine)    and Then (p=reject)
#   p=none, with rua  / no key / Next (p=quarantine)    and Then (p=reject)
#   p=none, t=y       / no key / Next (p=quarantine)    and Then (p=reject)
#
# Those rungs are deliberately excluded and deliberately left alone in the
# source: they carry the signing caveat and the "only once DKIM is signing"
# label, and whether a caveat is sufficient there is a separate decision from
# this one. START_STATES is every ladder state that is NOT on that list, which is
# what makes the exclusion visible rather than silent.
#
# A second, sharper assertion sits below it, because the combo criterion is
# vacuous for the case this task is about: on a test mode enforcing record the
# finding is already present, so taking the brake off cannot introduce it.
# ---------------------------------------------------------------------------

START_STATES = [
    ("p=quarantine", "v=DMARC1; p=quarantine; rua=mailto:r@example.com"),
    ("p=quarantine, t=y", "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com"),
    ("p=reject, t=y", "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com"),
    ("p=reject, no rua", "v=DMARC1; p=reject"),
    ("p=reject, pct=20", "v=DMARC1; p=reject; pct=20; rua=mailto:r@example.com"),
]

COMBO = "combo.enforcing_without_dkim"


def assess(record: str, weights: Weights, dkim: bool) -> DomainResult:
    zone = {
        ("x.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("x.test", "MX"): ["10 mail.x.test"],
        ("mail.x.test", "A"): ["192.0.2.1"],
        ("_dmarc.x.test", "TXT"): [record],
    }
    if dkim:
        zone[("default._domainkey.x.test", "TXT")] = [f"v=DKIM1; k=rsa; p={RSA_2048_P}"]
    return score(check_domain(FakeResolver(zone), "x.test"), weights)


@pytest.mark.parametrize("label,record", START_STATES, ids=[s[0] for s in START_STATES])
@pytest.mark.parametrize("dkim", [True, False], ids=["with key", "no key"])
def test_following_a_rung_never_introduces_enforcing_without_dkim(
    label: str, record: str, dkim: bool, weights: Weights
) -> None:
    before = assess(record, weights, dkim)
    had = COMBO in {f.code for f in before.findings}

    for rung in dmarc_rollout("x.test", before):
        after = assess(rung.value, weights, dkim)
        has = COMBO in {f.code for f in after.findings}
        assert not (has and not had), f"{label} / {rung.stage} / {rung.value}"


@pytest.mark.parametrize("label,record", START_STATES, ids=[s[0] for s in START_STATES])
def test_no_rung_offered_to_an_unsigned_domain_removes_its_test_mode_brake(
    label: str, record: str, weights: Weights
) -> None:
    """The assertion the combo criterion above cannot make.

    combo.enforcing_without_dkim reads p alone, so it is already present on a
    test mode enforcing record and cannot be introduced by removing the tag.
    This states the thing directly: for a domain with no usable key, no rung the
    ladder offers may hand back that domain's own record with the t tag gone.
    Driven from dmarc_rollout, so a future rung that does the same is caught.
    """
    before = assess(record, weights, dkim=False)
    if not before.dmarc.policy_test_mode:
        pytest.skip("not in test mode; no brake to remove")

    brake_removed = strip_test_mode_tag(record)
    for rung in dmarc_rollout("x.test", before):
        assert rung.value != brake_removed, f"{label} / {rung.stage}"


def first_suggested_dmarc_value(page: str) -> str | None:
    """The first _dmarc value printed under 'The records to publish'.

    Read off the rendered page rather than out of the suggestion objects,
    because the page is what a client copies from.
    """
    if "### DMARC" not in page:
        return None
    body = page.split("### DMARC", 1)[1].split("### DKIM", 1)[0]
    for line in body.splitlines():
        if line.startswith("Value: v=DMARC1"):
            return line[len("Value: ") :]
    return None


@pytest.mark.parametrize(
    "record",
    [
        "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
        "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com",
    ],
    ids=["quarantine", "reject"],
)
def test_a_client_who_follows_the_first_instruction_keeps_the_brake_on(
    record: str, weights: Weights
) -> None:
    """The construction that decided this task, as a test.

    Read the page's first DMARC record, publish it, re-run the assessment. On an
    unsigned domain the result must still be a domain in test mode: before the
    inversion this step handed over the record with t=y gone, and a client who
    did what the page said stopped withholding enforcement on mail nothing signs.
    """
    before = assess(record, weights, dkim=False)
    page = render_markdown(before)

    published = first_suggested_dmarc_value(page)
    assert published is not None, "no DMARC record suggested at all"

    after = assess(published, weights, dkim=False)

    assert after.dmarc.policy_test_mode, published
    assert "dmarc.policy_test_mode" in {f.code for f in after.findings}
    # Same policy, same brake: following the advice is a no-op on the record.
    assert after.dmarc.record == before.dmarc.record
    assert after.score == before.score


# ---------------------------------------------------------------------------
# no page may credit the t tag with preventing a delivery outcome
#
# The sentence this guard exists for, which shipped in the "Not yet" step:
#
#     "Until outbound mail is signed and the reports show it passing DKIM, that
#      tag is what is keeping this domain's own forwarded mail from being
#      refused."
#
# It is true only for a receiver implementing RFC 9989. A receiver still on
# RFC 7489 treats t as an unknown tag, ignores it, and applies the published
# policy - for that class the tag keeps nothing, and an unsigned domain's
# forwarded mail may already be being refused. The page said so itself four
# inches higher, where combo.enforcing_without_dkim fires at critical, so the
# note contradicted a finding on the same page.
#
# The assertion is on rendered pages rather than on the note constant, so the
# same claim reappearing in some other string is caught too.
# ---------------------------------------------------------------------------

# Verb x outcome, as phrases rather than a regex so a failure names the exact
# wording that reintroduced the claim.
PREVENTION_VERBS = [
    "keeping",
    "keeps",
    "keep",
    "preventing",
    "prevents",
    "prevent",
    "stopping",
    "stops",
    "stop",
]
PREVENTION_OUTCOMES = ["refused", "rejected", "held"]
TAG_PREVENTION_PHRASES = (
    [
        f"{verb} {article}mail from being {outcome}"
        for verb in PREVENTION_VERBS
        for outcome in PREVENTION_OUTCOMES
        for article in ("", "the ", "this ", "your ", "its ")
    ]
    + [f"tag is what is {verb} " for verb in ("keeping", "preventing", "stopping")]
    + [
        "tag prevents",
        "tag stops",
        "tag keeps",
        "t=y prevents",
        "t=y stops",
        "t=y keeps",
        "which prevents mail",
        "from being refused",
        "from being rejected",
        "from being held",
    ]
)

GUARDED_RECORDS = [
    "v=DMARC1; p=quarantine; t=y; rua=mailto:r@example.com",
    "v=DMARC1; p=reject; t=y; rua=mailto:r@example.com",
    "v=DMARC1; p=quarantine; rua=mailto:r@example.com",
    "v=DMARC1; p=reject; rua=mailto:r@example.com",
    "v=DMARC1; p=none; t=y; rua=mailto:r@example.com",
    "v=DMARC1; p=none; rua=mailto:r@example.com",
]


@pytest.mark.parametrize("record", GUARDED_RECORDS, ids=GUARDED_RECORDS)
@pytest.mark.parametrize("dkim", [True, False], ids=["with key", "no key"])
def test_no_page_claims_a_tag_prevents_a_delivery_outcome(
    record: str, dkim: bool, weights: Weights
) -> None:
    page = ladder_page(record, weights, dkim=dkim)
    found = [phrase for phrase in TAG_PREVENTION_PHRASES if phrase in page]
    assert found == [], found


def test_the_guard_catches_the_sentence_it_was_written_for() -> None:
    """The guard's own test. A phrase list that matches nothing is not a guard.

    Without this, deleting a phrase from the list would go unnoticed until the
    claim came back.
    """
    shipped = (
        "Until outbound mail is signed and the reports show it passing DKIM, that "
        "tag is what is keeping this domain's own forwarded mail from being refused."
    )
    assert [p for p in TAG_PREVENTION_PHRASES if p in shipped]
