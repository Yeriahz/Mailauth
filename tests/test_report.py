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
