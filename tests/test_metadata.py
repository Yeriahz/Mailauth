"""
tests/test_metadata.py - packaging metadata agrees with the package itself.

Two copies of the same facts exist by necessity: pyproject.toml is what the
build backend reads, and the dunders are what a caller reads at runtime. Nothing
keeps them in step on its own, so this does.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import mailauth

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def project() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]


def test_the_version_matches() -> None:
    assert project()["version"] == mailauth.__version__


def test_the_author_and_email_match() -> None:
    author = project()["authors"][0]
    assert author["name"] == mailauth.__author__
    assert author["email"] == mailauth.__email__


def test_the_maintainer_matches_the_author() -> None:
    metadata = project()
    assert metadata["maintainers"] == metadata["authors"]


def test_the_repository_url_matches() -> None:
    assert project()["urls"]["Repository"] == mailauth.__url__


def test_every_declared_url_is_https() -> None:
    for name, url in project()["urls"].items():
        assert url.startswith("https://"), f"{name} is not https: {url}"


def test_the_user_agent_is_derived_from_the_version() -> None:
    """The only string this tool sends to a server outside the user's control.

    Asserted against the derived value rather than a literal: a test that
    hardcodes the current number has to be edited every release, which is
    exactly how the previous one rotted to "mailauth/2.0" against a 1.0.0
    package.
    """
    from mailauth.checks.extras import USER_AGENT

    assert USER_AGENT.startswith(f"mailauth/{mailauth.__version__}")
    assert mailauth.__version__ in USER_AGENT


def released_versions() -> list[str]:
    """Version headings in CHANGELOG.md, newest first, ignoring Unreleased."""
    import re

    text = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text(
        encoding="utf-8"
    )
    return [
        m.group(1)
        for m in re.finditer(r"^##\s*\[([^\]]+)\]", text, re.MULTILINE)
        if m.group(1).lower() != "unreleased"
    ]


def test_the_changelog_documents_the_current_version() -> None:
    """A finding code is public interface, so a release that adds one is recorded.

    The version is parsed from the file rather than written here, so this test
    does not need editing at release time.
    """
    versions = released_versions()
    assert versions, "CHANGELOG.md has no released version heading"
    assert versions[0] == mailauth.__version__, (
        f"newest CHANGELOG entry is {versions[0]!r} but __version__ is "
        f"{mailauth.__version__!r}; a release that changes behaviour needs both"
    )
