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
