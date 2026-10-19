"""Addressing the origins by hostname instead of by port.

The ports do not go away -- the processes still listen on them and a
proxy reaches them there. What changes is how each origin addresses its
neighbours and how it recognises itself, and those must change together:
an allowance written in ports while the pages are served from hostnames
is an allowance for nothing.
"""

from __future__ import annotations

import importlib

import pytest

import service.origins as origins


@pytest.fixture
def hosted(monkeypatch):
    """The module re-read with a domain set, then put back as it was."""
    monkeypatch.setenv("OVPOC_DOMAIN", "diw.hu")
    importlib.reload(origins)
    yield origins
    monkeypatch.delenv("OVPOC_DOMAIN", raising=False)
    importlib.reload(origins)


def test_a_laptop_is_unchanged(monkeypatch):
    monkeypatch.delenv("OVPOC_DOMAIN", raising=False)
    importlib.reload(origins)
    assert origins.CHECKER.url == "http://127.0.0.1:8005"
    assert origins.CHECKER.hostname is None
    assert origins.CHECKER.matches("http://localhost:8005")


def test_each_origin_takes_its_own_hostname(hosted):
    assert hosted.CHECKER.url == "https://checker.diw.hu"
    assert hosted.EBB.url == "https://ebb.diw.hu"
    # `voter-app` is the origin's name; `voter` is what an audience reads.
    assert hosted.VOTER_APP.url == "https://voter.diw.hu"
    assert len({o.hostname for o in hosted.ALL}) == len(hosted.ALL)


def test_hosted_origins_are_https(hosted):
    """Not cosmetic: `crypto.subtle` is unavailable outside a secure
    context, so over plain HTTP the browser-side checks cannot run."""
    assert all(o.url.startswith("https://") for o in hosted.ALL)


def test_the_proxy_does_not_collapse_the_surfaces(hosted):
    """Every origin arrives from the proxy on 443.

    Matching by port there would make all eight the same surface, so the
    cross-origin allowances would admit every page to every endpoint --
    the isolation becoming the diagram the module docstring warns about.
    """
    assert hosted.CHECKER.matches("https://checker.diw.hu")
    assert hosted.CHECKER.matches("https://checker.diw.hu:443")
    assert not hosted.CHECKER.matches("https://ebb.diw.hu")
    assert not hosted.CHECKER.matches("https://checker.diw.hu.attacker.test")
    for other in hosted.ALL:
        if other is not hosted.CHECKER:
            assert not other.matches("https://checker.diw.hu")


def test_a_bare_port_no_longer_matches_under_a_domain(hosted):
    """The stage-1 form of the check must not keep working by accident."""
    assert not hosted.CHECKER.matches("http://127.0.0.1:8005")
