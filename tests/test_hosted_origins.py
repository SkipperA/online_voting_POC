"""Addressing the origins by hostname instead of by port.

The ports do not go away -- the processes still listen on them and a
proxy reaches them there. What changes is how each origin addresses its
neighbours and how it recognises itself, and those must change together:
an allowance written in ports while the pages are served from hostnames
is an allowance for nothing.
"""

from __future__ import annotations

import importlib
import pathlib

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


# --------------------------------------------------------------------------
# A setting the deployment does not deliver is a setting that does nothing
# --------------------------------------------------------------------------

#: Read by the service and deliberately not delivered to the container.
#: `OVPOC_PORT_OFFSET` separates two instances on one laptop; a deployment
#: separates them by hostname and has no use for it.
#:
#: `OVPOC_CONFIG_ORIGIN` is *not* in here, and the stale check below is
#: why: it is a property on `window` that `service/apps.py` writes into
#: every page, not a variable anything reads, so listing it would have
#: been an exception explaining nothing.
NOT_DEPLOYED = {"OVPOC_PORT_OFFSET"}


def test_every_variable_the_service_reads_is_delivered_by_the_deployment():
    """`deploy/.env` feeds Compose's interpolation and nothing else.

    A variable set there and absent from `compose.yaml`'s `environment:`
    block never reaches the office: the operator reads it as
    configuration and the process never sees it, so the setting silently
    does nothing and the symptom is the feature simply not working.
    That is how `OVPOC_OPEN_ENROLMENT` shipped -- documented in the
    README, written into `.env` on a server, and delivered nowhere.

    Either channel counts, because the Dockerfile is a deployment
    statement too: `OVPOC_BIND` and `OVPOC_REVISION` are set there and
    have no business in the compose file.
    """
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    read = set()
    for path in sorted((root / "service").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        read |= set(re.findall(r'environ\.get\(\s*"(OVPOC_[A-Z_]+)"', source))
        read |= set(re.findall(r'environ\[\s*"(OVPOC_[A-Z_]+)"', source))
        # `service/state.py` names its own in a constant, so that the
        # variable and the code that reads it cannot drift apart.
        read |= set(re.findall(r'=\s*"(OVPOC_[A-Z_]+)"', source))

    delivered = (root / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    delivered += (root / "deploy" / "Dockerfile").read_text(encoding="utf-8")

    missing = sorted(v for v in read - NOT_DEPLOYED if v not in delivered)
    assert not missing, (
        "the service reads these and the deployment delivers none of them: "
        + ", ".join(missing)
        + " — add them to deploy/compose.yaml's environment block, or to "
        "NOT_DEPLOYED with the reason")

    # And the exceptions must still be real, or the list becomes a place
    # to hide a variable rather than a place to explain one.
    stale = sorted(NOT_DEPLOYED - read)
    assert not stale, f"NOT_DEPLOYED names variables nothing reads: {stale}"
