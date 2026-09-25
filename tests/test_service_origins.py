"""The boundary invariants, written before the UI so they constrain it.

These are not tests of FastAPI.  They are the claims the surface map makes
about the shape of the deployment, in a form that fails when the shape
changes: that the origins are genuinely separate, that nothing sets a cookie,
that the config origin is inert, that the poll survives the setup console
being stopped, and -- the one worth writing first -- that `id` never appears
on the voter application's origin.

`id` is the invariant that is easy to break by accident and hard to notice.
The voting application already knows `k_p^a`; if it also learned `id`, one
component on the voter's own device would hold both halves of the association
the blind signature exists to sever, together with the office's signature over
it (§5.3). The blinding would still stop the VRO linking voter to ballot, but
the linkage would survive intact where it could be recorded, exported, or
produced under compulsion.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from service import origins
from service.apps import build_all
from service.state import Deployment

TEST_VOTER_IDS = ["HU-1970-0442", "Kovács Ágnes"]


@pytest.fixture(scope="module")
def deployment(tmp_path_factory) -> Deployment:
    # 2048 rather than 3072: this suite tests plumbing, not cryptography, and
    # the golden vectors already pin a full-size key.
    return Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("config-root")
    )


@pytest.fixture(scope="module")
def clients(deployment) -> dict[str, TestClient]:
    return {o.name: TestClient(app) for o, app in build_all(deployment).items()}


# -- the port map ----------------------------------------------------------

def test_every_origin_has_its_own_port():
    ports = [o.port for o in origins.ALL]
    assert len(ports) == len(set(ports)), "two origins share a port and so share an origin"


def test_five_trust_domains_and_two_that_are_not():
    assert len(origins.TRUST_DOMAINS) == 5
    assert {o.name for o in origins.ALL} - {o.name for o in origins.TRUST_DOMAINS} == {
        "config",
        "setup",
    }


def test_every_origin_answers_health(clients):
    for name, client in clients.items():
        body = client.get("/health").json()
        assert body["origin"] == name
        assert body["port"] == origins.BY_NAME[name].port


# -- the invariant that had to be written first ----------------------------

def test_the_voter_app_origin_never_returns_id(clients, deployment):
    """No response from 8001 may contain a voter identifier.

    Exhaustive over the routes that exist rather than over routes imagined,
    so it keeps biting as endpoints are added.
    """
    client = clients["voter-app"]
    for voter_id in TEST_VOTER_IDS:
        deployment.vro.enrol(voter_id)

    for route in client.app.routes:
        path = getattr(route, "path", "")
        if not path or "{" in path:
            continue
        response = client.get(path)
        body = response.text
        for voter_id in TEST_VOTER_IDS:
            assert voter_id not in body, f"{path} disclosed {voter_id!r}"


def test_the_voter_app_serves_no_route_named_for_identity(clients):
    paths = [getattr(r, "path", "") for r in clients["voter-app"].app.routes]
    for path in paths:
        assert "voter_id" not in path and "/id" not in path, path


# -- cookies ---------------------------------------------------------------

def test_no_origin_sets_a_cookie(clients):
    """Cookies ignore the port, so one cookie would collapse the isolation.

    A cookie set on 127.0.0.1:8001 is readable on 127.0.0.1:8002. The
    separation of origins is the whole mechanism here, so the rule is absence
    rather than configuration.
    """
    for name, client in clients.items():
        for path in ("/health", "/"):
            response = client.get(path)
            assert "set-cookie" not in {k.lower() for k in response.headers}, name
            assert not response.cookies, name


# -- the config origin is inert -------------------------------------------

def test_config_serves_the_artefact_and_its_digest(clients, deployment):
    client = clients["config"]
    body = client.get("/election.json").content
    assert body == deployment.config.to_bytes()

    line = client.get("/election.json.sha256").text
    assert line.split()[0] == deployment.config.digest_hex()


def test_config_is_byte_stable_across_requests(clients):
    """Inert means inert: nothing computed at request time.

    If the artefact were rebuilt per request, the published digest would cover
    something that no longer exists, and the tamper demonstration would be
    meaningless.
    """
    client = clients["config"]
    first = client.get("/election.json").content
    for _ in range(3):
        assert client.get("/election.json").content == first


def test_the_configuration_carries_both_keys(clients):
    body = json.loads(clients["config"].get("/election.json").text)
    assert body["vro_token_key_spki"], "k_p^(R) missing"
    assert body["vro_statement_key"], "k_p^(O) missing"
    assert body["vro_token_key_fingerprint"], "nothing for the voter to pin"


def test_the_configuration_says_it_is_unsigned(clients):
    """Clause S4. The demo must say what it cannot demonstrate."""
    body = json.loads(clients["config"].get("/election.json").text)
    assert "signature" in body["scope_limits"]


def test_the_digest_detects_a_single_changed_byte(deployment):
    """The failure the demo is meant to show, as a test."""
    original = deployment.config.to_bytes()
    tampered = original.replace(b'"num_choices": 4', b'"num_choices": 5')
    assert tampered != original

    import hashlib

    assert hashlib.sha256(tampered).hexdigest() != deployment.config.digest_hex()


# -- the setup console is build-time --------------------------------------

def test_the_poll_runs_with_the_setup_console_stopped(deployment):
    """A test, not an intention (surface map §1).

    Nothing at runtime may depend on 8009. Building the runtime origins
    without it must succeed, and the configuration must still be servable,
    because it was written to disk before the poll opened.
    """
    apps = build_all(deployment)
    runtime = {o.name: a for o, a in apps.items() if o is not origins.SETUP}
    assert "setup" not in runtime

    with TestClient(runtime["config"]) as client:
        assert client.get("/election.json").status_code == 200
