"""The demo path, end to end, through the HTTP surfaces.

`demo_svr.py` needs a running process and two terminals, so CI cannot run it.
This covers the same path through `TestClient`, which exercises the real
applications and the real `ovpoc` objects without binding a port.

What it is actually testing is not that the protocol works -- `test_end_to_end`
already does that in-process -- but that the *split across origins* did not
break it, and that the boundaries survive a complete run rather than only an
empty one.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot, b64, unb64
from service import origins
from service.apps import build_all
from service.state import Deployment

VOTERS = {"Anna": "HU-WALLET-000", "Béla": "HU-WALLET-001", "Csilla": "Kovács Ágnes"}


@pytest.fixture
def clients(tmp_path):
    deployment = Deployment.create(
        bits=2048, num_choices=3, document_root=tmp_path / "config"
    )
    apps = build_all(deployment)
    return deployment, {o.name: TestClient(a) for o, a in apps.items()}


def obtain_token(clients, voter_id, token_key):
    """B1–B18 across three origins, as the voter application would."""
    _, c = clients
    adhoc = keys.SigningKeyPair.generate()
    blinded, state = rsabssa.blind(token_key, adhoc.public_bytes)

    c["wallet"].post("/session", json={"voter_id": voter_id}).raise_for_status()
    outcome = c["wallet"].post(
        "/requests", json={"blinded_key": b64(blinded)}
    ).json()["outcome"]

    reply = c["vro"].get(f"/token-replies/{b64(blinded)}")
    assert reply.status_code == 200, outcome
    token = rsabssa.finalize(
        token_key, adhoc.public_bytes, unb64(reply.json()["blind_signature"]), state
    )
    assert rsabssa.verify(token_key, adhoc.public_bytes, token)
    return adhoc, token


def cast(clients, adhoc, token, selection):
    _, c = clients
    unsigned = Ballot(
        selection=selection, adhoc_public_key=adhoc.public_bytes, token=token,
        vote_signature=b"",
    )
    return c["ebb"].post("/ballots", json={
        "selection": selection,
        "adhoc_public_key": b64(adhoc.public_bytes),
        "token": b64(token),
        "vote_signature": b64(adhoc.sign(unsigned.signed_payload())),
    }).json()


def test_the_whole_path_across_origins(clients):
    deployment, c = clients
    config = c["config"].get("/election.json").json()
    from cryptography.hazmat.primitives import serialization

    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))

    for voter_id in VOTERS.values():
        c["setup"].post("/voters", json={"voter_id": voter_id}).raise_for_status()

    holders = {}
    for name, voter_id in VOTERS.items():
        adhoc, token = obtain_token((deployment, c), voter_id, token_key)
        holders[name] = adhoc
        assert cast((deployment, c), adhoc, token, 1)["accepted"]

    c["ebb"].post("/close").raise_for_status()
    view = c["ebb"].get("/published").json()
    assert len(view["records"]["accepted"]) == 3
    assert c["ebb"].get("/tally").json()["counts"]["1"] == 3


def test_the_blinded_value_is_the_only_credential_for_the_reply(clients):
    """B16: unguessable, and nothing else is invented to protect it."""
    deployment, c = clients
    c["setup"].post("/voters", json={"voter_id": "HU-WALLET-000"})
    assert c["vro"].get(f"/token-replies/{b64(b'not-a-real-c')}").status_code == 404


def test_a_second_token_is_refused_for_the_same_voter(clients):
    """Equality, enforced in `ovpoc`, merely reported here."""
    deployment, c = clients
    from cryptography.hazmat.primitives import serialization

    config = c["config"].get("/election.json").json()
    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))
    c["setup"].post("/voters", json={"voter_id": "HU-WALLET-000"})
    obtain_token((deployment, c), "HU-WALLET-000", token_key)

    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    outcome = c["wallet"].post(
        "/requests", json={"blinded_key": b64(blinded)}
    ).json()["outcome"]
    assert outcome == "TOKEN_ALREADY_ISSUED"
    assert c["vro"].get(f"/token-replies/{b64(blinded)}").status_code == 404


def test_no_origin_discloses_an_id_during_a_complete_run(clients):
    """The invariant, checked after traffic rather than on an empty server.

    An accented identifier is used deliberately: it is the case that would
    survive an ASCII-only test unnoticed.
    """
    deployment, c = clients
    from cryptography.hazmat.primitives import serialization

    config = c["config"].get("/election.json").json()
    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))
    voter_id = "Kovács Ágnes"
    c["setup"].post("/voters", json={"voter_id": voter_id})
    adhoc, token = obtain_token((deployment, c), voter_id, token_key)
    cast((deployment, c), adhoc, token, 1)

    # Every GET the voter application and the ballot box expose, after a full
    # run, must be free of the identifier.
    for name in ("voter-app", "ebb"):
        for route in c[name].app.routes:
            path = getattr(route, "path", "")
            if not path or "{" in path:
                continue
            assert voter_id not in c[name].get(path).text, f"{name}{path}"

    record = c["ebb"].get(f"/ballots/{b64(adhoc.public_bytes)}").text
    assert voter_id not in record

    log = c["vro"].get("/release-log").text
    assert voter_id not in log, "the release register must publish commitments only"


def test_the_wallet_does_not_echo_the_id_it_holds(clients):
    """8002 knows the id. That is not a reason to return it to a caller."""
    deployment, c = clients
    voter_id = "Kovács Ágnes"
    c["setup"].post("/voters", json={"voter_id": voter_id})
    body = c["wallet"].post("/session", json={"voter_id": voter_id}).text
    assert voter_id not in body

    # The one exception is deliberate and goes to the checker, not the app:
    # D1 needs [id, sig(id)], and §3.7 permits the wallet to produce it.
    credentials = c["wallet"].post("/release-query-credentials").json()
    assert credentials["voter_id"] == voter_id


def test_the_tally_is_refused_while_open_when_no_running_tally_is_configured(clients):
    """The operator gets no privileged early sight; neither does anyone."""
    deployment, c = clients
    assert deployment.ebb.tally_interval is None
    assert c["ebb"].get("/tally").status_code == 409
