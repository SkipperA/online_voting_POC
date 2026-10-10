"""The recount a stranger runs, on the files a stranger downloads.

`tools/verify_election.py` imports nothing from `ovpoc`. That is the point
of it: a verifier built out of the implementation would show that the code
agrees with itself, where the claim in Section 6 is that any citizen can
recompute the result from the published artefacts using standard
cryptographic libraries. This exercises that claim, as a program, against a
real election run to its close.

In process rather than over ports: `TestClient` is enough to drive origins
that do not call each other, and the three downloads are exactly what a
browser would have saved.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from ovpoc import keys, rsabssa
from ovpoc.messages import AuthRequest, Ballot, b64, unb64
from service import origins
from service.apps import build_all
from service.state import Deployment

VERIFIER = Path(__file__).resolve().parents[1] / "tools" / "verify_election.py"


def cast(deployment, clients, config_bytes, voter_id: str, selection: int) -> None:
    """One voter, end to end: token request, unblinding, submission."""
    config = json.loads(config_bytes)
    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))

    adhoc = keys.SigningKeyPair.generate()
    blinded, state = rsabssa.blind(token_key, adhoc.public_bytes)

    # The wallet origin reaches the office over HTTP (§5.3), which needs a
    # bound port; the office is called directly here instead. The transport
    # is not what this exercise is about -- the records are.
    wallet = deployment.wallets[voter_id]
    request = AuthRequest(voter_id=voter_id, blinded_key=blinded, wallet_signature=b"")
    request = AuthRequest(voter_id=voter_id, blinded_key=blinded,
                          wallet_signature=wallet.sign(request.signed_payload()))
    issued = deployment.vro.issue_token(request)
    assert issued.blind_signature is not None, issued.outcome
    token = rsabssa.finalize(
        token_key, adhoc.public_bytes, issued.blind_signature, state)

    unsigned = Ballot(selection=selection, adhoc_public_key=adhoc.public_bytes,
                      token=token, vote_signature=b"")
    accepted = clients[origins.EBB].post("/ballots", json={
        "selection": selection,
        "adhoc_public_key": b64(adhoc.public_bytes),
        "token": b64(token),
        "nonce": b64(unsigned.nonce),
        "vote_signature": b64(adhoc.sign(unsigned.signed_payload())),
    }).json()
    assert accepted["accepted"], accepted


@pytest.fixture
def closed_election(tmp_path):
    """A real election, run to the close, with its three files downloaded."""
    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "published")
    clients = {o: TestClient(app) for o, app in build_all(deployment).items()}

    for voter_id in ("HU-1", "HU-2", "HU-3"):
        deployment.enrol(voter_id)

    config_bytes = (tmp_path / "published" / "election.json").read_bytes()
    cast(deployment, clients, config_bytes, "HU-1", 1)
    cast(deployment, clients, config_bytes, "HU-2", 2)
    cast(deployment, clients, config_bytes, "HU-3", 1)

    clients[origins.EBB].post("/close")

    paths = {}
    for name, origin, path in (("election.json", origins.CONFIG, "/election.json"),
                               ("ledger.json", origins.EBB, "/ledger"),
                               ("releases.json", origins.VRO, "/releases")):
        response = clients[origin].get(path)
        assert response.status_code == 200, (name, response.status_code)
        paths[name] = tmp_path / name
        paths[name].write_bytes(response.content)
    return paths


def run_verifier(paths) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(paths["election.json"]),
         str(paths["ledger.json"]), str(paths["releases.json"])],
        capture_output=True, text=True)


def test_a_stranger_can_recompute_the_result_from_the_downloads(closed_election):
    """Every check at E6, from the files alone."""
    result = run_verifier(closed_election)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Every check passed" in result.stdout
    assert "option 1: 2" in result.stdout, "the tally is recomputed, not read"
    assert "option 2: 1" in result.stdout


def test_the_verifier_rejects_a_ledger_whose_records_were_edited(closed_election):
    """Otherwise it would be a reader rather than a verifier."""
    ledger = json.loads(closed_election["ledger.json"].read_bytes())
    ledger["accepted"][0]["record"]["selection"] = 3
    closed_election["ledger.json"].write_text(json.dumps(ledger))

    result = run_verifier(closed_election)
    assert result.returncode == 1
    assert "FAIL" in result.stdout


def test_the_verifier_rejects_a_ledger_checked_against_another_election(
    closed_election, tmp_path
):
    """The keys come from the configuration, so the configuration must match."""
    Deployment.create(bits=2048, num_choices=3, document_root=tmp_path / "other")
    closed_election["election.json"].write_bytes(
        (tmp_path / "other" / "election.json").read_bytes())

    result = run_verifier(closed_election)
    assert result.returncode == 1
    assert "pins the configuration being used" in result.stdout
