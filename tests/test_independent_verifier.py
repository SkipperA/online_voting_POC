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


def test_the_verifier_service_runs_the_same_checks(closed_election, tmp_path):
    """8007 reports what the command line reports, because it is the same code.

    A page that reimplemented the checks would be a second thing to get
    right, and could disagree with the first without anybody noticing.
    """
    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "unused")
    client = TestClient(build_all(deployment)[origins.VERIFIER])

    report = client.post("/check", json={
        "election": closed_election["election.json"].read_text(),
        "ledger": closed_election["ledger.json"].read_text(),
        "releases": closed_election["releases.json"].read_text(),
    }).json()

    assert report["ok"], [c for c in report["checks"] if not c["ok"]]
    assert report["tally"]["options"] == {"1": 2, "2": 1, "3": 0}
    assert report["tally"]["voters"] == 3

    # The election it is checking is not the one this origin belongs to.
    assert report["tally"]["election_id"] == json.loads(
        closed_election["election.json"].read_bytes())["election_id"]


def test_the_verifier_service_reports_a_broken_election_rather_than_refusing(
    closed_election, tmp_path
):
    """A failing check is an answer, not an error."""
    ledger = json.loads(closed_election["ledger.json"].read_bytes())
    ledger["accepted"][0]["record"]["selection"] = 3

    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "unused")
    client = TestClient(build_all(deployment)[origins.VERIFIER])
    response = client.post("/check", json={
        "election": closed_election["election.json"].read_text(),
        "ledger": json.dumps(ledger),
        "releases": closed_election["releases.json"].read_text(),
    })

    assert response.status_code == 200
    report = response.json()
    assert not report["ok"]
    assert any(not c["ok"] for c in report["checks"])


def test_the_verifier_service_hands_out_the_program_it_runs(tmp_path):
    """So the check that rests on nobody can be run somewhere else."""
    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "unused")
    client = TestClient(build_all(deployment)[origins.VERIFIER])

    served = client.get("/verify_election.py")
    assert served.status_code == 200
    assert "attachment" in served.headers["content-disposition"]
    assert served.text == VERIFIER.read_text(encoding="utf-8")
    assert "import ovpoc" not in served.text, "it must stay independent"


def _verifier_client(tmp_path):
    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "unused")
    return TestClient(build_all(deployment)[origins.VERIFIER])


def test_a_file_in_the_wrong_place_is_named_as_such(closed_election, tmp_path):
    """The first person to use this page got a bare KeyError: 'entries'.

    Three files and three slots is three chances to pair them wrongly, and
    an exception from inside the checks says which key was missing rather
    than which file to look at.
    """
    client = _verifier_client(tmp_path)
    response = client.post("/check", json={
        "election": closed_election["election.json"].read_text(),
        "ledger": closed_election["releases.json"].read_text(),   # swapped
        "releases": closed_election["ledger.json"].read_text(),   # swapped
    })

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "ballot box ledger" in detail
    assert "release register" in detail


def test_a_missing_file_says_what_was_expected_and_from_where(
    closed_election, tmp_path
):
    """Not 'entries', but which file and which origin serves it."""
    client = _verifier_client(tmp_path)
    response = client.post("/check", json={
        "election": closed_election["election.json"].read_text(),
        "ledger": closed_election["ledger.json"].read_text(),
        "releases": '{"nothing": true}',
    })

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "release register" in detail
    assert "entries" in detail, "it may say which keys, as long as it says which file"
    assert "office" in detail


def test_something_that_is_not_json_says_so(closed_election, tmp_path):
    client = _verifier_client(tmp_path)
    response = client.post("/check", json={
        "election": "this is not a file",
        "ledger": closed_election["ledger.json"].read_text(),
        "releases": closed_election["releases.json"].read_text(),
    })
    assert response.status_code == 400
    assert "not JSON" in response.json()["detail"]


def test_each_file_is_checked_as_it_is_chosen(live=None):
    """One input per file, and each one validated on arrival.

    Three inputs is the shape a person expects, so the slots are back; what
    must not come back is discovering a mismatch halfway through the
    verification as a missing key. The page names the file at the moment it
    is put in the wrong place, the supervision register included -- which is
    the file that looks like it belongs here and does not.
    """
    static = Path(__file__).resolve().parents[1] / "web" / "verifier" / "static"
    page = (static / "index.html").read_text()
    script = (static / "verifier.js").read_text()

    for slot in ("election", "ledger", "releases"):
        assert f'id="f-{slot}"' in page
        assert f"have-{slot}" in page, "and somewhere to say what arrived"
    assert "function kindOf" in script
    assert "supervision" in script, "the file that looks like it belongs here"


def test_the_downloads_are_named_for_what_they_are(tmp_path):
    """Two files from the office with similar names is how this went wrong.

    `releases-demo-2026.json` and `supervision-demo-2026.json` are
    different artefacts -- one public, one naming citizens -- and the
    second is the one that looks like it belongs in the check.
    """
    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "published")
    clients = {o: TestClient(app) for o, app in build_all(deployment).items()}
    clients[origins.EBB].post("/close")

    expected = {
        (origins.EBB, "/ledger"): "EBB_dump_demo-2026.json",
        (origins.VRO, "/releases"): "VRO_dump_demo-2026.json",
        (origins.SUPERVISOR, "/supervision"): "VRO_supervision_demo-2026.json",
    }
    for (origin, path), name in expected.items():
        disposition = clients[origin].get(path).headers["content-disposition"]
        assert name in disposition, (path, disposition)


def test_the_supervision_register_is_refused_with_its_name(closed_election, tmp_path):
    """Not "missing entries", but which file this is and where it belongs."""
    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "published")
    clients = {o: TestClient(app) for o, app in build_all(deployment).items()}
    clients[origins.EBB].post("/close")
    supervision = clients[origins.SUPERVISOR].get("/supervision").text

    client = _verifier_client(tmp_path / "other")
    response = client.post("/check", json={
        "election": closed_election["election.json"].read_text(),
        "ledger": closed_election["ledger.json"].read_text(),
        "releases": supervision,
    })

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "supervision register" in detail
    assert "/releases" in detail, "and where the right one comes from"
