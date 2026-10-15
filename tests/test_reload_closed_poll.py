"""A finished poll, served again from its own record.

Read-only: the box comes back shut, so nothing resumes and no chain
continues. Clause A7 is unchanged for a poll interrupted while open --
that state is never written, and is still lost.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from service.api import POLL_STATE
from service.apps import build_all
from service.state import Deployment


@pytest.fixture
def finished(tmp_path):
    """An election run to the close, with ballots and a rejected submission."""
    import sys
    sys.path.insert(0, "tests")
    deployment = Deployment.create(election_id="first", bits=2048, num_choices=3,
                                   document_root=tmp_path / "docs")
    deployment.data_dir = tmp_path / "data"
    deployment.save(deployment.data_dir)
    clients = {o.name: TestClient(a) for o, a in build_all(deployment).items()}
    clients["ebb"].post("/open")
    clients["setup"].post("/voters", json={"voter_id": "HU-WALLET-000"})
    # A submission the box will reject, so both ledgers have content.
    clients["ebb"].post("/ballots", json={"selection": 1, "adhoc_public_key": "AA",
                                          "token": "AA", "nonce": "AA",
                                          "vote_signature": "AA"})
    clients["ebb"].post("/close")
    return deployment, tmp_path


def reloaded(tmp_path, suffix="b"):
    return Deployment.load(tmp_path / "data", document_root=tmp_path / f"docs-{suffix}")


def test_the_close_writes_the_poll_beside_the_keys(finished):
    deployment, tmp_path = finished
    state = deployment.data_folder / POLL_STATE

    assert state.exists()
    # Beside the keys, not inside `closed/`: it carries the office's
    # openings and the citizens' signed requests, and `closed/` is the
    # folder somebody will zip and send.
    assert not (deployment.data_folder / "closed" / POLL_STATE).exists()
    body = json.loads(state.read_text())
    assert body["election_id"] == "first"
    assert "openings" in body["office"]


def test_the_poll_comes_back_shut(finished):
    _, tmp_path = finished
    restored = reloaded(tmp_path)

    view = restored.ebb.published_view()
    assert view["phase"] == "closed"
    assert "records" in view            # the close discloses them
    assert [a["phase"] for a in view["acts"]] == ["opened", "closed"]


def test_the_records_and_the_chain_come_back(finished):
    deployment, tmp_path = finished
    before = deployment.ebb.published_view()

    after = reloaded(tmp_path).ebb.published_view()

    assert after["records"] == before["records"]
    assert after["heads"] == before["heads"]
    assert after["head_signatures"] == before["head_signatures"]


def test_the_office_register_comes_back_with_its_openings(finished):
    deployment, tmp_path = finished
    before = deployment.vro.stored_state()

    after = reloaded(tmp_path).vro.stored_state()

    assert after == before
    # Including the download counter: assembling the archive must not
    # record a supervisor who never read anything.
    assert after["supervisor_downloads"] == 0


def test_an_altered_ledger_is_refused_rather_than_served(finished):
    """The verifier's own check, performed before anything is displayed."""
    deployment, tmp_path = finished
    state = deployment.data_folder / POLL_STATE
    body = json.loads(state.read_text())
    body["box"]["rejected"][0]["selection"] = 999
    state.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(ValueError, match="do not reproduce the heads"):
        reloaded(tmp_path)


def test_an_altered_release_register_is_refused(finished):
    deployment, tmp_path = finished
    state = deployment.data_folder / POLL_STATE
    body = json.loads(state.read_text())
    body["office"]["releases"].append({"commitment": "AA"})
    state.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(ValueError, match="do not reproduce the head"):
        reloaded(tmp_path)


def test_an_election_with_no_finished_poll_loads_as_before(tmp_path):
    deployment = Deployment.create(election_id="first", bits=2048, num_choices=3,
                                   document_root=tmp_path / "docs")
    deployment.data_dir = tmp_path / "data"
    deployment.save(deployment.data_dir)

    restored = reloaded(tmp_path)
    assert restored.ebb.published_view()["phase"] == "not opened"
    assert restored.vro.release_count() == 0


def test_a_reloaded_poll_still_serves_its_dumps(finished):
    """What the reload is for: the surfaces work on a past election."""
    deployment, tmp_path = finished
    restored = reloaded(tmp_path)
    clients = {o.name: TestClient(a) for o, a in build_all(restored).items()}

    ledger = clients["ebb"].get("/ledger")
    releases = clients["vro"].get("/releases")
    assert ledger.status_code == 200 and releases.status_code == 200
    assert ledger.json()["accepted"] == json.loads(
        (deployment.data_folder / "closed" / "ledger.json").read_text())["accepted"]
