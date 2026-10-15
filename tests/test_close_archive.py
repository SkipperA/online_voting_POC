"""The close writes the record a verifier needs, beside the election's keys.

Not a durable ballot box -- the registry is still in memory and clause A7
still holds for a poll in progress. What this removes is the window: the
three artefacts used to be reachable only between the close and the next
restart, so an election's evidence depended on somebody having clicked
three download buttons in that interval.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from service.api import CLOSED, canonical_bytes, ledger_dump, releases_dump
from service.apps import build_all
from service.state import Deployment


def durable(tmp_path, **kwargs):
    made = Deployment.create(bits=2048, num_choices=3,
                             document_root=tmp_path / "docs", **kwargs)
    made.data_dir = tmp_path / "data"
    made.save(made.data_dir)
    return made, {o.name: TestClient(a) for o, a in build_all(made).items()}


def test_the_close_writes_the_three_files(tmp_path):
    deployment, clients = durable(tmp_path, election_id="first")
    clients["ebb"].post("/open")

    body = clients["ebb"].post("/close").json()
    folder = deployment.data_folder / CLOSED

    assert body["archived"] == str(folder)
    assert sorted(f.name for f in folder.iterdir()) == [
        "README.md", "election.json", "ledger.json", "releases.json"]


def test_the_written_bytes_are_the_bytes_the_endpoints_serve(tmp_path):
    """A second rendering would hash to something the dumps do not name."""
    deployment, clients = durable(tmp_path, election_id="first")
    clients["ebb"].post("/open")
    clients["ebb"].post("/close")
    folder = deployment.data_folder / CLOSED

    assert (folder / "election.json").read_bytes() == deployment.config.to_bytes()
    assert (folder / "ledger.json").read_bytes() == canonical_bytes(ledger_dump(deployment))
    assert (folder / "releases.json").read_bytes() == canonical_bytes(releases_dump(deployment))
    # And the configuration on disk is the one the dumps pin.
    assert json.loads((folder / "ledger.json").read_text())["configuration_digest"] \
        == deployment.config.digest_hex()


def test_the_record_survives_the_election_being_superseded(tmp_path):
    """The point of the whole arrangement."""
    deployment, clients = durable(tmp_path, election_id="first")
    clients["ebb"].post("/open")
    clients["ebb"].post("/close")
    kept = deployment.data_folder / CLOSED

    deployment.mint(election_id="second", num_choices=3, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")

    assert deployment.data_folder / CLOSED != kept
    assert (kept / "ledger.json").exists()
    assert json.loads((kept / "election.json").read_text())["election_id"] == "first"


def test_a_later_close_does_not_overwrite_an_earlier_record(tmp_path):
    """Re-serving a past election with `--election` must not erase its poll."""
    deployment, clients = durable(tmp_path, election_id="first")
    clients["ebb"].post("/open")
    clients["ebb"].post("/close")
    recorded = (deployment.data_folder / CLOSED / "ledger.json").read_bytes()

    # The same election served again: a fresh, empty box over the same keys.
    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
    again = {o.name: TestClient(a) for o, a in build_all(restored).items()}
    again["ebb"].post("/open")
    body = again["ebb"].post("/close").json()

    assert body["archived"] is None
    assert (restored.data_folder / CLOSED / "ledger.json").read_bytes() == recorded


def test_an_ephemeral_run_writes_nothing(tmp_path):
    deployment = Deployment.create(election_id="first", bits=2048, num_choices=3,
                                   document_root=tmp_path / "docs")
    clients = {o.name: TestClient(a) for o, a in build_all(deployment).items()}
    clients["ebb"].post("/open")

    assert clients["ebb"].post("/close").json()["archived"] is None


def test_the_written_record_passes_the_independent_verifier(tmp_path):
    """Checked by the tool itself, not by this test's idea of the format."""
    import importlib.util

    deployment, clients = durable(tmp_path, election_id="first")
    clients["ebb"].post("/open")
    clients["ebb"].post("/close")
    folder = deployment.data_folder / CLOSED

    spec = importlib.util.spec_from_file_location(
        "verifier", __import__("pathlib").Path(__file__).parents[1]
        / "tools" / "verify_election.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    report = verifier.run_checks(
        (folder / "election.json").read_bytes(),
        (folder / "ledger.json").read_bytes(),
        (folder / "releases.json").read_bytes(),
    )
    failed = [c for c in report.checks if not c["ok"]]
    assert not failed, failed
    assert report.checks, "the verifier ran no checks at all"
