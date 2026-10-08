"""The election survives a restart; the poll does not.

The durable half is what the setup console authors before the poll opens.
The volatile half is what the poll produces. Getting this the wrong way round
-- minting a key at every startup, as the service did until now -- silently
voids every open page, every saved token request and every issued token, and
makes the pinning story on the voter's page aspirational: a fingerprint that
changes whenever a process restarts is not something anyone could have
pinned.
"""

from __future__ import annotations

import pytest

from service.state import Deployment
from service.store import NoElection


@pytest.fixture
def saved(tmp_path):
    deployment = Deployment.create(
        bits=2048, num_choices=3, document_root=tmp_path / "docs-a"
    )
    deployment.enrol("Kovács Ágnes")
    deployment.enrol("HU-0002")
    deployment.save(tmp_path / "data")
    return deployment, tmp_path


def test_the_key_and_therefore_the_fingerprint_survive(saved):
    original, tmp_path = saved
    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")

    assert restored.config.token_key_fingerprint == original.config.token_key_fingerprint
    assert restored.config.digest_hex() == original.config.digest_hex()
    assert restored.vro.office_public_key == original.vro.office_public_key


def test_the_register_and_the_personas_survive(saved):
    original, tmp_path = saved
    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")

    assert restored.vro.register == original.vro.register
    assert sorted(restored.wallets) == sorted(original.wallets)
    # An accented identifier round-trips: the store is UTF-8 and so is the
    # canonical form everything else is signed over.
    assert "Kovács Ágnes" in restored.vro.register
    assert (restored.wallets["Kovács Ágnes"].public_bytes
            == original.wallets["Kovács Ágnes"].public_bytes)


def test_the_ballot_box_does_not_survive_and_that_is_stated(saved):
    """Not a bug; a scope limit that must not be discovered mid-demonstration."""
    original, tmp_path = saved
    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")

    assert restored.ebb.accepted.entries == []
    assert restored.vro.release_count() == 0


def test_loading_an_absent_election_refuses_rather_than_minting_one(tmp_path):
    with pytest.raises(NoElection, match="no election at"):
        Deployment.load(tmp_path / "nothing-here")


def test_enrolment_is_persisted_as_it_happens(tmp_path):
    """Enrolment is Phase A, so it belongs to the durable half."""
    data = tmp_path / "data"
    first = Deployment.create(bits=2048, num_choices=3,
                              document_root=tmp_path / "docs-a")
    first.data_dir = data
    first.save(data)
    first.enrol("HU-LATE-001")

    restored = Deployment.load(data, document_root=tmp_path / "docs-b")
    assert "HU-LATE-001" in restored.vro.register


def test_the_store_says_what_it_is(tmp_path):
    """Committed with key material in the clear, so it must explain itself.

    The reader gains from seeing exactly what the demo holds on each voter's
    behalf — that is the substitution being made visible rather than hinted
    at. What must not happen is anyone taking it for a deployment artefact.
    """
    import json

    deployment = Deployment.create(bits=2048, num_choices=3,
                                   document_root=tmp_path / "docs")
    deployment.enrol("Kovács Ágnes")
    deployment.save(tmp_path / "data")

    body = json.loads((tmp_path / "data" / "election.store.json").read_text())
    assert "DEMONSTRATION KEY MATERIAL" in body["warning"]
    assert body["wallet_seeds"]["Kovács Ágnes"], "the seed is published on purpose"

    readme = (tmp_path / "data" / "README.md").read_text()
    assert "Committed on purpose" in readme
    assert "lost when the process stops" in readme

    # And it still loads, warning and all.
    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
    assert "Kovács Ágnes" in restored.vro.register


def test_the_publication_cadence_survives_and_is_pinned_by_the_digest(tmp_path):
    """A5 is a configuration act, so it has to reach all three places.

    The published configuration, which the voter app pins; the box, which
    obeys the cadence; and the durable store, so a restart runs the same
    election rather than a differently-timed one.
    """
    deployment = Deployment.create(
        bits=2048, num_choices=3, document_root=tmp_path / "docs-a"
    )
    deployment.data_dir = tmp_path / "data"
    before = deployment.config.digest_hex()

    deployment.set_tally_interval(900)

    assert deployment.config.digest_hex() != before, "the cadence is pinned"
    assert deployment.ebb.tally_interval_seconds == 900

    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
    assert restored.config.tally_interval_seconds == 900
    assert restored.ebb.tally_interval_seconds == 900
    assert restored.config.digest_hex() == deployment.config.digest_hex()


def test_an_election_saved_before_the_cadence_existed_still_loads(tmp_path):
    """A store written at version 1 is not a reason to lose an election.

    The field added at version 2 is optional and its absence means the
    version-1 behaviour, so the older file is read rather than refused --
    and the next save rewrites it at the current version.
    """
    import json

    deployment = Deployment.create(
        bits=2048, num_choices=3, document_root=tmp_path / "docs-a"
    )
    deployment.enrol("Kovács Ágnes")
    deployment.save(tmp_path / "data")

    store_file = tmp_path / "data" / "election.store.json"
    body = json.loads(store_file.read_text(encoding="utf-8"))
    body["store_version"] = 1
    del body["tally_interval_seconds"]
    store_file.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")

    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
    assert restored.ebb.tally_interval_seconds is None
    assert "Kovács Ágnes" in restored.vro.register

    restored.save(tmp_path / "data")
    rewritten = json.loads(store_file.read_text(encoding="utf-8"))
    assert rewritten["store_version"] == 2


def test_a_store_version_from_the_future_is_still_refused(tmp_path):
    """Reading an older shape is not the same as guessing at a newer one."""
    import json

    deployment = Deployment.create(
        bits=2048, num_choices=3, document_root=tmp_path / "docs-a"
    )
    deployment.save(tmp_path / "data")
    store_file = tmp_path / "data" / "election.store.json"
    body = json.loads(store_file.read_text(encoding="utf-8"))
    body["store_version"] = 99
    store_file.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(NoElection, match="store_version 99"):
        Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
