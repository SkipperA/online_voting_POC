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
