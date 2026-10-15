"""One directory per election, and a pointer saying which is current.

The console can mint over a running election, which is what it is for. It
must not mint over an election's *keys*: a ledger downloaded from a poll
that has been superseded is checkable only against the configuration it was
published under, and that configuration cannot be rebuilt once the token
key is gone. So minting allocates a new directory and moves the pointer,
and nothing already on disk is written over.

2048-bit moduli throughout; the size is not what these are about.
"""

from __future__ import annotations

import pytest

from service.state import Deployment
from service.store import NoElection, current, point_at


def minted(parent, document_root, election_id, **kwargs):
    made = Deployment.create(election_id=election_id, bits=2048,
                             document_root=document_root, **kwargs)
    made.data_dir = parent
    made.save(parent)
    return made


def test_each_election_gets_its_own_directory(tmp_path):
    data = tmp_path / "data"
    deployment = minted(data, tmp_path / "docs", "first", num_choices=3)
    first = deployment.data_folder

    deployment.mint(election_id="időközi-2027", num_choices=5, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")
    second = deployment.data_folder

    assert first != second
    assert first.exists() and second.exists()
    # Numbered as well as named, and the name is flattened to ASCII -- the
    # identifier itself is kept verbatim inside.
    assert first.name == "001-first" and second.name == "002-idokozi-2027"
    assert current(data) == second


def test_the_superseded_election_keeps_its_keys(tmp_path):
    data = tmp_path / "data"
    deployment = minted(data, tmp_path / "docs", "first", num_choices=3)
    first = deployment.data_folder
    fingerprint = deployment.config.token_key_fingerprint

    deployment.mint(election_id="second", num_choices=3, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")
    assert deployment.config.token_key_fingerprint != fingerprint

    # And the first one can be served again, which is what makes a ledger
    # downloaded from it checkable rather than merely kept.
    point_at(data, first)
    restored = Deployment.load(data, document_root=tmp_path / "docs-b")
    assert restored.config.token_key_fingerprint == fingerprint
    assert restored.config.election_id == "first"


def test_two_elections_of_the_same_name_do_not_collide(tmp_path):
    """The console will mint `demo-2026` over `demo-2026` without blinking."""
    data = tmp_path / "data"
    deployment = minted(data, tmp_path / "docs", "demo-2026", num_choices=3)
    first, fingerprint = deployment.data_folder, deployment.config.token_key_fingerprint

    deployment.mint(election_id="demo-2026", num_choices=3, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")

    assert deployment.data_folder != first
    point_at(data, first)
    assert (Deployment.load(data, document_root=tmp_path / "docs-b")
            .config.token_key_fingerprint == fingerprint)


def test_an_ordinary_save_writes_back_to_its_own_directory(tmp_path):
    """Correcting the schedule is not a new election and gets no directory."""
    data = tmp_path / "data"
    deployment = minted(data, tmp_path / "docs", "first", num_choices=3)
    folder = deployment.data_folder

    deployment.set_schedule("2027-03-04T06:00:00Z", "2027-03-04T22:00:00Z")

    assert deployment.data_folder == folder
    assert [d.name for d in sorted(data.iterdir()) if d.is_dir()] == [folder.name]


def test_the_single_election_layout_still_loads(tmp_path):
    """What a checkout of this repository has in `election-data/`.

    Read where it lies rather than migrated: moving a committed directory
    out from under a checkout is not something a start-up should do on its
    own initiative.
    """
    data = tmp_path / "data"
    legacy = Deployment.create(election_id="first", bits=2048, num_choices=3,
                               document_root=tmp_path / "docs")
    legacy.data_folder = data           # the layout that came before
    legacy.save(data)
    assert (data / "election.store.json").exists()
    assert not (data / "current").exists()

    restored = Deployment.load(data, document_root=tmp_path / "docs-b")
    assert restored.config.election_id == "first"
    # A save puts it back where it was found, not into a new directory.
    restored.set_schedule("2027-03-04T06:00:00Z", "2027-03-04T22:00:00Z")
    assert restored.data_folder == data


def test_a_pointer_naming_nothing_refuses(tmp_path):
    data = tmp_path / "data"
    minted(data, tmp_path / "docs", "first", num_choices=3)
    (data / "current").write_text("003-does-not-exist\n", encoding="utf-8")

    with pytest.raises(NoElection, match="holds no election"):
        Deployment.load(data, document_root=tmp_path / "docs-b")
