"""What the ballot asks, and where the answer is allowed to travel.

The names belong in `election.json`, which means they are inside the digest
every client pins and every surface watches. That is the reason to put them
there rather than anywhere else, and it is also the whole of the constraint:
a name is a thing readers see, never a thing the system decides by. So these
tests are mostly about where a name is *not*.

Five places it must not reach, each for its own reason:

* the ledger and the release register, because a verifier recomputes those
  and a recount that depended on a word would be a recount nobody else could
  run;
* the token-request document, because `pdfrequest` renders ASCII with
  standard-14 fonts and no embedded font, deliberately -- a document that
  silently renders *Előválasztás* as *Elöválasztás* is the dishonest
  rendering that module exists to prevent;
* the ballot box's acceptance, which turns on `num_choices` and has never
  heard of a name;
* the protest codes, which the system records and must never interpret;
* and the office, which issues a token against a register of identifiers and
  has no business knowing what anyone is choosing between.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from ovpoc import pdfrequest, rsabssa
from ovpoc.messages import canonical_bytes
from ovpoc.voter import Voter
from service import origins
from service.apps import build_all
# The verifier, reached the one way `service/api.py` reaches it. It imports
# nothing from this project, which is the point of it; loading it twice by
# two routes would be two things to keep in step.
from service.api import ledger_dump, releases_dump, run_checks
from service.state import Deployment

TEST_BITS = 2048

#: Accented, CJK and astral-plane, the three cases `tests/vectors/` already
#: pins for canonical JSON. A ballot is the most likely place in this system
#: for a non-ASCII string to be authored by hand, so the agreement the whole
#: wire contract rests on is exercised here at the same three widths.
AWKWARD = ["Kovács Ágnes", "日本語の候補", "𝔄stral Example", "Plain Ascii"]


@pytest.fixture
def deployment(tmp_path):
    return Deployment.create(
        bits=TEST_BITS, document_root=tmp_path / "config",
        election_id="wording-2026", num_choices=4,
        question="Who should the representative be?", options=AWKWARD)


def vote(deployment, voter_id: str, selection: int) -> None:
    """One citizen, through the real objects: enrol, token, unblind, cast."""
    deployment.enrol(voter_id)
    voter = Voter(voter_id, deployment.wallets[voter_id],
                  deployment.vro.public_key,
                  rsabssa.public_key_fingerprint(deployment.vro.public_key))
    response = deployment.vro.issue_token(voter.build_auth_request())
    assert response.issued, response.outcome
    voter.accept_token(response.blind_signature)
    deployment.ebb.submit(voter.cast(selection))


def closed(deployment, selections) -> None:
    deployment.ebb.open()
    for i, selection in enumerate(selections):
        vote(deployment, f"HU-{i:03d}", selection)
    deployment.ebb.close()


# -- the configuration -----------------------------------------------------

def test_the_configuration_carries_the_question_and_the_names(deployment):
    published = json.loads((deployment.document_root / "election.json").read_bytes())
    assert published["question"] == "Who should the representative be?"
    assert published["options"] == AWKWARD


def test_a_ballot_with_no_wording_says_so_rather_than_omitting_it(tmp_path):
    """Null, not absent.

    A reader of the file should be able to see that the question was asked
    of the operator and left unanswered, which is a different statement from
    a file written before anybody could ask it.
    """
    bare = Deployment.create(bits=TEST_BITS, document_root=tmp_path / "config")
    published = json.loads((bare.document_root / "election.json").read_bytes())
    assert published["question"] is None
    assert published["options"] is None
    assert "options" in published and "question" in published


def test_the_wording_is_inside_the_digest(deployment):
    """Which is the reason it lives in the configuration and not beside it.

    A name that could change without the digest changing would be a name
    every surface displayed and no surface could vouch for.
    """
    from dataclasses import replace

    before = deployment.config.digest_hex()
    renamed = replace(deployment.config, options=("Someone Else", *AWKWARD[1:]))
    assert renamed.digest_hex() != before


def test_a_name_outside_ascii_is_emitted_as_utf8_rather_than_escaped(deployment):
    """`\\u00e1` and `á` are different bytes, and the digest is over bytes.

    Python's `json.dumps` escapes non-ASCII by default and `JSON.stringify`
    does not, which is the divergence the golden vectors exist for. The
    configuration is written with `ensure_ascii=False` for the same reason,
    and a ballot is the likeliest place in this system for somebody to type
    an accent.
    """
    raw = deployment.config.to_bytes()
    for name in AWKWARD:
        assert name.encode("utf-8") in raw, name
    assert b"\\u" not in raw


def test_an_accented_ballot_runs_the_protocol_unchanged(deployment):
    """The names move no cryptography. Everything still verifies.

    Not a formality: the published configuration is what every client pins,
    so a name that perturbed the digest computation would be a name that
    stopped tokens verifying -- and it would do it only for some inputs,
    which is the shape of the bug that reaches an election rather than a
    test.
    """
    closed(deployment, [1, 2, 2, 3])
    report = run_checks(
        deployment.config.to_bytes(),
        canonical_bytes(ledger_dump(deployment)),
        canonical_bytes(releases_dump(deployment)),
    )
    assert report.as_dict()["ok"], report.as_dict()["checks"]


# -- where a name must not go ---------------------------------------------

def test_no_name_reaches_the_ledger_or_the_release_register(deployment):
    """A recount is run by somebody who downloaded three files.

    Two of the three carry the records, and they carry numbers. A tally that
    depended on a word would be a tally nobody could recompute without this
    origin's agreement about what the word was.
    """
    closed(deployment, [1, 2, 3, 4])
    for dump in (ledger_dump(deployment), releases_dump(deployment)):
        rendered = canonical_bytes(dump)
        for name in AWKWARD:
            assert name.encode("utf-8") not in rendered, (name, dump["format"])


def test_the_independent_verifier_counts_by_number_and_needs_no_name(deployment):
    """It is downloaded from the checker page and run elsewhere.

    It reads `num_choices` and reports the count per option by number. If it
    ever needed the names, every reader who ran it would need this origin to
    tell them what the ballot said.
    """
    closed(deployment, [1, 1, 2, 4])
    report = run_checks(
        deployment.config.to_bytes(),
        canonical_bytes(ledger_dump(deployment)),
        canonical_bytes(releases_dump(deployment)),
    ).as_dict()
    assert report["ok"]
    # Integers, not names and not even the strings a name would key by.
    assert sorted(report["tally"]["options"]) == [1, 2, 3, 4]


def test_no_name_reaches_the_token_request_document(deployment):
    """`pdfrequest` renders ASCII with no embedded font, on purpose.

    `ő` and `ű` are outside WinAnsiEncoding, so a document carrying a name
    would either refuse to render it or render it as a different letter --
    and the office decides by rebuilding the document from the payload, so a
    fourth field would be a field it might one day read. The request names
    the election by identifier and digest, and that is the whole of it.
    """
    assert pdfrequest.FIELDS == ("blinded_key", "config_digest", "election_id")
    document = pdfrequest.render(pdfrequest.payload_of(
        deployment.config.election_id, deployment.config.digest_hex(),
        b"\x01" * 256))
    for name in AWKWARD:
        assert name.encode("utf-8") not in document, name
    assert b"representative" not in document


def test_the_box_accepts_by_number_and_not_by_name(deployment):
    """Acceptance turns on `num_choices`, which is why it sits beside the list.

    Four names and four options: a selection of 4 is valid and 5 is invalid,
    and neither answer consults a word.
    """
    deployment.ebb.open()
    vote(deployment, "HU-in-range", 4)
    vote(deployment, "HU-out-of-range", 5)
    deployment.ebb.close()

    tally = deployment.ebb.tally()
    assert tally["valid"] == 1 and tally["invalid"] == 1
    assert sorted(tally["counts"]) == [1, 2, 3, 4]
    assert tally["protest_codes"] == {5: 1}


def test_a_protest_selection_acquires_no_name(deployment):
    """The list must never grow an entry for "something else".

    Two independent reasons, both in CLAUDE.md: a shared code agreed in
    advance forces organised protest to declare itself before voting opens,
    and some protest messages are ones no legitimate authority could
    register without appearing to endorse them. So the distribution is
    reported and the meaning is not.
    """
    deployment.ebb.open()
    vote(deployment, "HU-protest", -1)
    deployment.ebb.close()

    assert deployment.ebb.tally()["protest_codes"] == {-1: 1}
    assert len(deployment.config.options) == deployment.config.num_choices
    assert all("else" not in name.lower() for name in deployment.config.options)


# -- the console ----------------------------------------------------------

@pytest.fixture
def setup_console(deployment):
    apps = build_all(deployment)
    return TestClient(apps[origins.SETUP])


def mint(console, **changes) -> "TestClient":
    body = {
        "confirm": "wording-2026", "election_id": "minted-2026",
        "num_choices": 2, "bits": TEST_BITS,
        "opens": "2026-01-01T08:00:00Z", "closes": "2026-01-01T20:00:00Z",
    }
    body.update(changes)
    return console.post("/election", json=body)


def test_the_console_mints_a_named_ballot(setup_console, deployment):
    response = mint(setup_console, question="Igen vagy nem?",
                    options=["Igen", "Nem"])
    assert response.status_code == 200, response.text
    assert deployment.config.question == "Igen vagy nem?"
    assert deployment.config.options == ("Igen", "Nem")


def test_the_console_refuses_a_list_of_the_wrong_length(setup_console):
    """The two sit beside each other, so something has to stop them drifting.

    A shorter list leaves an option unnamed that a voter can still choose; a
    longer one names something nobody can vote for. Both would be a
    configuration describing a ballot that does not exist.
    """
    response = mint(setup_console, num_choices=3, options=["Igen", "Nem"])
    assert response.status_code == 422
    assert "2 names for 3 options" in response.json()["detail"]


def test_the_console_refuses_an_option_with_no_name(setup_console):
    response = mint(setup_console, options=["Igen", "   "])
    assert response.status_code == 422
    assert "not a name" in response.json()["detail"]


def test_an_unnamed_ballot_is_still_mintable(setup_console, deployment):
    """Numbered ballots are not a legacy state. An operator may want one."""
    assert mint(setup_console).status_code == 200
    assert deployment.config.question is None
    assert deployment.config.options is None


def test_minting_does_not_carry_the_previous_election_s_wording(
        setup_console, deployment):
    """There is no `keep_` for the wording, unlike the register.

    The register names citizens and is Phase A material the office
    administers; the wording is what *this* ballot asks. An election minted
    with nothing said about it is a numbered ballot, not the previous
    election's candidates under new keys.
    """
    assert mint(setup_console, num_choices=4).status_code == 200
    assert deployment.config.options is None


# -- what a store written before this still means -------------------------

def test_an_election_stored_before_the_wording_still_loads(tmp_path):
    """Absence means a numbered ballot, which is what those elections were.

    Refusing an election because its file predates a field that defaults to
    the old behaviour would lose the token key, the register and every
    persona for nothing -- the argument the store makes for every earlier
    version it still reads.
    """
    data = tmp_path / "elections"
    original = Deployment.create(bits=TEST_BITS, document_root=tmp_path / "config")
    original.data_dir = data
    folder = original.save(data)

    store_file = folder / "election.store.json"
    body = json.loads(store_file.read_text(encoding="utf-8"))
    body["store_version"] = 3
    del body["question"], body["options"]
    store_file.write_text(json.dumps(body), encoding="utf-8")

    reloaded = Deployment.load(data, document_root=tmp_path / "config-2")
    assert reloaded.config.question is None
    assert reloaded.config.options is None


def test_the_wording_survives_a_restart(tmp_path):
    """It is part of what an election *is*, so the store carries it whole.

    Derived back from the published configuration it would be derived from
    a file the next mint overwrites, and the election would come back as a
    different ballot under the same keys.
    """
    data = tmp_path / "elections"
    original = Deployment.create(
        bits=TEST_BITS, document_root=tmp_path / "config",
        num_choices=4, question="Kit válasszunk?", options=AWKWARD)
    original.data_dir = data
    original.save(data)

    reloaded = Deployment.load(data, document_root=tmp_path / "config-2")
    assert reloaded.config.question == "Kit válasszunk?"
    assert list(reloaded.config.options) == AWKWARD
    assert reloaded.config.digest_hex() == original.config.digest_hex()
