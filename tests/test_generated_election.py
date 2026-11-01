"""An election the server filled itself, and the label that says so.

Two things are under test. That the thing produced is a *real* poll —
every signature the protocol's own, the chain reaching the published head,
the recount holding — because an election whose cryptography were faked
would demonstrate nothing and could not be published as a challenge. And
that it cannot be served without saying what it is, because the first
property is exactly what makes the second one necessary: nothing
downstream can tell a generated election from a real one, by construction.

The dataset's own integrity is the third thing, and it is not cryptographic
at all. Two ordered registers are published, and if the generator ran voter
by voter then index *i* of one would be index *i* of the other and anyone
holding both could read the answer off two columns. So the tokens are all
issued first, in one order, and the ballots cast in another drawn
separately.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from ovpoc.messages import b64, canonical_bytes
from service import api, generate, origins, store
from service.apps import build_all
from service.generate import ANSWER_KEYS, Distribution, Progress
from service.state import Deployment

TEST_BITS = 2048
OPENS, CLOSES = "2026-01-01T08:00:00Z", "2026-01-01T20:00:00Z"

#: Sixty citizens cast, which is the figure the order test needs rather
#: than a round number: Spearman's rho between two independent orders has
#: a standard deviation of 1/sqrt(n-1), so sixty puts the threshold below
#: four standard deviations and the test does not fail on a bad afternoon.
PLAN = Distribution(per_option={1: 24, 2: 17, 3: 11},
                    protest={-1: 5, 99: 3},
                    abstentions=12, revotes=9)


def _election(root):
    made = Deployment.create(
        bits=TEST_BITS, election_id="gen-2026", num_choices=3,
        question="Ki legyen a képviselő?", options=["Egy", "Kettő", "Három"],
        generated=True, document_root=root / "config", trust_anchors=None)
    made.data_dir = root / "elections"
    made.save(made.data_dir)
    return made


@pytest.fixture
def deployment(tmp_path):
    return _election(tmp_path)


@pytest.fixture(scope="module")
def filled(tmp_path_factory):
    """One generated election for every test that only reads it.

    Module-scoped because filling one is a few hundred blind signatures and
    the tests below ask different questions of the same poll. Anything that
    mutates a deployment takes the function-scoped fixture instead.
    """
    made = _election(tmp_path_factory.mktemp("generated"))
    generate.populate(made, PLAN)
    api.archive_at_close(made)
    return made


# -- what it produced ------------------------------------------------------

def test_the_tally_is_the_distribution_that_was_asked_for(filled):
    tally = filled.ebb.tally()
    assert tally["counts"] == PLAN.per_option
    assert tally["valid"] == sum(PLAN.per_option.values())
    assert tally["protest_codes"] == PLAN.protest
    assert tally["voters"] == PLAN.casting


def test_submissions_outnumber_the_ballots_that_count(filled):
    """Supersession, demonstrated rather than asserted.

    Every submission is in the ledger and every one of them was accepted;
    what makes a ballot count is being the last under its ad-hoc key.
    """
    assert len(filled.ebb.accepted.entries) == PLAN.submissions
    assert filled.ebb.tally()["voters"] == PLAN.casting
    assert PLAN.submissions > PLAN.casting


def test_the_two_registers_are_not_even_the_same_length(filled):
    """Abstentions, and the case §3.7 cares most about.

    A released token with no ballot behind it is realistic: absence from
    the release register is conclusive, presence is not.
    """
    assert filled.vro.release_count() == PLAN.citizens
    assert len({e.payload["adhoc_public_key"]
                for e in filled.ebb.accepted.entries}) == PLAN.casting
    assert filled.vro.release_count() > PLAN.casting


def _spearman(ys: list[int]) -> float:
    """Rank correlation of `ys` against 0, 1, 2, … — no ties, so exact."""
    n = len(ys)
    differences = sum((i - y) ** 2 for i, y in enumerate(ys))
    return 1 - 6 * differences / (n * (n * n - 1))


def test_the_issuance_order_does_not_predict_the_casting_order(filled):
    """The whole integrity of the dataset, and not a cryptographic property.

    If the generator ran voter by voter, the citizen who asked first would
    be the citizen who cast first, and the challenge would be won by reading
    two columns with no cryptography involved at all.

    Rank correlation rather than positional equality, which is how this test
    was first written and why it is worth the comment: abstentions shift
    every later position by one, so a *perfectly* correlated run has almost
    no voter at the same index in both registers and sails past an equality
    check. What has to be absent is the order being predictable at all, and
    only a correlation measures that.
    """
    answer = json.loads(
        (filled.data_dir / ANSWER_KEYS /
         f"{filled.data_folder.name}.json").read_text(encoding="utf-8"))
    key_of = answer["citizen_to_adhoc_key"]

    cast_rank: dict[str, int] = {}
    for entry in filled.ebb.accepted.entries:
        cast_rank.setdefault(entry.payload["adhoc_public_key"], len(cast_rank))

    in_issuance_order = [
        entry["voter_id"]
        for entry in filled.vro.supervision_dump()["releases"]
        if key_of[entry["voter_id"]] in cast_rank]
    assert len(in_issuance_order) == PLAN.casting

    rho = _spearman([cast_rank[key_of[v]] for v in in_issuance_order])
    assert abs(rho) < 0.6, (
        f"issuance order predicts casting order (Spearman {rho:+.2f}); the "
        f"two have to be drawn separately, or the published dataset carries "
        f"a channel no real poll has")


def test_every_ballot_verifies_and_the_recount_holds(filled):
    """The reason for generating one rather than writing numbers in a file.

    The independent verifier is handed the three files a stranger
    downloads, and it imports nothing from this project.
    """
    report = api.run_checks(
        filled.config.to_bytes(),
        canonical_bytes(api.ledger_dump(filled)),
        canonical_bytes(api.releases_dump(filled)),
    ).as_dict()
    assert report["ok"], report["checks"]
    assert report["tally"]["options"] == PLAN.per_option


def test_the_identifiers_are_obviously_invented(filled):
    """Realism does not improve the challenge and a plausible identifier
    in a public dataset is a liability. A few carry characters outside
    ASCII, because the canonical-JSON agreement the wire contract rests on
    is otherwise pinned only by four fixtures."""
    register = sorted(filled.vro.register)
    assert len(register) == PLAN.citizens
    assert all(v.startswith("GEN-") for v in register)
    assert any(not v.isascii() for v in register)


def test_the_generated_electorate_does_not_outlive_its_election(deployment):
    """A synthetic citizen must never end up on a real election's roll."""
    generate.populate(deployment, PLAN)
    assert deployment.vro.register
    deployment.ebb.close() if not deployment.ebb.closed else None
    deployment.mint(election_id="real-2026", num_choices=2, bits=TEST_BITS,
                    opens=OPENS, closes=CLOSES, keep_register=False)
    assert deployment.vro.register == set()


# -- the answer key --------------------------------------------------------

def test_the_answer_key_is_outside_every_election_directory(filled):
    """A challenge whose answer sits in the directory being published is
    not a challenge."""
    answers = filled.data_dir / ANSWER_KEYS
    assert (answers / f"{filled.data_folder.name}.json").exists()
    assert not any(filled.data_folder.rglob("*answer*"))
    assert store.describe(answers) is None
    assert ANSWER_KEYS not in {row["directory"]
                               for row in store.listing(filled.data_dir)}


def test_the_answer_key_names_the_key_that_carries_each_ballot(filled):
    """It has to actually settle the challenge, or it is decoration."""
    answer = json.loads(
        (filled.data_dir / ANSWER_KEYS /
         f"{filled.data_folder.name}.json").read_text(encoding="utf-8"))
    key_of = answer["citizen_to_adhoc_key"]
    assert set(key_of) == set(filled.vro.register)

    in_the_ledger = {e.payload["adhoc_public_key"]
                     for e in filled.ebb.accepted.entries}
    cast = [k for k in key_of.values() if k in in_the_ledger]
    assert len(cast) == PLAN.casting
    # And an abstainer's key is in the answer and in no ballot, which is
    # the case that makes the mapping worth publishing a digest of.
    assert len(key_of) - len(cast) == PLAN.abstentions


# -- the label -------------------------------------------------------------

def test_the_configuration_says_it_was_generated(filled):
    published = json.loads(
        (filled.document_root / "election.json").read_bytes())
    assert published["generated"] is True
    assert filled.banner.generated is True


def test_every_page_carries_the_clause_and_the_band_says_so(filled):
    """Injected, so a surface added later cannot be added without it.

    The band as well as the aside, because what a label has to survive is a
    photograph of a screen.
    """
    clients = {o.name: TestClient(a) for o, a in build_all(filled).items()}
    for origin in origins.ALL:
        if origin is origins.VOTER_APP:
            continue                      # a 503 until somebody runs the build
        page = clients[origin.name].get("/").text
        assert "<code>S8</code>" in page, origin.name
        assert "no human chose" in page, origin.name


def test_an_ordinary_election_carries_none_of_it(tmp_path):
    """The other direction, which is the one that would rot quietly."""
    ordinary = Deployment.create(bits=TEST_BITS, trust_anchors=None,
                                 document_root=tmp_path / "config")
    clients = {o.name: TestClient(a) for o, a in build_all(ordinary).items()}
    page = clients["ebb"].get("/").text
    assert "<code>S8</code>" not in page and "no human chose" not in page


# -- nothing is served while it fills -------------------------------------

@pytest.fixture
def mid_run(deployment):
    """A deployment that believes it is filling, without the race.

    The thread is what the endpoint starts; what is under test here is the
    refusal, and a test that raced a real one would be a test that passed
    for the wrong reason some of the time.
    """
    deployment.populating = Progress(election_id="gen-2026", total=100,
                                     done=12, phase="issuing tokens")
    return deployment


def test_every_origin_but_the_console_refuses_while_it_fills(mid_run):
    clients = {o.name: TestClient(a) for o, a in build_all(mid_run).items()}
    for origin in origins.ALL:
        response = clients[origin.name].get("/")
        if origin is origins.SETUP:
            assert response.status_code == 200
            continue
        assert response.status_code == 503, origin.name
        assert "being filled" in response.json()["why"], origin.name
    assert clients["ebb"].get("/health").status_code == 200


def test_the_console_authors_nothing_while_it_fills(mid_run):
    console = TestClient(build_all(mid_run)[origins.SETUP])
    for path, body in (("/voters", {"voter_id": "HU-1"}),
                       ("/schedule", {"opens": OPENS, "closes": CLOSES}),
                       ("/tally-interval", {"seconds": 900})):
        response = console.post(path, json=body)
        assert response.status_code == 409, path
        assert "being filled" in response.json()["detail"], path
    assert console.get("/voters").status_code == 409
    # The two it must still answer: the page asks these to find out what is
    # happening, and a console that could not report a run would be a
    # console an operator had to guess at.
    assert console.get("/configuration").status_code == 200
    assert console.get("/elections/populate").json()["phase"] == "issuing tokens"


# -- the plan --------------------------------------------------------------

@pytest.mark.parametrize("plan, complaint", [
    (Distribution(per_option={4: 1}), "outside 1..3"),
    (Distribution(per_option={1: 1}, protest={2: 1}), "not a protest"),
    (Distribution(per_option={1: -1}), "cannot be negative"),
    (Distribution(per_option={}), "demonstrates nothing"),
    (Distribution(per_option={1: 2}, revotes=5), "among 2 who cast"),
])
def test_a_plan_the_ballot_cannot_carry_is_refused(plan, complaint):
    with pytest.raises(ValueError, match=complaint):
        plan.check(3)


# -- through the console ---------------------------------------------------

def request_body(**changes) -> dict:
    body = {
        "confirm": "gen-2026", "election_id": "conference-2026",
        "num_choices": 2, "bits": TEST_BITS,
        "opens": OPENS, "closes": CLOSES,
        "per_option": [6, 4], "protest": {"-1": 1},
        "abstentions": 2, "revotes": 1,
    }
    body.update(changes)
    return body


def wait_for(deployment, seconds: float = 60.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        running = deployment.populating
        if running is not None and running.finished:
            return
        time.sleep(0.05)
    raise AssertionError("the run did not finish")


def test_the_console_generates_an_election(deployment):
    """One act: minted, filled and closed, with nothing served in between."""
    deployment.ebb.open()
    deployment.ebb.close()               # the election being replaced leaves a record
    console = TestClient(build_all(deployment)[origins.SETUP])

    started = console.post("/elections/generate", json=request_body())
    assert started.status_code == 200, started.text
    wait_for(deployment)

    assert deployment.populating.error is None, deployment.populating.error
    assert deployment.config.election_id == "conference-2026"
    assert deployment.config.generated is True
    assert deployment.ebb.closed is True
    assert deployment.ebb.tally()["counts"] == {1: 6, 2: 4}
    assert (deployment.data_folder / "closed" / "ledger.json").exists()
    assert deployment.populating.answer_key


def test_the_console_refuses_a_distribution_of_the_wrong_shape(deployment):
    deployment.ebb.open()
    deployment.ebb.close()
    console = TestClient(build_all(deployment)[origins.SETUP])

    response = console.post(
        "/elections/generate", json=request_body(per_option=[6, 4, 2]))
    assert response.status_code == 422
    assert "3 counts for 2 options" in response.json()["detail"]
    assert deployment.populating is None, "a refusal left the deployment shut"


def test_generating_is_refused_while_the_current_poll_has_no_record(deployment):
    """The same rule as minting and switching: from the poll's side they
    are one act."""
    console = TestClient(build_all(deployment)[origins.SETUP])
    response = console.post("/elections/generate", json=request_body())
    assert response.status_code == 409
    assert "has not been opened" in response.json()["detail"]
