"""The token-request period: carried, published, and not enforced.

The article's rule is that token issuance closes before voting opens, so
that the office's release register and the box's ledger are drawn over
disjoint intervals and a position in one says nothing about a position in
the other. The POC does not enforce it -- clause A4 already covers
`opens` and `closes` on exactly that footing, and these two fields join
them rather than starting a new kind of thing.

**Why a period rather than one further date**, which is the whole reason
these are two fields: the rule is that the first period closes before the
second opens, and the relaxation the article allows is that they overlap.
Carrying both ends makes which of the two an election uses something a
reader can compute from the pinned configuration, rather than something a
deployment has to remember to say in prose. A single `issuance_closes`
would express the rule and leave the relaxation invisible.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from ovpoc.vro import Outcome
from ovpoc.voter import Voter
from service import origins, store
from service.apps import build_all
from service.state import Deployment

BITS = 2048
OPENS, CLOSES = "2026-09-25T08:00:00Z", "2026-09-25T20:00:00Z"
BEFORE = ("2026-09-18T08:00:00Z", "2026-09-24T20:00:00Z")
OVERLAPPING = ("2026-09-18T08:00:00Z", "2026-09-25T18:00:00Z")


def minted(tmp_path, **kwargs) -> Deployment:
    made = Deployment.create(
        bits=BITS, election_id="period", num_choices=2,
        opens=OPENS, closes=CLOSES,
        document_root=tmp_path / "published", trust_anchors=None, **kwargs)
    made.data_dir = tmp_path / "elections"
    made.save(made.data_dir)
    return made


@pytest.fixture
def console(tmp_path):
    made = minted(tmp_path)
    return made, TestClient(build_all(made)[origins.SETUP])


# -- what the configuration carries ---------------------------------------

def test_an_election_may_declare_no_period_at_all(tmp_path):
    """`None` is *not stated*, and must not read as *unlimited*.

    An administering body that has not decided should be able to publish a
    configuration saying so. Null rather than absent, for the reason
    `question` is null rather than absent: a reader should be able to tell
    a decision left unmade from a file written before anybody could make
    it.
    """
    body = json.loads(minted(tmp_path).config.to_bytes())
    assert body["token_requests_open"] is None
    assert body["token_requests_close"] is None
    assert "token_requests_open" in body, "absent is a different claim from null"


def test_the_period_is_inside_the_digest(tmp_path):
    """Which is the point of putting it in the configuration at all.

    The paper's argument is that a client can read the arrangement off an
    artefact it already pins. That only holds if the fields are covered by
    the digest -- otherwise the declaration could be changed under a reader
    who had checked it.
    """
    without = minted(tmp_path / "a")
    with_period = minted(tmp_path / "b",
                         token_requests_open=BEFORE[0],
                         token_requests_close=BEFORE[1])
    assert without.config.digest_hex() != with_period.config.digest_hex()


def test_the_file_says_the_periods_are_not_enforced(tmp_path):
    """Clause A4, in the artefact rather than only on a page.

    A reader who downloads `election.json` and never visits a surface
    should still learn that nothing consumes these. The scope note is the
    only thing in the file that can tell them.
    """
    body = json.loads(minted(tmp_path).config.to_bytes())
    note = body["scope_limits"]["schedule"]
    assert "A4" in note
    assert "not enforced" in note
    assert "token-request" in note


# -- not enforced, and that is the behaviour under test -------------------

def test_a_request_outside_the_declared_window_is_still_issued(tmp_path):
    """The POC records the declaration and acts on nothing.

    Asserted rather than left implicit, because "not enforced" is a
    promise about behaviour and the obvious next patch is one that makes
    the office consult a clock. If that is ever wanted it should be a
    deliberate change with this test rewritten, not a quiet one.
    """
    made = minted(tmp_path,
                  token_requests_open="2020-01-01T00:00:00Z",
                  token_requests_close="2020-01-02T00:00:00Z")
    made.enrol("Nagy Béla")

    # Asked of the office directly, which is where enforcement would have
    # to live: `vro.py` is the protocol and the transport contains no
    # protocol decisions. A clock consulted anywhere else would not be
    # this rule being enforced, it would be a surface declining to pass a
    # request on.
    voter = Voter(
        voter_id="Nagy Béla",
        wallet=made.wallets["Nagy Béla"],
        vro_public_key=made.vro.public_key,
        pinned_vro_fingerprint=made.config.token_key_fingerprint,
    )
    reply = made.vro.issue_token(voter.build_auth_request())

    # Long after the declared window shut, and the office does not look.
    assert reply.outcome is Outcome.ISSUED, reply.outcome
    assert made.config.token_requests_close < made.config.opens, (
        "the fixture should declare a window that has already shut")


# -- the console authors it -----------------------------------------------

def test_the_console_sets_both_periods_together(console):
    made, client = console
    reply = client.post("/schedule", json={
        "opens": OPENS, "closes": CLOSES,
        "token_requests_open": BEFORE[0], "token_requests_close": BEFORE[1]})
    assert reply.status_code == 200, reply.text
    assert made.config.token_requests_open == BEFORE[0]
    assert made.config.token_requests_close == BEFORE[1]
    assert reply.json()["digest"] == made.config.digest_hex()


def test_one_end_of_a_period_is_refused(console):
    """A window with one end cannot be read as a window.

    A configuration carrying only a close would look like a declaration
    while being unusable as one: a reader could not tell whether the
    window opened with the poll, with the configuration, or never.
    """
    _, client = console
    reply = client.post("/schedule", json={
        "opens": OPENS, "closes": CLOSES,
        "token_requests_close": BEFORE[1]})
    assert reply.status_code == 422
    assert "both ends or neither" in reply.text


def test_the_console_authors_the_relaxation_too(console):
    """Overlapping periods are a legitimate election, not an error.

    This is why the rule is not enforced at the endpoint either. A
    jurisdiction that will not turn away a late registrant publishes
    periods that overlap, and the console has to be able to author that
    election -- which is exactly what carrying two periods buys, and what
    a validator refusing the overlap would throw away.
    """
    made, client = console
    reply = client.post("/schedule", json={
        "opens": OPENS, "closes": CLOSES,
        "token_requests_open": OVERLAPPING[0],
        "token_requests_close": OVERLAPPING[1]})
    assert reply.status_code == 200, reply.text
    assert made.config.token_requests_close > made.config.opens


def test_clearing_the_period_is_possible(console):
    """A declaration can be withdrawn, like any other schedule field."""
    made, client = console
    client.post("/schedule", json={
        "opens": OPENS, "closes": CLOSES,
        "token_requests_open": BEFORE[0], "token_requests_close": BEFORE[1]})
    client.post("/schedule", json={"opens": OPENS, "closes": CLOSES})
    assert made.config.token_requests_open is None


# -- it survives a restart ------------------------------------------------

def test_the_period_comes_back_from_disk(tmp_path):
    """The store carries it whole rather than re-deriving it.

    A declaration that came back absent after a restart would be a
    different election under the same keys -- and the digest would say so,
    which is how a voter who had pinned the configuration would find out.
    """
    made = minted(tmp_path,
                  token_requests_open=BEFORE[0], token_requests_close=BEFORE[1])
    before = made.config.digest_hex()

    restored = Deployment.load(made.data_dir,
                               document_root=tmp_path / "published-b")
    assert restored.config.token_requests_open == BEFORE[0]
    assert restored.config.token_requests_close == BEFORE[1]
    assert restored.config.digest_hex() == before


def test_an_election_stored_before_the_fields_existed_still_loads(tmp_path):
    """Older stores declared no period, and must not acquire one.

    `store.read` uses `.get` for these deliberately. A default window
    invented at load would be this deployment making a declaration the
    administering body never made.
    """
    made = minted(tmp_path)
    path = made.data_folder / "election.store.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    del body["token_requests_open"]
    del body["token_requests_close"]
    body["store_version"] = 6
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")

    restored = Deployment.load(made.data_dir,
                               document_root=tmp_path / "published-c")
    assert restored.config.token_requests_open is None
    assert 6 in store.READABLE_STORE_VERSIONS
