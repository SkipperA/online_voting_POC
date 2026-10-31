"""The first start of a deployment that holds no election.

`deploy/README.md` has said for some time to mint the first election from
the setup console once the certificates are up. It could not be done: the
runtime loaded an election before serving anything, an empty volume raised,
and the console was one of the origins that then failed to start. On a
laptop `--init` is there to pass; a container runs `python -m service
--data /data` and has nowhere to pass it.

So an empty data directory is now a state the service comes up in, with the
console serving and every other origin refusing. What it is *not* is an
excuse to invent an election: nothing is minted until an operator mints it,
and a pointer naming a directory that holds no election is still a fatal
misconfiguration rather than a first start. Those two look alike on the way
out of `store.current`, which is why they are two exceptions.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from service import origins, store
from service.apps import build_all
from service.state import NO_ELECTION, Deployment
from service.store import NoElection, NoElectionYet

TEST_BITS = 2048

FIRST = {
    "confirm": "", "election_id": "first-2026", "num_choices": 2,
    "bits": TEST_BITS,
    "opens": "2026-01-01T08:00:00Z", "closes": "2026-01-01T20:00:00Z",
}


@pytest.fixture
def empty(tmp_path):
    """A deployment with nothing authored, and no anchors to go looking for."""
    return Deployment.unfurnished(
        document_root=tmp_path / "config", trust_anchors=None)


@pytest.fixture
def clients(empty):
    """Built *before* the first mint, and kept across it on purpose.

    Every origin's application closes over the deployment at start-up, which
    is why `mint` mutates in place. These are the same objects afterwards,
    so a test that mints through one of them is testing what a running
    container does rather than what a restart would do.
    """
    return {o.name: TestClient(app) for o, app in build_all(empty).items()}


# -- the two ways there is no election ------------------------------------

def test_an_empty_directory_is_a_first_start(tmp_path):
    with pytest.raises(NoElectionYet):
        store.current(tmp_path)


def test_a_pointer_naming_no_election_is_still_fatal(tmp_path):
    """An operator's mistake, and it must stay loud.

    Answering this the way an empty directory is answered would serve an
    empty deployment on top of an election still sitting on the disk, and
    the operator's evidence that something was wrong would be that the
    console offered to mint.
    """
    (tmp_path / "002-nope").mkdir()
    (tmp_path / store.POINTER).write_text("002-nope\n", encoding="utf-8")

    with pytest.raises(NoElection) as raised:
        store.current(tmp_path)
    assert not isinstance(raised.value, NoElectionYet)
    assert "holds no election" in str(raised.value)


def test_an_unfurnished_deployment_holds_no_election(empty):
    assert empty.served is False
    assert empty.config is None and empty.vro is None and empty.ebb is None
    assert empty.election_name == NO_ELECTION


# -- what the origins do about it -----------------------------------------

def test_every_origin_but_the_console_refuses(clients):
    for origin in origins.ALL:
        response = clients[origin.name].get("/")
        if origin is origins.SETUP:
            assert response.status_code == 200, "the console is how this ends"
            continue
        assert response.status_code == 503, origin.name
        assert response.json()["served"] is False, origin.name


def test_health_still_answers_on_a_refusing_origin(clients):
    """The question it answers does not depend on there being an election.

    Is this process up, and which code is it -- which is exactly what an
    operator asks while looking at a deployment refusing everything else.
    """
    response = clients["ebb"].get("/health")
    assert response.status_code == 200
    assert response.json()["origin"] == "ebb"


def test_a_browser_is_told_in_a_sentence_and_a_script_in_json(clients):
    page = clients["checker"].get("/", headers={"accept": "text/html"})
    assert page.status_code == 503
    assert "No election yet" in page.text
    assert origins.SETUP.url in page.text

    script = clients["checker"].get("/", headers={"accept": "application/json"})
    assert script.json()["served"] is False


def test_the_band_says_there_is_no_election(clients):
    """The console carries a band like every other page, and it must print.

    `election_name` exists for this: the one surface that works with nothing
    authored is a surface that has to say what it is looking at.
    """
    assert NO_ELECTION in clients["setup"].get("/").text


# -- the console with nothing authored ------------------------------------

def test_the_configuration_endpoint_answers_rather_than_refusing(clients):
    """It is how the page finds out which of its two states it is in."""
    body = clients["setup"].get("/configuration").json()
    assert body["served"] is False
    assert body["election_id"] is None


@pytest.mark.parametrize("method, path, body", [
    ("post", "/voters", {"voter_id": "HU-0001"}),
    ("get", "/voters", None),
    ("post", "/tally-interval", {"seconds": 900}),
    ("post", "/schedule", {"opens": "2026-01-01T08:00:00Z",
                           "closes": "2026-01-01T20:00:00Z"}),
])
def test_the_console_refuses_its_other_acts(clients, method, path, body):
    """A register belongs to an election; a cadence is a promise about one."""
    call = getattr(clients["setup"], method)
    response = call(path) if body is None else call(path, json=body)
    assert response.status_code == 409
    assert "no election" in response.json()["detail"]


# -- minting the first one ------------------------------------------------

def test_the_first_mint_needs_no_confirm(clients, empty):
    """`confirm` makes a destructive act take two hands.

    The first mint destroys nothing: there are no tokens to void, no
    receipts to disown and no fingerprint anybody pinned.
    """
    assert clients["setup"].post("/election", json=FIRST).status_code == 200
    assert empty.served is True
    assert empty.config.election_id == "first-2026"


def test_a_replacement_still_needs_confirm(clients):
    assert clients["setup"].post("/election", json=FIRST).status_code == 200
    second = dict(FIRST, election_id="second-2026", confirm="")
    response = clients["setup"].post("/election", json=second)
    assert response.status_code == 409
    assert "first-2026" in response.json()["detail"]


def test_the_origins_come_alive_without_a_restart(clients):
    """The whole reason `mint` mutates in place rather than returning anew.

    These clients were built before there was an election. A container has
    no way to be told to restart from inside itself, and an operator who had
    to restart it after the first mint would be back to editing files on the
    server -- which is the thing this is for.
    """
    assert clients["ebb"].get("/published").status_code == 503
    assert clients["setup"].post("/election", json=FIRST).status_code == 200
    assert clients["ebb"].get("/published").status_code == 200
    assert clients["config"].get("/election.json").status_code == 200


def test_the_first_mint_carries_the_policy_the_process_started_with(tmp_path):
    """Clause S7, and the third door onto the same fault.

    Who this office is willing to enrol is a property of the deployment, not
    of a poll. It used to live only on the office -- fine while there was
    always an office to read it from. A deployment with no election has
    none, so the value is held beside the trust anchors and carried into the
    first mint rather than re-read from an environment that may have moved.
    """
    empty = Deployment.unfurnished(
        document_root=tmp_path / "config", trust_anchors=None,
        open_enrolment=True)
    assert empty.open_enrolment is True

    empty.mint(election_id="first-2026", num_choices=2, bits=TEST_BITS,
               opens="2026-01-01T08:00:00Z", closes="2026-01-01T20:00:00Z")
    assert empty.vro.enrol_on_qualified_signature is True
    assert empty.vro.register == set()
