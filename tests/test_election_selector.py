"""Choosing which election is served, from the console rather than by hand.

An operator used to do this by editing `current` in the data volume and
restarting the container. It is the same act -- the pointer moves, so a
later restart serves the same election -- and the reason to put it on a page
is that the shell version is available only to whoever has the shell.

Two things are under test here rather than one. The mechanism: `switch_to`
fills the running `Deployment` in place, exactly as `mint` does and for the
same reason, so every origin's application keeps the object it closed over
at start-up and nothing needs a restart. And the rule: the served election
may be put aside only once its poll has left a record, which is a rule about
evidence rather than about tidiness. An election that was served and then
replaced with nothing written down is indistinguishable afterwards from one
that was quietly rerun.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import textwrap

import pytest
from fastapi.testclient import TestClient

from service import api, origins, store
from service.apps import build_all
from service.state import Deployment

TEST_BITS = 2048
OPENS, CLOSES = "2026-01-01T08:00:00Z", "2026-01-01T20:00:00Z"


@pytest.fixture
def data(tmp_path):
    return tmp_path / "elections"


@pytest.fixture
def deployment(tmp_path, data):
    """One election, saved, with nowhere to look for anchors."""
    made = Deployment.create(
        bits=TEST_BITS, election_id="first-2026", num_choices=2,
        document_root=tmp_path / "config", trust_anchors=None)
    made.data_dir = data
    made.save(data)
    return made


@pytest.fixture
def console(deployment):
    return TestClient(build_all(deployment)[origins.SETUP])


def finish(deployment) -> None:
    """Open, close, and write the record -- what the console now requires."""
    deployment.ebb.open()
    deployment.ebb.close()
    api.archive_at_close(deployment)


def second(deployment, election_id="second-2026"):
    """Mint a second election beside the first, leaving the first a record."""
    first = deployment.data_folder
    finish(deployment)
    deployment.mint(election_id=election_id, num_choices=2, bits=TEST_BITS,
                    opens=OPENS, closes=CLOSES)
    return first, deployment.data_folder


# -- the listing -----------------------------------------------------------

def test_the_listing_describes_every_election_and_says_which_is_served(
        deployment, data):
    first, latest = second(deployment)
    rows = {row["directory"]: row for row in store.listing(data)}

    assert set(rows) == {first.name, latest.name}
    assert rows[first.name]["election_id"] == "first-2026"
    assert rows[latest.name]["election_id"] == "second-2026"
    assert rows[latest.name]["served"] is True
    assert rows[first.name]["served"] is False
    assert rows[first.name]["minted_at"] and rows[latest.name]["minted_at"]


def test_a_directory_that_is_not_an_election_is_left_out(deployment, data):
    """The anchors live beside the elections, and so does whatever else.

    A folder that is not an election is skipped rather than listed as a
    broken one: this page is a list of what can be served.
    """
    (data / "trust-anchors").mkdir()
    (data / "half-made").mkdir()
    (data / "half-made" / "election.store.json").write_text("{}", encoding="utf-8")

    listed = {row["directory"] for row in store.listing(data)}
    assert "trust-anchors" not in listed and "half-made" not in listed


def test_an_interrupted_poll_reports_an_unknown_count_rather_than_nought(
        deployment, data):
    """Nought and unknown must not look alike.

    A poll that was never closed wrote no record, so how many tokens it
    released is not nought: it is gone. Clause A7, and the page says the
    word rather than printing a number that reads as a fact.
    """
    row, = store.listing(data)
    assert row["closed"] is False
    assert row["tokens_released"] is None


def test_a_closed_poll_reports_the_office_s_own_figure(deployment, data):
    finish(deployment)
    row, = store.listing(data)
    assert row["closed"] is True
    assert row["tokens_released"] == 0


def test_the_listing_loads_no_election(deployment, data, monkeypatch):
    """Nine rows must not mean nine key loads.

    `describe` reads JSON and asks whether files exist. Breaking the one
    expensive thing `read` does -- parsing a PKCS#8 private key -- leaves
    the listing working, and would not if it were reading elections.
    """
    import service.store as store_module

    def refuse(*args, **kwargs):
        raise AssertionError("the listing parsed a private key")

    monkeypatch.setattr(store_module.serialization,
                        "load_pem_private_key", refuse)
    assert len(store.listing(data)) == 1


# -- the mechanism ---------------------------------------------------------

DEPLOYMENT_WIDE = {
    # Where the published configuration is written.
    "document_root",
    # Where the elections live. Replacing one does not move them.
    "data_dir",
    # Whose signatures this office believes, and whom it will enrol: both
    # properties of the deployment rather than of a poll, which is the
    # whole reason the anchors sit beside the elections rather than inside
    # one.
    "trust_anchors",
    "open_enrolment",
    # A demonstration mode on the back office, not election state.
    "manual_release",
}


def _assigned_to_self(method: str) -> set[str]:
    """Which `self.x = ...` a method performs, read out of its source."""
    source = textwrap.dedent(inspect.getsource(getattr(Deployment, method)))
    return {
        target.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name) and target.value.id == "self"
    }


@pytest.mark.parametrize("method", ["mint", "switch_to"])
def test_replacing_the_election_accounts_for_every_field(method):
    """The thing that is easy to get wrong, and silent when it is.

    Both acts replace the election inside an object every origin closed
    over, so both have to move every field that belongs to an election and
    leave every field that belongs to the deployment. A field added later
    and forgotten in one of them is a new election serving a scrap of the
    old one, with nothing to show for it.

    The exemption list is checked in both directions, so it stays a place
    to explain a field rather than a place to hide one.
    """
    fields = {f.name for f in dataclasses.fields(Deployment)}
    assigned = _assigned_to_self(method)

    assert DEPLOYMENT_WIDE <= fields, "the exemption list names a dead field"
    assert not (DEPLOYMENT_WIDE & assigned), (
        f"{method} assigns a field the list calls deployment-wide")
    assert not (fields - assigned - DEPLOYMENT_WIDE), (
        f"{method} leaves a field of the previous election in place")


def test_switching_serves_the_other_election(deployment, data):
    first, _ = second(deployment)
    was = deployment.config.token_key_fingerprint

    deployment.switch_to(first)

    assert deployment.config.election_id == "first-2026"
    assert deployment.config.token_key_fingerprint != was
    assert deployment.data_folder == first


def test_switching_moves_the_pointer(deployment, data):
    """So a later restart serves the same election, as `--election` does."""
    first, _ = second(deployment)
    deployment.switch_to(first)
    assert store.current(data) == first


def test_switching_keeps_the_directory_it_read(deployment, data):
    """`mint` clears `data_folder`; a switch must not.

    Cleared, the next save would allocate a fresh directory and write this
    election's register into it, beside the one it was just read from.
    """
    first, _ = second(deployment)
    before = {d.name for d in data.iterdir() if d.is_dir()}

    deployment.switch_to(first)
    deployment.enrol("HU-0001")

    assert deployment.data_folder == first
    assert {d.name for d in data.iterdir() if d.is_dir()} == before, (
        "the enrolment allocated a new directory instead of writing back")
    stored = json.loads(
        (first / "election.store.json").read_text(encoding="utf-8"))
    assert stored["electoral_register"] == ["HU-0001"]


def test_switching_carries_the_policy_rather_than_re_reading_it(
        deployment, data, monkeypatch):
    """Clause S7, and the fault CLAUDE.md records three times already.

    Whom this office enrols is a property of the deployment, decided at
    start-up. An environment that moved afterwards must not reach the
    office through a switch any more than it reaches one through a mint.
    """
    first, _ = second(deployment)
    assert deployment.open_enrolment is False
    monkeypatch.setenv("OVPOC_OPEN_ENROLMENT", "1")

    deployment.switch_to(first)

    assert deployment.open_enrolment is False
    assert deployment.vro.enrol_on_qualified_signature is False
    assert deployment.vro.signature_validation is None


def test_switching_clears_what_the_previous_poll_was_in_the_middle_of(
        deployment, data):
    first, _ = second(deployment)
    deployment.held_requests["HU-0001"] = object()
    deployment.token_replies[b"c"] = b"s_c"

    deployment.switch_to(first)

    assert deployment.held_requests == {} and deployment.token_replies == {}


def test_a_closed_poll_comes_back_when_it_is_served_again(deployment, data):
    """The reason past elections are kept at all.

    A finished poll is served again from its own record: the box shut, the
    chain re-derived, the office's register with its openings. Read-only --
    nothing resumes.
    """
    from ovpoc import rsabssa
    from ovpoc.voter import Voter

    deployment.ebb.open()
    deployment.enrol("HU-0001")
    voter = Voter("HU-0001", deployment.wallets["HU-0001"],
                  deployment.vro.public_key,
                  rsabssa.public_key_fingerprint(deployment.vro.public_key))
    response = deployment.vro.issue_token(voter.build_auth_request())
    voter.accept_token(response.blind_signature)
    deployment.ebb.submit(voter.cast(1))
    first = deployment.data_folder
    deployment.ebb.close()
    api.archive_at_close(deployment)

    deployment.mint(election_id="second-2026", num_choices=2, bits=TEST_BITS,
                    opens=OPENS, closes=CLOSES)
    assert len(deployment.ebb.accepted.entries) == 0

    deployment.switch_to(first)

    assert deployment.ebb.closed is True
    assert len(deployment.ebb.accepted.entries) == 1
    assert deployment.ebb.tally()["valid"] == 1
    assert deployment.vro.release_count() == 1


# -- the rule, on the console ---------------------------------------------

def test_the_console_serves_a_past_election(console, deployment, data):
    first, _ = second(deployment)
    finish(deployment)

    response = console.post("/elections/serve", json={"directory": first.name})
    assert response.status_code == 200, response.text
    assert response.json()["election_id"] == "first-2026"
    assert deployment.config.election_id == "first-2026"


def test_the_console_refuses_while_the_box_is_open(console, deployment, data):
    """A poll that is open has never been written anywhere."""
    first, _ = second(deployment)
    deployment.ebb.open()

    response = console.post("/elections/serve", json={"directory": first.name})
    assert response.status_code == 409
    assert "ballot box is open" in response.json()["detail"]


def test_the_console_refuses_an_election_that_left_no_record(
        console, deployment, data):
    """The case worth forcing rather than permitting.

    Nobody should accept an election whose service stopped for a while and
    then resumed as though nothing had happened, so an election that was
    served is made to leave a record before it is put aside -- even an
    empty one, dated and signed, which is evidence of the gap rather than
    a cover for it.
    """
    first, _ = second(deployment)
    assert deployment.ebb.opened is False

    response = console.post("/elections/serve", json={"directory": first.name})
    assert response.status_code == 409
    assert "has not been opened" in response.json()["detail"]


def test_minting_is_refused_by_the_same_rule(console, deployment):
    """One rule for both acts: from the poll's side they are the same act."""
    response = console.post("/election", json={
        "confirm": "first-2026", "election_id": "next-2026",
        "num_choices": 2, "bits": TEST_BITS, "opens": OPENS, "closes": CLOSES})
    assert response.status_code == 409
    assert "has not been opened" in response.json()["detail"]


def test_serving_the_election_already_served_is_refused(
        console, deployment, data):
    """It would be a fresh empty box over the same keys, for nothing."""
    _, latest = second(deployment)
    finish(deployment)

    response = console.post("/elections/serve", json={"directory": latest.name})
    assert response.status_code == 409
    assert "already the election being served" in response.json()["detail"]


@pytest.mark.parametrize("directory", ["../elsewhere", "a/b", ".", "", "  "])
def test_a_directory_name_is_not_a_path(console, deployment, directory):
    finish(deployment)
    response = console.post("/elections/serve", json={"directory": directory})
    assert response.status_code == 422


def test_an_unknown_directory_is_a_404(console, deployment):
    finish(deployment)
    response = console.post("/elections/serve", json={"directory": "099-nope"})
    assert response.status_code == 404


def test_the_listing_endpoint_says_whether_it_may_be_changed(console, deployment):
    body = console.get("/elections").json()
    assert body["durable"] is True
    assert body["may_replace"] is False
    assert "has not been opened" in body["why_not"]

    finish(deployment)
    body = console.get("/elections").json()
    assert body["may_replace"] is True and body["why_not"] is None
    assert [row["election_id"] for row in body["elections"]] == ["first-2026"]


def test_an_ephemeral_deployment_has_nothing_to_choose_between(tmp_path):
    """One election and no disk. Not the same as being forbidden to mint."""
    made = Deployment.create(bits=TEST_BITS, document_root=tmp_path / "config",
                             trust_anchors=None)
    console = TestClient(build_all(made)[origins.SETUP])

    body = console.get("/elections").json()
    assert body["durable"] is False and body["elections"] == []
    assert console.post(
        "/elections/serve", json={"directory": "anything"}).status_code == 409


def test_the_store_records_when_an_election_was_minted(deployment, data):
    """Not the file's modification time, which moves on every enrolment."""
    body = json.loads(
        (deployment.data_folder / "election.store.json").read_text(encoding="utf-8"))
    minted = body["minted_at"]
    assert minted and minted.endswith("Z")

    deployment.enrol("HU-0001")
    again = json.loads(
        (deployment.data_folder / "election.store.json").read_text(encoding="utf-8"))
    assert again["minted_at"] == minted
