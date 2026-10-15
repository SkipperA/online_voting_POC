"""Minting a new election, and correcting the one being served.

Two acts with deliberately different reach. The schedule is recorded rather
than enforced, so correcting it voids nothing and only the digest moves.
Minting replaces every key pair, which voids every token already issued --
the test says so explicitly, because an election whose keys quietly changed
underneath a pinned fingerprint is the failure the durable store exists to
prevent.

2048-bit moduli throughout: these tests generate several, and the size is
not what they are about.
"""

from __future__ import annotations

import pytest

from service.state import Deployment
from service.store import current, read


@pytest.fixture
def deployment(tmp_path):
    made = Deployment.create(
        election_id="first", bits=2048, num_choices=3,
        opens="2026-01-01T08:00:00Z", closes="2026-01-01T20:00:00Z",
        document_root=tmp_path / "docs",
    )
    made.enrol("Kovács Ágnes")
    made.data_dir = tmp_path / "data"
    made.save(made.data_dir)
    return made


def test_the_schedule_is_authored_not_hard_coded(deployment, tmp_path):
    deployment.set_schedule("2027-03-04T06:00:00Z", "2027-03-04T22:00:00Z")

    assert deployment.config.opens == "2027-03-04T06:00:00Z"
    assert deployment.config.closes == "2027-03-04T22:00:00Z"
    # And it survives a restart, which is the whole of the complaint against
    # the literals: a schedule the service forgot was a schedule nobody set.
    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
    assert restored.config.closes == "2027-03-04T22:00:00Z"


def test_correcting_the_schedule_voids_no_token(deployment):
    fingerprint = deployment.config.token_key_fingerprint
    deployment.set_schedule("2027-03-04T06:00:00Z", "2027-03-04T22:00:00Z")

    assert deployment.config.token_key_fingerprint == fingerprint


def test_minting_replaces_every_key(deployment):
    before = (
        deployment.config.token_key_fingerprint,
        deployment.vro.office_public_key,
        deployment.ebb.statement_key.public_bytes,
    )
    deployment.mint(
        election_id="second", num_choices=5, bits=2048,
        opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z",
    )

    after = (
        deployment.config.token_key_fingerprint,
        deployment.vro.office_public_key,
        deployment.ebb.statement_key.public_bytes,
    )
    assert all(a != b for a, b in zip(before, after))
    assert deployment.config.election_id == "second"
    assert deployment.ebb.num_choices == 5


def test_minting_keeps_the_register_unless_told_otherwise(deployment):
    wallet = deployment.wallets["Kovács Ágnes"].public_bytes

    deployment.mint(election_id="second", num_choices=3, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")
    assert deployment.vro.register == {"Kovács Ágnes"}
    # The persona is the same citizen, not a new one: the wallet key is
    # certified outside the election and does not turn over with it.
    assert deployment.wallets["Kovács Ágnes"].public_bytes == wallet
    assert deployment.population.lookup("Kovács Ágnes") is not None

    deployment.mint(election_id="third", num_choices=3, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z",
                    keep_register=False)
    assert deployment.vro.register == set()
    assert deployment.wallets == {}


def test_minting_rewrites_the_durable_half(deployment, tmp_path):
    deployment.mint(election_id="second", num_choices=5, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z",
                    tally_interval_seconds=900)

    body = read(current(tmp_path / "data"))
    assert body["election_id"] == "second"
    assert body["num_choices"] == 5
    assert body["tally_interval_seconds"] == 900
    assert body["opens"] == "2027-05-05T07:00:00Z"


def test_a_store_predating_the_schedule_still_loads(deployment, tmp_path):
    """Version 2 on disk, read as what it was serving before the field."""
    import json

    from service.store import current
    store = current(tmp_path / "data") / "election.store.json"
    body = json.loads(store.read_text(encoding="utf-8"))
    body["store_version"] = 2
    del body["opens"], body["closes"]
    store.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")

    restored = Deployment.load(tmp_path / "data", document_root=tmp_path / "docs-b")
    assert restored.config.opens == "2026-09-25T08:00:00Z"


def test_minting_reaches_every_origin_without_a_restart(tmp_path):
    """The reason this test exists.

    `vro_app` and `ebb_app` each bound the office and the box to a local
    name when the application was built. Minting replaces both objects, so
    those two origins went on serving the previous election -- the old token
    key on 8003, the discarded registry on 8004 -- while 8000 and 8009
    showed the new one. Nothing failed; the deployment simply disagreed with
    itself, which is the worst shape for a demonstration to fail in.
    """
    from fastapi.testclient import TestClient

    from service import origins
    from service.apps import build_all

    deployment = Deployment.create(
        election_id="first", bits=2048, num_choices=3,
        document_root=tmp_path / "docs",
    )
    clients = {o.name: TestClient(app) for o, app in build_all(deployment).items()}
    clients["ebb"].post("/open")

    before = clients["vro"].get("/back-office/keys").json()["k_p^(R) fingerprint"]
    assert clients["ebb"].get("/published").json()["phase"] == "open"

    deployment.mint(election_id="second", num_choices=5, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")

    assert clients["vro"].get("/back-office/keys").json()["k_p^(R) fingerprint"] != before
    published = clients["ebb"].get("/published").json()
    # A new box, which starts shut as every box does (A9) -- not the opened
    # one this origin was holding a moment ago.
    assert published["phase"] != "open"
    assert published["statement_key"] != "" and published["acts"] == []
    # And the config origin serves the minted election, not a snapshot.
    served = clients["config"].get("/election.json").json()
    assert served["election_id"] == "second" and served["num_choices"] == 5


def test_an_election_named_in_hungarian_can_be_downloaded(tmp_path):
    """Header values are latin-1; `ő` and `ű` are not in it.

    Until the console could set the identifier it was always `demo-2026`
    and this could not be reached. The first election named in Hungarian
    turned both dumps into a 500 raised while the response was being
    built -- so no CORS header was ever attached, and the checker on 8005
    could only say it had failed to read anything.
    """
    from fastapi.testclient import TestClient

    from service.apps import build_all

    deployment = Deployment.create(
        election_id="időközi-2027", bits=2048, num_choices=3,
        document_root=tmp_path / "docs",
    )
    clients = {o.name: TestClient(app) for o, app in build_all(deployment).items()}
    clients["ebb"].post("/open")
    clients["ebb"].post("/close")

    for origin, path in (("ebb", "/ledger"), ("vro", "/releases")):
        response = clients[origin].get(path)
        assert response.status_code == 200, f"{path}: {response.text}"
        disposition = response.headers["content-disposition"]
        # The real name travels percent-encoded; the fallback is ASCII and
        # still recognisable rather than a hash or a generic "dump".
        assert "filename*=UTF-8''" in disposition
        assert "id%C5%91k%C3%B6zi-2027" in disposition
        assert 'filename="' in disposition and "idokozi-2027" in disposition
    # And the identifier itself is untouched in the file the browser gets.
    assert clients["ebb"].get("/ledger").json()["election_id"] == "időközi-2027"


def test_the_console_refuses_the_cadence_once_the_box_is_open(tmp_path):
    """And says so on the control rather than only in a 409."""
    from fastapi.testclient import TestClient

    from service.apps import build_all

    deployment = Deployment.create(
        election_id="first", bits=2048, num_choices=3,
        document_root=tmp_path / "docs",
    )
    clients = {o.name: TestClient(app) for o, app in build_all(deployment).items()}

    assert clients["setup"].post("/tally-interval", json={"seconds": 10}).status_code == 200
    assert clients["setup"].get("/configuration").json()["box_opened"] is False

    clients["ebb"].post("/open")
    refused = clients["setup"].post("/tally-interval", json={"seconds": 11})
    assert refused.status_code == 409
    assert "open" in refused.json()["detail"]
    assert deployment.ebb.tally_interval_seconds == 10
    # The page reads this to disable the control.
    assert clients["setup"].get("/configuration").json()["box_opened"] is True

    # Minting gives a new, shut box, so the cadence is choosable again.
    deployment.mint(election_id="second", num_choices=3, bits=2048,
                    opens="2027-05-05T07:00:00Z", closes="2027-05-05T19:00:00Z")
    assert clients["setup"].post("/tally-interval", json={"seconds": 11}).status_code == 200
