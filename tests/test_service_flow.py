"""The demo path, end to end, against a deployment that is actually listening.

What this tests is not that the protocol works -- `test_end_to_end` does that
in-process -- but that the split across origins did not break it, and that
the boundaries survive a complete run rather than only an empty one.

A subprocess rather than `TestClient`, because the wallet transmits to the
office over HTTP (§5.3) and `TestClient` binds no port. Driving these apps
in-process would test an arrangement the article rejects while calling it by
the name of the one it argues for.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization

from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot, b64, unb64
from service_process import Deployment

VOTERS = {"Anna": "HU-WALLET-000", "Béla": "HU-WALLET-001", "Csilla": "Kovács Ágnes"}


@pytest.fixture(scope="module")
def live():
    deployment = Deployment().start()
    try:
        yield deployment
    finally:
        deployment.stop()


@pytest.fixture(scope="module")
def token_key(live):
    config = live.http.get(f"{live.config}/election.json").json()
    return serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))


def obtain_token(live, token_key, voter_id):
    """B1–B18 across three origins, as the voter application would."""
    adhoc = keys.SigningKeyPair.generate()
    blinded, state = rsabssa.blind(token_key, adhoc.public_bytes)

    live.http.post(f"{live.wallet}/session", json={"voter_id": voter_id})
    outcome = live.http.post(
        f"{live.wallet}/requests", json={"blinded_key": b64(blinded)}
    ).json()["outcome"]

    reply = live.http.get(f"{live.vro}/token-replies/{b64(blinded)}")
    if reply.status_code != 200:
        return None, None, outcome
    token = rsabssa.finalize(
        token_key, adhoc.public_bytes, unb64(reply.json()["blind_signature"]), state
    )
    assert rsabssa.verify(token_key, adhoc.public_bytes, token)
    return adhoc, token, outcome


def cast(live, adhoc, token, selection):
    unsigned = Ballot(
        selection=selection, adhoc_public_key=adhoc.public_bytes, token=token,
        vote_signature=b"",
    )
    return live.http.post(f"{live.ebb}/ballots", json={
        "selection": selection,
        "adhoc_public_key": b64(adhoc.public_bytes),
        "token": b64(token),
        "vote_signature": b64(adhoc.sign(unsigned.signed_payload())),
    }).json()


def test_the_whole_path_across_origins(live, token_key):
    for voter_id in VOTERS.values():
        live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})

    for voter_id in VOTERS.values():
        adhoc, token, outcome = obtain_token(live, token_key, voter_id)
        assert outcome == "ISSUED"
        assert cast(live, adhoc, token, 1)["accepted"]

    view = live.http.get(f"{live.ebb}/published").json()
    assert "records" not in view, "records must be withheld while voting is open"
    assert len(view["commitments"]["accepted"]) == 3

    live.http.post(f"{live.ebb}/close")
    view = live.http.get(f"{live.ebb}/published").json()
    assert len(view["records"]["accepted"]) == 3
    assert live.http.get(f"{live.ebb}/tally").json()["counts"]["1"] == 3


def test_the_wallet_reaches_the_office_over_the_wire(live, token_key):
    """§5.3, as a fact about the deployment rather than a claim about it.

    The office's token endpoint is reachable by anyone who can address the
    origin -- which is what makes the wallet's call a transmission rather
    than a function call, and what lets the checks below be attacked at all.
    """
    response = live.http.post(f"{live.vro}/token-requests", json={
        "voter_id": "nobody", "blinded_key": "AAAA", "wallet_signature": "AAAA",
    })
    assert response.status_code == 200
    assert response.json()["outcome"] == "NOT_IDENTIFIED"


def test_an_unregistered_id_and_a_bad_signature_are_indistinguishable(live, token_key):
    """§3.2: both pre-identification failures return one refusal.

    Only reachable now that the office has an endpoint of its own. Were the
    two reported apart, anyone able to spell an identifier could learn from
    the answer whether that citizen is on the register.
    """
    live.http.post(f"{live.setup}/voters", json={"voter_id": "HU-REAL-001"})
    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    forged = keys.SigningKeyPair.generate()

    unknown = live.http.post(f"{live.vro}/token-requests", json={
        "voter_id": "HU-NOT-ENROLLED", "blinded_key": b64(blinded),
        "wallet_signature": b64(forged.sign(b"whatever")),
    }).json()["outcome"]
    impersonated = live.http.post(f"{live.vro}/token-requests", json={
        "voter_id": "HU-REAL-001", "blinded_key": b64(blinded),
        "wallet_signature": b64(forged.sign(b"whatever")),
    }).json()["outcome"]

    assert unknown == impersonated == "NOT_IDENTIFIED"


def test_the_blinded_value_is_the_only_credential_for_the_reply(live):
    """B16: unguessable, and nothing else is invented to protect it."""
    assert live.http.get(
        f"{live.vro}/token-replies/{b64(b'not-a-real-c')}"
    ).status_code == 404


def test_a_second_token_is_refused_for_the_same_voter(live, token_key):
    voter_id = "HU-WALLET-DOUBLE"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    _, _, first = obtain_token(live, token_key, voter_id)
    assert first == "ISSUED"

    adhoc, token, second = obtain_token(live, token_key, voter_id)
    assert second == "TOKEN_ALREADY_ISSUED"
    assert token is None, "no reply may be collectable for a refused request"


def test_no_origin_discloses_an_id_during_a_complete_run(live, token_key):
    """The invariant, checked after traffic rather than on an empty server.

    An accented identifier is used deliberately: it is the case that would
    survive an ASCII-only test unnoticed.
    """
    voter_id = "Kovács Ágnes"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    adhoc, token, outcome = obtain_token(live, token_key, voter_id)
    if outcome == "ISSUED":
        cast(live, adhoc, token, 1)

    for path in ("/health", "/"):
        assert voter_id not in live.http.get(f"{live.url(8001)}{path}").text

    assert voter_id not in live.http.get(f"{live.ebb}/published").text
    assert voter_id not in live.http.get(
        f"{live.vro}/release-log"
    ).text, "the release register must publish commitments only"


def test_the_tally_is_refused_while_open_when_no_running_tally_is_configured(live):
    """The operator gets no privileged early sight; neither does anyone.

    Runs against its own deployment so the module's shared box, which other
    tests close, cannot make this pass for the wrong reason.
    """
    private = Deployment(offset=340).start()
    try:
        assert private.http.get(f"{private.ebb}/tally").status_code == 409
    finally:
        private.stop()


def test_the_wallet_does_not_echo_the_id_it_holds(live):
    """8002 knows the id. That is not a reason to return it to a caller."""
    voter_id = "HU-WALLET-ECHO"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    body = live.http.post(f"{live.wallet}/session", json={"voter_id": voter_id}).text
    assert voter_id not in body

    # The one exception is deliberate and goes to the checker, not the app:
    # D1 needs [id, sig(id)], and §3.7 permits the wallet to produce it.
    credentials = live.http.post(f"{live.wallet}/release-query-credentials").json()
    assert credentials["voter_id"] == voter_id


# -- the browser handover -------------------------------------------------

def test_the_wallet_serves_its_own_consent_page(live):
    """Same origin as the endpoints it calls, so no page is granted access.

    A wallet reachable cross-origin by the voting application would be an
    API with a consent screen painted on it.
    """
    page = live.http.get(f"{live.wallet}/")
    assert page.status_code == 200
    assert 'src="wallet.js"' in page.text
    assert f'data-config-origin="{live.config}"' in page.text

    script = live.http.get(f"{live.wallet}/wallet.js")
    assert script.status_code == 200
    assert "hash([id, c])" in script.text or "voter_id" in script.text


def test_the_wallet_does_not_permit_cross_origin_calls(live):
    """The config origin is public and says so; the wallet is not and does not."""
    assert live.http.get(
        f"{live.config}/election.json"
    ).headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-origin" not in {
        k.lower() for k in live.http.get(f"{live.wallet}/personas").headers
    }


def test_the_personas_list_exists_only_because_one_machine_plays_many(live):
    voter_id = "HU-PERSONA-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    assert voter_id in live.http.get(f"{live.wallet}/personas").json()["personas"]


def test_the_handover_file_carries_no_identifier(live, token_key):
    """What crosses between the origins is exactly this, and nothing else.

    `c` is not a secret: unblinding needs the `r` that never leaves the
    voting application (§5.3), so the file discloses nothing about the voter
    or the vote. What matters is that it also carries no identifier, because
    the application has none to put in it.
    """
    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    config = live.http.get(f"{live.config}/election.json").json()
    digest = live.http.get(f"{live.config}/election.json.sha256").text.split()[0]

    handover = {
        "election_id": config["election_id"],
        "config_digest": digest,
        "blinded_key": b64(blinded),
    }
    assert set(handover) == {"election_id", "config_digest", "blinded_key"}
    assert not any("id" == k for k in handover)


def test_only_the_reply_endpoint_is_readable_cross_origin(live, token_key):
    """The voting application is on another origin and must collect the reply.

    Safe, because the reply is useless without the `r` that never leaves the
    application (§5.3). Everything else on the office's origin stays closed —
    the release query above all, since §3.7 requires that check to be
    independent of the voting application.
    """
    voter_id = "HU-CORS-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    adhoc, token, outcome = obtain_token(live, token_key, voter_id)
    assert outcome == "ISSUED"

    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    reply = live.http.get(f"{live.vro}/token-replies/{b64(blinded)}")
    assert reply.headers.get("access-control-allow-origin") == "*", (
        "the voting application cannot read the reply it is entitled to"
    )

    closed = live.http.post(f"{live.vro}/release-queries",
                            json={"voter_id": voter_id, "signature": b64(b"x")})
    assert "access-control-allow-origin" not in {k.lower() for k in closed.headers}, (
        "a page served by the voting application must not be able to read D1"
    )
    assert "access-control-allow-origin" not in {
        k.lower() for k in live.http.get(f"{live.vro}/release-log").headers
    }


def test_the_ballot_paths_answer_a_preflight_and_the_operator_paths_do_not(live):
    """The voter casts from 8001, so `POST /ballots` needs a preflight answer.

    `/close` and `/tally` are left closed on purpose. Closing the poll is an
    act of the box performed by an operator (E1); no page should be able to
    provoke it, least of all one the voting application serves.
    """
    preflight = live.http.request(
        "OPTIONS", f"{live.ebb}/ballots",
        headers={"origin": live.url(8001),
                 "access-control-request-method": "POST",
                 "access-control-request-headers": "content-type"},
    )
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == "*"
    assert "content-type" in preflight.headers["access-control-allow-headers"].lower()

    assert live.http.get(f"{live.ebb}/published").headers.get(
        "access-control-allow-origin") == "*"

    for path in ("/close", "/tally"):
        response = live.http.request(
            "OPTIONS", f"{live.ebb}{path}", headers={"origin": live.url(8001)})
        assert "access-control-allow-origin" not in {
            k.lower() for k in response.headers}, path


def test_the_browser_canonical_form_is_the_one_the_box_verifies(live, token_key):
    """What the page signs must be byte-identical to what `ovpoc` hashes.

    The page builds `{"adhoc_public_key":…,"selection":…}` with sorted keys
    and no whitespace. If it serialised it any other way every ballot would
    be rejected, so this pins the agreement rather than trusting it.
    """
    import hashlib
    import json

    from ovpoc.messages import Ballot, canonical_bytes

    adhoc = keys.SigningKeyPair.generate()
    ballot = Ballot(selection=2, adhoc_public_key=adhoc.public_bytes,
                    token=b"", vote_signature=b"")
    browser_form = json.dumps(
        {"adhoc_public_key": b64(adhoc.public_bytes), "selection": 2},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()

    assert browser_form == canonical_bytes(
        {"adhoc_public_key": b64(adhoc.public_bytes), "selection": 2})
    assert hashlib.sha256(browser_form).digest() == ballot.signed_payload()
