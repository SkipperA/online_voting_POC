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


def test_the_office_opens_to_the_application_and_the_checker_and_nobody_else(
        live, token_key):
    """Two allowances, each for a different reason.

    `GET /token-replies/…` opens to `*`: the reply is useless without the `r`
    that never leaves the voting application (§5.3), so there is nothing to
    withhold from anyone.

    `/release-log` and `/release-queries` open to the *checker origin by
    name*. §3.7 requires the token-request check to be independent of the
    voting application, so `*` would hand 8001 exactly the access the design
    withholds. Naming the checker keeps that argument intact rather than
    trading it for convenience.
    """
    voter_id = "HU-CORS-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    adhoc, token, outcome = obtain_token(live, token_key, voter_id)
    assert outcome == "ISSUED"

    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    assert live.http.get(
        f"{live.vro}/token-replies/{b64(blinded)}"
    ).headers.get("access-control-allow-origin") == "*"

    checker_port = str(8005 + live.offset)
    allowed = live.http.get(f"{live.vro}/release-log").headers.get(
        "access-control-allow-origin")
    assert allowed and allowed != "*" and allowed.endswith(checker_port), allowed

    preflight = live.http.request(
        "OPTIONS", f"{live.vro}/release-queries",
        headers={"origin": f"http://127.0.0.1:{checker_port}",
                 "access-control-request-method": "POST"})
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"].endswith(checker_port)


def test_the_ballot_paths_open_the_tally_to_the_checker_and_close_to_nobody(live):
    """Three answers, three reasons.

    `/ballots` and `/published` open to `*` — the voter casts from 8001 and
    the published view is public by construction. `/tally` opens to the
    checker alone: anyone may recompute the result from the released records,
    so reading the box's own figure is no privilege, but it is the checker's
    job rather than the application's. `/close` opens to nobody, because it
    is an act of the box performed by an operator (E1).
    """
    preflight = live.http.request(
        "OPTIONS", f"{live.ebb}/ballots",
        headers={"origin": live.url(8001),
                 "access-control-request-method": "POST",
                 "access-control-request-headers": "content-type"})
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == "*"
    assert "content-type" in preflight.headers["access-control-allow-headers"].lower()

    assert live.http.get(f"{live.ebb}/published").headers.get(
        "access-control-allow-origin") == "*"

    tally = live.http.get(f"{live.ebb}/tally").headers.get("access-control-allow-origin")
    assert tally and tally.endswith(str(8005 + live.offset)), tally

    closed = live.http.request(
        "OPTIONS", f"{live.ebb}/close", headers={"origin": live.url(8001)})
    assert "access-control-allow-origin" not in {k.lower() for k in closed.headers}


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


def test_the_setup_console_serves_its_own_page_and_the_register(live):
    page = live.http.get(f"{live.setup}/")
    assert page.status_code == 200 and 'src="setup.js"' in page.text
    assert live.http.get(f"{live.setup}/setup.js").status_code == 200

    live.http.post(f"{live.setup}/voters", json={"voter_id": "HU-CONSOLE-001"})
    assert "HU-CONSOLE-001" in live.http.get(f"{live.setup}/voters").json()["voters"]


def test_the_checker_serves_a_page_and_holds_nothing(live):
    """8005 is static. It decides nothing and signs nothing.

    Every conclusion it draws comes from artefacts published by the party
    being audited — which is what makes them worth drawing, since the records
    carry their own signatures and a denial is signed under `k_s^(O)`.
    """
    page = live.http.get(f"{live.url(8005)}/")
    assert page.status_code == 200
    assert live.vro in page.text and live.ebb in page.text
    assert "Independence is a property, not an address" in page.text

    script = live.http.get(f"{live.url(8005)}/checker.js")
    assert script.status_code == 200
    # It must not reach the voting application, and must not sign anything.
    assert live.url(8001) not in script.text
    assert "subtle.sign" not in script.text


def test_the_wallet_can_produce_the_release_query_as_a_file(live):
    """The same clumsy handover as the token request, for the same reason.

    The wallet grants nothing cross-origin, so the credentials reach the
    checker only because the voter carried them.
    """
    voter_id = "HU-D1-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    live.http.post(f"{live.wallet}/session", json={"voter_id": voter_id})
    credentials = live.http.post(f"{live.wallet}/release-query-credentials").json()

    assert set(credentials) == {"voter_id", "signature"}
    answer = live.http.post(f"{live.vro}/release-queries", json=credentials).json()
    assert answer["outcome"] == "NOT_RELEASED"
    assert answer["signed_denial"], "an absence cannot be exhibited, so it is signed"


def test_the_wallet_shows_its_key_pair_and_what_it_transmitted(live, token_key):
    """A demonstration in which the keys are invisible teaches nothing.

    Both responses are marked as impossible in a deployment: under eIDAS
    `k_s^(v)` is hardware-bound and cannot be read by the wallet application
    itself, let alone returned over HTTP.
    """
    voter_id = "HU-SHOW-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    live.http.post(f"{live.wallet}/session", json={"voter_id": voter_id})

    keys_shown = live.http.get(f"{live.wallet}/keys").json()
    assert keys_shown["k_s^(v)"] and keys_shown["k_p^(v)"]
    assert "hardware-bound" in keys_shown["_never_exposed_in_a_deployment"]

    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    result = live.http.post(
        f"{live.wallet}/requests", json={"blinded_key": b64(blinded)}).json()

    assert result["outcome"] == "ISSUED"
    # The wallet's own page may see what the wallet sent; the voting
    # application may not, and reaches a different origin to ask.
    assert set(result["transmitted"]) == {
        "_transport", "voter_id", "blinded_key", "wallet_signature"}
    assert "§5.3" in result["transmitted"]["_transport"]
    assert len(result["signed_bytes"]) == 64, "hash([id, c]) as hex"


def test_the_voter_app_still_cannot_reach_what_the_wallet_shows(live):
    """The wallet's pages are same-origin; 8001 is granted nothing."""
    assert "access-control-allow-origin" not in {
        k.lower() for k in live.http.get(f"{live.wallet}/keys").headers}


def test_the_checker_can_re_read_and_timestamps_its_answers(live):
    """A D1 answer describes the register at the instant it was asked.

    Left on screen after a token has been released, a negative answer does
    not merely go stale: it displays, as current, the very claim the check
    exists to make. The page carries a re-read control and stamps both the
    published view and the D1 answer with the time they were obtained.
    """
    page = live.http.get(f"{live.url(8005)}/").text
    assert 'id="refresh"' in page and 'id="asof"' in page
    assert 'id="d1-again"' in page and 'id="d1-asof"' in page

    script = live.http.get(f"{live.url(8005)}/checker.js").text
    assert "d1-again" in script and "toLocaleTimeString" in script


def test_the_office_console_shows_recorded_beside_disclosed(live, token_key):
    """§3.2 is the gap between the two columns, so both must be visible.

    The office records which of the two pre-identification failures actually
    occurred and discloses neither. A console that showed only the disclosed
    outcome would hide the mechanism; one that showed only the recorded
    reason would imply the office tells the requester.
    """
    live.http.post(f"{live.setup}/voters", json={"voter_id": "HU-AUDIT-001"})
    forged = keys.SigningKeyPair.generate()
    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    live.http.post(f"{live.vro}/token-requests", json={
        "voter_id": "HU-AUDIT-001", "blinded_key": b64(blinded),
        "wallet_signature": b64(forged.sign(b"nope"))})

    audit = live.http.get(f"{live.vro}/back-office/audit").json()
    entry = next(e for e in audit["entries"] if e["voter_id"] == "HU-AUDIT-001")
    assert entry["disclosed"] == "NOT_IDENTIFIED"
    assert entry["reason_withheld"] is True
    assert entry["recorded"] != entry["disclosed"], (
        "the recorded reason must be more specific than the one disclosed")
    assert "coercer" in audit["_never_exposed_in_a_deployment"]


def test_the_office_console_names_what_each_key_is_for(live):
    body = live.http.get(f"{live.vro}/back-office/keys").json()
    assert "oracle" in body["_never_exposed_in_a_deployment"] or body["k_p^(R)"]
    assert "never a token" in body["k_p^(O) purpose"]
    assert "§3.3" in body["k_p^(R) purpose"]

    page = live.http.get(f"{live.vro}/").text
    assert "No deployment exposes this" in page
    assert live.http.get(f"{live.vro}/office.js").status_code == 200


def test_the_file_pickers_accept_by_extension_as_well_as_mime_type(live):
    """Safari matches `accept` against the type the OS reports for the file.

    A downloaded .json is often not reported as application/json, and the
    picker then greys out the very file the page just produced. Listing the
    extension is what makes the control usable.
    """
    for url in (f"{live.wallet}/", f"{live.url(8005)}/"):
        page = live.http.get(url).text
        assert 'accept=".json' in page, url


def test_the_wallet_has_exactly_one_persona_control(live):
    """A wallet belongs to one citizen; two selectors meant one session.

    The release-query step used to offer its own dropdown, and choosing a
    name there re-opened the session — so the next token request was signed
    under that identifier instead of the one the wallet was opened as. One
    control, chosen first, and every later step acts for that person.
    """
    page = live.http.get(f"{live.wallet}/").text
    assert page.count("<select") == 1, "only the step-1 persona selector may exist"
    assert 'id="query-whose"' in page, "the query step must name whose wallet it is"

    script = live.http.get(f"{live.wallet}/wallet.js").text
    assert "query-persona" not in script
    # The release query must not re-open the session.
    after = script[script.index("save-query').onclick"):]
    assert "'/session'" not in after[:400]


def test_staged_signing_is_off_by_default_and_real_when_on(live, token_key):
    """Validate and reserve, then sign as a separate act.

    Off by default, so every scripted caller sees `issue_token` as one act.
    On, the voter's application sees no difference except that its reply is
    not there yet — which is the state B16 was built to tolerate.
    """
    voter_id = "HU-STAGED-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    assert live.http.get(f"{live.vro}/back-office/pending").json()["manual_release"] is False

    live.http.post(f"{live.vro}/back-office/mode", json={"manual": True})
    try:
        adhoc, token, outcome = obtain_token(live, token_key, voter_id)
        assert outcome == "AWAITING_RELEASE"
        assert token is None, "no reply is collectable before the operator acts"

        held = live.http.get(f"{live.vro}/back-office/pending").json()
        assert [r["voter_id"] for r in held["pending"]] == [voter_id]

        # Nothing published while the request is held: a commitment written
        # at validation would make the pause visible to anyone counting.
        assert voter_id not in live.http.get(f"{live.vro}/release-log").text

        before = live.http.get(f"{live.vro}/release-log").json()["count"]
        released = live.http.post(
            f"{live.vro}/back-office/release", json={"voter_id": voter_id}).json()
        assert released["outcome"] == "ISSUED"
        assert live.http.get(f"{live.vro}/release-log").json()["count"] == before + 1
    finally:
        live.http.post(f"{live.vro}/back-office/mode", json={"manual": False})


def test_a_held_request_can_be_cancelled_and_the_voter_may_ask_again(live, token_key):
    voter_id = "HU-STAGED-002"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    live.http.post(f"{live.vro}/back-office/mode", json={"manual": True})
    try:
        assert obtain_token(live, token_key, voter_id)[2] == "AWAITING_RELEASE"
        assert live.http.post(
            f"{live.vro}/back-office/cancel", json={"voter_id": voter_id}
        ).json()["cancelled"] is True
        assert obtain_token(live, token_key, voter_id)[2] == "AWAITING_RELEASE"
    finally:
        live.http.post(f"{live.vro}/back-office/mode", json={"manual": False})
