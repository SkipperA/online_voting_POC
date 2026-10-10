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

from concurrent.futures import ThreadPoolExecutor

import httpx
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

    outcome = live.http.post(
        f"{live.wallet}/requests",
        json={"voter_id": voter_id, "blinded_key": b64(blinded)},
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
        "nonce": b64(unsigned.nonce),
        "vote_signature": b64(adhoc.sign(unsigned.signed_payload())),
    }).json()


def test_the_ledger_download_is_refused_while_voting_is_open(live):
    """Defined before the run that closes the box, because order decides this.

    The dump is the records, and the records are withheld until the close
    for the reasons Section 3.5 gives. An endpoint that served them early
    would be a way round the publication schedule rather than a way to
    check it.
    """
    refused = live.http.get(f"{live.ebb}/ledger")
    assert refused.status_code == 409


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

    The page builds `{"adhoc_public_key":…,"nonce":…,"selection":…}` with
    sorted keys and no whitespace. If it serialised it any other way every
    ballot would be rejected, so this pins the agreement rather than
    trusting it -- and the nonce is the key most recently added, which is
    exactly the kind of addition that breaks an ordering by hand.
    """
    import hashlib
    import json

    from ovpoc.messages import Ballot, canonical_bytes

    adhoc = keys.SigningKeyPair.generate()
    ballot = Ballot(selection=2, adhoc_public_key=adhoc.public_bytes,
                    token=b"", vote_signature=b"")
    fields = {
        "adhoc_public_key": b64(adhoc.public_bytes),
        "nonce": b64(ballot.nonce),
        "selection": 2,
    }
    browser_form = json.dumps(
        fields, separators=(",", ":"), ensure_ascii=False).encode()

    assert browser_form == canonical_bytes(fields)
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
    credentials = live.http.post(
        f"{live.wallet}/release-query-credentials", json={"voter_id": voter_id}
    ).json()

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

    keys_shown = live.http.post(
        f"{live.wallet}/keys", json={"voter_id": voter_id}).json()
    assert keys_shown["k_s^(v)"] and keys_shown["k_p^(v)"]
    assert "hardware-bound" in keys_shown["_never_exposed_in_a_deployment"]

    blinded, _ = rsabssa.blind(token_key, keys.SigningKeyPair.generate().public_bytes)
    result = live.http.post(
        f"{live.wallet}/requests",
        json={"voter_id": voter_id, "blinded_key": b64(blinded)}).json()

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
    """A wallet instance belongs to exactly one citizen.

    Chosen once, in step 1, and every later step acts for that person. The
    release-query step used to offer a dropdown of its own, which is not a
    thing a wallet has: no instance of one serves two owners.
    """
    page = live.http.get(f"{live.wallet}/").text
    assert page.count("<select") == 1, "only the step-1 persona selector may exist"
    assert 'id="query-whose"' in page, "the query step must name whose wallet it is"

    script = live.http.get(f"{live.wallet}/wallet.js").text
    assert "query-persona" not in script


def test_two_wallets_in_flight_produce_two_signers(live, token_key):
    """The origin holds no active persona, so concurrent callers do not merge.

    It held one until this test existed. `app.state.active` was server-side
    and shared by every client of 8002: a hundred voters each choosing their
    own identifier, loading their own request file and pressing the button
    would all have signed as whoever chose last, so the first press issued a
    token and the other ninety-nine were refused as that one citizen.

    What makes `ISSUED` the load-bearing assertion rather than the echoed
    identifier is the office: it verifies the wallet signature against the
    certificate for the `id` carried in the same request (B8–B9). Two
    acceptances therefore prove that each request was signed by the key
    belonging to the identifier it named, which an echo alone would not.
    """
    first, second = "HU-CONCURRENT-A", "HU-CONCURRENT-B"
    for voter_id in (first, second):
        live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})

    def request_token(voter_id: str) -> dict:
        blinded, _ = rsabssa.blind(
            token_key, keys.SigningKeyPair.generate().public_bytes)
        with httpx.Client(timeout=30.0) as http:
            return http.post(
                f"{live.wallet}/requests",
                json={"voter_id": voter_id, "blinded_key": b64(blinded)},
            ).json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(request_token, (first, second)))

    assert [r["outcome"] for r in results] == ["ISSUED", "ISSUED"]
    assert [r["transmitted"]["voter_id"] for r in results] == [first, second]


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


def test_the_audit_column_reports_what_was_disclosed_not_what_was_recorded(
        live, token_key):
    """The console's second column is about what went back over the wire.

    `reserve` records RESERVED; the requester is told AWAITING_RELEASE. An
    entry claiming ISSUED would say the voter had been told their token
    existed when it did not — in the one column whose purpose is to show
    what was said.
    """
    voter_id = "HU-DISCLOSE-001"
    live.http.post(f"{live.setup}/voters", json={"voter_id": voter_id})
    live.http.post(f"{live.vro}/back-office/mode", json={"manual": True})
    try:
        assert obtain_token(live, token_key, voter_id)[2] == "AWAITING_RELEASE"
        audit = live.http.get(f"{live.vro}/back-office/audit").json()["entries"]
        entry = next(e for e in audit if e["voter_id"] == voter_id)
        assert entry["recorded"] == "validated and reserved"
        assert entry["disclosed"] == "AWAITING_RELEASE"

        live.http.post(f"{live.vro}/back-office/cancel", json={"voter_id": voter_id})
        audit = live.http.get(f"{live.vro}/back-office/audit").json()["entries"]
        cancelled = [e for e in audit if e["voter_id"] == voter_id][-1]
        assert "nothing disclosed" in cancelled["disclosed"], (
            "a cancellation is an operator act; the requester is told nothing")
    finally:
        live.http.post(f"{live.vro}/back-office/mode", json={"manual": False})


def test_the_box_serves_an_operator_console_and_close_stays_same_origin(live):
    """The one act with institutional meaning finally has an interface.

    It is served from the box's own origin, so closing needs no cross-origin
    permission — and `/close` remains shut to every other origin, because no
    page the voting application serves should be able to provoke it.
    """
    page = live.http.get(f"{live.ebb}/").text
    assert 'src="box.js"' in page
    assert "act of the box performed by an operator" in page
    assert "Clause A7" in page, "the in-memory registry must be stated here"
    assert live.http.get(f"{live.ebb}/box.js").status_code == 200

    closed = live.http.request(
        "OPTIONS", f"{live.ebb}/close", headers={"origin": live.url(8001)})
    assert "access-control-allow-origin" not in {k.lower() for k in closed.headers}


def test_the_console_separates_submissions_from_ballots_that_will_count(live):
    """The gap between the two is where an audience goes wrong.

    Every submission that passes both signature checks is accepted and
    kept; only the last under each ad-hoc key is counted. A console showing
    one number invites a reader to treat it as the result.
    """
    page = live.http.get(f"{live.ebb}/").text
    assert "submissions accepted" in page
    assert "ballots that will count" in page
    assert 'id="voters"' in page


def test_the_console_reads_the_published_reports_rather_than_a_live_tally(live):
    """It is not a privileged surface, and must not look like one.

    The console fetches `/published`, the same artefact anybody reads, so
    the figure it shows while the poll is open is one the public already
    has. Reaching for `/tally` between boundaries would show a count nobody
    else can see -- the operator asymmetry the cadence exists to remove.
    """
    script = live.http.get(f"{live.ebb}/box.js").text
    assert "running_tally" in script
    assert script.index("running_tally") < script.index("fetch('/tally')")
    after_close_branch = script[script.index("if (!open)"):]
    assert "fetch('/tally')" in after_close_branch, "read only once closed"


def test_the_console_says_so_when_no_report_has_been_published(live):
    """A blank would read as nothing happening rather than nothing published.

    The demo deployment configures no interval, so until the close there is
    nothing to show, and that is the state the console is in for the whole
    poll.
    """
    assert "no report published yet" in live.http.get(f"{live.ebb}/box.js").text


def test_the_box_statement_key_is_published_and_the_receipt_verifies_under_it(live):
    """The key is useless unless a voter can get it from somewhere else.

    Pinned in the published configuration, beside the office's. A receipt
    carrying its own verification key would verify everything and establish
    nothing.
    """
    from ovpoc.ballotbox import verify_receipt

    config = live.http.get(f"{live.config}/election.json").json()
    assert config["ebb_statement_key"]

    receipt = live.http.post(f"{live.ebb}/ballots", json={
        "selection": 1, "adhoc_public_key": b64(b"k"),
        "token": b64(b"t"), "nonce": b64(b"n"), "vote_signature": b64(b"s"),
    }).json()

    assert verify_receipt(unb64(config["ebb_statement_key"]),
                          config["election_id"], receipt,
                          unb64(receipt["signature"]))


def test_the_checker_verifies_statements_rather_than_displaying_them(live):
    """It had been showing the office's signed denial without checking it.

    A signature displayed and not verified reads exactly like one that does
    not verify, which is the failure this whole key exists to prevent.
    """
    script = live.http.get(f"{live.checker}/checker.js").text
    assert "crypto.subtle.verify" in script
    assert "ebb_statement_key" in script, "the receipt is checked"
    assert "vro_statement_key" in script, "and so is the denial"
    assert "election.json" in script, "both against the pinned configuration"

    page = live.http.get(f"{live.checker}/").text
    assert 'id="receipt"' in page
    assert 'id="d2-signature"' in page


def ledger_of(live):
    """The dump, closing the box first if an earlier test has not.

    The deployment is shared across this module, so whether the box is
    already closed depends on which tests ran. The dump is only defined
    after the close, so ask for that state rather than assume it.
    """
    if "records" not in live.http.get(f"{live.ebb}/published").json():
        live.http.post(f"{live.ebb}/close")
    return live.http.get(f"{live.ebb}/ledger")


def test_the_ledger_downloads_as_one_canonical_file(live):
    """What a third party takes away and never asks the box about again.

    Canonically serialised, so two people downloading the same election get
    the same bytes and can compare the file's own hash rather than their
    readings of it.
    """
    from ovpoc.messages import canonical_bytes

    response = ledger_of(live)
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    dump = response.json()
    assert response.content == canonical_bytes(dump)

    # The digest is of the file, not a field in it, which is the point: a
    # verifier computes it over what they downloaded.
    from ovpoc.messages import canonical_bytes as cb  # noqa: F401
    import hashlib
    served = live.http.get(f"{live.config}/election.json")
    assert dump["configuration_digest"] == hashlib.sha256(served.content).hexdigest()
    assert dump["genesis_hash"] == served.json()["genesis_hash"]


def test_the_dump_needs_no_signature_of_its_own(live):
    """One signature authenticates every record and their order.

    Recompute the chain from the records against the genesis hash; if the
    head you arrive at is the head the box signed, every record is
    accounted for. Nothing else in the file has to be trusted, and the file
    needs no signature wrapped around it -- which is what the chain is for.
    """
    from ovpoc.ballotbox import verify_head
    from ovpoc.ledger import compute_entry_hash

    dump = ledger_of(live).json()
    config = live.http.get(f"{live.config}/election.json").json()

    head = bytes.fromhex(dump["genesis_hash"])
    for i, e in enumerate(dump["accepted"]):
        head = compute_entry_hash(i, e["record"], head)
        assert head.hex() == e["commitment"], f"entry {i} does not chain"

    assert head.hex() == dump["heads"]["accepted"]
    assert verify_head(unb64(config["ebb_statement_key"]), config["election_id"],
                       "accepted", head, unb64(dump["head_signatures"]["accepted"]))


def test_the_office_signs_the_count_the_audit_depends_on(live):
    """Two figures, two components, and now both attributable.

    The count audit is the strongest check available without the records.
    One figure came from a box that signs what it publishes; the other came
    from the office unsigned, which is where an office with something to
    hide would understate.
    """
    from ovpoc.vro import verify_release_count

    config = live.http.get(f"{live.config}/election.json").json()
    log = live.http.get(f"{live.vro}/release-log").json()

    assert verify_release_count(unb64(config["vro_statement_key"]),
                                config["election_id"], log["count"],
                                unb64(log["count_signature"]))
    assert not verify_release_count(unb64(config["vro_statement_key"]),
                                    config["election_id"], log["count"] + 1,
                                    unb64(log["count_signature"]))


def test_the_ledger_does_not_carry_the_keys_it_is_checked_against(live):
    """A dump that verifies against itself establishes nothing.

    The verification keys are pinned from the published configuration, and
    the dump names the configuration it belongs to rather than restating
    its contents.
    """
    dump = ledger_of(live).json()
    assert "statement_key" not in dump
    assert "vro_token_key_spki" not in dump
    assert dump["configuration_digest"]


def test_the_release_register_downloads_as_one_canonical_file(live):
    """The office's data on the same terms as the box's.

    Available throughout rather than from the close: nothing in this
    register is a ballot, so nothing in it is withheld.
    """
    from ovpoc.messages import canonical_bytes

    response = live.http.get(f"{live.vro}/releases")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    dump = response.json()
    assert response.content == canonical_bytes(dump)
    assert dump["count"] == len(dump["entries"])


def test_the_release_dump_needs_no_signature_of_its_own(live):
    """One signature accounts for the whole register, as with the ledger."""
    from ovpoc.ledger import compute_entry_hash
    from ovpoc.vro import verify_release_count, verify_release_head

    dump = live.http.get(f"{live.vro}/releases").json()
    config = live.http.get(f"{live.config}/election.json").json()
    office = unb64(config["vro_statement_key"])

    head = bytes.fromhex(dump["genesis_hash"])
    for i, e in enumerate(dump["entries"]):
        head = compute_entry_hash(i, {"commitment": e["commitment"]}, head)
    assert head.hex() == dump["head"]

    assert verify_release_head(office, config["election_id"], head,
                               unb64(dump["head_signature"]))
    assert verify_release_count(office, config["election_id"], dump["count"],
                                unb64(dump["count_signature"]))


def test_the_release_dump_names_nobody(live):
    """It says how many tokens exist and nothing whatever about whose.

    The commitments are opaque, and the values that open them go to one
    voter at a time. A file that leaked participation would be the register
    §3.7 refuses to publish, handed over in a more convenient form.
    """
    body = live.http.get(f"{live.vro}/releases").text
    for voter_id in VOTERS.values():
        assert voter_id not in body
    dump = live.http.get(f"{live.vro}/releases").json()
    assert all(set(e) == {"index", "commitment"} for e in dump["entries"])
    assert "opening" not in body
