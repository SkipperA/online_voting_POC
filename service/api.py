"""The endpoints of the four remaining origins.

Everything here parses, calls `ovpoc`, and serialises.  No acceptance rule,
no ordering rule and no disclosure rule lives in this file: those are in
`src/ovpoc`, where the sabotage suite can reach them.  The test of that claim
is that the mutation report does not change when this file is added.

Field names follow `docs/wire-contract.md`.  Binary values are base64url
without padding, as canonical JSON already requires, so a reader needs one
decoder rather than two.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from ovpoc import keys, rsabssa
from ovpoc.ballotbox import BoxStillOpen, verify_phase
from ovpoc.messages import AuthRequest, Ballot, b64, canonical_bytes, unb64
from ovpoc.vro import release_query_payload

from . import origins
from .state import Deployment


def _for_checker(request) -> str:
    """The checker's origin, as the browser will have spelled it.

    Echoed rather than canonical: the surface is identified by its port, so
    a page served at localhost and one at 127.0.0.1 are the same checker.
    Anything else gets the canonical name and is refused by the browser,
    which is the point -- this is still a named origin and not `*`.
    """
    sent = request.headers.get("origin")
    return sent if origins.CHECKER.matches(sent) else origins.CHECKER.url

# Loaded rather than imported: the verifier lives in `tools/` and
# deliberately imports nothing from this project, which is the whole of its
# value. Reaching into it one way keeps that true.
VERIFIER_SOURCE = Path(__file__).resolve().parents[1] / "tools" / "verify_election.py"
_spec = importlib.util.spec_from_file_location("ovpoc_verifier", VERIFIER_SOURCE)
_verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_verifier)
run_checks = _verifier.run_checks

#: The dump's own version, independent of the wire contract and the
#: store: a verifier written against one shape should refuse another
#: rather than read it hopefully.
LEDGER_FORMAT = "ovpoc-ledger/1"
RELEASES_FORMAT = "ovpoc-releases/1"
SUPERVISION_FORMAT = "ovpoc-supervision/1"


# --------------------------------------------------------------------------
# Wallet — 8002
# --------------------------------------------------------------------------

class PersonaBody(BaseModel):
    voter_id: str


class SignBody(BaseModel):
    voter_id: str
    blinded_key: str


def wallet_app(deployment: Deployment, base) -> FastAPI:
    """The wallet holds `id` and signs; the voting application never gets it.

    B4 gives the wallet the blinded value and nothing else.  B7 has the
    wallet transmit `[id, c, s]` to the office *itself* rather than returning
    a signed request for the application to forward: were the application to
    handle `id`, one component on the voter's own device would hold both
    halves of the association the blind signature exists to sever, together
    with the office's signature over it (§5.3).

    What keeps that boundary is the origin rather than the shape of the
    replies below.  A wallet reachable cross-origin by the voting
    application would be an API with a consent screen painted on it, so this
    origin grants nothing to anyone and every handover is a file the voter
    carries.  Inside that closure the wallet's own page may see whose wallet
    it is, which is the whole of what a consent screen is for.

    Every endpoint here names its persona in the call.  One process plays a
    whole electorate, and the alternative is server-side state recording who
    is active -- which, being shared by every client of this origin, makes
    the last selection the signer for all of them: a hundred voters choosing
    a hundred identifiers would produce one token and ninety-nine refusals
    for a citizen who never asked.  A real wallet has one owner, one key and
    no parameter.  Clause A3.
    """
    app = base(origins.WALLET)

    def _persona(voter_id: str) -> keys.SigningKeyPair:
        try:
            return deployment.wallets[voter_id]
        except KeyError:
            raise HTTPException(404, "no such persona on this demo machine")

    @app.post("/requests")
    async def sign_and_transmit(body: SignBody) -> dict:
        """B5–B7. The voter authorises; the wallet signs and transmits.

        The office is called directly rather than through a reply to the
        application, so the application never sees the request it caused.
        """
        voter_id = body.voter_id
        wallet = _persona(voter_id)
        blinded = unb64(body.blinded_key)
        request = AuthRequest(
            voter_id=voter_id,
            blinded_key=blinded,
            wallet_signature=b"",
        )
        request = AuthRequest(
            voter_id=voter_id,
            blinded_key=blinded,
            wallet_signature=wallet.sign(request.signed_payload()),
        )
        # Transmitted to the office over the wire, from this origin to that
        # one. A direct call into `deployment.vro` would be the arrangement
        # §5.3 rejects, wearing the name of the one it argues for -- and no
        # test could tell the two apart.
        async with httpx.AsyncClient(timeout=30.0) as http:
            reply = await http.post(
                f"{origins.VRO.url}/token-requests",
                json={
                    "voter_id": request.voter_id,
                    "blinded_key": b64(request.blinded_key),
                    "wallet_signature": b64(request.wallet_signature),
                },
            )
        # The outcome, and nothing that names anyone, is all the *application*
        # may be told. This is the wallet's own page asking, from the wallet's
        # own origin, so it may also see what the wallet built and sent --
        # which is the point of a demonstration.
        return {
            "outcome": reply.json()["outcome"],
            "transmitted": {
                "_transport": (
                    "sent by the wallet to the office over HTTP, from this "
                    "origin to that one. It does not pass through the voting "
                    "application: §5.3 -- one component holding both id and "
                    "k_p^a would keep the association the blind signature "
                    "exists to sever, with the office's signature as proof."
                ),
                "voter_id": request.voter_id,
                "blinded_key": b64(request.blinded_key),
                "wallet_signature": b64(request.wallet_signature),
            },
            "signed_bytes": request.signed_payload().hex(),
        }

    @app.post("/keys")
    async def wallet_keys(body: PersonaBody) -> dict:
        """The persona's key pair, for the demonstration.

        A real wallet exposes no such endpoint. Under eIDAS the signature key
        is hardware-bound by regulation: it cannot be read by the wallet
        application itself, let alone returned over HTTP. It is shown here
        because a demonstration in which the keys are invisible teaches
        nothing about what the keys do.

        A POST for what is plainly a read, because the persona travels in the
        body as it does everywhere else on this origin: `fetch` forbids a body
        on GET, and the alternative puts an identifier in a URL that the
        browser keeps in its history and the server writes to a log.
        """
        voter_id = body.voter_id
        pair = _persona(voter_id)
        return {
            "_never_exposed_in_a_deployment": (
                "k_s^(v) is hardware-bound under eIDAS. No interface, file or "
                "log may contain it. This endpoint exists for the demo only."
            ),
            "voter_id": voter_id,
            "k_p^(v)": b64(pair.public_bytes),
            "k_s^(v)": b64(
                pair.private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
        }

    @app.get("/personas")
    async def personas() -> dict:
        """The list exists only because one machine plays a whole electorate.

        A real wallet has one owner and offers no such choice. Clause A3.
        """
        return {"personas": sorted(deployment.wallets)}

    @app.post("/release-query-credentials")
    async def release_credentials(body: PersonaBody) -> dict:
        """D1. The wallet signs the query; the checker carries it.

        §3.7 permits this: the wallet is not the component under audit, so
        signing in it is ordinary. What the check requires is independence
        from the *voting application*, which is why these credentials go to
        the checker origin and never to 8001.
        """
        voter_id = body.voter_id
        wallet = _persona(voter_id)
        return {
            "voter_id": voter_id,
            "signature": b64(wallet.sign(release_query_payload(voter_id))),
        }

    return app


# --------------------------------------------------------------------------
# VRO — 8003
# --------------------------------------------------------------------------

class TokenRequestBody(BaseModel):
    voter_id: str
    blinded_key: str
    wallet_signature: str


class ReleaseQueryBody(BaseModel):
    voter_id: str
    signature: str


def vro_app(deployment: Deployment, base) -> FastAPI:
    app = base(origins.VRO)
    vro = deployment.vro

    @app.middleware("http")
    async def reply_is_readable_cross_origin(request, call_next):
        """Only `GET /token-replies/…` may be read by another origin.

        The voting application is on 8001 and collects the reply from here,
        so that one endpoint must be cross-origin readable. It is safe to make
        it so: §5.3 notes that an intercepted `c` yields an intercepted `s_c`
        and no advantage whatever, because unblinding needs the `r` that never
        leaves the application.

        Nothing else on this origin is opened. `/release-queries` in
        particular must stay closed to a page the voting application serves:
        §3.7 requires that check to be independent of the voting application,
        and a blanket allowance would hand 8001 exactly the access the design
        withholds.
        """
        path = request.url.path
        # The checker audits this office, so it must be able to read the
        # register and ask the release question. Named origin, not `*`: the
        # closure that matters is against a page the *voting application*
        # serves (§3.7), and naming the checker keeps that argument intact
        # instead of trading it for convenience.
        for_checker = path in ("/release-log", "/release-queries", "/releases")
        if request.method == "OPTIONS" and for_checker:
            return Response(status_code=204, headers={
                "Access-Control-Allow-Origin": _for_checker(request),
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "content-type",
                "Access-Control-Max-Age": "600",
            })
        response = await call_next(request)
        if request.method == "GET" and path.startswith("/token-replies/"):
            response.headers["Access-Control-Allow-Origin"] = "*"
        elif for_checker:
            response.headers["Access-Control-Allow-Origin"] = _for_checker(request)
        return response

    @app.post("/token-requests")
    async def token_request(body: TokenRequestBody) -> dict:
        """B7–B15. The office receives `[id, c, s]` and decides.

        Reachable by anyone who can address this origin, which is the point:
        the office's checks must withstand a request that did not come from a
        wallet at all. Every one of those checks is in `ovpoc.vro`; this
        function chooses nothing and, in particular, does not decide what may
        be disclosed -- the outcome enum already encodes that boundary, with
        the two pre-identification failures collapsed into one refusal
        (§3.2).
        """
        try:
            blinded = unb64(body.blinded_key)
            signature = unb64(body.wallet_signature)
        except ValueError:
            raise HTTPException(400, "malformed base64url field")

        request = AuthRequest(
            voter_id=body.voter_id,
            blinded_key=blinded,
            wallet_signature=signature,
        )
        if deployment.manual_release:
            # Validate and claim the identifier; the signature waits for an
            # operator. The voter's application sees no difference except
            # that its reply is not there yet, which is the state B16 was
            # built to tolerate.
            reserved = vro.reserve(request)
            if reserved.outcome.name == "RESERVED":
                deployment.held_requests[request.voter_id] = request
                # What the requester is actually told. The office records
                # RESERVED; the transport names the state in its own
                # vocabulary, and the audit log must show the disclosure
                # rather than the internal result.
                return {"outcome": "AWAITING_RELEASE"}
            return {"outcome": reserved.outcome.name}

        response = vro.issue_token(request)
        if response.issued:
            # Held for collection at B16 rather than returned here: the reply
            # belongs to the application, which is not the party that asked.
            deployment.token_replies[blinded] = response.blind_signature
        return {"outcome": response.outcome.name}

    @app.get("/token-replies/{blinded_key}")
    async def collect(blinded_key: str) -> dict:
        """B16. The application collects by presenting `c`.

        404 until the reply exists, and the client polls. Nothing clever:
        no held connection, no framework feature doing the waiting where a
        reader cannot see it. `c` is unguessable and was generated by the
        application, so presenting it is sufficient and no second credential
        is invented. Action table gap 5, resolved in the dullest direction.
        """
        try:
            reply = deployment.token_replies[unb64(blinded_key)]
        except (KeyError, ValueError):
            raise HTTPException(404, "no reply for this blinded value")
        return {"blind_signature": b64(reply)}

    @app.post("/release-queries")
    async def release_query(body: ReleaseQueryBody) -> dict:
        """D1, answered by the office over its own register."""
        answer = vro.query_token_release(body.voter_id, unb64(body.signature))
        out = {"outcome": answer.outcome.name, "released": answer.released}
        if answer.opening is not None:
            out["opening"] = b64(answer.opening)
            out["index"] = answer.index
        if answer.signed_denial is not None:
            out["signed_denial"] = b64(answer.signed_denial)
        return out

    @app.get("/back-office/keys")
    async def office_keys() -> dict:
        """The office's two key pairs, for the demonstration.

        No deployment exposes this. `k_s^(R)` is the blind-signing key and is
        an oracle by construction — anything that could read it could mint
        tokens at will. It is shown because a demonstration in which the keys
        are invisible teaches nothing about why there are two of them.
        """
        return {
            "_never_exposed_in_a_deployment":
                "k_s^(R) and k_s^(O) exist only inside the signing operations.",
            "k_p^(R)": b64(
                vro.public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)),
            "k_p^(R) fingerprint": rsabssa.public_key_fingerprint(vro.public_key),
            "k_p^(R) purpose": (
                "signs tokens, and nothing else, for this election only. One "
                "key for every voter: a per-voter key would let the office "
                "re-link a ballot to the citizen who asked (§3.3)."
            ),
            "k_p^(O)": b64(vro.office_public_key),
            "k_p^(O) purpose": (
                "signs the office's statements — the denial of §3.7 — and "
                "never a token. A statement signed under the token key could "
                "be manufactured by any registered voter through an ordinary "
                "request, so it would be worthless as evidence."
            ),
        }

    @app.get("/back-office/pending")
    async def pending() -> dict:
        return {
            "manual_release": deployment.manual_release,
            "pending": [
                {"voter_id": v, "blinded_key": b64(r.blinded_key)[:48] + "…"}
                for v, r in deployment.held_requests.items()
            ],
        }

    @app.post("/back-office/mode")
    async def set_mode(body: dict) -> dict:
        """Whether the office signs at once or waits for an operator.

        A deployment has no such switch: it signs as soon as it has
        validated, and the reservation exists for concurrency rather than
        for deliberation. The switch is here so a demonstration can hold a
        real state open long enough to be looked at.
        """
        deployment.manual_release = bool(body.get("manual"))
        return {"manual_release": deployment.manual_release}

    @app.post("/back-office/release")
    async def operator_release(body: dict) -> dict:
        """6/A, performed as a deliberate act.

        The release commitment is written here and not at validation —
        before the signature, as §5.4 requires, and not one moment earlier.
        Publishing it at reservation would make the office's deliberation
        visible to anyone counting, and overstate the tokens that exist.
        """
        voter_id = body.get("voter_id", "")
        request = deployment.held_requests.pop(voter_id, None)
        if request is None:
            raise HTTPException(404, "no held request for that id")
        response = vro.release(request)
        if response.issued:
            deployment.token_replies[request.blinded_key] = response.blind_signature
        return {"outcome": response.outcome.name}

    @app.post("/back-office/cancel")
    async def operator_cancel(body: dict) -> dict:
        """A claim that will never complete needs a route back.

        Without this the citizen stays reserved with nothing published, no
        token, and no way to ask again.
        """
        voter_id = body.get("voter_id", "")
        deployment.held_requests.pop(voter_id, None)
        return {"cancelled": vro.cancel_reservation(voter_id)}

    @app.get("/back-office/audit")
    async def office_audit() -> dict:
        """What the office recorded, beside what it disclosed.

        §3.2 is entirely about the gap between these two columns. The office
        records the true reason for every refusal; it returns one
        indistinguishable answer for the two failures that arise before it
        knows who it is speaking to, because otherwise anyone able to spell
        an identifier could learn from the answer whether that citizen holds
        a certificate and appears on the register.

        A console may show both, because it is the office looking at itself.
        No deployment exposes this over HTTP, and the office's own log is a
        participation list — which is the thing §3.7 spends a page keeping
        out of anyone else's hands.
        """
        return {
            "_never_exposed_in_a_deployment": (
                "This is the office's private log. It names who asked and "
                "when, which is precisely what a coercer demanding "
                "participation needs."
            ),
            "entries": [
                {
                    "voter_id": entry.voter_id,
                    "recorded": entry.reason,
                    # RESERVED is what the office recorded; what the
                    # requester was told is the transport's word for that
                    # state, and this column is about what was said.
                    # RESERVED is what the office recorded. What the
                    # requester was told is the transport's word for that
                    # state, and this column is about what was said — a
                    # cancellation says nothing to anybody at all.
                    "disclosed": (
                        "— (operator act; nothing disclosed)"
                        if entry.reason == "reservation cancelled"
                        else "AWAITING_RELEASE"
                        if entry.outcome.name == "RESERVED"
                        else entry.outcome.name
                    ),
                    "reason_withheld": entry.outcome.name == "NOT_IDENTIFIED",
                }
                for entry in vro.audit_log
            ],
        }

    @app.get("/releases")
    async def releases() -> Response:
        """The release register as one file, on the ledger's terms.

        Available throughout, unlike the box's dump: the register is
        published as tokens are released (Table 1), and nothing in it is
        withheld until the close because nothing in it is a ballot.

        Like the ledger it carries no signature of its own and needs none.
        Recompute the chain from the commitments against the genesis hash;
        if the head you reach is the head the office signed under k_p^(O),
        the whole register is accounted for by that one signature.

        What it does not carry is who. The commitments name nobody, and
        the values that open them are released to one voter at a time, to
        the voter who can authenticate a query about their own. A reader of
        this file learns how many tokens exist and nothing whatever about
        whose (Section 3.7).
        """
        head, head_signature = vro.signed_release_head()
        count, count_signature = vro.signed_release_count()
        dump = {
            "format": RELEASES_FORMAT,
            "election_id": deployment.config.election_id,
            "configuration_digest": deployment.config.digest_hex(),
            "genesis_hash": deployment.config.genesis_hash.hex(),
            "entries": [
                {"index": e.index, "commitment": e.payload["commitment"]}
                for e in vro.release_log.entries
            ],
            "head": head.hex(),
            "head_signature": b64(head_signature),
            "count": count,
            "count_signature": b64(count_signature),
            "supervisor_downloads": vro.supervisor_downloads,
        }
        name = f"VRO_dump_{deployment.config.election_id}.json"
        return Response(
            content=canonical_bytes(dump),
            media_type="application/json",
            headers={"content-disposition": f'attachment; filename="{name}"'},
        )

    @app.get("/release-log")
    async def release_log() -> dict:
        """The published register: commitments, and nothing about whose.

        Published as tokens are released (Table 1). The commitments are never
        opened here -- one at a time, to the voter who can authenticate a
        query about their own, and to nobody else.

        The count is signed under the office's statement key. It is one of
        the two figures in the count audit, and the other comes from a box
        that signs what it publishes; unsigned, the strongest aggregate
        check in the design rested on an unattributable claim made by the
        party with the motive to understate it.
        """
        head, head_signature = vro.signed_release_head()
        count, count_signature = vro.signed_release_count()
        return {
            "entries": [e.payload for e in vro.release_log.entries],
            "head": head.hex(),
            "head_signature": b64(head_signature),
            "count": count,
            "count_signature": b64(count_signature),
            "supervisor_downloads": vro.supervisor_downloads,
        }

    return app


# --------------------------------------------------------------------------
# Electronic ballot box — 8004
# --------------------------------------------------------------------------

class BallotBody(BaseModel):
    selection: int
    adhoc_public_key: str
    token: str
    nonce: str
    vote_signature: str


def ebb_app(deployment: Deployment, base) -> FastAPI:
    app = base(origins.EBB)
    box = deployment.ebb

    # The voter casts from 8001 and checks from 8005, so the ballot paths and
    # the published view must be readable across origins. `POST /ballots`
    # carries a JSON content type, which is not a simple request, so the
    # preflight has to be answered too.
    #
    # `/close` and `/tally` are deliberately left out. Closing the poll is an
    # act of the box performed by an operator (E1); a page should not be able
    # to provoke it, least of all a page the voting application serves.
    #: `/ledger` joins the published view here: both are artefacts anyone
    #: may read (Table 1), and the checker offers the download. Navigation
    #: would not need it, but a page that fetches the file to save it does,
    #: and the two should not differ by how the button happens to work.
    CROSS_ORIGIN = {"/ballots", "/published", "/ledger"}

    def _open(path: str) -> bool:
        return path in CROSS_ORIGIN or path.startswith("/ballots/")

    @app.middleware("http")
    async def ballot_paths_are_cross_origin(request, call_next):
        if not _open(request.url.path):
            return await call_next(request)
        if request.method == "OPTIONS":
            return Response(status_code=204, headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "content-type",
                "Access-Control-Max-Age": "600",
            })
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    @app.middleware("http")
    async def tally_is_readable_by_the_checker(request, call_next):
        """`/tally` opens to the checker alone; `/close` to nobody.

        Anyone may recompute the result from the released records, so reading
        the box's own figure is no privilege. Closing the poll is an act of
        the box performed by an operator (E1), and no page should provoke it.
        """
        response = await call_next(request)
        if request.url.path == "/tally":
            response.headers["Access-Control-Allow-Origin"] = _for_checker(request)
        return response

    @app.post("/ballots")
    async def submit(body: BallotBody) -> dict:
        """C3–C6. Accept or reject, then return the receipt.

        The box decides; this function only carries the answer. Note there is
        no anonymising channel on localhost -- clause A2. The submission is
        as traceable as any other localhost request.
        """
        ballot = Ballot(
            selection=body.selection,
            adhoc_public_key=unb64(body.adhoc_public_key),
            token=unb64(body.token),
            nonce=unb64(body.nonce),
            vote_signature=unb64(body.vote_signature),
        )
        try:
            result = box.submit(ballot)
        except BoxStillOpen as exc:       # pragma: no cover - defensive
            raise HTTPException(409, str(exc))
        return {
            "accepted": result.accepted,
            "reason": result.reason,
            "index": result.index,
            "entry_hash": b64(result.entry_hash),
            "signature": b64(result.signature),
        }

    @app.get("/ledger")
    async def ledger() -> Response:
        """E3. The whole registry as one file, for checking elsewhere.

        The point is not the endpoint. A third party who checks through a
        service the box operates has checked nothing the operator could not
        have arranged; what carries the claim of Section 6 -- that any
        citizen can recompute the result with standard libraries -- is that
        the records leave here as bytes and are never consulted again.

        It needs no signature of its own. A verifier who recomputes the chain
        from these records against the genesis hash and arrives at the head
        the box signed has authenticated every record and their order with
        that one signature; that is what the chain is for.

        Serialised canonically, so that two people downloading the same
        election get the same bytes and can compare the file's own hash
        across mirrors (Section 3.5) rather than comparing their readings of
        it. Refused while voting is open, for the reason the records are
        withheld at all.

        The office's released-token count is deliberately absent. The audit
        it feeds is worth something precisely because the two figures come
        from two components, so the box does not vouch for the office's: a
        verifier fetches it from the office, signed under k_p^(O).
        """
        view = deployment.ebb.published_view()
        if "records" not in view:
            raise HTTPException(409, "the registry is published in clear at the close")

        dump = {
            "format": LEDGER_FORMAT,
            "election_id": deployment.config.election_id,
            "configuration_digest": deployment.config.digest_hex(),
            "genesis_hash": deployment.config.genesis_hash.hex(),
            "accepted": [
                {"index": c["index"], "commitment": c["commitment"], "record": r}
                for c, r in zip(view["commitments"]["accepted"], view["records"]["accepted"])
            ],
            "rejected": [
                {"index": c["index"], "commitment": c["commitment"], "record": r}
                for c, r in zip(view["commitments"]["rejected"], view["records"]["rejected"])
            ],
            "heads": view["heads"],
            "head_signatures": view["head_signatures"],
        }
        name = f"EBB_dump_{deployment.config.election_id}.json"
        return Response(
            content=canonical_bytes(dump),
            media_type="application/json",
            headers={"content-disposition": f'attachment; filename="{name}"'},
        )

    @app.get("/published")
    async def published() -> dict:
        """C7 and E3–E4. The view changes at the close; no row moves back."""
        return box.published_view()

    @app.get("/ballots/{adhoc_public_key}")
    async def find(adhoc_public_key: str) -> dict:
        """D3. `k_p^a` is the lookup secret while voting is open (§3.7).

        Unguessable, known only to the application and the box, and it
        confers no power to sign anything -- which is what lets the check run
        on a device the voting application does not control.
        """
        try:
            record = box.find_ballot(unb64(adhoc_public_key))
        except ValueError:
            raise HTTPException(400, "malformed key")
        if record is None:
            raise HTTPException(404, "no ballot filed under that key")
        return record

    @app.post("/open")
    async def open_poll() -> dict:
        """A9. The other act, and the one that had no interface.

        Creating the deployment used to be the opening, which meant a
        demonstration could never show the state before it: a box that is
        not yet open refuses submissions for a different reason than one
        that has shut, and neither could be shown.
        """
        try:
            box.open()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        at, _ = box.opened_at()
        return {"open": True, "at": at}

    @app.post("/close")
    async def close() -> dict:
        """E1. An act of the box, performed by an operator, not a clock."""
        try:
            box.close()
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        return {"closed": True, "head": b64(box.accepted.head())}

    @app.get("/tally")
    async def tally() -> dict:
        """The last published figures, not the live count.

        Refused while open until the first publication point. The operator
        gets no privileged early sight: before a boundary there is no tally
        to be had, for anyone, and after one there is a tally the public
        has too. The 409 carries that rather than hiding it behind an empty
        result.
        """
        try:
            return box.tally()
        except BoxStillOpen as exc:
            raise HTTPException(409, str(exc))

    return app


# --------------------------------------------------------------------------
# Setup console — 8009
# --------------------------------------------------------------------------

class EnrolBody(BaseModel):
    voter_id: str


class TallyIntervalBody(BaseModel):
    seconds: int | None = None


def supervisor_app(deployment: Deployment, base) -> FastAPI:
    """8006 — the release register with the identifiers in it.

    No supervisor list and no signature. The protection is the perimeter:
    this origin is reachable only from inside the operator's network, and
    whoever can reach it is a supervisor by construction. That is how it
    would be deployed, behind a VPN whose key is the credential, and
    building a registry and a replay defence in front of a demonstration
    would have protected it from nobody.

    Its own origin rather than a path on the office, because a browser
    origin is scheme, host and port: a page that can read identifiers must
    not share a fetch policy with the endpoints a voter's device talks to.
    It is also the one origin that must not be exposed when the rest are.

    Open only once the box has closed. While the poll is open this is a live
    list of who has and has not taken part, which is the lever §3.7
    describes -- an enforcer of a boycott needs to establish only that a
    citizen did not participate. Reading the box's state from here is a
    shortcut this deployment can take because both run in one process; a
    real one needs the box's signed statement that it closed.
    """
    app = base(origins.SUPERVISOR)

    def _dump() -> dict:
        # The office opens supervision on the box's *signed statement* that
        # it closed, verified under the key pinned in the published
        # configuration -- not on the box's memory, which is what reading
        # `published_view()` from here amounted to. Both run in one process,
        # so the old check was correct and proved nothing: a separate
        # deployment would have had to ask, and this is what it would ask
        # for. The statement is also what a supervisor can be shown, if
        # they want to know on whose word the register was released.
        closed = deployment.ebb.closed_at()
        if closed is None or not verify_phase(
            deployment.config.ebb_statement_key, deployment.config.election_id,
            "closed", closed[0], closed[1],
        ):
            raise HTTPException(409, "supervision opens when the ballot box closes")
        closed_at, closing_statement = closed
        return {
            "format": SUPERVISION_FORMAT,
            "election_id": deployment.config.election_id,
            "configuration_digest": deployment.config.digest_hex(),
            "genesis_hash": deployment.config.genesis_hash.hex(),
            **deployment.vro.supervision_dump(),
            "supervisor_downloads": deployment.vro.supervisor_downloads,
            # On whose word this was released. A supervisor can check it
            # under the same key, and so can anyone they show it to.
            "closed_at": closed_at,
            "closing_statement": b64(closing_statement),
        }

    @app.get("/certificates")
    async def certificates() -> dict:
        """The public keys the request signatures verify under.

        A supervisor must not take these from the office: a signature
        checked against a key the signer handed over verifies whatever the
        signer likes. In a deployment they come from the certification
        authority, against published trust lists -- the same place the
        electoral roll comes from, and for the same reason.

        They are served here because a demonstration with no certification
        authority in it would otherwise have no way to check a signature at
        all, which is worse. The page says where they came from.
        """
        return {
            "_not_an_authority": (
                "Served by the demonstration, not by a certification "
                "authority. A supervisor checking an office against keys "
                "that office supplied is checking it against itself."),
            "certificates": {
                voter_id: b64(certificate.public_key)
                for voter_id, certificate
                in deployment.vro.population_register.entries.items()
            },
        }

    @app.get("/data")
    async def data() -> dict:
        """For the page. Counted like any other release of the register."""
        return _dump()

    @app.get("/supervision")
    async def download() -> Response:
        """The same thing as a file, canonically serialised.

        It needs no signature of its own: recompute each commitment from its
        [id, opening] pair, chain them, and the head the office already
        signed accounts for the whole file.
        """
        dump = _dump()
        name = f"VRO_supervision_{deployment.config.election_id}.json"
        return Response(
            content=canonical_bytes(dump),
            media_type="application/json",
            headers={"content-disposition": f'attachment; filename="{name}"'},
        )

    return app


class VerificationBody(BaseModel):
    """The files as downloaded, verbatim.

    Text rather than parsed JSON, because the configuration digest is over
    the bytes that were served: re-rendering the object would change them
    and the ledger would appear to pin a configuration nobody published.
    Byte-for-byte is also the only thing worth checking -- a file that has
    been through a parser is no longer the file the box signed for.
    """

    election: str
    ledger: str
    releases: str


def verification_endpoints(app: FastAPI, deployment: Deployment) -> FastAPI:
    """The cross-check, on the checker origin.

    It held an origin of its own for a while, and should not have: a
    browser origin is a boundary between parties who must not read each
    other's data, and there is no such boundary between a visitor checking
    the published artefacts and a visitor checking files they were given.
    Same reader, same privileges -- none -- and neither holds election
    state. The distinction that is real is between asking the parties and
    asking nothing, which is a section on a page.

    What that merge costs is a sentence that used to be true of the
    origin: that it reads nothing from the deployment. It stays true of
    the verification, which reads only its arguments.

    It runs `tools/verify_election.py`, the same code the command line
    runs, loaded rather than reimplemented. A second implementation in the
    page would be a second thing to get right and could disagree with the
    first without anybody noticing.

    Being convenient, it is also the weaker check, and the page says so: a
    verdict from an origin the operator serves is a verdict from the
    operator. The script is downloadable here precisely so that the real
    check can be run somewhere else.
    """
    #: What each of the three files has to contain to be that file. Enough
    #: to tell them apart and to say which one is in the wrong place --
    #: not a schema, and not a substitute for the checks themselves.
    EXPECTED = {
        "election": ("the election configuration",
                     ("election_id", "vro_token_key_spki", "vro_statement_key",
                      "ebb_statement_key", "num_choices", "genesis_hash")),
        "ledger": ("the ballot box ledger",
                   ("format", "accepted", "rejected", "heads", "head_signatures")),
        "releases": ("the release register",
                     ("format", "entries", "head", "count")),
    }

    OTHER_FILES = {
        "ovpoc-supervision": (
            "the supervision register from the supervisor origin. That one "
            "names citizens and is a different artefact; the check needs the "
            "public release register the office serves at /releases"),
    }

    def _kind_of(parsed: dict) -> str | None:
        """Which of the three this looks like, by its own contents."""
        if isinstance(parsed, dict):
            if parsed.get("format", "").startswith("ovpoc-ledger"):
                return "ledger"
            if parsed.get("format", "").startswith("ovpoc-releases"):
                return "releases"
            if "vro_token_key_spki" in parsed:
                return "election"
        return None

    def _other_file(parsed: dict) -> str | None:
        """A file of ours, but not one of these three."""
        kind = parsed.get("format", "").rsplit("/", 1)[0] if isinstance(parsed, dict) else ""
        return OTHER_FILES.get(kind)

    def _parsed(slot: str, text: str) -> dict:
        """Read one file, and say what is wrong with it in words.

        A bare KeyError from deep inside the checks tells the reader that
        something called 'entries' was missing and nothing about which of
        three files to look at -- which is exactly how this failed the
        first time somebody used it.
        """
        label, required = EXPECTED[slot]
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"{label} is not JSON: {exc}")

        other = _other_file(parsed)
        if other:
            raise HTTPException(400, f"the file given as {label} is {other}.")

        looks_like = _kind_of(parsed)
        if looks_like and looks_like != slot:
            raise HTTPException(400, (
                f"the file given as {label} looks like "
                f"{EXPECTED[looks_like][0]}. The three go in their own slots."))

        missing = [key for key in required if key not in parsed]
        if missing:
            source = {"election": "config origin", "ledger": "ballot box",
                      "releases": "office"}[slot]
            raise HTTPException(400, (
                f"{label} is missing {', '.join(missing)}. It should be the "
                f"file the {source} serves."))
        return parsed

    @app.post("/check")
    async def check(body: VerificationBody) -> dict:
        for slot, text in (("election", body.election), ("ledger", body.ledger),
                           ("releases", body.releases)):
            _parsed(slot, text)
        try:
            report = run_checks(
                body.election.encode("utf-8"),
                body.ledger.encode("utf-8"),
                body.releases.encode("utf-8"),
            )
        except Exception as exc:
            raise HTTPException(400, (
                "the three files are each of the right kind, but one of them "
                f"could not be read through: {exc}"))
        return report.as_dict()

    @app.get("/verify_election.py")
    async def script() -> Response:
        """The verifier itself, so it can be run away from this origin."""
        return Response(VERIFIER_SOURCE.read_text(encoding="utf-8"),
                        media_type="text/x-python",
                        headers={"content-disposition":
                                 'attachment; filename="verify_election.py"'})

    return app


def setup_app(deployment: Deployment, base) -> FastAPI:
    """Build-time only. The poll must run with this origin stopped.

    A2, A3 and A5 happen here and then this origin has no further part. It is
    started by `python -m service` for convenience and can be omitted with
    `--without setup`, which is a test rather than an intention.
    """
    app = base(origins.SETUP)

    @app.post("/voters")
    async def enrol(body: EnrolBody) -> dict:
        public_key = deployment.enrol(body.voter_id)
        return {"enrolled": True, "wallet_public_key": b64(public_key)}

    @app.get("/voters")
    async def voters() -> dict:
        """The register, which is a set of identifiers and nothing else."""
        return {"voters": sorted(deployment.vro.register)}

    @app.post("/tally-interval")
    async def tally_interval(body: TallyIntervalBody) -> dict:
        """A5. The publication cadence, in seconds.

        There is no "running tally or not": there is an interval, and the
        close is always a publication point. An interval longer than the
        poll therefore means the close is the only one, which is what a
        small electorate wants -- the figure is a function of how many
        voters stand behind each published number, not of clock
        convenience.
        """
        try:
            deployment.set_tally_interval(body.seconds)
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))
        return {
            "tally_interval_seconds": body.seconds,
            "digest": deployment.config.digest_hex(),
        }

    @app.get("/configuration")
    async def configuration() -> dict:
        return {
            "election_id": deployment.config.election_id,
            "digest": deployment.config.digest_hex(),
            "token_key_fingerprint": deployment.config.token_key_fingerprint,
            "tally_interval_seconds": deployment.config.tally_interval_seconds,
            "register_size": len(deployment.vro.register),
        }

    return app
