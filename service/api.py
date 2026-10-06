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

import httpx
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from ovpoc import rsabssa
from ovpoc.ballotbox import BoxStillOpen
from ovpoc.messages import AuthRequest, Ballot, b64, unb64
from ovpoc.vro import release_query_payload

from . import origins
from .state import Deployment


# --------------------------------------------------------------------------
# Wallet — 8002
# --------------------------------------------------------------------------

class SessionBody(BaseModel):
    voter_id: str


class SignBody(BaseModel):
    blinded_key: str


def wallet_app(deployment: Deployment, base) -> FastAPI:
    """The wallet holds `id` and signs; it does not hand `id` back.

    B4 gives the wallet the blinded value and nothing else.  B7 has the
    wallet transmit `[id, c, s]` to the office *itself* rather than returning
    a signed request for the application to forward: were the application to
    handle `id`, one component on the voter's own device would hold both
    halves of the association the blind signature exists to sever, together
    with the office's signature over it (§5.3).

    So no response from this origin contains `voter_id` either.  The session
    endpoint is the exception that proves it -- it *accepts* an id, because a
    demo machine plays a whole electorate and something has to choose whose
    wallet is active.  A real wallet has one owner and no such endpoint.
    Clause A3.
    """
    app = base(origins.WALLET)
    app.state.active: str | None = None

    @app.post("/session")
    async def open_session(body: SessionBody) -> dict:
        if body.voter_id not in deployment.wallets:
            raise HTTPException(404, "no such persona on this demo machine")
        app.state.active = body.voter_id
        return {"active": True}      # deliberately not echoing the id

    def _active() -> str:
        if app.state.active is None:
            raise HTTPException(409, "no wallet session open")
        return app.state.active

    @app.post("/requests")
    async def sign_and_transmit(body: SignBody) -> dict:
        """B5–B7. The voter authorises; the wallet signs and transmits.

        The office is called directly rather than through a reply to the
        application, so the application never sees the request it caused.
        """
        voter_id = _active()
        wallet = deployment.wallets[voter_id]
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

    @app.get("/keys")
    async def wallet_keys() -> dict:
        """The persona's key pair, for the demonstration.

        A real wallet exposes no such endpoint. Under eIDAS the signature key
        is hardware-bound by regulation: it cannot be read by the wallet
        application itself, let alone returned over HTTP. It is shown here
        because a demonstration in which the keys are invisible teaches
        nothing about what the keys do.
        """
        voter_id = _active()
        pair = deployment.wallets[voter_id]
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
    async def release_credentials() -> dict:
        """D1. The wallet signs the query; the checker carries it.

        §3.7 permits this: the wallet is not the component under audit, so
        signing in it is ordinary. What the check requires is independence
        from the *voting application*, which is why these credentials go to
        the checker origin and never to 8001.
        """
        voter_id = _active()
        wallet = deployment.wallets[voter_id]
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
        for_checker = path in ("/release-log", "/release-queries")
        if request.method == "OPTIONS" and for_checker:
            return Response(status_code=204, headers={
                "Access-Control-Allow-Origin": origins.CHECKER.url,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "content-type",
                "Access-Control-Max-Age": "600",
            })
        response = await call_next(request)
        if request.method == "GET" and path.startswith("/token-replies/"):
            response.headers["Access-Control-Allow-Origin"] = "*"
        elif for_checker:
            response.headers["Access-Control-Allow-Origin"] = origins.CHECKER.url
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
            if reserved.outcome.name == "ISSUED":
                deployment.held_requests[request.voter_id] = request
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
        if answer.nonce is not None:
            out["nonce"] = b64(answer.nonce)
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
                    "disclosed": entry.outcome.name,
                    "reason_withheld": entry.outcome.name == "NOT_IDENTIFIED",
                }
                for entry in vro.audit_log
            ],
        }

    @app.get("/release-log")
    async def release_log() -> dict:
        """The published register: commitments, and nothing about whose.

        Published as tokens are released (Table 1). The commitments are never
        opened here -- one at a time, to the voter who can authenticate a
        query about their own, and to nobody else.
        """
        return {
            "entries": [e.payload for e in vro.release_log.entries],
            "head": vro.release_log.head().hex(),
            "count": vro.release_count(),
        }

    return app


# --------------------------------------------------------------------------
# Electronic ballot box — 8004
# --------------------------------------------------------------------------

class BallotBody(BaseModel):
    selection: int
    adhoc_public_key: str
    token: str
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
    CROSS_ORIGIN = {"/ballots", "/published"}

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
            response.headers["Access-Control-Allow-Origin"] = origins.CHECKER.url
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
            "ledger_head": b64(result.ledger_head),
        }

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

    @app.post("/close")
    async def close() -> dict:
        """E1. An act of the box, performed by an operator, not a clock."""
        box.close()
        return {"closed": True, "head": b64(box.accepted.head())}

    @app.get("/tally")
    async def tally() -> dict:
        """Refused while open unless a running tally is configured.

        The operator gets no privileged early sight: with `tally_interval`
        unset there is no tally to be had, for anyone. The 409 carries that
        rather than hiding it behind an empty result.
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

    @app.get("/configuration")
    async def configuration() -> dict:
        return {
            "election_id": deployment.config.election_id,
            "digest": deployment.config.digest_hex(),
            "token_key_fingerprint": deployment.config.token_key_fingerprint,
        }

    return app
