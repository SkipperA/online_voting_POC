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
from fastapi import FastAPI, HTTPException
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
        # The outcome, and nothing that names anyone. The application learns
        # only whether to start collecting the reply.
        return {"outcome": reply.json()["outcome"]}

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

        response = vro.issue_token(
            AuthRequest(
                voter_id=body.voter_id,
                blinded_key=blinded,
                wallet_signature=signature,
            )
        )
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

    @app.get("/configuration")
    async def configuration() -> dict:
        return {
            "election_id": deployment.config.election_id,
            "digest": deployment.config.digest_hex(),
            "token_key_fingerprint": deployment.config.token_key_fingerprint,
        }

    return app
