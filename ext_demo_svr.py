#!/usr/bin/env python3
"""ext_demo.py, over the wire: fifteen scenarios against running origins.

Every rejection below is produced by a server refusing a real request, not by
a method call on an object the script already holds.  That is the whole
difference from `ext_demo.py`, and it matters for the ones where the attacker
is a client: a check that only ever runs in-process has never been asked to
withstand anything.

**Four scenarios from `ext_demo.py` are absent, deliberately.**

`key_substitution` and `malicious_response` are attacks by the *office*, not
on it.  A client cannot make a server misbehave from outside, so running them
here would need the VRO to grow a deliberately-hostile mode -- attack code in
the service layer, switched on from the setup console.  That may yet be worth
it; it is not decided, so they stay in `ext_demo.py`.

`forgery` (multiplicative forgery against the raw RSA operation) and `ledger`
(altering a stored entry to break the chain) reach inside objects the network
never exposes.  A server version would have to *simulate* the tampering, which
is the thing the leaflet calls theatre.  They stay in-process, where they are
real.

Run `python -m service` in one terminal, then this script in another.
"""

from __future__ import annotations

import os
import sys
import textwrap
from dataclasses import dataclass, field

import httpx
from cryptography.hazmat.primitives import serialization

from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot, b64, unb64
from ovpoc.vro import verify_release_answer

OFFSET = int(os.environ.get("OVPOC_PORT_OFFSET", "0"))


def url(port: int) -> str:
    return f"http://127.0.0.1:{port + OFFSET}"


CONFIG, APP, WALLET, VRO, EBB, SETUP = (
    url(8000), url(8001), url(8002), url(8003), url(8004), url(8009)
)


# -- presentation ----------------------------------------------------------

@dataclass
class Report:
    passed: int = 0
    failed: list = field(default_factory=list)


REPORT = Report()


def rule(title: str) -> None:
    print("\n" + "═" * 78 + f"\n {title}\n" + "═" * 78)


def head(title: str) -> None:
    print(f"\n── {title} " + "─" * max(0, 74 - len(title)))


def say(text: str, indent: int = 2) -> None:
    print(textwrap.fill(" ".join(text.split()), width=78,
                        initial_indent=" " * indent, subsequent_indent=" " * indent))


def field_(label: str, value) -> None:
    print(f"  {label:<34} {value}")


def check(description: str, ok: bool) -> bool:
    if ok:
        REPORT.passed += 1
    else:
        REPORT.failed.append(description)
    print(f"  [{'✓' if ok else '✗'}] {description}")
    return ok


SCENARIOS: list = []


def scenario(title: str):
    def wrap(fn):
        SCENARIOS.append((title, fn))
        return fn
    return wrap


# -- the voter's application side -----------------------------------------

class App:
    """Holds the ad-hoc key pair and the blinding state. Never holds `id`."""

    def __init__(self, ctx: "Ctx"):
        self.ctx = ctx
        self.adhoc = keys.SigningKeyPair.generate()
        self.token: bytes | None = None

    def obtain(self, voter_id: str) -> str:
        http = self.ctx.http
        blinded, state = rsabssa.blind(self.ctx.token_key, self.adhoc.public_bytes)
        http.post(f"{WALLET}/session", json={"voter_id": voter_id})
        outcome = http.post(
            f"{WALLET}/requests", json={"blinded_key": b64(blinded)}
        ).json()["outcome"]
        reply = http.get(f"{VRO}/token-replies/{b64(blinded)}")
        if reply.status_code == 200:
            self.token = rsabssa.finalize(
                self.ctx.token_key, self.adhoc.public_bytes,
                unb64(reply.json()["blind_signature"]), state,
            )
        return outcome

    def sign(self, selection: int, key=None, token=None) -> dict:
        key = key or self.adhoc
        unsigned = Ballot(selection=selection, adhoc_public_key=self.adhoc.public_bytes,
                          token=token or self.token or b"", vote_signature=b"")
        return {
            "selection": selection,
            "adhoc_public_key": b64(self.adhoc.public_bytes),
            "token": b64(token or self.token or b""),
            "vote_signature": b64(key.sign(unsigned.signed_payload())),
        }


@dataclass
class Ctx:
    http: httpx.Client
    token_key: object
    options: dict
    counter: int = 0

    def enrol(self, tag: str) -> str:
        self.counter += 1
        voter_id = f"HU-{tag}-{self.counter:03d}"
        self.http.post(f"{SETUP}/voters", json={"voter_id": voter_id})
        return voter_id

    def voter(self, tag: str) -> tuple[App, str]:
        voter_id = self.enrol(tag)
        app = App(self)
        outcome = app.obtain(voter_id)
        assert outcome == "ISSUED", outcome
        return app, voter_id

    def submit(self, body: dict) -> dict:
        return self.http.post(f"{EBB}/ballots", json=body).json()


# ==========================================================================
# Submissions the box must refuse
# ==========================================================================

@scenario("A ballot with no authentication at all")
def s_no_auth(ctx: Ctx) -> None:
    say("""Anyone can address the ballot box; submitting requires no secret.
        The first line of defence is therefore that an unauthenticated
        submission buys nothing.""")
    adhoc = keys.SigningKeyPair.generate()
    result = ctx.submit({
        "selection": 1, "adhoc_public_key": b64(adhoc.public_bytes),
        "token": b64(b"\x00" * 384), "vote_signature": b64(b"\x00" * 64),
    })
    check("rejected", not result["accepted"])
    field_("reason given", result["reason"])


@scenario("A token invented from random bytes")
def s_forged_token(ctx: Ctx) -> None:
    say("""The token is an ordinary RSA-PSS signature over the ad-hoc public
        key, verified against the key pinned from the config origin. Inventing
        one means forging a signature under a key nobody outside the office
        holds.""")
    adhoc = keys.SigningKeyPair.generate()
    unsigned = Ballot(selection=1, adhoc_public_key=adhoc.public_bytes,
                      token=os.urandom(384), vote_signature=b"")
    result = ctx.submit({
        "selection": 1, "adhoc_public_key": b64(adhoc.public_bytes),
        "token": b64(os.urandom(384)),
        "vote_signature": b64(adhoc.sign(unsigned.signed_payload())),
    })
    check("rejected despite a well-formed ballot signature", not result["accepted"])


@scenario("A token copied from somebody else's published ballot")
def s_stolen_token(ctx: Ctx) -> None:
    say("""After the close every token is public. The token certifies the
        ad-hoc key it was issued over, and the selection must be signed by the
        matching private half -- which the thief does not have. This is also
        why a rejected ballot must supersede nothing: otherwise a reader of
        the box could annul a stranger's vote.""")
    victim, _ = ctx.voter("VICTIM")
    genuine = ctx.submit(victim.sign(1))
    check("the victim's ballot is accepted", genuine["accepted"])

    thief = App(ctx)
    thief.adhoc = victim.adhoc          # the public key is public
    forged = keys.SigningKeyPair.generate()
    stolen = ctx.submit(thief.sign(2, key=forged, token=victim.token))
    check("the copy is rejected", not stolen["accepted"])

    record = ctx.http.get(f"{EBB}/ballots/{b64(victim.adhoc.public_bytes)}").json()
    check("the victim's recorded selection is untouched", record["selection"] == 1)


@scenario("A selection altered after it was signed")
def s_tampered(ctx: Ctx) -> None:
    say("""The ballot signature covers hash([i, k_p^a]), so changing the
        selection in transit invalidates it. The network carries signed data
        and can neither forge a vote nor alter one undetectably (§3.9).""")
    voter, _ = ctx.voter("TAMPER")
    body = voter.sign(1)
    body["selection"] = 2               # a proxy rewrites it in flight
    result = ctx.submit(body)
    check("rejected", not result["accepted"])


@scenario("A selection signed with a key other than the certified one")
def s_wrong_key(ctx: Ctx) -> None:
    say("""The box checks two things and they must agree: that the token
        certifies this ad-hoc key, and that the selection is signed by that
        same key. Satisfying one is not enough.""")
    voter, _ = ctx.voter("WRONGKEY")
    other = keys.SigningKeyPair.generate()
    result = ctx.submit(voter.sign(1, key=other))
    check("rejected: the token is genuine, the ballot signature is not",
          not result["accepted"])


# ==========================================================================
# Token requests the office must refuse
# ==========================================================================

@scenario("A token requested in somebody else's name")
def s_impersonation(ctx: Ctx) -> None:
    say("""The office's endpoint is reachable by anyone, so it must withstand
        a request no wallet made. Impersonation fails because the request
        signature is checked against the certificate the population register
        holds for that id -- infrastructure the design consults rather than
        builds.""")
    voter_id = ctx.enrol("REAL")
    blinded, _ = rsabssa.blind(ctx.token_key, keys.SigningKeyPair.generate().public_bytes)
    attacker = keys.SigningKeyPair.generate()
    outcome = ctx.http.post(f"{VRO}/token-requests", json={
        "voter_id": voter_id, "blinded_key": b64(blinded),
        "wallet_signature": b64(attacker.sign(b"anything")),
    }).json()["outcome"]
    check("refused", outcome != "ISSUED")
    field_("outcome", outcome)
    check("no reply is collectable",
          ctx.http.get(f"{VRO}/token-replies/{b64(blinded)}").status_code == 404)


@scenario("An identifier that is on no register")
def s_unregistered(ctx: Ctx) -> None:
    say("""§3.2: the two failures that arise *before* the office knows who it
        is speaking to must be reported identically. Otherwise anyone able to
        spell an identifier could submit an unsigned request and learn from
        the answer whether that citizen holds a certificate -- the token
        endpoint would become a register lookup service.""")
    real = ctx.enrol("KNOWN")
    blinded, _ = rsabssa.blind(ctx.token_key, keys.SigningKeyPair.generate().public_bytes)
    attacker = keys.SigningKeyPair.generate()

    def ask(voter_id: str) -> str:
        return ctx.http.post(f"{VRO}/token-requests", json={
            "voter_id": voter_id, "blinded_key": b64(blinded),
            "wallet_signature": b64(attacker.sign(b"anything")),
        }).json()["outcome"]

    unknown, known = ask("HU-NOBODY-AT-ALL"), ask(real)
    field_("id that exists", known)
    field_("id that does not", unknown)
    check("indistinguishable — the endpoint is not a register oracle",
          unknown == known == "NOT_IDENTIFIED")


@scenario("A second token for the same voter")
def s_double_token(ctx: Ctx) -> None:
    say("""Equality: one voter, one token. The office refuses the second
        request and, because the release is recorded before anything is
        returned, the published count cannot understate what was issued.""")
    voter_id = ctx.enrol("DOUBLE")
    first, second = App(ctx), App(ctx)
    check("first request issued", first.obtain(voter_id) == "ISSUED")
    outcome = second.obtain(voter_id)
    check("second refused", outcome == "TOKEN_ALREADY_ISSUED")
    field_("outcome", outcome)


# ==========================================================================
# Things the voter is entitled to do
# ==========================================================================

@scenario("Re-voting, and which ballot counts")
def s_revote(ctx: Ctx) -> None:
    say("""A later accepted ballot supersedes an earlier one. Both stay in the
        registry: supersession is applied when counting, so the history stays
        auditable. This is what lets a coerced voter recast in private, within
        the limits §1 sets out.""")
    voter, _ = ctx.voter("REVOTE")
    ctx.submit(voter.sign(1))
    ctx.submit(voter.sign(2))
    record = ctx.http.get(f"{EBB}/ballots/{b64(voter.adhoc.public_bytes)}").json()
    check("the box returns the later selection", record["selection"] == 2)


@scenario("A protest ballot is invalid, not rejected")
def s_protest(ctx: Ctx) -> None:
    say("""A ballot that authenticates perfectly but marks no listed option is
        *invalid* — a deliberate protest. It is as genuine as any other, is
        published, and supersedes an earlier ballot. A ballot that fails a
        cryptographic check is *rejected* and supersedes nothing.""")
    voter, _ = ctx.voter("PROTEST")
    ctx.submit(voter.sign(1))
    protest = ctx.submit(voter.sign(-7))
    check("accepted, though the selection is out of range", protest["accepted"])
    record = ctx.http.get(f"{EBB}/ballots/{b64(voter.adhoc.public_bytes)}").json()
    check("and it supersedes the earlier vote", record["selection"] == -7)


@scenario("Supersession applies among accepted ballots only")
def s_supersession(ctx: Ctx) -> None:
    say("""The rule that makes the previous two safe. Were a rejected
        submission allowed to supersede, any reader of the box could copy a
        voter's public key and token, attach nonsense, and annul their vote
        without holding any secret at all.""")
    voter, _ = ctx.voter("SUPER")
    ctx.submit(voter.sign(1))
    bogus = keys.SigningKeyPair.generate()
    ctx.submit(voter.sign(2, key=bogus))
    record = ctx.http.get(f"{EBB}/ballots/{b64(voter.adhoc.public_bytes)}").json()
    check("the genuine ballot still stands", record["selection"] == 1)


@scenario("The token-request check, and what it may disclose")
def s_release_query(ctx: Ctx) -> None:
    say("""D1, answered by the office over its own register. The query carries
        a signature of `id` made in the wallet, so only that voter can ask —
        an unauthenticated lookup would turn the register into a public record
        of who took part, which is exactly what a boycott enforcer needs.""")
    voter, voter_id = ctx.voter("CHECK")
    credentials = ctx.http.post(f"{WALLET}/release-query-credentials").json()
    answer = ctx.http.post(f"{VRO}/release-queries", json=credentials).json()
    log = ctx.http.get(f"{VRO}/release-log").json()

    check("a token was released in this voter's name", answer["released"])
    verified = verify_release_answer(
        log["entries"], voter_id,
        type("A", (), {"released": True, "nonce": unb64(answer["nonce"]),
                       "index": answer["index"]})(),
    )
    check("the answer opens this voter's own published commitment", verified)
    check("the published register names nobody",
          all("voter_id" not in e for e in log["entries"]))
    field_("the entry itself", log["entries"][answer["index"]])

    forged = keys.SigningKeyPair.generate()
    refused = ctx.http.post(f"{VRO}/release-queries", json={
        "voter_id": voter_id, "signature": b64(forged.sign(b"anything")),
    }).json()
    check("an unsigned enquiry about somebody else is refused",
          refused["outcome"] != "RELEASED")
    field_("outcome for the stranger", refused["outcome"])


# ==========================================================================
# What anyone can establish afterwards
# ==========================================================================

@scenario("What is published while voting is open, and what is not")
def s_publication(ctx: Ctx) -> None:
    say("""Commitments, positions, the chain head and running counts are
        published continuously; the records themselves are withheld. The voter
        can still retrieve their own by presenting k_p^a, which is a lookup
        secret until the close and public afterwards.""")
    voter, _ = ctx.voter("PUBLISH")
    receipt = ctx.submit(voter.sign(1))
    view = ctx.http.get(f"{EBB}/published").json()

    check("no records are published while open", "records" not in view)
    check("commitments are", len(view["commitments"]["accepted"]) > 0)
    check("the receipt carries the position and the head",
          receipt["index"] is not None and receipt["ledger_head"])
    check("the voter can still fetch their own record",
          ctx.http.get(
              f"{EBB}/ballots/{b64(voter.adhoc.public_bytes)}"
          ).status_code == 200)
    check("a key nobody holds fetches nothing",
          ctx.http.get(
              f"{EBB}/ballots/{b64(keys.SigningKeyPair.generate().public_bytes)}"
          ).status_code == 404)


@scenario("Provability: what the voter can show a third party")
def s_provability(ctx: Ctx) -> None:
    say("""Under this variant the voter's handle is the ad-hoc key they
        control, so after the close they can prove authorship by signing a
        challenge — to an adjudicator, and equally to a vote buyer. That is
        point B on the paper's diagram, and it is a legislative choice rather
        than a technical one.""")
    voter, _ = ctx.voter("PROVE")
    ctx.submit(voter.sign(3 if 3 in ctx.options else 1))
    challenge = os.urandom(32)
    proof = voter.adhoc.sign(challenge)
    check("the voter can demonstrate control of k_s^a",
          keys.verify_signature(voter.adhoc.public_bytes, proof, challenge))
    bystander = keys.SigningKeyPair.generate()
    check("a bystander cannot forge such a proof",
          not keys.verify_signature(
              voter.adhoc.public_bytes, bystander.sign(challenge), challenge))


@scenario("Closing, and an independent recount")
def s_recount(ctx: Ctx) -> None:
    say("""The close is an act of the ballot box, not a wall-clock assertion.
        Afterwards every record is released in clear and anyone can verify
        each token and each ballot signature and recompute the result, using
        ordinary cryptographic libraries and no privileged access.""")
    late, _ = ctx.voter("LATE")
    ctx.http.post(f"{EBB}/close")
    check("submissions after the close are not recorded",
          not ctx.submit(late.sign(1))["accepted"])

    view = ctx.http.get(f"{EBB}/published").json()
    records = view["records"]["accepted"]
    released = ctx.http.get(f"{VRO}/release-log").json()["count"]
    check("records are released in clear at the close", len(records) > 0)

    latest = {}
    ok_tokens = ok_sigs = True
    for payload in records:
        ballot = Ballot.from_dict(payload)
        ok_tokens &= rsabssa.verify(ctx.token_key, ballot.adhoc_public_key, ballot.token)
        ok_sigs &= keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload())
        latest[payload["adhoc_public_key"]] = ballot.selection

    check("every ballot carries a genuine VRO token", ok_tokens)
    check("every selection is signed by the certified key", ok_sigs)
    check(f"distinct ballots ({len(latest)}) ≤ tokens released ({released})",
          len(latest) <= released)

    tally = ctx.http.get(f"{EBB}/tally").json()
    announced = {int(k): v for k, v in tally["counts"].items()}
    computed = {i: sum(1 for s in latest.values() if s == i) for i in announced}
    check("an outsider's count matches the published tally", computed == announced)
    field_("announced", announced)
    field_("recomputed", computed)

    # E7: the tally must report the distribution over distinct out-of-range
    # values rather than one aggregate. Collapsing them would let an
    # organised protest disappear into a single "invalid" figure, which is
    # the opposite of what requirement 7 asks for.
    announced_protest = {int(k): v for k, v in tally["protest_codes"].items()}
    computed_protest = {}
    for selection in latest.values():
        if selection not in announced:
            computed_protest[selection] = computed_protest.get(selection, 0) + 1
    check("distinct protest selections are reported apart, not merged",
          computed_protest == announced_protest)
    field_("protest codes announced", announced_protest or "none cast")


# ==========================================================================

def main() -> int:
    http = httpx.Client(timeout=30.0)
    try:
        config = http.get(f"{CONFIG}/election.json", timeout=3.0).json()
    except httpx.TransportError:
        raise SystemExit(
            f"no service on {CONFIG} — run `python -m service` in another terminal."
        )
    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))
    ctx = Ctx(http=http, token_key=token_key,
              options={i: i for i in range(1, config["num_choices"] + 1)})

    rule("EXTENDED DEMONSTRATION · every rejection below comes from a server")
    field_("election", config["election_id"])
    field_("k_p^(R) pinned from 8000", config["vro_token_key_fingerprint"][:40] + "…")
    say("""Fifteen scenarios. Four from the in-process version are absent on
        purpose, and the module docstring says which and why — a demo that
        quietly dropped them would be claiming more than it showed.""")

    for title, fn in SCENARIOS:
        rule(title)
        fn(ctx)

    rule("SUMMARY")
    field_("checks passed", REPORT.passed)
    field_("checks failed", len(REPORT.failed))
    for description in REPORT.failed:
        print(f"    ✗ {description}")
    print()
    return 1 if REPORT.failed else 0


if __name__ == "__main__":
    sys.exit(main())
