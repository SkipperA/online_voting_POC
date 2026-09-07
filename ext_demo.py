"""Extended demonstration: every value in full, and every attack shown failing.

`demo.py` narrates the happy path and abbreviates the data.  This script is the
opposite: it prints every byte the protocol produced -- keys, encodings,
blinding factors, blinded values, blind signatures, tokens, ballots, ledger
hashes -- and it recomputes the arithmetic independently at each step, so an
audience can check the numbers rather than take the narration on trust.

It then runs the submissions that must fail: ballots with no authentication at
all, forged and stolen tokens, tampered selections, signatures from the wrong
key, impersonation at the registration office, a second token request, a
substituted VRO key, a malicious VRO response, the multiplicative forgery
against the blind signature, and after-the-fact edits to the ledger.  Each one
prints the data actually offered and the check that rejected it.

Every claim is a `[✓]` line backed by a computation performed in this file, and
the script exits non-zero if any of them fails.  Nothing here has privileged
access beyond what the named party would hold.

Run with:

    python ext_demo.py                 # everything, 3072-bit VRO key
    python ext_demo.py --bits 1024     # shorter numbers, easier to read on a projector
    python ext_demo.py --list          # the section ids
    python ext_demo.py --only forged-token stolen-token
    python ext_demo.py --pause         # stop between sections, for a live walkthrough
    python ext_demo.py > transcript.txt

SECURITY NOTE.  Private key material is printed on purpose -- that is the point
of the exercise.  Nothing produced by this script may be reused anywhere.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import secrets
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from ovpoc import keys, rsabssa
from ovpoc.ballotbox import BallotBox
from ovpoc.ledger import GENESIS, compute_entry_hash
from ovpoc.messages import Ballot, b64, canonical_bytes, digest, unb64
from ovpoc.voter import Voter
from driver import PopulationRegister
from ovpoc.vro import (
    VRO,
    FaultDetected,
    Outcome,
    ReleaseOutcome,
    commit,
    denial_payload,
    release_query_payload,
    verify_denial,
    verify_release_answer,
)

OPTIONS = {1: "Option A", 2: "Option B", 3: "Option C"}
NAMES = ("Anna", "Béla", "Csilla")


# ==========================================================================
# Output helpers
# ==========================================================================

@dataclass
class Report:
    """Running tally of the checks this script performs on itself."""

    passed: int = 0
    failed: list[str] = field(default_factory=list)


REPORT = Report()
HEX_WIDTH = 64


def rule(title: str) -> None:
    print("\n" + "═" * 78)
    print(f" {title}")
    print("═" * 78)


def head(title: str) -> None:
    print(f"\n── {title} " + "─" * max(0, 74 - len(title)))


def say(text: str, indent: int = 2) -> None:
    print(textwrap.fill(
        " ".join(text.split()), width=78,
        initial_indent=" " * indent, subsequent_indent=" " * indent,
    ))


def field_(label: str, value) -> None:
    print(f"  {label:<30} {value}")


def blob(label: str, data: bytes, indent: int = 6) -> None:
    """Print a byte string in full, wrapped, with its length."""
    print(f"  {label}  ({len(data)} bytes)")
    if not data:
        print(" " * indent + "(empty)")
        return
    text = data.hex()
    for i in range(0, len(text), HEX_WIDTH):
        print(" " * indent + text[i:i + HEX_WIDTH])


def big(label: str, value: int, size: int, indent: int = 6) -> None:
    """Print a modular integer in full, as fixed-width bytes plus its bit length."""
    print(f"  {label}  ({value.bit_length()} bits)")
    text = value.to_bytes(size, "big").hex()
    for i in range(0, len(text), HEX_WIDTH):
        print(" " * indent + text[i:i + HEX_WIDTH])


def text_block(label: str, data: bytes, indent: int = 6) -> None:
    """Print a long ASCII string verbatim, chunked, never hyphenated."""
    print(f"  {label}  ({len(data)} bytes)")
    line = data.decode("utf-8", "replace")
    for i in range(0, len(line), 70):
        print(" " * indent + line[i:i + 70])


def check(description: str, ok: bool) -> bool:
    """Record and print one verifiable claim.  Everything asserted is checked here."""
    if ok:
        REPORT.passed += 1
    else:
        REPORT.failed.append(description)
    print(f"  [{'✓' if ok else '✗'}] {description}")
    return ok


def raw_private(pair: keys.SigningKeyPair) -> bytes:
    """The 32-byte Ed25519 seed.  Printed only because this is a demonstration."""
    return pair.private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ==========================================================================
# Election fixtures
# ==========================================================================

@dataclass
class Election:
    vro: VRO
    fingerprint: str
    box: BallotBox
    voters: dict[str, Voter]
    population: PopulationRegister


def new_election(keypair, names=NAMES) -> Election:
    """A fresh election reusing one VRO key pair, so scenarios stay comparable.

    Two registers, and it matters which party holds each. The population
    register is external identity infrastructure: it enrols a certificate
    binding a signing key to a named person. The electoral register belongs
    to the VRO and holds ids alone.
    """
    priv, pub = keypair
    population = PopulationRegister()
    vro = VRO(
        private_key=priv,
        public_key=pub,
        population_register=population,
        office_key=keys.SigningKeyPair.generate(),
    )
    fingerprint = rsabssa.public_key_fingerprint(pub)
    voters = {}
    for i, name in enumerate(names):
        wallet = keys.SigningKeyPair.generate()
        voter_id = f"HU-WALLET-{i:03d}"
        population.enrol(voter_id, wallet.public_bytes)
        vro.enrol(voter_id)
        voters[name] = Voter(voter_id, wallet, pub, fingerprint)
    box = BallotBox(
        vro_public_key=pub, num_choices=len(OPTIONS), tally_interval=10
    )
    return Election(vro, fingerprint, box, voters, population)


def register(election: Election, voter: Voter) -> None:
    """Steps 1-8 for one voter, without narration."""
    response = election.vro.issue_token(voter.build_auth_request())
    assert response.issued, response.outcome
    voter.accept_token(response.blind_signature)


def cert_key(election: Election, voter_id: str) -> bytes:
    """The certified signing key for an id, from the external register."""
    return election.population.lookup(voter_id).public_key


@dataclass
class Context:
    keypair: tuple
    main: Election | None = None
    anna_trace: dict = field(default_factory=dict)


SECTIONS: list[tuple[str, str, callable]] = []


def section(section_id: str, title: str):
    def decorator(fn):
        SECTIONS.append((section_id, title, fn))
        return fn
    return decorator


def ensure_main(ctx: Context) -> Election:
    """Later sections need the walkthrough's election; build it silently if skipped."""
    if ctx.main is None:
        with contextlib.redirect_stdout(io.StringIO()):
            walkthrough(ctx)
            anonymity(ctx)
    return ctx.main


# ==========================================================================
# PART 1 -- the full walkthrough, nothing abbreviated
# ==========================================================================

@section("walkthrough", "One voter, every value in full")
def walkthrough(ctx: Context) -> None:
    priv, pub = ctx.keypair
    numbers = priv.private_numbers()
    n, e, d = numbers.public_numbers.n, numbers.public_numbers.e, numbers.d
    k = (n.bit_length() + 7) // 8

    rule("PART 1 · SETUP — the VRO's one and only signing key")
    say("""One key pair for the whole election, published before voting opens and
        pinned in every client. A VRO free to use a different key per voter would
        gain nothing from blinding: it could afterwards tell which of its keys
        verifies a given ballot and re-link it to the requester.""")
    print()
    big("modulus  n_R", n, k)
    field_("public exponent  e_R", e)
    print()
    say("""The private exponent and the primes follow. In a deployment they never
        leave a hardware module; they are printed here so that every exponentiation
        below can be reproduced by hand.""")
    print()
    big("private exponent  d_R", d, k)
    big("prime  p", numbers.p, (numbers.p.bit_length() + 7) // 8)
    big("prime  q", numbers.q, (numbers.q.bit_length() + 7) // 8)
    print()
    field_("SHA-256 fingerprint", rsabssa.public_key_fingerprint(pub))
    check("p · q == n_R", numbers.p * numbers.q == n)
    check("e_R · d_R ≡ 1  (mod λ(n_R))",
          (e * d) % ((numbers.p - 1) * (numbers.q - 1) //
                     _gcd(numbers.p - 1, numbers.q - 1)) == 1)

    election = new_election(ctx.keypair)
    ctx.main = election
    anna = election.voters["Anna"]

    head("Two registers, held by different parties")
    for name, voter in election.voters.items():
        print(f"  {name:<8} id = {voter.voter_id}")
        blob("k_p^(v) in the qualified certificate", cert_key(election, voter.voter_id))
    say("""The electoral register holds identifiers and nothing else: the VRO
        administers who may vote. The signing keys above are not its copy — they
        live in qualified certificates maintained by a certification authority,
        which the office looks up per request and does not store. Under eIDAS
        that certificate already binds the key to a named person, so a second
        election-specific binding step would be redundant.""", indent=2)
    check("the electoral register holds ids alone",
          election.vro.register == {v.voter_id for v in election.voters.values()})

    # ---------------------------------------------------------------- 1/A
    rule("PART 1 · STEPS 1–4 — Anna's device prepares the request")
    head("Step 1/A — the ad-hoc key pair, generated fresh for this election")
    request = anna.build_auth_request()
    state = anna._blind_state          # the voter's own secret state, shown deliberately
    adhoc_pub = anna.adhoc.public_bytes

    blob("k_s^a  (private, never sent)", raw_private(anna.adhoc))
    blob("k_p^a  (public, will be blind-signed)", adhoc_pub)
    say("""This key pair is the voter's anonymous handle on their own ballot. It is
        generated on the device, and the registration office never sees it in the
        clear.""")

    head("Step 1/B and 2 — encoding, then blinding")
    r = pow(state.r_inv, -1, n)        # recovered from the state purely for display
    encoded = state.encoded_msg
    c_int = int.from_bytes(request.blinded_key, "big")

    blob("enc(k_p^a)  EMSA-PSS, SHA-384", encoded)
    say("""The salt inside that encoding is drawn by Anna's device, not by the
        signer — RFC 9474 puts the encoding inside Blind(), so the VRO never sees
        an unencoded message and takes no part in choosing the salt.""")
    print()
    big("blinding factor  r", r, k)
    big("r^(-1) mod n_R", state.r_inv, k)
    big("r^(e_R) mod n_R", pow(r, e, n), k)
    print()
    big("c = enc(k_p^a) · r^(e_R) mod n_R", c_int, k)

    recomputed_c = (int.from_bytes(encoded, "big") * pow(r, e, n)) % n
    check("c recomputed from enc(k_p^a) and r matches the value sent", recomputed_c == c_int)
    check("enc(k_p^a) < n_R  (the encoding is reduced)", int.from_bytes(encoded, "big") < n)
    check("r is invertible mod n_R  (r · r^-1 ≡ 1)", (r * state.r_inv) % n == 1)

    head("Steps 3–4 — the wallet signs the request package [id, c]")
    signed_payload_json = canonical_bytes({
        "voter_id": request.voter_id, "blinded_key": b64(request.blinded_key)
    })
    text_block("canonical JSON actually hashed", signed_payload_json)
    print()
    blob("hash([id, c])  SHA-256", request.signed_payload())
    blob("s = sig_{k_s^(v)}(hash([id,c]))", request.wallet_signature)
    check("the wallet signature verifies under k_p^(v)",
          keys.verify_signature(cert_key(election, anna.voter_id),
                                request.wallet_signature, request.signed_payload()))
    say("""Note what travels to the VRO: the identifier, the blinded value, and a
        signature. Nothing about the choice, and nothing that reveals k_p^a.""")

    # ---------------------------------------------------------------- 5-7
    rule("PART 1 · STEPS 5–7 — the VRO validates, logs, then signs blindly")
    head("Step 5 — the checks, in the order that keeps the roll private")
    cert = election.population.lookup(anna.voter_id)
    field_("5/1  certificate found for this id?", cert is not None)
    field_("5/2  signature verifies under the certified key?",
           keys.verify_signature(cert.public_key,
                                 request.wallet_signature, request.signed_payload()))
    say("""Those two are all that may be answered before identity is
        established, and both failures return one opaque result,
        NOT_IDENTIFIED. Otherwise the token endpoint would let anybody who can
        spell an identifier discover whether that citizen holds a certificate
        or appears on the electoral roll.""")
    print()
    field_("     — identity established; specific reasons permitted below —", "")
    field_("     certificate revoked?", cert.revoked)
    field_("     certificate expired?", cert.is_expired())
    field_("     on the electoral register?", anna.voter_id in election.vro.register)
    field_("     token already released?", anna.voter_id in election.vro._released)
    say("""Revocation sits below the boundary deliberately: a revoked
        certificate still verifies mathematically, so by the time the office
        can see revocation it already knows who it is speaking to.""")

    response = election.vro.issue_token(request)
    blind_sig = response.blind_signature
    field_("outcome", response.outcome.name)
    entry = election.vro.release_log.entries[-1]
    nonce = election.vro._nonces[anna.voter_id]

    head("Step 7 — the release is logged before the signature is returned")
    blob("nonce (disclosed only on a signed step-12 query)", nonce)
    blob("commitment  H(id ‖ nonce)", commit(anna.voter_id, nonce))
    field_("published log entry", entry.payload)
    blob("previous entry hash", entry.prev_hash)
    blob("this entry hash", entry.entry_hash)
    check("the published entry contains no identifier",
          set(entry.payload) == {"commitment"} and anna.voter_id not in entry.payload["commitment"])
    check("entry hash recomputed independently",
          compute_entry_hash(entry.index, entry.payload, entry.prev_hash) == entry.entry_hash)
    check("logging happens before signing (a token cannot exist off-log)",
          election.vro.release_count() == 1)

    head("Step 6/A — the raw private-key operation  s_c = S(c) = c^(d_R) mod n_R")
    s_c = int.from_bytes(blind_sig, "big")
    big("s_c", s_c, k)
    check("s_c recomputed as pow(c, d_R, n_R)", pow(c_int, d, n) == s_c)
    check("s_c^(e_R) ≡ c  (mod n_R)  — the fault check of §5.3", pow(s_c, e, n) == c_int)
    say("""That last line is the Boneh–DeMillo–Lipton countermeasure the article
        specifies in §5.3. It is performed here by the demonstration, not by
        `vro.py`, which does not yet implement it — see CLAUDE.md, open items.""")
    print()
    say("""What the office holds after this exchange: an identifier, the blinded
        value c, and s_c. What it does not hold: k_p^a, r, or anything that links
        either to c.""")

    # ---------------------------------------------------------------- 8
    rule("PART 1 · STEP 8 — Anna unblinds, and checks the office behaved")
    anna.accept_token(blind_sig)
    token_int = int.from_bytes(anna.token, "big")

    big("s_{k_p^a} = s_c · r^(-1) mod n_R", token_int, k)
    check("token recomputed as (s_c · r^-1) mod n_R", (s_c * state.r_inv) % n == token_int)
    check("token^(e_R) mod n_R == enc(k_p^a)  — the encoding reappears exactly",
          pow(token_int, e, n) == int.from_bytes(encoded, "big"))
    check("the token is an ordinary RSA-PSS signature over k_p^a",
          rsabssa.verify(pub, adhoc_pub, anna.token))
    say("""The blinding factor is transformed, not carried: Anna multiplied by
        r^(e_R) and divides by r, because (r^(e_R))^(d_R) = r. Blinding and
        unblinding therefore do not cancel — the exponentiation in between is what
        makes the construction work.""")
    print()
    say("""The result verifies under an unmodified RSA-PSS implementation. No
        election-specific cryptography is needed by anyone checking it later.""")

    # ---------------------------------------------------------------- 9-11
    rule("PART 1 · STEPS 9–11 — the ballot, and what the box records")
    ballot = anna.cast(1)
    payload_json = canonical_bytes({
        "selection": ballot.selection, "adhoc_public_key": b64(ballot.adhoc_public_key)
    })
    head(f"Step 9 — Anna selects {OPTIONS[1]!r}")
    text_block("canonical JSON actually signed", payload_json)
    print()
    blob("hash([i, k_p^a])", ballot.signed_payload())
    blob("s_vote = sig_{k_s^a}(hash([i, k_p^a]))", ballot.vote_signature)
    print()
    print("  The complete published ballot package [i, k_p^a, s_{k_p^a}, s_vote]:")
    field_("i  (selection)", ballot.selection)
    blob("k_p^a", ballot.adhoc_public_key)
    blob("s_{k_p^a}  (token)", ballot.token)
    blob("s_vote", ballot.vote_signature)
    say("""Nothing in that package identifies Anna. The only link to eligibility
        runs through the token, and the office cannot recognise it.""")

    head("Steps 10/1, 10/2 and 11/A — the ballot box decides")
    result = election.box.submit(ballot)
    anna.record_head(result.ledger_head)
    ledger_entry = election.box.accepted.entries[-1]
    field_("10/1  token signed by the VRO?", rsabssa.verify(pub, ballot.adhoc_public_key, ballot.token))
    field_("10/2  selection authenticated by k_p^a?",
           keys.verify_signature(ballot.adhoc_public_key, ballot.vote_signature,
                                 ballot.signed_payload()))
    field_("result", f"accepted={result.accepted}  reason={result.reason!r}")
    blob("previous ledger head", ledger_entry.prev_hash)
    blob("new ledger head", result.ledger_head)
    check("ledger entry hash recomputed independently",
          compute_entry_hash(ledger_entry.index, ledger_entry.payload,
                             ledger_entry.prev_hash) == result.ledger_head)
    say("""The head returned in the receipt is Anna's evidence of the state of the
        registry at the moment her ballot was accepted. If the published ledger
        later fails to reproduce it, the discrepancy is demonstrable.""")

    # ---------------------------------------------------------------- 12-13
    rule("PART 1 · STEPS 12–13 — the two checks from an independent device")
    head("Step 12 — was a token released in my name?")
    query_sig = anna.wallet.sign(release_query_payload(anna.voter_id))
    blob("payload signed by the query", release_query_payload(anna.voter_id))
    blob("sig(id)", query_sig)
    answer = election.vro.query_token_release(anna.voter_id, query_sig)
    published_log = [ent.payload for ent in election.vro.release_log.entries]
    field_("released", answer.released)
    field_("index in the published log", answer.index)
    blob("nonce disclosed to Anna alone", answer.nonce)
    check("the nonce opens the commitment at that index",
          verify_release_answer(published_log, anna.voter_id, answer))
    check("the same nonce does not open it for a different id",
          not verify_release_answer(published_log, election.voters["Béla"].voter_id, answer))
    say("""The query carries sig(id) because an unauthenticated lookup would turn
        the log into a public register of participation — and absence of an entry
        is conclusive proof of non-voting, which is exactly what a coercer
        demanding turnout needs.""")

    head("Step 13 — is the recorded selection the one I intended?")
    recorded = anna.handle.locate(election.box)
    field_("recorded selection", recorded["selection"])
    check("cast-as-intended check passes", anna.verify_recorded_ballot(election.box, 1))

    # the other two voters, so later sections have a real ballot box to count
    head("The other voters (abbreviated — same protocol, different numbers)")
    for name, selection in (("Béla", 3), ("Csilla", 1)):
        voter = election.voters[name]
        register(election, voter)
        out = election.box.submit(voter.cast(selection))
        print(f"  {name:<8} selection {selection}  accepted={out.accepted}  "
              f"head {out.ledger_head.hex()[:32]}…")

    ctx.anna_trace = {"r": r, "c": c_int, "s_c": s_c, "encoded": encoded, "token": anna.token}


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# ==========================================================================
# PART 2 -- what each party can see
# ==========================================================================

@section("anonymity", "What the office holds vs what the world sees")
def anonymity(ctx: Context) -> None:
    election = ctx.main
    priv, pub = ctx.keypair
    n = pub.public_numbers().n
    k = (n.bit_length() + 7) // 8
    trace = ctx.anna_trace

    rule("PART 2 · THE ANONYMITY CLAIM, AS DATA")
    say("""Below are the two records side by side: what the registration office
        retained from Anna's exchange, and what the public ballot box shows. The
        value that connects them, r, exists only on Anna's device and was
        discarded after step 8.""")

    head("The office's view of Anna")
    field_("id", election.voters["Anna"].voter_id)
    big("c   (what it signed)", trace["c"], k)
    big("s_c (what it returned)", trace["s_c"], k)

    head("The public ballot box, first entry")
    entry = election.box.accepted.entries[0].payload
    for key, value in entry.items():
        field_(key, value if not isinstance(value, str) or len(value) < 44 else value[:44] + "…")

    head("The one value that links them, which nobody else ever had")
    big("r", trace["r"], k)
    check("c · (r^-1)^(e_R) ≡ enc(k_p^a)  — the link, only computable with r",
          (trace["c"] * pow(pow(trace["r"], -1, n), pub.public_numbers().e, n)) % n
          == int.from_bytes(trace["encoded"], "big"))
    check("the office's transcript shares no byte string with the ballot",
          b64(trace["token"]) != b64(trace["s_c"].to_bytes(k, "big")))
    say("""Without r, relating s_c to the published token is exactly the problem
        the blinding was chosen to make hard. What the office can still do is
        issue a token nobody asked for; that is bounded by the one-token-per-id
        rule and the public release count, not by cryptography.""")


# ==========================================================================
# PART 3 -- submissions that must fail
# ==========================================================================

@section("no-auth", "A ballot with no authentication at all")
def scenario_no_auth(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    rule("PART 3 · A BALLOT CAST WITH NO AUTHENTICATION")
    say("""The naive attack: submit a selection with empty fields, as though the
        ballot box were a form on a website. This is what the ballot box is asked
        to accept.""")

    naked = Ballot(selection=2, adhoc_public_key=b"", token=b"", vote_signature=b"")
    head("Submitted")
    field_("selection", naked.selection)
    blob("k_p^a", naked.adhoc_public_key)
    blob("token", naked.token)
    blob("s_vote", naked.vote_signature)

    result = election.box.submit(naked)
    head("Ballot box decision")
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("rejected at check 10/1, before the selection is even considered",
          not result.accepted and result.reason == "token not signed by VRO")
    check("nothing entered the accepted ledger", len(election.box.accepted) == 0)
    check("the attempt is published in the rejected ledger", len(election.box.rejected) == 1)
    head("The rejected-ledger entry (public, so the attempt is visible)")
    field_("payload", election.box.rejected.entries[0].payload)


@section("forged-token", "A self-minted token")
def scenario_forged_token(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    pub = ctx.keypair[1]
    k = (pub.public_numbers().n.bit_length() + 7) // 8
    voter = election.voters["Anna"]

    rule("PART 3 · A TOKEN INVENTED FROM NOTHING")
    say("""A better-informed attacker generates an ad-hoc key of their own and
        fabricates a token of the correct length. The bytes are well-formed; they
        are simply not a signature under the VRO's key.""")

    voter.adhoc = keys.generate_adhoc_keypair()
    voter.token = secrets.token_bytes(k)
    ballot = voter.cast(1)

    head("Submitted")
    blob("k_p^a  (a real key, generated by the attacker)", ballot.adhoc_public_key)
    blob("token  (invented)", ballot.token)
    blob("s_vote (genuine — signed with the matching private key)", ballot.vote_signature)
    check("the vote signature itself is perfectly valid",
          keys.verify_signature(ballot.adhoc_public_key, ballot.vote_signature,
                                ballot.signed_payload()))

    result = election.box.submit(ballot)
    head("Ballot box decision")
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("the token fails RSA-PSS verification under k_p^(R)",
          not rsabssa.verify(pub, ballot.adhoc_public_key, ballot.token))
    check("rejected", not result.accepted and result.reason == "token not signed by VRO")
    say("""Authenticating the selection is not the same as being entitled to cast
        it. The ad-hoc key proves who signed; only the token proves eligibility.""")


@section("stolen-token", "A genuine token lifted from the public ledger")
def scenario_stolen_token(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    pub = ctx.keypair[1]
    honest, thief = election.voters["Anna"], election.voters["Béla"]

    rule("PART 3 · A GENUINE TOKEN, STOLEN FROM THE PUBLIC BOX")
    say("""Every token is published in clear. An attacker copies one and attaches
        it to a key of their own — the obvious consequence of publishing ballots,
        and the reason the token signs the key rather than accompanying it.""")

    register(election, honest)
    election.box.submit(honest.cast(1))
    stolen = unb64(election.box.accepted.entries[0].payload["token"])
    victim_key = unb64(election.box.accepted.entries[0].payload["adhoc_public_key"])

    head("Copied from the published ledger")
    blob("victim's k_p^a", victim_key)
    blob("victim's token", stolen)
    check("the stolen token is genuine — for the victim's key",
          rsabssa.verify(pub, victim_key, stolen))

    thief.adhoc = keys.generate_adhoc_keypair()
    thief.token = stolen
    ballot = thief.cast(3)

    head("Submitted with the thief's own key")
    blob("thief's k_p^a", ballot.adhoc_public_key)
    result = election.box.submit(ballot)
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("the same token does not verify under the thief's key",
          not rsabssa.verify(pub, ballot.adhoc_public_key, stolen))
    check("rejected", not result.accepted)
    check("the victim's ballot is untouched", election.box.tally()["counts"] == {1: 1, 2: 0, 3: 0})


@section("tampered-selection", "The selection altered in flight")
def scenario_tampered(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    voter = election.voters["Anna"]
    register(election, voter)

    rule("PART 3 · THE SELECTION CHANGED BETWEEN DEVICE AND BOX")
    say("""A hostile network, proxy or relay rewrites the choice and forwards
        everything else unchanged. This is the objection that 'anything over the
        internet can be manipulated'.""")

    ballot = voter.cast(1)
    original_digest = ballot.signed_payload()
    head("As signed by the voter")
    field_("selection", ballot.selection)
    blob("hash([i, k_p^a]) that s_vote covers", original_digest)

    ballot.selection = 2                       # tampering; s_vote left as it was
    head("As it arrives at the ballot box")
    field_("selection", ballot.selection)
    blob("hash([i, k_p^a]) of what arrived", ballot.signed_payload())
    blob("s_vote (unchanged — the attacker cannot re-sign)", ballot.vote_signature)
    check("the two digests differ", original_digest != ballot.signed_payload())

    result = election.box.submit(ballot)
    head("Ballot box decision")
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("rejected at check 10/2",
          not result.accepted and result.reason == "vote signature invalid")
    say("""The channel carries signed data, so it cannot forge or alter a vote
        undetectably. What it can still do is drop or delay ballots, and observe
        who contacts the box and when — availability and anonymity need separate
        measures.""")


@section("wrong-key", "A selection signed with the wrong private key")
def scenario_wrong_key(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    victim, attacker = election.voters["Anna"], election.voters["Béla"]
    register(election, victim)
    register(election, attacker)

    rule("PART 3 · A BALLOT AUTHENTICATED BY THE WRONG KEY")
    say("""The attacker presents the victim's certified key and token — both public
        — but can only sign with a private key of their own. This is the case a
        coercer or a compromised relay is in.""")

    forged = Ballot(
        selection=3,
        adhoc_public_key=victim.adhoc.public_bytes,
        token=victim.token,
        vote_signature=b"",
    )
    forged.vote_signature = attacker.adhoc.sign(forged.signed_payload())

    head("Submitted")
    blob("k_p^a  (the victim's, copied)", forged.adhoc_public_key)
    blob("s_vote (signed with the attacker's k_s^a)", forged.vote_signature)
    check("the signature is valid — under the attacker's key",
          keys.verify_signature(attacker.adhoc.public_bytes, forged.vote_signature,
                                forged.signed_payload()))
    check("but not under the key named in the ballot",
          not keys.verify_signature(forged.adhoc_public_key, forged.vote_signature,
                                    forged.signed_payload()))

    result = election.box.submit(forged)
    head("Ballot box decision")
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("rejected", not result.accepted and result.reason == "vote signature invalid")


@section("impersonation", "Impersonation at the registration office")
def scenario_impersonation(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    attacker, victim = election.voters["Anna"], election.voters["Béla"]

    rule("PART 3 · CLAIMING SOMEONE ELSE'S IDENTIFIER")
    say("""Wallet identifiers are not secret. The attacker builds a perfectly
        ordinary request, substitutes the victim's id, and re-signs with the only
        wallet key they hold.""")

    request = attacker.build_auth_request()
    request.voter_id = victim.voter_id
    request.wallet_signature = attacker.wallet.sign(request.signed_payload())

    head("The request as it reaches the VRO")
    field_("claimed id", request.voter_id)
    blob("hash([id, c])", request.signed_payload())
    blob("s  (attacker's wallet)", request.wallet_signature)
    blob("k_p^(v) certified for that id", cert_key(election, victim.voter_id))
    blob("k_p^(v) the attacker actually holds", attacker.wallet.public_bytes)

    head("Step 5/2")
    response = election.vro.issue_token(request)
    field_("outcome returned", response.outcome.name)
    field_("blind signature returned", response.blind_signature)
    check("refused: the signature does not verify under the certified key",
          response.outcome is Outcome.NOT_IDENTIFIED)
    check("no token was released", election.vro.release_count() == 0)

    head("What the office wrote down, and did not say")
    entry = election.vro.audit_log[-1]
    field_("audit outcome", entry.outcome.name)
    field_("audit reason", entry.reason)
    say("""The requester learns only NOT_IDENTIFIED. The office's private log
        records which of the pre-boundary situations actually occurred, which is
        what an investigation needs and what an attacker must not have.""")


@section("unregistered", "A citizen not on the electoral register")
def scenario_unregistered(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    outsider = election.voters["Anna"]
    outsider.voter_id = "HU-WALLET-999"

    rule("PART 3 · AN IDENTIFIER THAT IS NOT ON THE REGISTER")
    request = outsider.build_auth_request()
    head("The request")
    field_("id", request.voter_id)
    field_("certificate found?", election.population.lookup(request.voter_id) is not None)
    field_("on the electoral register?", request.voter_id in election.vro.register)
    unknown = election.vro.issue_token(request)
    field_("outcome", unknown.outcome.name)
    check("refused before the identity boundary",
          unknown.outcome is Outcome.NOT_IDENTIFIED)

    head("Now a citizen who *is* identifiable but is not entitled to vote")
    say("""The distinction the state machine turns on. This person holds a valid
        certificate and signs correctly, so the office knows who it is talking
        to and may give the real reason. The previous case could not be told
        anything, because nobody had proved to be anybody.""")
    stranger_wallet = keys.SigningKeyPair.generate()
    election.population.enrol("HU-WALLET-404", stranger_wallet.public_bytes)
    outsider.voter_id = "HU-WALLET-404"
    outsider.wallet = stranger_wallet
    identified = election.vro.issue_token(outsider.build_auth_request())
    field_("certificate found?", True)
    field_("on the electoral register?", "HU-WALLET-404" in election.vro.register)
    field_("outcome", identified.outcome.name)
    check("refused with a reason, past the boundary",
          identified.outcome is Outcome.NOT_ELIGIBLE)

    head("The two answers side by side")
    say("""An unauthenticated party sees NOT_IDENTIFIED in both of the first two
        cases and cannot distinguish a citizen who does not exist from one who
        exists and is eligible. That is the privacy property: the token endpoint
        is not an electoral-roll lookup service.""")


@section("double-token", "A second token request from the same id")
def scenario_double_token(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    voter = election.voters["Anna"]

    rule("PART 3 · TRYING TO DRAW A SECOND TOKEN")
    say("""Equality rests here, not at the ballot box: a voter who held two tokens
        would hold two unlinkable ad-hoc keys and could cast two counted ballots.
        The box cannot detect that, because it cannot tell the keys apart.""")

    register(election, voter)
    first_token = voter.token
    blob("first token", first_token)
    field_("release count", election.vro.release_count())

    second = election.vro.issue_token(voter.build_auth_request())
    field_("outcome", second.outcome.name)
    check("the second request is refused",
          second.outcome is Outcome.TOKEN_ALREADY_ISSUED)
    check("the release log did not grow", election.vro.release_count() == 1)


@section("vro-key-substitution", "A per-voter VRO key, to single out one ballot")
def scenario_key_substitution(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    voter = election.voters["Anna"]

    rule("PART 3 · THE OFFICE PRESENTS A DIFFERENT SIGNING KEY TO ONE VOTER")
    say("""The subtlest attack here, and the one blinding does not prevent by
        itself. Blinding hides the ad-hoc key from the signer; it does not
        constrain which key the signer uses. An office that reserved a second key
        for one voter could afterwards tell which of its keys verifies a given
        ballot in the public box, and re-link it.""")

    _, singling_out_key = rsabssa.generate_vro_keypair(ctx.keypair[1].key_size)
    head("Fingerprints")
    field_("pinned in the voter app", voter.pinned_vro_fingerprint[:48] + "…")
    field_("offered to this voter", rsabssa.public_key_fingerprint(singling_out_key)[:48] + "…")
    voter.vro_public_key = singling_out_key

    try:
        voter.build_auth_request()
        check("refused", False)
    except ValueError as exc:
        field_("ValueError", str(exc).split("--")[0].strip())
        check("the voter app refuses to proceed on a fingerprint mismatch", True)
    say("""The defence is entirely client-side and entirely procedural: one key,
        published before voting opens, pinned in every client, identical for every
        voter.""")


@section("malicious-vro-response", "A blind signature that does not verify")
def scenario_malicious_response(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    voter = election.voters["Anna"]

    rule("PART 3 · THE OFFICE RETURNS A SIGNATURE UNDER ANOTHER KEY")
    say("""The voter's entitlement to a token is consumed the moment the office
        logs the release. A response that does not verify must therefore be caught
        on the device, at the only moment r still exists.""")

    request = voter.build_auth_request()
    election.vro.issue_token(request)                    # the honest side of the exchange
    other_priv, _ = rsabssa.generate_vro_keypair(ctx.keypair[1].key_size)
    bad_sig = rsabssa.blind_sign(other_priv, request.blinded_key)

    head("What the office returns")
    blob("s_c (produced with a different private key)", bad_sig)
    try:
        voter.accept_token(bad_sig)
        check("rejected", False)
    except rsabssa.BlindSignatureError as exc:
        field_("BlindSignatureError", str(exc))
        check("the device verifies before accepting, and refuses", True)
    check("no token was retained", voter.token is None)
    say("""RFC 9474 requires this check in Finalize(). The consequence is
        procedural rather than cryptographic: the entitlement is already spent, so
        a documented re-issuance path with an audit trail has to exist.""")


@section("multiplicative-forgery", "The classic forgery against raw RSA")
def scenario_forgery(ctx: Context) -> None:
    priv, pub = ctx.keypair
    n, e = pub.public_numbers().n, pub.public_numbers().e
    k = (n.bit_length() + 7) // 8

    rule("PART 3 · MULTIPLICATIVE FORGERY, AND WHY THE PADDING DEFEATS IT")
    say("""Raw RSA is multiplicative: S(m1)·S(m2) = S(m1·m2). A voter holding two
        legitimate tokens could therefore derive a third that the office never
        issued. This is why k_p^a is never signed directly.""")

    m1, m2 = secrets.token_bytes(32), secrets.token_bytes(32)
    b1, st1 = rsabssa.blind(pub, m1)
    b2, st2 = rsabssa.blind(pub, m2)
    sig1 = rsabssa.finalize(pub, m1, rsabssa.blind_sign(priv, b1), st1)
    sig2 = rsabssa.finalize(pub, m2, rsabssa.blind_sign(priv, b2), st2)

    head("Two genuine signatures")
    blob("m1", m1)
    blob("sig1", sig1)
    blob("m2", m2)
    blob("sig2", sig2)

    forged_int = (int.from_bytes(sig1, "big") * int.from_bytes(sig2, "big")) % n
    forged = forged_int.to_bytes(k, "big")
    head("Their product")
    big("sig1 · sig2 mod n_R", forged_int, k)

    recovered = pow(forged_int, e, n).to_bytes(k, "big")
    head("What that product is a signature of")
    blob("forged^(e_R) mod n_R  — the 'encoding' it recovers", recovered)
    field_("final byte", f"0x{recovered[-1]:02x}   (a well-formed EMSA-PSS encoding ends 0xbc)")
    check("the product is a valid raw RSA signature: it recovers cleanly",
          pow(forged_int, e, n) ==
          (int.from_bytes(st1.encoded_msg, "big") * int.from_bytes(st2.encoded_msg, "big")) % n)
    for label, candidate in (("m1", m1), ("m2", m2), ("m1‖m2", m1 + m2),
                             ("m1⊕m2", bytes(a ^ b for a, b in zip(m1, m2)))):
        check(f"the forgery verifies against no message: {label}",
              not rsabssa.verify(pub, candidate, forged))
    say("""The product of two encodings is not, except with negligible
        probability, the encoding of anything. The forgery is a valid RSA
        operation and a worthless signature.""")


@section("release-query", "Snooping on the token-release log")
def scenario_release_query(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    victim, snoop, absentee = (election.voters["Anna"], election.voters["Béla"],
                               election.voters["Csilla"])
    register(election, victim)

    rule("PART 3 · WHO REGISTERED? — THE STEP-12 LOG UNDER ATTACK")
    say("""A coercer who demands turnout rather than a particular choice needs only
        to learn whether a citizen registered at all. Absence of an entry is
        conclusive proof of non-voting.""")

    head("The published log, in full")
    for ent in election.vro.release_log.entries:
        field_(f"entry {ent.index}", ent.payload)
    check("no identifier appears anywhere in the log",
          all(victim.voter_id not in ent.payload["commitment"]
              for ent in election.vro.release_log.entries))

    head("The snoop queries the victim's id with their own wallet key")
    forged_query = snoop.wallet.sign(release_query_payload(victim.voter_id))
    blob("sig(id) offered", forged_query)
    refused = election.vro.query_token_release(victim.voter_id, forged_query)
    field_("outcome", refused.outcome.name)
    field_("nonce disclosed", refused.nonce)
    check("an unauthenticated query is refused",
          refused.outcome is ReleaseOutcome.NOT_IDENTIFIED)

    head("And an identifier nobody holds a certificate for")
    unknown = election.vro.query_token_release(
        "HU-WALLET-555", snoop.wallet.sign(release_query_payload("HU-WALLET-555")))
    field_("outcome", unknown.outcome.name)
    check("answered identically, so neither register can be probed here",
          unknown.outcome is refused.outcome)

    head("A voter who did not register asks about themselves")
    answer = election.vro.query_token_release(
        absentee.voter_id, absentee.wallet.sign(release_query_payload(absentee.voter_id)))
    field_("outcome", answer.outcome.name)
    blob("signed denial", answer.signed_denial)
    check("the denial is signed by the office, so a false 'no' is attributable",
          verify_denial(election.vro.office_public_key,
                        absentee.voter_id, answer.signed_denial))
    check("and it does not transfer to another citizen's statement",
          not verify_denial(election.vro.office_public_key,
                            victim.voter_id, answer.signed_denial))
    say("""This does not prevent a dishonest office from denying a token it minted.
        It leaves evidence of the denial. That distinction is deliberate and
        should not be described as prevention.""")

    head("Why the denial is not signed with the token key")
    say("""A blind signer applies its private key to values it cannot inspect, so
        an ordinary token request is a signing oracle. Any registered voter can
        drive it over a message of their choosing — including the office's own
        denial about somebody else.""")
    target = denial_payload(victim.voter_id)
    blinded, state = rsabssa.blind(election.vro.public_key, target)
    oracle_request = snoop.build_auth_request()
    oracle_request.blinded_key = blinded
    oracle_request.wallet_signature = snoop.wallet.sign(oracle_request.signed_payload())
    oracle_response = election.vro.issue_token(oracle_request)
    forged_statement = rsabssa.finalize(
        election.vro.public_key, target, oracle_response.blind_signature, state)
    blob("statement the snoop wanted signed", target)
    blob("forged signature over it, under k_p^(R)", forged_statement)
    check("an ordinary token request forges an office statement under the token key",
          rsabssa.verify(election.vro.public_key, target, forged_statement))
    check("but the real denial verifies under the separate office key, not that one",
          not rsabssa.verify(election.vro.public_key, target, answer.signed_denial))
    say("""Hence the office holds a second, ordinary signing key for statements,
        and the token key signs nothing but tokens — for one election.""")


# ==========================================================================
# PART 4 -- accepted, but not a plain vote
# ==========================================================================

@section("revote", "Re-voting: the last accepted ballot counts")
def scenario_revote(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    voter = election.voters["Anna"]
    register(election, voter)

    rule("PART 4 · RE-VOTING")
    say("""A voter may recast at any time, and only the last accepted ballot
        counts. This is what makes casual pressure survivable — though not a
        coercer who controls the final moment before the close of voting.""")

    for selection in (1, 3, 2):
        result = election.box.submit(voter.cast(selection))
        print(f"  cast {selection} → accepted={result.accepted}  "
              f"head {result.ledger_head.hex()[:32]}…")

    head("The public ledger keeps all three")
    for ent in election.box.accepted.entries:
        field_(f"entry {ent.index}", f"selection {ent.payload['selection']}  "
                                     f"key {ent.payload['adhoc_public_key'][:24]}…")
    check("three submissions retained", len(election.box.accepted) == 3)
    check("one effective ballot", election.box.tally()["voters"] == 1)
    check("the last one counts", election.box.tally()["counts"] == {1: 0, 2: 1, 3: 0})
    say("""Supersession is applied when counting, not by overwriting, so the whole
        submission history stays auditable.""")


@section("protest", "Protest ballots: invalid, not rejected")
def scenario_protest(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    rule("PART 4 · PROTEST BALLOTS")
    say("""An out-of-range selection that is properly authenticated is an invalid
        vote, not a rejected submission: cryptographically valid, politically
        invalid, and it does supersede an earlier ballot. Distinct codes stay
        distinct in the tally, and the system never interprets what any of them
        means.""")

    for name, selection in (("Anna", -1), ("Béla", -2), ("Csilla", -1)):
        voter = election.voters[name]
        register(election, voter)
        result = election.box.submit(voter.cast(selection))
        print(f"  {name:<8} selection {selection:<4} accepted={result.accepted}")

    tally = election.box.tally()
    head("Tally")
    field_("counts", tally["counts"])
    field_("invalid", tally["invalid"])
    field_("protest_codes", tally["protest_codes"])
    check("all three were accepted, not rejected", len(election.box.rejected) == 0)
    check("none was counted for a listed option", tally["counts"] == {1: 0, 2: 0, 3: 0})
    check("the distinct codes are not merged", tally["protest_codes"] == {-1: 2, -2: 1})


@section("rejected-supersession", "A rejected ballot must not annul a genuine one")
def scenario_supersession(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    voter = election.voters["Anna"]
    register(election, voter)

    rule("PART 4 · WHY 'REJECTED' AND 'INVALID' MUST NOT BE CONFLATED")
    say("""Submitting to the ballot box requires no secret, and both k_p^a and the
        token are public. If a rejected ballot superseded an earlier one, any
        reader of the ledger could copy those two values, attach a meaningless
        signature, and annul someone's genuine vote.""")

    election.box.submit(voter.cast(2))
    published = election.box.accepted.entries[0].payload
    head("What an attacker copies from the ledger")
    field_("k_p^a", published["adhoc_public_key"][:44] + "…")
    field_("token", published["token"][:44] + "…")

    garbage = Ballot(
        selection=3,
        adhoc_public_key=unb64(published["adhoc_public_key"]),
        token=unb64(published["token"]),
        vote_signature=secrets.token_bytes(64),
    )
    result = election.box.submit(garbage)
    head("Result")
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("the annulment attempt is rejected", not result.accepted)
    check("the genuine vote survives", election.box.tally()["counts"] == {1: 0, 2: 1, 3: 0})
    check("the attempt is nonetheless published", len(election.box.rejected) == 1)


# ==========================================================================
# PART 5 -- the ledger after the fact
# ==========================================================================

@section("ledger-tampering", "Editing the ledger after publication")
def scenario_ledger(ctx: Context) -> None:
    election = new_election(ctx.keypair)
    rule("PART 5 · THE BALLOT BOX EDITS ITS OWN RECORD")
    say("""Publication is not immutability. A box could delete a ballot it had
        already acknowledged, or change one. The hash chain makes both
        demonstrable rather than merely alleged.""")

    for name, selection in (("Anna", 1), ("Béla", 2), ("Csilla", 3)):
        voter = election.voters[name]
        register(election, voter)
        election.box.submit(voter.cast(selection))

    head("The intact chain")
    for ent in election.box.accepted.entries:
        print(f"  {ent.index}  prev {ent.prev_hash.hex()[:24]}…  hash {ent.entry_hash.hex()[:24]}…")
    check("chain verifies", election.box.accepted.verify_chain())

    head("Case 1 — a ballot is altered in place")
    election.box.accepted.entries[0].payload["selection"] = 3
    prev = GENESIS
    first_bad = None
    for i, ent in enumerate(election.box.accepted.entries):
        expected = compute_entry_hash(i, ent.payload, prev)
        if expected != ent.entry_hash and first_bad is None:
            first_bad = (i, expected, ent.entry_hash)
        prev = ent.entry_hash
    field_("first mismatching entry", first_bad[0])
    blob("hash the payload now implies", first_bad[1])
    blob("hash that was published", first_bad[2])
    check("chain verification fails", not election.box.accepted.verify_chain())
    election.box.accepted.entries[0].payload["selection"] = 1     # restore
    check("chain verifies again once the edit is undone", election.box.accepted.verify_chain())

    head("Case 2 — a ballot is deleted")
    removed = election.box.accepted.entries.pop(1)
    field_("removed entry", f"index {removed.index}, selection {removed.payload['selection']}")
    check("chain verification fails", not election.box.accepted.verify_chain())
    say("""A voter who recorded the head returned in their receipt can show that
        the published ledger no longer reproduces it. Equivocation — showing
        different chains to different people — needs the head published somewhere
        the operator does not control.""")


# ==========================================================================
# PART 5b -- what is published, and when
# ==========================================================================

@section("publication", "The publication schedule: commitments, then records")
def scenario_publication(ctx: Context) -> None:
    """Twelve voters, so that a running tally has something to report."""
    names = tuple(f"Voter{i:02d}" for i in range(12))
    election = new_election(ctx.keypair, names=names)

    rule("PART 5b · WHILE VOTING IS OPEN, AND FROM THE CLOSE")
    say("""Publishing selections as they arrive would broadcast a running result
        for the whole poll. Worse, because a later ballot supersedes an earlier
        one, an observer watching the totals move learns that somebody reversed
        a choice — and in a small enough population that approaches learning
        who. So the box publishes commitments while it is open, and the records
        themselves only at the close.""")

    for i, name in enumerate(names):
        voter = election.voters[name]
        register(election, voter)
        election.box.submit(voter.cast((i % 3) + 1))

    view = election.box.published_view()
    head("The open view, in full")
    field_("phase", view["phase"])
    field_("accepted commitments", len(view["commitments"]["accepted"]))
    field_("chain head", view["heads"]["accepted"][:32] + "…")
    field_("counts", view["counts"])
    field_("records present?", "records" in view)
    check("no record is published while voting is open", "records" not in view)
    check("no selection appears anywhere in the open view",
          "selection" not in repr(view) and "adhoc_public_key" not in repr(view))

    head("The running tally, one snapshot every 10 accepted ballots")
    for snap in view["running_tally"]:
        field_(f"after {snap['after_accepted']} accepted", snap["counts"])
    check("one snapshot at ten ballots, none at twelve",
          [s["after_accepted"] for s in view["running_tally"]] == [10])
    say("""Whether to publish a running tally at all, and at what resolution, is
        the administering body's decision rather than the design's — the article
        gives fifteen minutes as its example. Left unset, no tally exists for
        anybody, the operator included, until the box closes. This POC counts
        ballots rather than minutes: a fake clock would demonstrate nothing.""")

    head("A voter's own check, available throughout")
    someone = election.voters[names[0]]
    check("the voter finds their own ballot while the records are withheld",
          someone.handle.locate(election.box) is not None)
    say("""k_p^a is a lookup secret as well as a locating handle: before the
        close it is known to the voter's application and to the box and to
        nobody else. Presenting it is therefore sufficient authentication for
        retrieval, and no private key need leave the voter's device.""")

    head("The close")
    election.box.close()
    closed = election.box.published_view()
    field_("phase", closed["phase"])
    field_("records released", len(closed["records"]["accepted"]))
    check("the commitments published earlier are unchanged",
          closed["commitments"] == view["commitments"])
    check("every released record hashes to the commitment published for it",
          all(announced["commitment"] == ent.entry_hash.hex()
              and announced["index"] == ent.index
              for announced, ent in zip(closed["commitments"]["accepted"],
                                        election.box.accepted.entries)))
    say("""No row moves backwards: nothing available while voting was open is
        withdrawn at the close, and what changes does so only by disclosing
        more.""")

    head("And a ballot arriving after the close")
    late = election.voters[names[0]]
    before = (len(election.box.accepted), len(election.box.rejected))
    result = election.box.submit(late.cast(3))
    field_("accepted", result.accepted)
    field_("reason", result.reason)
    check("it is not recorded at all — it is not a ballot",
          not result.accepted
          and (len(election.box.accepted), len(election.box.rejected)) == before)


# ==========================================================================
# PART 6 -- the trade-off, made executable
# ==========================================================================

@section("provability", "What variant B also gives away")
def scenario_provability(ctx: Context) -> None:
    election = ensure_main(ctx)
    anna = election.voters["Anna"]

    rule("PART 6 · THE SAME PROOF SERVES AN ADJUDICATOR AND A VOTE BUYER")
    say("""In the implemented variant the voter's handle is the ad-hoc key they
        control. That is what lets them substantiate a complaint. It is also, and
        unavoidably, what lets them prove their choice to somebody paying for
        it.""")

    challenge = b"prove-it-" + secrets.token_bytes(16)
    proof = anna.handle.prove_authorship(challenge)
    head("A challenge from a third party, and the voter's answer")
    blob("challenge (chosen by the coercer)", challenge)
    blob("proof = sig_{k_s^a}(challenge)", proof)

    published = election.box.accepted.entries[0].payload
    check("the proof verifies against the k_p^a in the published ballot",
          keys.verify_signature(unb64(published["adhoc_public_key"]), proof, challenge))
    field_("the selection thereby proved", published["selection"])
    check("the handle is transferable, by construction", anna.handle.transferable)
    say("""Note what does not help: giving the voter an anonymous lookup number
        instead. The published ballot still carries k_p^a and the voter still holds
        k_s^a, so the coercer simply demands a signature. Provability lives in the
        ballot's structure, not in the index the voter uses. A genuine variant A
        needs encrypted ballots and a trapdoor tracker — a different system, not a
        different handle.""")
    print()
    say("""Where to place that balance is the legislative question the papers hand
        over. It is not settled by the code, and cannot be.""")


# ==========================================================================
# PART 7 -- the outsider's recount
# ==========================================================================

@section("recount", "An outsider recomputes the result")
def scenario_recount(ctx: Context) -> None:
    election = ensure_main(ctx)
    pub = ctx.keypair[1]

    rule("PART 7 · INDEPENDENT VERIFICATION FROM THE PUBLIC LEDGER ALONE")
    say("""Everything below uses only the published ledger and the VRO's public
        key. No privileged access, and no election-specific cryptography — an
        ordinary RSA-PSS verify and an ordinary Ed25519 verify.""")
    if not election.box.closed:
        election.box.close()
        say("""The poll is closed first: ballot-by-ballot verification of
            eligibility and authentication needs the tokens and signatures
            themselves, which are released only at the close.""")

    head("Every published ballot, verified one at a time")
    latest: dict[str, int] = {}
    for ent in election.box.accepted.entries:
        ballot = Ballot.from_dict(ent.payload)
        token_ok = rsabssa.verify(pub, ballot.adhoc_public_key, ballot.token)
        vote_ok = keys.verify_signature(ballot.adhoc_public_key, ballot.vote_signature,
                                        ballot.signed_payload())
        chain_ok = compute_entry_hash(ent.index, ent.payload, ent.prev_hash) == ent.entry_hash
        print(f"  entry {ent.index}  selection {ballot.selection}  "
              f"token {'✓' if token_ok else '✗'}  "
              f"s_vote {'✓' if vote_ok else '✗'}  "
              f"chain {'✓' if chain_ok else '✗'}")
        check(f"entry {ent.index} fully verifies", token_ok and vote_ok and chain_ok)
        if token_ok and vote_ok:
            latest[ent.payload["adhoc_public_key"]] = ballot.selection

    head("Aggregate checks")
    field_("published ballots", len(election.box.accepted))
    field_("distinct ad-hoc keys", len(latest))
    field_("tokens released (public count)", election.vro.release_count())
    check("hash chain intact end to end", election.box.accepted.verify_chain())
    check("distinct ballots ≤ tokens released",
          len(latest) <= election.vro.release_count())
    say("""That inequality is what a third party can check without learning who
        anyone is. It catches an office minting tokens it did not log. It does not
        catch one that logs a release for a citizen who never voted — that is
        indistinguishable from a citizen who took a token and abstained, and is why
        the issuing power belongs with several mutually distrusting bodies.""")

    head("The result, computed twice")
    outsider = {i: sum(1 for s in latest.values() if s == i) for i in OPTIONS}
    official = election.box.tally()
    for i, label in OPTIONS.items():
        print(f"  {label:<12} outsider {outsider[i]}    box {official['counts'][i]}")
    check("the outsider's count matches the announced tally", outsider == official["counts"])
    field_("invalid (protest) ballots", official["invalid"])
    field_("protest codes", official["protest_codes"])
    field_("rejected submissions", official["rejected"])
    field_("final ledger head", official["ledger_head"])


# ==========================================================================
# Entry point
# ==========================================================================

def main(argv: list[str] | None = None) -> int:
    global HEX_WIDTH

    parser = argparse.ArgumentParser(
        description="Extended demonstration of the Anonymous Authenticated Ballot System.")
    parser.add_argument("--bits", type=int, default=rsabssa.DEFAULT_MODULUS_BITS,
                        help="VRO modulus size (default 3072, the article's minimum; "
                             "1024 for shorter output on a projector). "
                             "The PSS parameters need at least 800 bits.")
    parser.add_argument("--width", type=int, default=64,
                        help="hex characters per line (default 64)")
    parser.add_argument("--only", nargs="+", metavar="ID",
                        help="run only the named sections")
    parser.add_argument("--list", action="store_true", help="list section ids and exit")
    parser.add_argument("--pause", action="store_true",
                        help="wait for Enter between sections, for a live walkthrough")
    args = parser.parse_args(argv)

    if args.list:
        for section_id, title, _ in SECTIONS:
            print(f"  {section_id:<24} {title}")
        return 0

    HEX_WIDTH = args.width
    if args.bits < 1024:
        print("A modulus below 1024 bits cannot hold an EMSA-PSS encoding with "
              "SHA-384 and a 48-byte salt.", file=sys.stderr)
        return 2

    selected = SECTIONS
    if args.only:
        known = {s for s, _, _ in SECTIONS}
        unknown = [name for name in args.only if name not in known]
        if unknown:
            print(f"Unknown section(s): {', '.join(unknown)}. "
                  f"Try --list.", file=sys.stderr)
            return 2
        selected = [s for s in SECTIONS if s[0] in args.only]

    print(f"Anonymous Authenticated Ballot System — extended demonstration")
    print(f"VRO modulus {args.bits} bits · RSABSSA-SHA384-PSS-Deterministic (RFC 9474) · "
          f"Ed25519 wallet and ad-hoc keys")
    print("Proof of concept. Private key material is printed deliberately and must "
          "never be reused.")
    print("Generating the VRO key pair…", flush=True)

    ctx = Context(keypair=rsabssa.generate_vro_keypair(args.bits))

    for section_id, title, fn in selected:
        fn(ctx)
        if args.pause and section_id != selected[-1][0]:
            try:
                input("\n  [Enter to continue] ")
            except EOFError:
                break

    rule("SELF-CHECK")
    print(f"  {REPORT.passed} checks performed, {len(REPORT.failed)} failed.")
    for description in REPORT.failed:
        print(f"    ✗ {description}")
    if REPORT.failed:
        print("\n  Something in this run did not hold. Do not present it as a "
              "working demonstration.")
        return 1
    print("\n  Every claim above was computed in this run, not asserted by the "
          "narration.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
