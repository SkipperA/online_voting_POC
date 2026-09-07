# Project context for Claude

Read this before making changes. It exists so that design decisions and
terminology stay consistent across sessions.

## What this is

A proof-of-concept implementation of the Anonymous Authenticated Ballot System
described in Ferenc Vágujhelyi's paper *Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System* (July 2026) and its policy companion
*Online Voting as an Evolution of Electoral Infrastructure*.

Two purposes, in this order:

1. A **reference implementation** to accompany the technical article — the
   protocol made executable, with an adversarial test suite.
2. A **demonstrator** that can be shown to a non-technical audience.

It is not, and must never be presented as, election-ready software.

## Terminology — use these exact terms

| Use | Not |
|---|---|
| ballot box | urn |
| Voter Registration Office (VRO) | registrar, authority |
| token | certificate, credential |
| ad-hoc key pair | session key, temporary key |
| Digital Identity Wallet | eID, digital ID |
| cast-as-intended verification | vote checking |

## Architecture

Protocol logic is **pure** and lives in `src/ovpoc/`. It has no HTTP, no
database, and no framework dependency. HTTP wrappers (FastAPI) will live in a
separate `src/ovpoc_api/` layer and must contain no protocol decisions. Any
rule about what makes a ballot valid belongs in `ballotbox.py`, never in a
route handler.

| Module | Role | Diagram steps |
|---|---|---|
| `rsabssa.py` | RSA blind signatures, RFC 9474 | 2, 6/A, 8 |
| `keys.py` | Wallet and ad-hoc Ed25519 keys | 1/A, 3 |
| `messages.py` | Wire objects, canonical serialisation | 4, 9 |
| `ledger.py` | Hash-chained append-only log | 7, 11/A, 11/B |
| `vro.py` | Eligibility, token issue, release log | 5, 6, 7, 12 |
| `ballotbox.py` | Acceptance, storage, publication, tally | 10, 11 |
| `voter.py` | The voter's whole flow in one file | 1–4, 8, 9, 13 |
| `driver/population_register.py` | **Not a component.** External identity service | — |

**`driver/` is outside the library deliberately.** The population register
answers `id` with a qualified certificate; the design consults it and does not
build it (§3.2). If a lookup table for identity ever appears inside
`src/ovpoc/`, the code has started contradicting the paper. The *electoral*
register is `VRO.register` — a set of ids, and nothing else.

## Design decisions already settled — do not silently revisit

- **No election-specific registration or binding step.** Under eIDAS a
  qualified certificate already binds the signing key to a named person, so a
  second, election-administered copy of that association would be redundant and
  would add an attack surface (rebinding). The office looks the certificate up
  per request. `VRO.enrol` therefore takes one argument: an id.
- **Step 5 is a state machine with an identity boundary, and the order is
  load-bearing.** Certificate lookup, then signature verification; both
  failures return the single opaque `Outcome.NOT_IDENTIFIED`. Only below that
  boundary may the office give a reason: revoked, expired, not eligible,
  already issued. Otherwise the token endpoint becomes an electoral-roll
  lookup for anyone who can spell an identifier. The audit log records the true
  reason in every case and is never returned to the requester. Two mutations in
  `tools/sabotage.py` (`eligibility_checked_before_identity`,
  `revocation_reported_before_identity`) exist to catch a refactor that
  reorders this.
- **Revocation is reported *after* the signature verifies, and this diverges
  from the paper on purpose.** A revoked certificate still verifies
  mathematically, so by the time the office can see revocation it already knows
  who it is speaking to. The article's §3.2 and §5.4 enumerate certificate
  validity before signature verification; that order is expository and this one
  is the privacy-preserving one. Do not reconcile them silently in either
  direction.
- **The token key signs nothing but tokens.** A blind signer applies its private
  key to values it cannot inspect, so an ordinary token request is a signing
  oracle: any registered voter can obtain the office's signature over a message
  of their own choosing (§3.3). Office statements — currently step-12 denials —
  are signed under a separate `office_key`. `test_attacks.py` forges a statement
  under the token key to show why.
- **RSA blind signatures per RFC 9474**, PSS-encoded. Never sign `k_p^a`
  directly: raw RSA is multiplicative and forgeable. `test_attacks.py`
  demonstrates the attack failing; keep that test.
- **The VRO public key is pinned.** A VRO free to use a different key per voter
  defeats blinding entirely, since it could later tell which key verifies a
  given ballot. `Voter.build_auth_request` refuses to proceed on a fingerprint
  mismatch. This is load-bearing.
- **The PSS salt is chosen by the client, not the signer.** RFC 9474 puts
  `EMSA-PSS-ENCODE` inside `Blind()`, so the VRO never sees an unencoded
  message and cannot choose the salt. The article's §4.1 said otherwise until
  August 2026 and has been corrected; `docs/blind-signature.md` §2.3 records
  both. If an older PDF of the article is to hand, it is the stale copy.
- **Token release is logged before the signature is returned**, so no token can
  exist outside the public log.
- **Three words, not two: rejected / accepted / valid.** A ballot failing its
  cryptographic checks is *rejected* and supersedes nothing. A ballot passing
  both checks is *accepted* and supersedes the same voter's earlier accepted
  ballot. Within the accepted, a selection in range makes the vote *valid* and
  one outside it makes the vote *invalid* — still accepted, still superseding,
  counted as invalid. So `BallotBox.accepted` names the ledger and
  `tally()["valid"]` a count within it. Conflating rejected with invalid lets a
  coercer erase a genuine vote.
- **Publication is two-phase, and the interval is a dial.** While open the box
  publishes commitments, positions, head and counts; the records are released at
  the close. `published_view()` is the whole of what a citizen sees, and
  `tally_interval` decides whether a running tally exists at all. Left at
  `None` — the article's default — `tally()` refuses until the close, for the
  operator too. The POC's demos use ten accepted ballots; the article's example
  is fifteen minutes, and the substitution is deliberate, since a fake clock
  would demonstrate nothing. The article's remedy for the no-running-tally case
  is to encrypt the selection under a Shamir-shared election key; that is
  deliberately outside the formal model in §5, and no encryption work belongs
  in this POC.
- **`close()` is reversible here.** A real deployment needs it one-way. That is
  an operational property, not a protocol one, and the docstring says so.
- **Protest selections stay unofficial: the system never interprets them.**
  `tally()` reports the exact distribution of out-of-range selections
  (`protest_codes`), not one scalar count — but the system never
  interprets, endorses, or pre-registers what any code means. Two reasons,
  not one: (1) requiring voters to agree on a shared code in advance would
  force organised protest to declare itself before voting opens, which in
  a fragile or locally captured election is when a hostile authority is
  best placed to retaliate; (2) some protest messages — e.g. an extremist
  group signalling numeric strength — are ones no legitimate authority
  could officially register without appearing to endorse them, and Requirement
  7 does not permit content-based rejection of protest ballots. A protest
  selection is a message to the public, never a legally supported choice.
  Coordination on a shared code happens through informal channels the
  system has no visibility into and is never asked to judge. This adds no
  new exposure — each ballot's `selection` was already public in the
  ledger; the change only stops the summary from discarding a distinction
  the ledger exposed all along.
- **Supersession is applied at tally time**, not by overwriting. The full
  submission history stays auditable.
- **The release log publishes commitments, not voter ids.** `H(id || nonce)`,
  with the nonce disclosed only on a step-12 query carrying `sig(id)`. A
  plaintext log would be a public participation register, and while absence of an
  entry does not show how anyone voted, it is conclusive proof of *non*-voting --
  which is what a coercer demanding turnout needs. The published count still
  supports the aggregate `ballots <= tokens` audit, so both properties are kept.
- **Negative answers to step-12 queries are signed.** This does not stop a
  dishonest VRO denying a token it minted; it makes the denial attributable if
  later contradicted. Do not describe it as prevention.
- **Ed25519 for the ad-hoc and wallet keys.** A real wallet would use ECDSA
  P-256 in a secure element; `keys.py` keeps the interface narrow so it can be
  swapped.

## Open, deliberately not yet implemented

- **Variant A — the anonymous random-number tracker.** The current code
  implements variant B: the voter's handle on their ballot is the ad-hoc key
  they control, so authorship is provable to an adjudicator *and* to a vote
  buyer. Variant A binds the ballot to a random identifier instead, which the
  voter can check but cannot use as proof. It requires a trapdoor-style
  construction (compare the Selene line of work) and is the novel contribution
  intended for the technical article. Design it as a pluggable verification
  handle, not a fork.
- **Threshold token issuance** across several mutually distrusting bodies, so no
  single VRO can mint tokens for absent voters.
- **Anonymising submission channel.** Signing protects integrity, not
  anonymity: the network layer sees who contacts the ballot box and when.
- **Post-close verification with out-of-band return codes**, to close the
  silent-override window after a voter's final check.
- **The wallet transmits, rather than the application relaying.** §5.3 has the
  wallet conduct the exchange with the office itself, so that no single
  component holds both `id` and `k_p^a` together with the office's signature
  over their association. One `Voter` object here holds both. It is a modelling
  simplification, but it means the code does not demonstrate the property §5.3
  argues for, and `docs/threats.md` records that.
- **Several certificates per voter.** §3.2 says the office must accept a request
  signed under any valid certificate naming the requester. `lookup` returns
  exactly one, which runs the protocol but does not exercise the question.

## Working style

- Tests alongside code, in the same change. The adversarial suite is the point
  of the project, not an extra.
- Every attack the design claims to defeat gets a test that names it and shows
  it failing. Attacks the design does *not* defeat go in `docs/threats.md`, so
  their absence is deliberate.
- **Add a mutation to `tools/sabotage.py` for every new defence, and re-run it.**
  A passing negative test can pass for the wrong reason; the sabotage run is what
  shows a test actually constrains the check it names. Adding the key-pinning
  mutation is how the missing pinning test was found. `docs/sabotage.md` is
  generated -- never hand-edit it.
- Keep `docs/protocol.md` in step with the code. It is the only place that maps
  diagram step to paper notation to function, so every rename lands there and
  nowhere else -- `VRO.token_released` sat in that table long after the method
  became `VRO.query_token_release`. `docs/blind-signature.md` is the normative
  reference for the blind-signature core and deliberately names no functions, so
  it does not move when code is renamed.
- Comments explain *why*, especially where a naive implementation would be
  insecure. Assume a reviewer looking for weaknesses.
- Do not add dependencies without asking. The trust story is better the
  shorter the list.

## Markdown and math in `docs/`

GitHub renders math with KaTeX but runs its Markdown pass over the content
first. That pass strips backslash-escapes and pairs `_` and `*` as emphasis, so
plain `$...$` and `$$...$$` corrupt LaTeX *silently*: `\;` arrives as `;`, `\!`
as `!`, `\,` as `,`, and `\{` vanishes into a grouping brace. The equation still
renders, just wrongly -- `S\!(x)` reaches the reader as `S!(x)`, which can be
taken for a factorial.

Use only the protected delimiters, which take their content literally:

- Display: ` ```math ` fenced blocks
- Inline: `` $`...`$ ``

Two further constraints:

- `\operatorname` is blocklisted by KaTeX. Use `\mathrm`.
- Keep `aligned` blocks to two columns. A third annotation column overflows
  GitHub's content width and is clipped without warning.

Do not treat a rendering fault as a content fault. Stripping spacing macros,
avoiding braces, or flattening notation to make something display is fixing the
symptom; the delimiters are the cause.

The protected syntax is GitHub-specific -- `` $`...`$ `` shows literal backticks
in VS Code's preview, Obsidian, and Pandoc. A document that must read well off
GitHub should be compiled, not reformatted.

## Commands

```
pip install -e ".[dev]"
python -m pytest -q          # full suite (46 tests)
python demo.py               # narrated end-to-end run
python ext_demo.py           # narrated end-to-end run with all tests
python tools/sabotage.py     # regenerate docs/sabotage.md
```
