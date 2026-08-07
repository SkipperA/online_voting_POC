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
| `vro.py` | Registration, eligibility, token issue | 5, 6, 7, 12 |
| `ballotbox.py` | Validation, storage, tally | 10, 11 |
| `voter.py` | The voter's whole flow in one file | 1–4, 8, 9 |

## Design decisions already settled — do not silently revisit

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
- **Rejected ≠ invalid.** A ballot failing its cryptographic checks is
  *rejected* and does not supersede an earlier ballot. A properly signed ballot
  with an out-of-range selection is an *invalid vote*, is counted as such, and
  does supersede. Conflating these lets a coercer erase a genuine vote.
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
- **Signature check after blind signing.** The VRO should verify
  `s_c^e == c (mod n)` before releasing `s_c`. It is nearly free at `e = 65537`
  and catches a fault during CRT exponentiation, where a single faulty
  signature leaks `p` (Boneh–DeMillo–Lipton). Specified in
  `docs/blind-signature.md` §4(3) and in the article's §5.3; still not in
  `vro.py`. Implementing it needs a matching mutation in `tools/sabotage.py`
  and an update to annotation 6/A of the system diagram.

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
- Keep `docs/protocol.md` in step with the code; it is what the article cites.
  `docs/blind-signature.md` is the normative reference for the blind-signature
  core -- `rsabssa.py` and the token-issuance path in `vro.py` and `voter.py`.
  Its §9 maps specification steps to functions, so a rename there is a change to
  both.
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
python -m pytest -q          # full suite (29 tests)
python demo.py               # narrated end-to-end run
python tools/sabotage.py     # regenerate docs/sabotage.md
```
