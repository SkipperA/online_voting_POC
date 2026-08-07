# Protocol mapping

Each numbered step below corresponds to a label in the system diagram
(*Anonymous Authenticated Ballot System*, 26 July 2026), to the formal
description in Section 5 of the technical paper, and to
[`blind-signature.md`](blind-signature.md) where that document specifies the
step in full.

This file is the single mapping between the three. It deliberately carries no
cryptographic argument: for the blinding construction, its parameters, and its
security properties, see `blind-signature.md`.

Notation appears in code spans rather than rendered math, so that this table
stays readable in any viewer. `S` is the raw private-key operation and `enc` the
padded encoding, as in the paper's Section 4.1 — `sig(m) = S(enc(m))`.

| Step | Paper notation | Code | Spec |
|---|---|---|---|
| 1/A | generate `k_s^a, k_p^a` | `keys.generate_adhoc_keypair` | §2.2 |
| 1/B, 2 | `c = enc(k_p^a) · r^{e_R} mod n_R` | `rsabssa.blind` | §4 (1) |
| 3 | `s = sig_{k_s^(v)}(hash([id,c]))` | `SigningKeyPair.sign` on `AuthRequest.signed_payload` | §4 (2) |
| 4 | send `[id, c, s]` | `Voter.build_auth_request` | §4 (2) |
| 5, 5/1, 5/2 | validate request | `VRO.issue_token` | §4 (2) |
| 6/A | `s_c = S(c) = c^{d_R} mod n_R` | `rsabssa.blind_sign` | §4 (3) |
| 6/B | reject | `RegistrationError` | — |
| 7 | register the token release | `VRO.release_log`, `vro.commit` | §4 (2) |
| 8 | `s_{k_p^a} = s_c · r^{-1} mod n_R` | `rsabssa.finalize` | §4 (4) |
| 8 | check the token before casting | `rsabssa.verify` | §4 (4) |
| 9 | `[i, k_p^a, s_{k_p^a}, s_vote]` | `Voter.cast`, `messages.Ballot` | §4 (5) |
| 10/1, 10/2 | validate ballot | `BallotBox.submit` | §4 (5) |
| 11/A, 11/B | valid / rejected registries | `BallotBox.valid`, `BallotBox.rejected` | §4 (5) |
| 12 | independent token-release check | `VRO.query_token_release` | §4 (2) |
| — | ballot-value check (variant B handle) | `handles.AdHocKeyHandle`, `Voter.verify_recorded_ballot` | §7 (1) |

The last row has no diagram label because the diagram shows only the
token-request check. The ballot-value check of the paper's Section 3.6 is the
voter's other independent-channel check, and the handle it uses is what places
the system on the provability axis — see `blind-signature.md` §7.

## Two points the table cannot carry

**`blind_sign` applies `S`, not `sig`.** Step 6/A is the raw private-key
operation on a value the voter has already encoded. Writing it as
`sig_{k_s^(R)}(c)` would describe an implementation that encodes a second time
and destroys the blinding. The distinction is made in the paper's Section 5.3
and in the module docstring of `rsabssa.py`.

**Blinding and unblinding are not inverse mappings.** Step 1/B multiplies by
`r^{e_R}`; step 8 divides by `r`, not by `r^{e_R}`. The factor is transformed by
passing through the exponentiation, since `(r^{e_R})^{d_R} = r`. Any notation
that presents the two steps as a mapping and its inverse makes the false
identity look plausible; `blind-signature.md` §5 derives it properly.
