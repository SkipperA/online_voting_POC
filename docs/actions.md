# Online voting — action and data-flow table

Derived from `Online_Voting.tex`. Every interaction the article specifies, from
creating an election to publishing the final result, with the acting party, the
surface acted on, and the direction of the data.

Remedy and complaint-handling processes are out of scope, as the design does not
yet include them. Section references are to the technical article.

**Components.** Voter app, Voter Registration Office (VRO), Electronic Ballot Box
(EBB). The Digital Identity Wallet is a protocol participant but not a component:
it is eIDAS infrastructure the design assumes rather than builds (§3.6). The
certificate lookup service is likewise external (§3.2).

---

## Phase A — Setting up the election

| # | Action | Actor | System | Data: sender → receiver |
|---|---|---|---|---|
| A1 | Electoral register exists as a set of entries `[id]`, derived from enrolment in civil registration | jurisdiction's registration process | outside the system (§3.2) | external enrolment → register |
| A2 | Supply a register drawn for this election; entitlement differs from poll to poll | administering body | → VRO | register → VRO |
| A3 | Administer the register: hold and read it, never populate it | VRO operator | VRO back-office | register → VRO (read-only) |
| A4 | Generate the token signing key pair `k_s^(R)`, `k_p^(R)`, reserved to this election and to no other protocol | VRO operator | VRO back-office (§3.3) | internal to VRO |
| A5 | Fix the election configuration: identifier, `k_p^(R)`, choice list `1..N`, opening and closing times, registry genesis hash | administering body | *not assigned in the article* | configuration → public |
| A6 | Publish and pin the configuration before opening | administering body / VRO | published artefact, pinned in the voter app (Table 1, row 1) | publisher → voter app, and → anyone |
| A7 | Initialise the registry at the genesis hash | ballot box operator | EBB | internal to EBB |
| A8 | If no running tally is to be published: generate the election encryption key, distribute the private half in Shamir shares | several independent public bodies | outside the three components (§3.5) | key generator → share-holders |
| A9 | Open the poll | administering body | EBB, VRO | — |

## Phase B — Obtaining a token

| # | Action | Actor | System | Data: sender → receiver |
|---|---|---|---|---|
| B1 | Open the app; no login, no account | voter | voter app | — |
| B2 | Generate the ad-hoc key pair `k_s^a`, `k_p^a`; draw the blinding factor `r` | voter app | voter app (§5.2) | internal |
| B3 | Compute `c = enc(k_p^a) · r^{e_R} mod n_R` | voter app | voter app | internal |
| B4 | Hand over the blinded value, and nothing else | voter app | app → wallet | `c` : voter app → wallet |
| B5 | Authorise the signature | voter | wallet | — |
| B6 | Form and sign the request `s = sig_{k_s^(v)}(hash([id, c]))` | wallet | wallet (§5.3) | internal to wallet |
| B7 | Transmit the request to the office directly, not back through the app | wallet | wallet → VRO | `[id, c, s]` : wallet → VRO |
| B8 | Obtain the qualified certificate for the person named by `id` | VRO | certificate lookup, outside the VRO package (§3.2, §5.4) | `id` : VRO → lookup service; certificate or `NOT_IDENTIFIED` : service → VRO |
| B9 | Verify `s` on `hash([id, c])` under the certified key `k_p^(v)` | VRO | VRO | internal |
| B10 | Confirm the certificate is valid and not revoked | VRO | VRO | internal |
| B11 | Confirm the person holding `id` is eligible to vote — that is, that `id` is on the register, presence being the whole of the eligibility statement (§3.2) | VRO | VRO | internal |
| B12 | Check that no token has yet been released for this `id` | VRO | VRO | internal |
| B13 | Apply the raw private-key operation: `s_c = S(c) = c^{d_R} mod n_R` | VRO | VRO | internal |
| B14 | Fault-check the result: confirm `s_c^{e_R} ≡ c (mod n_R)` | VRO | VRO (§5.4) | internal |
| B15 | Record the release **before** returning anything: append the commitment `hash([id, nonce])`, increment the published count | VRO | VRO release register | commitment → public register |
| B16 | Collect the reply by presenting `c` | voter app | app ↔ VRO, direct (§5.3) | `c` : app → VRO; `s_c` : VRO → app |
| B17 | Unblind: `s_{k_p^a} = s_c · r^{-1}` | voter app | voter app (§5.5) | internal |
| B18 | Verify the unblinded token under the pinned `k_p^(R)` before `r` is discarded | voter app | voter app (§3.3, §5.5) | internal |

**Disclosure boundary.** B8 and B9 sit before identity is established, so both
failures return one indistinguishable refusal. Only from B10 onward may the office
give a reason (§3.2).

## Phase C — Casting

| # | Action | Actor | System | Data: sender → receiver |
|---|---|---|---|---|
| C1 | Choose an option `i`, or a value outside `1..N` as a protest ballot | voter | voter app | — |
| C2 | Sign the selection: `s_vote = sig_{k_s^a}(hash([i, k_p^a]))` | voter app | voter app (§5.6) | internal |
| C3 | Submit over an anonymising channel | voter app | app → EBB (§3.9) | `[i, k_p^a, s_{k_p^a}, s_vote]` : app → EBB |
| C4 | Verify the token under `k_p^(R)`; verify `s_vote` under `k_p^a`; accept or reject | EBB | EBB (§5.7) | internal |
| C5 | Append the entry to the hash chain; apply supersession among **accepted** ballots only | EBB | EBB | internal |
| C6 | Return the receipt | EBB | EBB → app | acceptance status, entry position, current chain head : EBB → voter app |
| C7 | Publish the entry commitment and position, the new chain head, the running counts | EBB | EBB → public | commitments, head, counts : EBB → anyone |
| C8 | Mirror the chain head through channels the operator does not control | independent mirrors | outside the EBB (§3.5) | head : EBB → mirrors → anyone |

## Phase D — Checks while the poll is open

| # | Action | Actor | System | Data: sender → receiver |
|---|---|---|---|---|
| D1 | Token-request check: was a token released in my name? | voter | independent checker, separate from the voting app | `[id, sig_{k_s^(v)}(id)]` : wallet-signed query → VRO; release status and the opening value of the voter's own commitment : VRO → voter |
| D2 | Inclusion check: recompute the record hash, match against the published commitment at the stated position under the stated head | voter | any device that can hash (§3.7) | none — offline against published artefacts |
| D3 | Selection check: retrieve the record filed under the ad-hoc key, confirm the recorded choice | voter | independent device → EBB | `k_p^a` : voter → EBB; ballot record : EBB → voter |
| D4 | Count audit: confirm accepted entries do not exceed tokens released | any third party | published counters (§3.5) | public → anyone |
| D5 | Re-vote; the last accepted ballot supersedes the earlier one | voter | voter app, repeating C1–C6 | as C3–C6 |

## Phase E — Close and publication

| # | Action | Actor | System | Data: sender → receiver |
|---|---|---|---|---|
| E1 | Close the poll; stop accepting submissions | administering body | EBB | — |
| E2 | If the selection was encrypted: publish the election private key reconstructed from the shares | independent share-holders | outside the three components (§3.5) | share-holders → anyone |
| E3 | Release every record in clear — selection, `k_p^a`, token, ballot signature — for accepted and rejected submissions alike | EBB | EBB → public | full ledger : EBB → anyone |
| E4 | Publish the final chain head and final counts | EBB | EBB → public | head, counts : EBB → anyone |
| E5 | Publish the final token-release count; the release commitments are never opened publicly | VRO | VRO → public (Table 1) | count : VRO → anyone |
| E6 | Recount independently: every token under `k_p^(R)`, every `s_vote` under its `k_p^a`, supersession among accepted only, each record against its earlier commitment, and the chain head | any citizen | published ledger, standard crypto libraries (§3.5, §6) | public → anyone |
| E7 | Compute the tally, preserving the distribution over distinct out-of-range values rather than one aggregate | any citizen | published ledger (§5.7) | public → anyone |
| E8 | Publish the official tally beside the independently computable one | administering body | Table 1, tally row | official body → anyone |
| E9 | Post-close verification of one's own ballot; under the provable variant, prove authorship by demonstrating control of `k_s^a` | voter | any device | voter → any third party |

---

## Flows the article implies but does not assign

Five gaps, each a decision rather than an omission to be patched mechanically.

1. **The election configuration has no author.** Step A5 has contents (Table 1,
   footnote a) but no named party, no signature, and no stated distribution path.
   Everything downstream — pinning, token verification, range checking — rests on
   it, making it the least specified object in the design.

2. **Nobody operates the checker.** Steps D1–D3 require independence from the
   component under audit, which is a property, not a party. No operator is named.

3. **The close is a time, not an act.** Step E1 is treated as a moment. With
   re-voting and supersession the boundary matters: the article does not say
   whether acceptance is judged by arrival at the box or by a published cut, nor
   who attests that the box stopped.

4. **The office is both committer and sole opener.** The nonce in B15 is generated
   by the VRO and returned to the voter in D1. The article notes the residue that
   the office learns who checked; it does not note that the office alone knows the
   nonces.

5. **No retrieval discipline for `s_c`.** Step B16 has the app collecting the reply
   by presenting `c`, but nothing on polling, held connections, or retries. Minor
   for the article, load-bearing for the implementation.

---

## Note for the wire-contract table

B7, B8, B16, C3, C6, D1 and D3 are the request/response pairs that need
field-level specification. The phase A rows are the ones with nothing yet to
specify.
