# Wire contract

Every field that crosses a boundary in this design, and the clause of the
technical article it discharges.

**What this document is for.** `docs/protocol.md` maps *steps* to functions.
This maps *fields* to obligations. The question it answers is the one a
reviewer asks and neither the article nor the code answers alone: for each
value on the wire, why is it there, and what would break without it? The
second question it answers is less comfortable and more useful — which fields
discharge nothing the article asks for, and which article requirements have no
field at all. Both lists are at the end, and they are short on purpose.

Section numbers refer to *Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System*. Requirement numbers are the eight of
§1. Code names are as of the commit that introduced this file; a rename lands
here as well as in `docs/protocol.md`.

Notation follows the article: $`id`$ the voter identifier, $`c`$ the blinded
value, $`s`$ the wallet signature over the request, $`s_c`$ the blind
signature, $`k_p^a`$ the ad-hoc public key, $`s_{k_p^a}`$ the token,
$`s_{vote}`$ the ballot signature.

---

## 1. Certificate lookup — VRO → population register

External, and not part of the system (§3.2). Implemented in `driver/`.

| Field | Code | Discharges | Note |
|---|---|---|---|
| `person_id` (request) | `PopulationRegister.lookup(person_id)` | §3.2, §5.1 | The only argument. The office holds no key material of its own, so every request begins here |
| `subject` | `Certificate.subject` | §3.2 | The person the certificate names. Must equal the `id` requested; the invariant is currently structural, since `lookup` is keyed by `id` |
| `public_key` | `Certificate.public_key` | §3.2, §5.4 | $`k_p^{(v)}`$, the key $`s`$ is verified under. Deliberately *not* stored by the office — that storage would be the wallet binding §3.2 removes |
| `not_after` | `Certificate.not_after` | §3.2 | Expiry. Reported only past the identity boundary |
| `revoked` | `Certificate.revoked` | §3.2 | Likewise. A revoked certificate still verifies mathematically, which is why revocation is not an identity failure |
| absent entry → `None` | — | §3.2 | One opaque negative for every reason the lookup can fail. The office must not be able to distinguish them, having established nothing yet |

The article requires (§3.2) that the office accept a request signed under **any**
valid certificate naming the requester. This interface returns one. See the
gaps list.

---

## 2. Token request — wallet → VRO

Steps 3–4. The article's package $`[\,id,\, c,\, s\,]`$ (§5.3).

| Field | Code | Discharges | Note |
|---|---|---|---|
| `voter_id` | `AuthRequest.voter_id` | Req. 1, §5.3 | The wallet holds it; the voting application never receives it, so no single component holds both `id` and $`k_p^a`$ |
| `blinded_key` | `AuthRequest.blinded_key` | Req. 3, §5.2 | $`c = \mathrm{enc}(k_p^a)\cdot r^{e_R} \bmod n_R`$. Carries no information about $`k_p^a`$, so the office may log it without weakening anonymity |
| `wallet_signature` | `AuthRequest.wallet_signature` | Req. 1, §5.3 | $`s = sig_{k_s^{(v)}}(hash([id,c]))`$. Binds the request to a named person and to *this* blinded value, so neither can be substituted in transit |
| — (signed bytes) | `AuthRequest.signed_payload()` | §5.3 | Canonical JSON over `voter_id` and base64url `blinded_key`, then SHA-256. Signatures are over bytes: two serialisations of one logical request are two different messages |

---

## 3. Token response — VRO → voting application

Steps 6/A and 6/B. The article gives $`s_c`$ and a rejection; the outcome
vocabulary below is the code's, and §5.4 does not yet enumerate it.

| Field | Code | Discharges | Note |
|---|---|---|---|
| `outcome` | `TokenResponse.outcome` | §5.4 | Six values. Which of them a requester may see is the whole of the identity boundary |
| `blind_signature` | `TokenResponse.blind_signature` | Req. 1, §5.4 | $`s_c = S(c) = c^{d_R} \bmod n_R`$. Present only on `ISSUED`. Note $`S`$, not $`sig`$: $`c`$ already carries the voter's encoding |
| `ISSUED` | `Outcome.ISSUED` | Req. 1 | |
| `NOT_IDENTIFIED` | `Outcome.NOT_IDENTIFIED` | *no section* | Returned for a missing certificate **and** for a signature that does not verify. Merging them is what stops the endpoint answering questions about citizens the requester has not proved to be — see the gaps list |
| `CERTIFICATE_REVOKED` | `Outcome.CERTIFICATE_REVOKED` | §3.2 | Post-identity only |
| `CERTIFICATE_EXPIRED` | `Outcome.CERTIFICATE_EXPIRED` | §3.2 | Post-identity only |
| `NOT_ELIGIBLE` | `Outcome.NOT_ELIGIBLE` | Req. 1, §5.1 | Post-identity only. The electoral register is the office's own list |
| `TOKEN_ALREADY_ISSUED` | `Outcome.TOKEN_ALREADY_ISSUED` | Req. 2, §5.4 | Equality rests here and not at the ballot box, which cannot tell two ad-hoc keys apart |
| — (never returned) | `AuditEntry.voter_id / outcome / reason` | *no section* | The office's private log records the true reason in every case, including which pre-identity situation occurred |

**The office's own check.** Before releasing $`s_c`$ the office confirms
$`s_c^{e_R} \equiv c \pmod{n_R}`$ (§5.4, `rsabssa.check_blind_signature`). A
failure raises `FaultDetected` and is deliberately *not* an outcome: it reports
that the office's hardware misbehaved, not a reason to refuse a requester.

---

## 4. Token-release register — VRO, published

Step 7. Written **before** $`s_c`$ is returned (§5.4).

| Field | Code | Discharges | Note |
|---|---|---|---|
| `commitment` | `vro.commit(id, nonce)` | §3.7, Table 1 | $`hash(id \Vert nonce)`$. Hiding, so a third party cannot test a guessed `id`; binding, so the office cannot later open it to a different one |
| entry index, `prev_hash`, `entry_hash` | `Ledger.Entry` | §3.5 | The register is itself hash-chained, so entries cannot be back-dated into it |
| count | `VRO.release_count()` | §3.5, Table 1 | The aggregate audit: accepted ballots must not outnumber released tokens. Names nobody |
| `nonce` | `VRO._nonces` | §3.7 | Private. Disclosed only through §5 below |

The register never opens publicly, in either phase (Table 1). Its harm is not a
running result but a public list of who did and did not participate.

---

## 5. Release query — voter → VRO, and back

Step 12, the token-request check (§3.7).

| Field | Code | Discharges | Note |
|---|---|---|---|
| `voter_id` (request) | `query_token_release(voter_id, …)` | §3.7 | |
| `signature` (request) | `release_query_payload(id)` | §3.7 | $`sig_{k_s^{(v)}}(\cdot)`$ over domain-separated bytes, so a signature captured from a token request cannot be replayed here |
| `outcome` | `ReleaseAnswer.outcome` | §3.7 | `RELEASED` / `NOT_RELEASED` / `NOT_IDENTIFIED`, the last for an unknown `id` or a bad signature alike |
| `nonce` | `ReleaseAnswer.nonce` | §3.7, Table 1 | Opens the querier's own commitment, and only theirs |
| `index` | `ReleaseAnswer.index` | §3.7 | Position in the published register, so the voter checks the answer against the register rather than trusting the reply |
| `signed_denial` | `ReleaseAnswer.signed_denial` | §3.7 | Signed under the office's **statement** key, never the token key (§3.3): the token key is a blind-signing oracle any voter can drive. Makes a false denial attributable, not impossible |

---

## 6. Ballot — voting application → ballot box

Step 9. The article's package $`[\,i,\, k_p^a,\, s_{k_p^a},\, s_{vote}\,]`$ (§5.6).

| Field | Code | Discharges | Note |
|---|---|---|---|
| `selection` | `Ballot.selection` | Req. 2, Req. 7 | $`i`$. In $`1..N`$ makes the vote *valid*; outside it, *invalid* — still accepted, still superseding |
| `adhoc_public_key` | `Ballot.adhoc_public_key` | Req. 3, Req. 4 | $`k_p^a`$. The voter's anonymous handle. Before the close it is also a lookup secret (§3.7) |
| `token` | `Ballot.token` | Req. 1 | $`s_{k_p^a}`$, an ordinary RSA-PSS signature over $`k_p^a`$ under $`k_p^{(R)}`$, so any third party verifies it with a standard library (§5.5) |
| `vote_signature` | `Ballot.vote_signature` | Req. 1, Req. 4 | $`s_{vote} = sig_{k_s^a}(hash([i, k_p^a]))`$. Covers the selection *and* the key, so neither can be lifted from a published ballot and reused |
| — (signed bytes) | `Ballot.signed_payload()` | §5.6 | Canonical JSON, as in §2 above |

Nothing here identifies the voter. The link to eligibility runs only through
`token`.

---

## 7. Receipt — ballot box → voter

Steps 10–11. §3.4, and the evidence the provability claim rests on (§5.8,
Req. 8).

| Field | Code | Discharges | Note |
|---|---|---|---|
| `accepted` | `SubmissionResult.accepted` | Req. 1, Req. 7 | Passed both cryptographic checks. Not the same as *valid* |
| `reason` | `SubmissionResult.reason` | Req. 7 | `"accepted"`, `"token not signed by VRO"`, `"vote signature invalid"`, or `"voting has closed"` |
| `ledger_head` | `SubmissionResult.ledger_head` | §3.5 | The head at the moment of acceptance. With it the voter can later show that the entry was not removed, reordered, or altered — demonstrable rather than merely alleged |
| entry position | `Ledger.Entry.index` | §3.5, Table 1 | Available on the entry; **not currently carried on the receipt.** See the gaps list |

---

## 8. Published view — ballot box → anyone

§3.5 and Table 1. `BallotBox.published_view()` is the whole of what a citizen
sees.

| Field | Phase | Code | Discharges |
|---|---|---|---|
| `phase` | both | `published_view()["phase"]` | §3.5 |
| `commitments.accepted[].index` / `.commitment` | both | `Entry.index`, `Entry.entry_hash` | §3.5, Table 1 row 2 |
| `commitments.rejected[]` | both | as above | Req. 7 — rejected submissions are published too, so attempts are visible |
| `heads.accepted` / `.rejected` | both | `Ledger.head()` | §3.5, Table 1 row 3 |
| `counts.accepted` / `.rejected` | both | `len(Ledger)` | §3.5, Table 1 row 4 |
| `running_tally[]` | both | `_snapshots` | §3.5 — present only if `tally_interval` is set |
| `records.accepted[]` / `.rejected[]` | **closed only** | `Entry.payload` | Req. 5, §3.5, Table 1 row 5 |

Nothing moves backwards: what is published while voting is open stays
published, and the phase change only discloses more.

**The voter's own lookup**, `find_ballot(k_p^a)`, works in both phases and is
authenticated by $`k_p^a`$ alone (§3.7). It is what keeps the voter's checks
available while the records are withheld from everybody else.

---

## 9. Tally — computed, not received

| Field | Code | Discharges | Note |
|---|---|---|---|
| `counts` | `tally()["counts"]` | Req. 5 | Per option $`1..N`$ |
| `valid` | `tally()["valid"]` | Req. 7 | Accepted ballots with an in-range selection |
| `invalid` | `tally()["invalid"]` | Req. 7 | Accepted, out of range |
| `protest_codes` | `tally()["protest_codes"]` | Req. 7, §5.7 | The distribution over distinct out-of-range values, never one scalar. The system does not interpret any of them |
| `voters` | `tally()["voters"]` | Req. 2 | Distinct ad-hoc keys with an effective ballot |
| `rejected` | `tally()["rejected"]` | Req. 7 | Submissions that never became anybody's vote |
| `ledger_head` | `tally()["ledger_head"]` | §3.5 | The state the count was taken from |

Refused while voting is open unless `tally_interval` is set — the operator gets
no privileged early sight of the result either (§3.5).

---

## 10. Election configuration — published before voting opens

Table 1 footnote (a).

| Field | Code | Discharges | Note |
|---|---|---|---|
| $`k_p^{(R)}`$ | `BallotBox.vro_public_key`, `Voter.pinned_vro_fingerprint` | §3.3 | Published *and pinned*. A per-voter signing key would defeat blinding, and only the client-side check constrains that |
| choice list $`1..N`$ | `BallotBox.num_choices` | Req. 7 | Fixes which selections are in range |
| genesis hash | `ledger.GENESIS` | §3.5 | |
| publication resolution | `BallotBox.tally_interval` | §3.5 | The administering body's decision, not the design's |
| opening and closing times | — | §3.5 | **Not implemented.** `close()` is called, not scheduled |

---

## Fields with no clause behind them

Each of these is in the code and discharges nothing the article currently
asks for. That is a prompt to write the clause or drop the field, not evidence
of either.

1. **`NOT_IDENTIFIED`, and the identity boundary generally.** The article
   enumerates the office's checks (§5.4) but says nothing about which failures
   may be reported to whom. The privacy property — that the token endpoint
   cannot be used as an electoral-roll lookup — is real, is tested, and is
   unstated. It also *reverses* the enumeration order of §3.2 and §5.4 for
   revocation, deliberately. This is the largest gap between code and paper.
2. **The audit log.** Nothing in the article requires the office to record the
   true reason, or forbids returning it.
3. **The separate office statement key.** §3.3 requires the token key serve no
   other purpose, which implies this key must exist, but no clause names it or
   says what signs a denial.
4. **`phase` as an explicit artefact.** Table 1 describes the two phases; the
   article does not require the box to publish which one it is in.

## Requirements with no field behind them

1. **Several certificates per voter** (§3.2). `lookup` returns one.
2. **Entry position on the receipt** (§3.5, Table 1 row 2). The article has the
   receipt carry the position *and* the head; `SubmissionResult` carries only
   the head. The position is available from the entry, so this is a one-field
   omission rather than a missing mechanism — but as written the article's
   inclusion check cannot be performed from the receipt alone.
3. **Opening and closing times** as published configuration (§3.5).
4. **Encrypted selections** under a Shamir-shared election key, for the case
   where no running tally is published (§3.5). Deliberately outside the formal
   model of §5, and deliberately absent here.
5. **Mirrored publication of the chain head** through channels the operator
   does not control (§3.5). Without it the chain constrains nobody: a
   dishonest box can maintain two consistent chains and show each to a
   different audience.
6. **The wallet transmitting rather than the application relaying** (§5.3). One
   `Voter` object holds both `id` and $`k_p^a`$, so the POC does not
   demonstrate the property that section argues for.
