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

## 0. Canonical JSON

Several rows below say "canonical JSON" without saying what it means, which
was survivable while one implementation existed and is not now. Everything
signed or hashed in this design is signed or hashed over these bytes, so a
second implementation that serialises differently does not merely disagree
about formatting: its signatures fail to verify here, and ours fail to verify
there.

| Rule | Why it is not a matter of taste |
|---|---|
| Keys sorted by code point | Insertion order is a property of the producing language, not of the message |
| Separators `,` and `:` with no surrounding whitespace | Any other spacing is a different byte string and therefore a different message |
| Non-ASCII characters emitted as UTF-8, **not** escaped as `\uXXXX` | Python's `json.dumps` escapes by default; `JSON.stringify`, Swift's `JSONEncoder` and RFC 8785 do not. An identifier carrying an accent is where this bites, and nowhere else — which is why no single-implementation test can find it |
| Binary fields as base64url, padding stripped | One decoder rather than two, and no `+` or `/` to survive a URL |

In code: `ovpoc.messages.canonical_bytes`, and `digest` for the SHA-256 over
the result.

**The vectors are the specification, not this table.** `tests/vectors/` carries
fixed inputs with the bytes and digests this implementation produces from
them, including accented, CJK and astral-plane cases. `tests/test_vectors.py`
checks the Python against them and `interop/src/verify-vectors.ts` checks an
independently written TypeScript implementation against the same files. A
reader implementing this protocol should run against those files rather than
against the prose above.

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
| — (signed bytes) | `AuthRequest.signed_payload()` | §5.3 | Canonical JSON (§0) over `voter_id` and base64url `blinded_key`, then SHA-256. Signatures are over bytes: two serialisations of one logical request are two different messages |

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
| `commitment` | `vro.commit(id, opening)` | §3.7, Table 1 | $`hash(id \Vert opening)`$. Hiding, so a third party cannot test a guessed `id`; binding, so the office cannot later open it to a different one |
| entry index, `prev_hash`, `entry_hash` | `Ledger.Entry` | §3.5 | The register is itself hash-chained, so entries cannot be back-dated into it |
| count | `VRO.release_count()` | §3.5, Table 1 | The aggregate audit: accepted ballots must not outnumber released tokens. Names nobody |
| `opening` | `VRO._openings` | §3.7 | Private. Disclosed only through §5 below |

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
| `opening` | `ReleaseAnswer.opening` | §3.7, Table 1 | Opens the querier's own commitment, and only theirs |
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
| `nonce` | `Ballot.nonce` | Req. 2 | $`n`$, 16 random bytes drawn afresh for every submission. Not a secret. It makes two honest ballots for the same selection differ, so a replay can be told from a re-vote (§5.7) |
| `vote_signature` | `Ballot.vote_signature` | Req. 1, Req. 4 | $`s_{vote} = sig_{k_s^a}(hash([i, k_p^a, n]))`$. Covers the selection, the key *and* the nonce, so none can be lifted from a published ballot and reused |
| — (signed bytes) | `Ballot.signed_payload()` | §5.6 | Canonical JSON (§0), as in §2 above |

Nothing here identifies the voter. The link to eligibility runs only through
`token`.

### The ledger dump (`GET /ledger`, EBB, from the close)

One canonically serialised file, so two downloaders of the same election get
identical bytes and can compare the file's own hash across mirrors rather
than comparing their readings of it.

| Field | Note |
|---|---|
| `format` | `ovpoc-ledger/1`. A verifier written against one shape refuses another rather than reading it hopefully |
| `election_id`, `configuration_digest`, `genesis_hash` | Which election, and which published configuration it is checked against. The verification keys are deliberately *not* here: a dump that verifies against itself establishes nothing |
| `accepted[]`, `rejected[]` | `{index, commitment, record}` in registry order |
| `heads`, `head_signatures` | The final heads and the box's statements over them, under `k_p^(B)` |

The dump carries no signature of its own and needs none. Recompute the chain
from the records against the genesis hash; if the head you reach is the head
the box signed, every record and their order are authenticated by that one
signature. That is what the chain is for.

The office's released-token count is deliberately absent. The audit it feeds
is worth something precisely because the two figures come from two
components, so the box must not vouch for the office's: fetch it from
`GET /release-log` on the VRO, where `count` is accompanied by
`count_signature` under `k_p^(O)`.

### The release register dump (`GET /releases`, VRO, throughout)

The office's data on the ledger's terms, and available from the opening
rather than from the close: nothing in this register is a ballot, so
nothing in it is withheld.

| Field | Note |
|---|---|
| `format` | `ovpoc-releases/1` |
| `election_id`, `configuration_digest`, `genesis_hash` | As for the ledger. The keys are pinned from the published configuration, not read from the file |
| `entries[]` | `{index, commitment}` in order. `hash([id, opening])`, one per token released |
| `head`, `head_signature` | The register's chain head and the office's statement over it, under `k_p^(O)` |
| `count`, `count_signature` | The figure the count audit needs, and the office's statement over it |

It carries no signature of its own for the same reason the ledger does not:
recompute the chain from the commitments against the genesis hash, and the
signed head accounts for all of it.

It names nobody. The commitments are opaque by construction and the values
that open them are released to one voter at a time, to the voter who can
authenticate a query about their own. A file that disclosed participation
would be the plaintext register of §3.7, handed over in a more convenient
form.

### The supervision register (8006, from the close)

Its own origin, reachable only from inside the operator's network. No
supervisor list, no signature, no nonce: whoever can reach the origin is a
supervisor, and the control is the perimeter it is served behind. `GET /`
is the console, `GET /data` the same content for that page, `GET
/supervision` the canonical file.

| Field | Note |
|---|---|
| `releases[]` | `{index, voter_id, opening, commitment}`. The openings are here because a supervisor cannot verify the commitments without them |
| `audit[]` | `{voter_id, outcome, reason}` in order, including the true reason behind refusals the requester saw as one indistinguishable answer (§3.2). No timestamps |
| `head`, `head_signature`, `count`, `count_signature` | As in the public dump, so the two can be compared |
| `supervisor_downloads` | Also published on `/releases` and `/release-log`, so the office cannot hand the register out quietly |

Open only from the close: while the poll runs this is a live list of who
has and has not taken part, which is the lever §3.7 describes.

Nothing is taken on trust. The console recomputes each commitment as
`H(id ‖ opening)`, chains them as `H(indexₖ ‖ prev ‖ canonical(payload))`
from the genesis hash, and verifies the head and count signatures against
`k_p^(O)` from the published configuration — not against anything in the
data.

What it catches that nothing else does: a release naming somebody not on
the roll, and two releases for one identifier — the atomicity failure of
§5.4, still invisible in the public artefacts but demonstrable here
afterwards. What it does not catch is a single well-formed release for an
eligible citizen who abstained and never checked; only the voter's signed
request would separate that from a genuine one, and the office does not
retain it. That residual belongs to distributed issuance.

The electoral register is not in the file. A supervisor comparing these
identifiers against a roll this office supplied would be comparing the
office against its own copy; the roll comes from the citizen registry, with
current eligibility.