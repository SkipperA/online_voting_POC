# Stage 1 — surface and boundary map

What runs where, what crosses between, and what each boundary must never
carry. This is the document the TypeScript voter client is written against.

Section references are to *Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System*. Row references (B4, C3, …) are to
`Online_Voting_Action_Table.md`. Field names are those of
`docs/wire-contract.md`.

---

## 1. Origins

Seven origins. **Five trust domains.** The count differs on purpose and the
difference is stated here so that nobody adds them up wrong.

An origin is scheme + host + port, so seven ports on `127.0.0.1` are seven
distinct origins with fully separate storage, `postMessage` targets, and
service workers. Named hosts in `/etc/hosts` read better in a demonstration
but buy nothing technically.

| Port | Origin | Trust domain? | Serves | Must never serve |
|---|---|---|---|---|
| 8000 | **config** | No — inert | `election.json`, `election.json.sha256`. Static files, no logic, no state | Anything computed at request time |
| 8001 | **voter app** | Yes | The voting client: ad-hoc keygen, blinding, unblinding, token verification, ballot signing, submission | Any code path that reads `id` |
| 8002 | **wallet** | Yes | Consent page and the signing daemon behind it (`driver/wallet/`) | `k_s^{(v)}` to anything, including its own page |
| 8003 | **VRO** | Yes | Token endpoints, release query, back-office console | The voter app's bundle; `k_p^{(R)}` as a pin source |
| 8004 | **EBB** | Yes | Ballot submission, receipts, published view, lookup by `k_p^a` | Anything keyed by `id` |
| 8005 | **checker** | Yes | The three independent checks of §3.7 | Any script loaded from 8003 or 8004 |
| 8009 | **setup console** | No — build-time | Authoring UI; writes `election.json` into 8000's document root, then has no role | Any endpoint the poll depends on at runtime |

**The config origin is inert. The setup console is build-time.** The poll must
run correctly with 8009 stopped, and that is a test, not an intention.

### Why the voter app cannot be a checker

§3.7 requires each check to be independent of what it audits, and no more than
that. The selection check audits the voting application, so it must run
somewhere that application does not control. A separate browser page is
sufficient and need not be separate hardware — but it must be a separate
origin, and in stage 3 it must remain a web page rather than a screen inside
the signed binary. A forged app that spoofs the ballot and the check together
defeats both at once.

### Cookies

Cookies ignore the port component of an origin. A cookie set on
`127.0.0.1:8001` is readable on `127.0.0.1:8002`, and the isolation above
becomes a fiction. So: **no cookies anywhere, no sessions, `credentials:
'omit'` on every fetch, no `Set-Cookie` from any surface.** The voter app has
no login by construction; nothing else in the demo needs one.

---

## 2. The configuration artefact

Authored by the setup console at 8009, served as a static file from 8000.

**Contents** (Table 1, footnote a; `wire-contract.md` §10): election
identifier, `k_p^{(R)}`, choice list `1..N`, genesis hash, publication
resolution (`tally_interval`), opening and closing times.

**Consumers.** All four runtime trust domains agree on this one object:

- voter app — pins `k_p^{(R)}` **at build time**, not at runtime;
- EBB — initialises the registry at the genesis hash (A7), takes `num_choices`
  and `tally_interval`;
- VRO — takes the election identifier;
- checker — takes the verification parameters.

**Why the pin is build-time.** If the voter bundle fetched `k_p^{(R)}` from
the VRO at startup, the office would be supplying the key its own signature is
checked against, and §3.3's defence against per-voter signing keys would
evaporate. `voter.py` already refuses to proceed on a fingerprint mismatch;
the TypeScript client must do the same, and the fingerprint must be on screen.

**The two-glance check.** The setup console imports `k_p^{(R)}` from the VRO
back office and displays its fingerprint beside the fingerprint the VRO
console displays, for a human to compare. Deliberately two surfaces and two
glances rather than an automatic fetch: it is the honest picture of what
pinning means, and it demonstrates well.

**A failure worth demonstrating.** Change one byte of the served file. The
voter app refuses on the pinned-fingerprint check.

No signature over the configuration in the demo (clause S4). The published
hash is what makes tampering demonstrable.

---

## 3. Boundaries

For each: direction, fields, and what the boundary would violate by carrying
anything more.

### B4 — blinded value, voter app → wallet

`postMessage` to the wallet origin with an explicit `targetOrigin`.

| Carries | Why |
|---|---|
| `c` | The blinded value, and nothing else (§3.6) |

The wallet must not receive `k_p^a`, `r`, or the selection. It signs a hash
over `[id, c]` with `c` opaque to it — which is also a good teaching surface,
since the consent screen can show the voter an identifier it does know and a
blob it visibly cannot interpret.

### B4-reply — acknowledgement, wallet → voter app

**A bare acknowledgement. No `id`, no `s`, no `s_c`, no certificate detail.**

This is the boundary I would guard hardest. §5.3's whole argument is that the
wallet transmits rather than the application relaying: if the reply carries
anything identifying, the voting application holds both halves of the
association the blind signature exists to sever, together with the office's
signature on it as evidence. The reply schema must have no field capable of
carrying it.

### B7 — token request, wallet → VRO

Direct, server to server. Not through the voter app.

| Field | Value |
|---|---|
| `voter_id` | `id` |
| `blinded_key` | `c` |
| `wallet_signature` | `s = sig_{k_s^{(v)}}(hash([id, c]))` |

### B8 — certificate lookup, VRO → population register

External, `driver/`. One argument (`person_id`), returning the full qualified
certificate or one opaque negative. The office must not be able to distinguish
the reasons a lookup failed, having established nothing yet.

### B7-reply — token response, VRO → wallet

`outcome` only, from the six-value vocabulary. The identity boundary is the
whole point: `NOT_IDENTIFIED` covers both a missing certificate and a
signature that does not verify. Only past that boundary may a reason be given.
The blind signature is **not** returned here.

### B16 — blind signature collection, voter app → VRO

A separate, deliberately unauthenticated endpoint (§5.3). It takes bare `c`.

**Retrieval discipline:** the app POSTs `c` on a single held request that
returns only once the release has been recorded; idempotent on `c` for
retries. This makes the B15-before-B16 ordering of §5.4 structural rather than
a matter of the caller behaving well — which is the property the article
argues for, since a returned-then-recorded ordering would leave a token in
circulation the register does not account for.

| Returns | Value |
|---|---|
| `blind_signature` | `s_c = S(c) = c^{d_R} mod n_R` |

The endpoint is unauthenticated on purpose, not by oversight: an intercepted
`c` yields an intercepted `s_c` and no advantage, since unblinding needs the
`r` that never leaves the application.

### C3 — ballot, voter app → EBB

Over the (absent, clause A2) anonymising channel.

| Field | Value |
|---|---|
| `selection` | `i` |
| `adhoc_public_key` | `k_p^a` |
| `token` | `s_{k_p^a}` |
| `vote_signature` | `s_vote = sig_{k_s^a}(hash([i, k_p^a]))` |

Nothing here identifies the voter. **The EBB must never receive `id`**, and
must expose no endpoint keyed by it.

### C6 — receipt, EBB → voter app

| Field | Value |
|---|---|
| `accepted` | Passed both cryptographic checks — not the same as *valid* |
| `reason` | Acceptance or the specific failure |
| `index` | Entry position in the registry |
| `ledger_head` | The head at the moment of acceptance |

The last two are what let the inclusion check run offline against published
artefacts, with no query to the component under audit.

### D1 — release query, checker → wallet → VRO

The checker invokes the wallet daemon for a signature over domain-separated
bytes, then queries the VRO. Same wallet, second consent screen — which
demonstrates the wallet's actual status as a shared external dependency
serving two independent surfaces rather than a component of either.

| Field | Value |
|---|---|
| `voter_id` (request) | `id` |
| `signature` (request) | Over `release_query_payload(id)`, domain-separated so a token-request signature cannot be replayed here |
| `outcome` | `RELEASED` / `NOT_RELEASED` / `NOT_IDENTIFIED` |
| `nonce` | Opens the querier's own commitment, and only theirs |
| `index` | Position in the published register |
| `signed_denial` | Under the office's **statement** key, never the token key |

The statement key matters: the token key is a blind-signing oracle any voter
can drive (§3.3). A false denial must be attributable, and signing it under
the oracle key would make it forgeable.

### D3 — selection check, checker → EBB

| Sends | Returns |
|---|---|
| `k_p^a` | The record filed under it |

Authenticated by `k_p^a` alone (§3.7). Before the close it is a lookup secret
as well as a locating handle: the VRO never sees it, and no published artefact
contains it. No signature needed, and no private key leaves the voter's device
to reach the machine the check runs on.

### Published view — EBB → anyone

Unauthenticated. Commitments, positions, chain heads, counts in both phases;
records in clear only from the close. Nothing moves backwards.

---

## 4. Negative claims worth testing

Each of these is a property the architecture asserts. Each is testable, and
untested it is decoration.

1. **No cookies.** No surface emits `Set-Cookie`; every fetch omits
   credentials.
2. **The wallet's reply to the voter app is a bare acknowledgement.** The
   reply schema has no field capable of carrying `id`, `s`, or `s_c`.
3. **The voter app never holds `id`.** No code path in the bundle reads it;
   no response it receives contains it.
4. **The EBB never receives `id`.** No endpoint accepts or is keyed by it.
5. **The VRO never receives `k_p^a`.** Only `c`, and only before signing.
6. **The checker loads no code from what it audits.** `script-src 'self'` on
   8005; `connect-src` to 8003 and 8004 but no script from either.
7. **The poll runs with the setup console stopped.** Full end-to-end with 8009
   down.
8. **The voter app refuses on a fingerprint mismatch.** Already enforced in
   `voter.py`; must hold in the TypeScript client.
9. **Blinding, unblinding, ad-hoc keygen and token verification are
   client-side.** No server endpoint accepts an unblinded `k_p^a` before
   signing, and none returns or receives `r`.

---

## 5. Which surface displays which scope clause

From `Demo_Scope_Limits.md`. Built in rather than retrofitted, so the screen
and the presenter say the same thing.

| Surface | Clauses |
|---|---|
| voter app | A2 (no anonymising channel), A3 (browser-delivered code), O3 (provable variant only) |
| wallet | S1 (software stub, hardware in deployment) |
| VRO | S2 (fixture certificate lookup), S3 (fixture register), A1 (single issuing office), O1 (one operator for several bodies) |
| EBB | A4 (times recorded, not enforced), O2 (no complaint process) |
| checker | A2, O2 |
| setup console | S4 (no authoring body, no signature), O1 |
| config origin | Nothing — it is a file |

---

## 6. Interop obligations for the TypeScript client

The fork is accepted; `voter.py` is retained as the reference oracle. What
must be tested across the two implementations:

- **Golden vectors for canonical serialisation.** `canonical_bytes` is
  sorted-key, separator-tight JSON with base64url binary fields. The current
  field set is ASCII strings and integers, so JS `JSON.stringify` should
  agree — but "should" is not a test, and this is the classic place for a
  silent break.
- **Cross-implementation blind signature, both directions.** TS blind →
  Python `blind_sign` → TS finalize → Python verify, and the mirror. This is
  worth more than it looks: `emsa_pss_encode` in `rsabssa.py` is hand-written
  from RFC 8017 §9.1.1 and the existing suite can only check it against
  itself. An independently written, RFC-test-vector-validated implementation
  on the other side of the wire is a check the 47 tests structurally cannot
  perform.
- **Fingerprint agreement.** `public_key_fingerprint` is SHA-256 over the DER
  SubjectPublicKeyInfo; the TS client must compute the same string from the
  same key.
- **Ed25519 raw encoding.** 32-byte raw public keys on both sides; WebCrypto
  exports SPKI and JWK, not raw, so the conversion needs a vector test.

Library choice: `@cloudflare/blindrsa-ts` (RFC 9474, `SHA384.PSS.Deterministic`,
WebCrypto-backed) and WebCrypto Ed25519, with `@noble/ed25519` as fallback.
