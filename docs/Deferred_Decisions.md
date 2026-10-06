# Deferred decisions

Open questions and pending amendments, held here so that stage 1 can proceed
without them and so that a later reader can act on each without re-deriving the
reasoning.

Settled decisions live in `CLAUDE.md`. This file holds only what is *not*
settled, plus corrections known to be needed but not yet applied. An item
leaves this file when it is applied, not when it is decided.

Section references are to *Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System*. Row references are to
`docs/actions.md`. Clause references are to `docs/Demo_Scope_Limits.md`.

---

## 1. Article amendments

### 1.1 "Official" in the tally row — Table 1

The tally row conflates two different things: the ballot box's automatic
function over the released records, and the official result as a legal act by
the administering body. Now that the tally is settled as a deterministic
function the EBB computes and publishes at close (row E8), the word *official*
is wrong for what the box produces.

The row should name a publisher for each: the EBB publishes the tally, the
administering body declares the official result, and the two are different
artefacts even when one body does both.

**Applied in `docs/actions.md` already** (E8 and the new E10). The article has
not been amended.

### 1.2 The office statement key is not in the configuration — Table 1

Table 1 footnote (a) lists the configuration as the election identifier,
`k_p^{(R)}`, the choice list, the opening and closing times, and the genesis
hash. The office's statement key is absent, yet §3.3 implies it must exist —
the token key is a blind-signing oracle and cannot sign statements — and a
signed denial is worth nothing unless the voter and the checker hold an
authentic copy of the key that verifies it. Pinning is how every other key in
this design is protected.

The decision is taken and recorded in `docs/actions.md` (A4b, A5),
`docs/wire-contract.md` and the surface map: the key is `k_p^{(O)}`, generated
by the VRO operator, published and pinned in the configuration beside
`k_p^{(R)}`. The article has not been amended.

**Notation caution.** `S` is already the raw private-key operation in §5, so
`k_p^{(S)}` would collide on the same page. `(O)` for "office statements" is
provisional; if a better symbol is chosen it should be chosen before the
current one spreads further.

### 1.3 Mirroring the chain head — §3.5

§3.5 currently names "several independent mirrors, a printed record, or a
public notice" as the defence against a box maintaining two internally
consistent chains for two audiences. Nothing in that list carries an incentive
to check.

The candidate replacement is supervision by competing parties, which reuses the
adversarial motive §2 already credits to mutual oversight in a polling station,
and keeps the proposal's framing as an evolution of electoral administration
rather than a new apparatus to be staffed from nothing.

Three points the amendment must make, since the obvious formulation misses two
of them:

- **Attesting the genesis fixes the start, not the chain.** A box showing head
  H to one party and H′ to another, both descending from the same attested
  genesis, is exactly the equivocation §3.5 is about. The mechanism is that
  each party independently records heads *during* the poll; genesis attestation
  is the first entry in that log.
- **What is recorded is the pair, not the head.** A timestamped head alone is
  weak evidence, because the box can dispute arrival order. Two parties holding
  different heads at the *same index* is conclusive and needs no adjudicator.
  So the artefact is a list of signed `(index, head)` observations taken at
  moments of each party's own choosing.
- **A hash chain detects a fork but cannot prove consistent extension before
  the close.** A party holding a head at index *i* and a later head at index
  *j* cannot verify the second extends the first without replaying records
  *i+1..j*, which are withheld until the close. A Merkle tree would give
  consistency proofs during the poll, at the cost of §3.5's claim that the
  mechanism introduces no assumption beyond a collision-resistant hash.
  Recommendation is to keep the chain and state the limit.

Known weaknesses of the party-supervision answer, to be stated rather than
elided:

- It rests on plurality. A jurisdiction with one effective party gets nothing,
  and the policy paper's own argument about hostile or locally captured
  authorities applies with full force.
- Attestation must mean signatures, not minutes, or a party can later deny what
  it recorded. That is new key management for bodies that do not currently hold
  election keys.
- A party observer in a polling station watches a process they understand. Here
  they hold 32 bytes. Comparing is trivial; knowing what was attested is not.

### 1.5 Token release is not atomic — §5.4

§5.4 establishes the order: record the release, then return `s_c`. The
argument is about interruption, and it is right — recording first fails in
the harmless direction, since a logged release that never completed appears
only as a token nobody used. But it reasons about one request in isolation,
and the silence about concurrent ones is the kind a reader implementing the
design would not notice until load testing.

**The defect.** The office checks that no token has been released for this
`id`, then records, then signs. Nothing makes those three steps atomic. Two
requests for the same identifier arriving together can both pass the check
before either records, and both receive a token. Requirement 2 is then broken
— one voter, two counted ballots — and *nothing in the published artefacts
shows it*, because two commitments for one citizen are indistinguishable from
two citizens. The aggregate audit still balances. The voter's own D1 check
still answers truthfully. There is no observer who can see it.

**What the design needs.** The eligibility check and the release must be one
atomic act: claim the identifier or fail, and only the winner proceeds to
sign. That is a reservation held from before the check until the commitment
is written — a state the design does not currently name, and which a
deployment needs whether or not anything ever pauses in the middle.

Two consequences to specify with it.

*The reservation must publish nothing.* No commitment, no increment to the
count, until the release itself. Otherwise the pause becomes visible in the
published artefacts, and a third party could distinguish an office that is
deliberating from one that is not — which is not a property the design
offers, and not one it should acquire by accident.

*A reservation that never completes needs a documented route back.* In
production the gap is closed by a crash rather than by anyone deciding; the
consequence is the same either way — a citizen reserved, nothing published,
no token, and no way to ask again. §5.5 already requires a documented
re-issuance path with an audit trail for the case where the voter's own
verification of `s_{k_p^a}` fails. This is the second caller for that same
procedure, which is an argument for specifying it in the article rather than
leaving it to deployment.

**Status.** The POC is single-threaded, so it cannot exhibit the race. The
operator-triggered signing console (item 3b.3) is the first consumer of the
reservation state: it holds a real state open long enough to be looked at,
rather than inventing a demonstration-only one. The console is therefore
worth building *after* this is settled, not as the reason for settling it.

### 1.6 Whether party supervision resolves A5 and E1 jointly

If competing parties attest the genesis before the poll opens, the same act can
cover `k_p^{(R)}`, the choice list and the times — which is gap 1 and clause
S4, a configuration that currently has no signer. And the close becomes an act
rather than a timestamp — gap 3 — because the cut is the final head the parties
attest.

One institution, three standing open questions. The convergence is neat enough
to warrant suspicion, and taking it would be the largest single edit to §3 on
this list. Deliberately not taken. If it is taken, `docs/actions.md` rows A5,
A9 and E1 change with it, and clauses S4 and A4 are affected.

### 1.7 The count audit is stated over the wrong quantity — §3.5

§3.5 offers one check that speaks about the ballots collectively rather than
one at a time: "the running count lets any third party confirm that the
number of accepted entries does not exceed the number of tokens the VRO
reports having released."

**That bound does not hold.** A token certifies one ad-hoc key, and §3.4
permits a voter to cast under it as often as they like — re-voting is the
design's answer to coercion. Two ballots from one voter are two accepted
entries against one released token, so the stated inequality is violated by
the design operating exactly as intended. A checker implementing §3.5
literally reports honest re-voting as fraud, which is what it did here.

**The bound that holds is over distinct ad-hoc keys**, not entries: one
token, one key, any number of ballots under it.

**And it is not available while voting is open.** Distinct keys cannot be
counted from the published artefacts before the close, because the records
are withheld and only commitments are published (Table 1). So §3.5's "throughout
the voting period" is wrong twice: the quantity is wrong, and the timing is
wrong for the corrected quantity.

What remains available during the poll is weaker and worth stating as such:
the number of accepted entries and the number of tokens released are both
public, and neither bounds the other. An office minting tokens nobody uses
is invisible either way; §3.7's third qualification already says so.

Corrected in `web/checker/static/checker.js`, which now reports the figures
without a verdict while the poll is open, and checks distinct keys against
tokens at the close. The article has not been amended.

---

## 2. Scope limits (`docs/Demo_Scope_Limits.md`)

### 2.1 New Absent clause — threshold encryption of the selection *(written: A5)*

Covers rows A8 and E2, currently silent in the demo.

*Absent* rather than *out of scope*, and the reasoning matters for how it is
spoken. §3.5 sets the condition: where no running tally is published, the
operator would otherwise see selections individually while the public sees
nothing, and that asymmetry should be removed by encrypting the selection under
a key held in shares. The design as formalised in §5 withholds contents until
the close and therefore publishes no running tally, so §3.5's own condition is
met and §3.5's own remedy applies. §3.5 then says plainly that §5 sets the
design out with the selection in clear. The demo follows §5.

The extension is scoped rather than structural, in the same way A1 is: §3.5
notes that acceptance turns on the two signatures and never on the selection
value, so the ballot box's verification is unchanged. Key generation at A8,
shares held by independent bodies, chained ciphertexts, the reconstructed key
published at E2, every citizen decrypting at the close.

**Draft label:** *Selections are stored in clear, so the ballot box operator can
read a ballot before the poll closes. The design says that where no running
tally is published the selection should be encrypted under a key held in
shares; this build does not do that.*

**Undecided:** which surface displays it. The EBB is where selections sit in
clear; the voter app is where a voter would care.

### 2.2 New Absent clause — chain-head mirroring and equivocation *(written: A6)*

Covers row C8.

C8 splits into one part the demo can show and one it cannot. Rollback and
truncation are detectable by a single observer retaining `(index, head)` pairs
over time, and the checker at 8005 can do that honestly. Equivocation across
audiences requires genuinely separate observers with separate motives, which
one machine under one operator cannot supply; a second origin on the same box
demonstrates the shape of the property, not the property.

So: a working head-history check on the checker, plus a clause naming party
supervision (item 1.3) as the deployment answer and saying why the demo cannot
show it.

### 2.3 Clause numbering collides with action-table rows

Scope clauses A1–A4 already collide with action-table rows A1–A9, before the
two new clauses above are added. The surface map's §5 lists "A4 (times
recorded, not enforced)" for the EBB; action-table A4 generates the token
signing key pair. Two namespaces, four collisions, in documents that cite each
other constantly.

Two candidate fixes:

1. **Convention.** Always write "clause A4", never a bare "A4", for a scope
   limit. `Demo_Scope_Limits.md` and the surface map already do this in places
   and not in others. Cheapest, and leaves the collision latent.
2. **Rename.** Move clauses to `SUB-n` / `ABS-n` / `OOS-n`. One-time cost
   across two documents, and the ambiguity is gone rather than managed.

Undecided. Should be settled before a fifth Absent clause is written, not
after.

---

## 3. Tooling

### 3.1 `tools/sabotage.py` exits 0 even when a mutation goes undetected

`main()` prints the undetected count and returns 0 regardless. The CI guarantee
therefore rests entirely on `git diff --exit-code docs/sabotage.md`: an
undetected mutation changes the report, so the diff catches it. That works, but
indirectly, and a mutation added without regenerating the report would pass the
exit code while failing the diff. The tool should return non-zero when
`uncaught` is non-empty.

### 3.2 `docs/sabotage.md` has no cheap staleness check

`tools/golden_vectors.py --check` reports drift in a second. The sabotage
report has no equivalent: the only way to learn it is stale is to spend four
and a half minutes regenerating it, or to push and watch CI fail. A `--check`
mode would not help, since it would still have to run every mutation.

The cheap alternative is a hint rather than a check: record in the report the
names of the tests present at generation time, so a mismatch against the
current suite is detectable instantly. Imperfect — a test could change
behaviour without changing name — but it catches the common case, which is a
new test added and the report not regenerated.

### 3.3 `npm audit` reports two high-severity advisories

Both are `sjcl`, reached through `@cloudflare/blindrsa-ts`, and both concern
missing point-on-curve validation in `sjcl.ecc`. The blind-signature path uses
sjcl only for bignum arithmetic and never touches its ECC code, so the
advisories do not apply here. `npm audit` is deliberately **not** a CI step for
that reason; recorded so that the omission reads as a decision rather than an
oversight. Revisit if blindrsa-ts changes its dependency or its usage.

*(The two `rsabssa.py` items that stood here — the retried non-invertible
blinding factor and the missing RFC 9474 step 4 — were closed in `66659cc` and
`9dfa3b1`, with `ModulusCompromised` and three tests.)*

---

## 3b. Stage 1 defects, open

### 3b.1 The voter application loses its ad-hoc key on reload

The key pair is generated non-extractable and nothing is stored, so reloading
8001 orphans the ballot: the voter cannot find their record, cannot re-vote,
and their single entitlement is already spent. A real application would not
behave this way.

Fixing it means generating the key extractable and putting it in
`localStorage`, which withdraws the "this page cannot read `k_s^a`" property
the page currently advertises — and §3.7's second qualification becomes
sharper, since a compromised device that holds the signing key can cast a
silent override after the voter's last check. At stage 3 the iOS keychain
gives both; in a browser it is a choice.

Undecided. Either persist and withdraw the claim, or keep the claim and warn
on the page that a reload loses the ballot.

### 3b.2 The close has no interface

`POST /close` is reachable only by curl, and is deliberately shut to
cross-origin requests: closing is an act of the box performed by an operator
(E1), so no page should be able to provoke it. But the EBB has no operator
surface at all, which makes the one act with the clearest institutional
meaning the only one with no way to perform it.

Either a sixth browser surface for the box operator, or a clause saying the
act is deliberately curl-only and why. Undecided.

### 3b.3 Operator-triggered signing, and the state it needs

The office's console should let an operator see a validated request and
perform the blind signature as a deliberate act, which is what makes 6/A
visible at all. `issue_token` already falls into two halves — six checks that
return early, then recording and signing — so the split itself is small.

What is not small is the seam. Pausing between validation and signature turns
§5.4's "interruption" from a fault into a normal operating state, so the
reservation of item 1.5 has to exist first. With it the console is
straightforward: validate reserves, sign releases and commits, cancel clears
the reservation, and every transition appears in the audit log beside what
was disclosed.

Needs a sabotage mutation of its own: publish the commitment at validation
rather than at signature, and something must notice that the count now
overstates. An invariant with no mutation behind it is described rather than
defended.

### 3b.4 The wallet is told more than delivery, and stops being told

**Settled: the wallet needs one fact only — that the office received the
token request.** Nothing after that is its business.

The reasoning is the wallet's position rather than the content of the
answer. It is the one component holding `id`; the voting application holds
`k_p^a` and must never hold `id` (§5.3). A wallet that also learned whether
a token was afterwards released would be accumulating the fact that this
citizen completed — a participation record against precisely the identifier
the rest of the design keeps away from it. That the wallet could already
infer most of it is not a reason to hand it the remainder.

Two consequences, one applied and one open.

*Applied in the page copy.* After a held request the wallet shows
`AWAITING_RELEASE` and says that this remains the correct answer even after
an operator signs, because the voting application collects the reply and
nothing comes back through the wallet. An earlier attempt added a `/status`
endpoint letting the wallet ask the office whether the token had been
released; it was removed for the reason above.

*Open.* `AWAITING_RELEASE` is the transport's word for `Outcome.RESERVED`,
and it describes the office's internal state rather than the delivery. If
the wallet should be told only that the request arrived, the honest answer
is a single acknowledgement — received and accepted for processing — with
the office's internal state not disclosed at all. That is a narrowing of
what the office says, so it touches §3.2's disclosure boundary and should be
decided there rather than in the page.

### 3b.5 A test asserts page copy the server demonstrably serves

While making the above change, one test asserting the new wallet copy fails
inside the module's shared live fixture, while a direct fetch of the same
URL returns a page containing that copy. The code is right and the test
disagrees with reality, which means either the fixture is serving something
other than what it appears to or the assertion is malformed.

Not diagnosed. The first move is to run that test alone with the deployment
left running and curl the same URL alongside it. Worth resolving before any
further test is written against served page content, since the same fixture
carries several.

---

## 4. Surface map (`docs/Stage1_Surface_and_Boundary_Map.md`)

### 4.1 Line 290 is wrong about WebCrypto (still open)

The interop list states that WebCrypto "exports SPKI and JWK, not raw". It
exports raw: `exportKey('raw', publicKey)` on an Ed25519 public key returns the
32 bytes, verified in Node 22, and equal to the trailing 32 bytes of the SPKI
export where a fallback is wanted.

Ed25519 in WebCrypto shipped in Safari 17.0, Firefox 129 and Chrome 137, so the
floor is roughly Safari 17+, Chrome/Edge 137+, Firefox 130+, Node 20+. Worth
stating in the map, since it is the browser floor for the whole voter app.

### 4.2 Whether `@noble/ed25519` stays as a fallback

The map names it as a fallback for WebCrypto Ed25519. Given native support in
every current engine, and that a pure-JS implementation needs the private
scalar as ordinary bytes and so forfeits non-extractability, the fallback may
cost more than it buys — and it would run on precisely the oldest and least
patched engines. Undecided.

### 4.3 §7 row-coverage table not yet written

Every row A1–E10, its origin, and the clause where there is no surface. Blocked
only on 2.2 above, which is now decided in outline.

---

## 5. Not deferred — settled, recorded here only as pointers

- E8 publishes from the EBB as a deterministic function of the released
  records. The demonstrable check is the checker's independent TypeScript
  recomputation against the EBB's Python: two implementations, one
  specification, same input. Applied in `docs/actions.md`.
- A8/E2 becomes an Absent clause rather than a silence. Text drafted at 2.1,
  not yet applied.
- `@cloudflare/blindrsa-ts` 0.4.4 exposes `RSABSSA.SHA384.PSS.Deterministic`
  and interoperates with `rsabssa.py` in both directions. Recorded in
  `CLAUDE.md`.
- Canonical JSON emits non-ASCII as UTF-8 rather than escaping it
  (`ensure_ascii=False`), which is what every other implementation does and
  what RFC 8785 specifies. Defined in `docs/wire-contract.md` §0 and pinned by
  `tests/vectors/canonical-json.json`.
- The golden vectors are the conformance artefact for stages 1 and 3:
  `tools/golden_vectors.py` generates them reproducibly, `tests/test_vectors.py`
  and `interop/src/verify-vectors.ts` consume them, and CI runs both.
- The Voting Administrator authors the election configuration (A5). Any citizen
  uses the check services; each party may serve the endpoints over its own data,
  because what they return is self-authenticating. The close is an act of the
  EBB (E1). Recorded in `docs/actions.md`, where the three gap entries are
  narrowed to what actually remains.
- The office statement key `k_p^{(O)}` goes into the election configuration;
  refusals and denials are signed under it, never under the token key.
- **Action-table gap 5 (retrieval of `s_c`) is resolved.** B16 is a plain GET
  that returns 404 until the reply exists, keyed by the blinded value; the
  application polls. `c` is unguessable and was generated by the application,
  so no second credential is invented. Nothing is held open and no framework
  feature does the waiting where a reader cannot see it.
- **The wallet handover is a file the voter carries.** 8001 saves
  `token-request.json`; the wallet reads it, checks the election identifier
  and the configuration digest against the configuration it fetches itself,
  refuses on mismatch, then signs and transmits from its own origin. Nothing
  returns through the page, because nothing needs to: the application already
  holds `c`. In a deployment this is an app-to-app invocation; the clumsiness
  is the point, since nothing passes between the origins except what the voter
  moved.
- **The cross-origin contract is closed by default.** Three allowances only —
  the whole config origin, `GET /token-replies/…` on the office, and the
  ballot paths on the box. `/release-queries`, `/release-log`, `/close` and
  `/tally` stay closed, and the closures are asserted in tests because an
  absent header is invisible in review. Set out in the surface map.
- **The election is durable and the poll is not.** The setup console writes
  both key pairs, the electoral register and the wallet personas; the runtime
  loads them and refuses to start if they are absent. The ballot box, the hash
  chain and the released-token register are in memory. Clause A7.
- **The checker is served at 8005 and holds nothing.** Static files; every
  conclusion it draws comes from artefacts published by the party being
  audited. D1 arrives as a file the voter carries from the wallet, so the
  wallet still grants nothing cross-origin. The page states that in this
  deployment the independence is asserted rather than demonstrated, since one
  operator runs the checker and the audited parties alike.
- **Cross-origin allowances are named, not wildcarded, where the argument
  depends on who is asking.** `/release-log`, `/release-queries` and `/tally`
  open to the checker origin by name: `*` would hand the voting application
  exactly the access §3.7 withholds. `/token-replies/…`, `/ballots` and
  `/published` open to `*`, because there is nothing in them to withhold from
  anyone. `/close` opens to nobody.
- **The config origin serves an index of the whole deployment.** Seven
  origins with their trust-domain status, the election's fingerprint and
  digest, the order a run goes in, and what is published when. The origin
  table is injected from `service/origins.py`, so a port that moves in code
  moves on the page — unlike the surface map's prose table, which can drift.
- `ext_demo.py`'s wrong-key scenario drew a second modulus without constraining
  it, so roughly one run in ten failed in `blind_sign` rather than reaching the
  device check it exists to show. Fixed in `7d434da`.
