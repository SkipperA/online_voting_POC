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

### 1.2 Mirroring the chain head — §3.5

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

### 1.3 Whether party supervision resolves A5 and E1 jointly

If competing parties attest the genesis before the poll opens, the same act can
cover `k_p^{(R)}`, the choice list and the times — which is gap 1 and clause
S4, a configuration that currently has no signer. And the close becomes an act
rather than a timestamp — gap 3 — because the cut is the final head the parties
attest.

One institution, three standing open questions. The convergence is neat enough
to warrant suspicion, and taking it would be the largest single edit to §3 on
this list. Deliberately not taken. If it is taken, `docs/actions.md` rows A5,
A9 and E1 change with it, and clauses S4 and A4 are affected.

---

## 2. Scope limits (`docs/Demo_Scope_Limits.md`)

### 2.1 New Absent clause — threshold encryption of the selection

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

### 2.2 New Absent clause — chain-head mirroring and equivocation

Covers row C8.

C8 splits into one part the demo can show and one it cannot. Rollback and
truncation are detectable by a single observer retaining `(index, head)` pairs
over time, and the checker at 8005 can do that honestly. Equivocation across
audiences requires genuinely separate observers with separate motives, which
one machine under one operator cannot supply; a second origin on the same box
demonstrates the shape of the property, not the property.

So: a working head-history check on the checker, plus a clause naming party
supervision (item 1.2) as the deployment answer and saying why the demo cannot
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

### 3.2 `npm audit` reports two high-severity advisories

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
- `ext_demo.py`'s wrong-key scenario drew a second modulus without constraining
  it, so roughly one run in ten failed in `blind_sign` rather than reaching the
  device check it exists to show. Fixed in `7d434da`.
