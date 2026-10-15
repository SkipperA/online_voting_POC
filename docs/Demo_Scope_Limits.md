# Demo scope limits

The single list from which two things are derived: the labels shown in the
stage 1 UI, and the scope clauses spoken during a demonstration. They are
written once here so that the screen and the presenter cannot drift apart.

Four kinds of clause, deliberately kept separate. Conflating them is what
makes an audience stop trusting a demonstration, because the honest answer to
"so it doesn't do X?" is different in each case.

| Kind | Prefix | What it means | The honest answer |
|---|---|---|---|
| **Substituted** | `S` | Deployment has the real thing; the demo stands a stub in its place | "It does, and this is a stand-in for it." |
| **Absent** | `A` | The design specifies it; this build omits it | "The design does, this build doesn't, and here is what it would take." |
| **Out of scope** | `O` | The proposal does not claim it | "The proposal doesn't settle that, deliberately." |
| **Exposed** | `X` | The demo shows what a deployment keeps hidden, so that it can be seen rather than taken on trust | "Yes, on purpose. A deployment never shows it, and here is where it would live instead." |

The fourth kind is not a limitation of fidelity and is the one an audience is
most likely to misread, which is why it is named rather than left to the
surrounding prose. Its prefix is `X` and not `E`: the action table's phase E
is the close of the poll, and `E1` is already that row.

The screen shows the kind and the clause together. A clause that reaches no
surface is either a clause nobody needs or a label somebody forgot, and
`test_every_scope_note_names_a_kind_and_a_real_clause` is what decides which.

Section references are to *Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System*. Phase references are to
`Online_Voting_Action_Table.md`.

---

## Substituted

### S1 — The Digital Identity Wallet

The wallet is a software Ed25519 key held by a local daemon under `driver/`.
In deployment `k_s^{(v)}` is hardware-bound by regulation (§3.7) and cannot
leave the wallet at all.

What makes the substitution credible rather than merely convenient: the
daemon signs through the same standard interface an HSM, a TPM, or a secure
element would present. Nothing in the protocol depends on where the private
key sits, only on the signature it produces. Moving the key into hardware is
an implementation change behind an unchanged interface, not a redesign.

**Label:** *Wallet is a software stub. In deployment the signing key is held
in hardware and cannot be exported.*

### S2 — The certificate lookup

`driver/population_register.py` answers an `id` with a qualified certificate
from a fixture table. In deployment this is the trust infrastructure: a
published trust list, a real revocation check, and the ability to accept a
request signed under **any** valid certificate naming the requester (§3.2).
The fixture returns one certificate per person; the article requires that any
of several be accepted. That difference is recorded in the gaps list of
`docs/wire-contract.md` and is not closed by the demo.

**Label:** *Certificate lookup is a fixture. It is external infrastructure the
design consults, not a component the design builds.*

### S3 — The electoral register

A handful of invented identifiers, enrolled by hand. Enrolment is outside the
system by construction (§3.2): the register derives from civil registration
under the law of the jurisdiction, and the office administers it without
populating it. Presence in the register is the whole of the eligibility
statement; there is no second predicate.

**Label:** *Fixture register. Enrolment happens outside this system, by
whatever process the jurisdiction already uses.*

### S4 — The configuration author

`election.json` is produced by a build-time setup console and served as a
static file beside its hash. In deployment the configuration would need an
authoring body and a signature under a key that body controls. The article
names neither; this is gap #1 of the action table, and the console does not
close it — it only supplies an operator for the demonstration.

**Label:** *Configuration authored at build time. In deployment this artefact
needs a named authoring body and a signature; the proposal does not yet say
which body.*

---

### S5 — Supervisor authentication

Covers action-table rows E11 and E12.

Supervision of the release register is the measure that catches a lone
dishonest office for every citizen at once, whether or not any of them
performs the check of §3.7 — and the price of it is that the supervisor reads
a list of who asked for a ballot. That price is only worth paying to an
appointed person, which means a deployment authenticates the supervisor and
records who read the register when.

This build does neither. There is no login on 8006: whoever can reach the
origin is a supervisor, and the control is the perimeter it is served behind.
The read counter is published, so the office cannot hand the register out
quietly, but nothing establishes *who* read it.

The substitution is the perimeter standing in for an appointment. It is the
same shape as S1 and S2 — a real control replaced by one that demonstrates the
boundary without enforcing it — and it is stated here because the surface
asserts it on the page while the single list did not carry it.

**Label:** *No login: whoever can reach this origin is a supervisor. A
deployment appoints one and records who read the register.*

---

## Absent

### A1 — Distributed token issuance

One Registration Office issues every token. §6 and the policy paper both state
that the issuing power must be split across mutually distrustful bodies, since
a single office could mint valid-looking tokens for citizens who did not vote,
indistinguishable from genuine ones.

This is the largest gap between the demo and the design, and it is a scoped
extension rather than a redesign: the ballot box verifies a token against a
published key, and threshold issuance changes who holds the private half, not
what the box does. Worth building if a research partner has serious interest.

**Label:** *Single issuing office. The design requires this power to be split
across independent bodies; the demo does not.*

### A2 — The anonymising channel

On localhost there is none, and the demo therefore cannot demonstrate the
property it most needs to: a token release and a ballot submission seconds
apart from the same address are trivially linkable by timing (§3.8).

The distinction to draw for an audience is that the demo shows the
*cryptography* does not leak the link, not that the *deployment* does not.
Those are separate claims and the second one is not on screen.

**Label:** *No anonymising channel. On one machine the network can link a
token request to a ballot by timing; the cryptography cannot.*

### A3 — Browser-delivered code (stage 1 only)

Client-side cryptography is only as trustworthy as the bytes the server sent.
In the browser, "the blinding runs on your device" is true about where the
computation happens and false about who controls the code.

This clause is a property of browser delivery, not of the design, and stage 3
removes it: an App Store binary is not supplied by the VRO, so the office no
longer provides the code that checks the office's key. What replaces it is a
different and smaller dependency — the signing and review chain, plus the
build pipeline — which is why a reproducible build with a published binary
hash belongs in stage 3 alongside the visible key fingerprint.

**Label (stage 1 only):** *This code was delivered by a web server. On iOS the
same code arrives as a signed binary independent of every election server.*

### A4 — Scheduled opening and closing

The configuration carries opening and closing times (Table 1, footnote a) that
the implementation does not consume: `open()` and `close()` are both called by
an operator, not scheduled — the box starts shut and refuses every submission
until somebody opens it. `election.json` therefore contains two fields nothing
reads.

This touches gap #3 of the action table — the close is treated as a moment,
and the article does not say whether acceptance turns on arrival at the box or
on a published cut, nor who attests that the box stopped. Leave the fields in
the file and label them; removing them would hide the gap.

**Label:** *Opening and closing times are recorded but not enforced. The poll
is opened and closed by operator actions.*

---

### A5 — Threshold encryption of the selection

Covers action-table rows A8 and E2.

§3.5 sets the condition: where no running tally is published, the operator
would otherwise see selections individually while the public sees nothing, and
that asymmetry should be removed by encrypting the selection under a key held
in shares by several independent bodies. The design as formalised in §5
withholds contents until the close and publishes no running tally, so §3.5's
own condition is met and its own remedy applies. §3.5 then says plainly that
§5 sets the design out with the selection in clear. This build follows §5.

The extension is scoped rather than structural: acceptance turns on the two
signatures and never on the selection value, so the ballot box's verification
is unchanged.

**Label:** *Selections are stored in clear, so the ballot box operator can read
a ballot before the poll closes. The design says that where no running tally is
published the selection should be encrypted under a key held in shares; this
build does not do that.*

---

### A6 — Mirroring the chain head

Covers action-table row C8.

The row splits. Rollback and truncation are detectable by a single observer
who retains `(index, head)` pairs over time, and the checker can do that
honestly. Equivocation — a box showing one chain to one audience and another
to another — requires genuinely separate observers with separate motives,
which one machine under one operator cannot supply. A second origin on the
same box demonstrates the shape of the property, not the property.

The deployment answer is supervision by competing parties, who record signed
`(index, head)` observations of their own choosing; two parties holding
different heads at the same index is conclusive and needs no adjudicator.

**Label:** *One machine cannot demonstrate that the ballot box is unable to
show different histories to different people. What is shown here is that a
single observer detects rollback.*

---

### A7 — The poll's own state is in memory

The setup console writes the durable half of the election — both key pairs,
the electoral register, the wallet personas — and the runtime reloads it, so a
restart keeps the election. Everything the poll itself produces is in memory:
the ballot box, the hash chain, the released-token register. A restart loses
the votes.

The split is deliberate and is the right way round for a demonstration: the
election survives, the poll does not. But a real ballot box does not forget
its contents when its process stops, and the receipts a voter holds would then
refer to a chain that no longer exists — which is exactly the evidence the
design says they are. The substitution is storage, not the protocol.

One narrowing, since this was written. At the close, the box writes the three
files a verifier takes — the configuration as published, the ledger and the
release register — into `closed/` under the election's own directory. That is
the *published* record of a finished poll, not a durable registry: a restart
during voting still loses everything. What it removes is a window rather than
the clause. The artefacts used to be reachable only between the close and the
next restart, so an election's evidence depended on somebody having downloaded
three files in that interval, and an election whose evidence depends on that
is not evidencing anything.

A second narrowing, of the same shape. The close also writes the poll itself
— the records, the acts, the publication snapshots, and the office's register
with the openings and the citizens' signed requests — into `poll.state.json`
beside the keys, so a finished election can be served again and its surfaces
shown. That is read-only: the box comes back shut, nothing resumes, and no
chain continues. A poll interrupted *while open* is still never written and
still lost, which is the clause. Loading re-derives the chain from the records
and refuses anything that does not reproduce the heads the box signed, so an
altered file is not served at all.

**Label:** *Votes are held in memory. Restarting the service loses them and
keeps the election.*

---


## Out of scope

### O1 — Which public body holds which role

The demo collapses several bodies into one operator so that the architecture
can be seen without first learning a jurisdiction.

State this as a scope clause rather than an apology. The proposal's own
position is that the allocation is a legislative choice: Section 7 of the
policy paper puts "what independent institutions should jointly hold electoral
trust" among the questions that belong to elected representatives. The
collapse is therefore not a simplification of the proposal but a refusal to
pre-empt something the proposal explicitly declines to decide.

**Label:** *One operator stands for several public bodies. Which body holds
which role is a legislative decision the proposal deliberately leaves open.*

### O2 — Remedy and complaint handling

Out of scope of the action table by its own second paragraph, and out of scope
here. The design produces the *evidence* a complaint would rest on — the
receipt, the entry position, the chain head, and after the close the ability
to prove authorship. What an adjudicator does with that evidence is public
administration, not architecture.

**Label:** *No complaint process. The demo produces the evidence a complaint
would rest on, not the procedure for hearing one.*

### O3 — Variant A, the non-provable handle

`handles.py` argues at length that variant A is a different system rather than
a different handle: every published ballot carries `k_p^a` and the voter
retains `k_s^a`, so a coercer need only say "sign this nonce." A genuine
variant A needs encrypted ballots, trapdoor trackers, and a verifiable tally
over ciphertexts — which costs the property that any third party can recompute
the result with a standard library.

**Label:** *This build implements the provable variant. The coercion-resistant
variant is a different system, not a setting.*

---

## Exposed

### X1 — The voter's own secrets on screen

Covers action-table rows B2, B3 and B17.

The voting application displays `k_s^a`, the blinding factor `r` and the
unblinding inverse `r^-1`. Every one of them is a value whose whole security
argument is that nobody but the voter's device ever holds it: `r` in
particular is what makes the two verifications of §5.5 impossible to join, so
a reader who sees it could link the citizen to the ballot.

They are on screen because the blinding is the part of the design an audience
is least willing to take on trust, and the only way to show that unblinding
yields an ordinary signature is to show the factor it was removed with. A
deployment generates these inside the device and never renders them.

**Label:** *Keys in red never leave the device in a deployment. They are
shown here so the blinding can be followed.*

---

### X2 — The office's participation log

Covers action-table rows B15 and D1.

The back office shows which identifiers asked for a token and when. That is a
participation list — the object §3.7 spends a page keeping out of everyone's
hands, because its *absence* of an entry is conclusive evidence that a citizen
did not take part, which is exactly what an enforcer of a boycott needs.

It is shown because the whole argument for publishing commitments rather than
identifiers is only legible beside what the office actually holds. No
deployment exposes this surface to anyone but the office itself, and the
published register carries commitments and a count instead.

**Label:** *This is what the office holds, not what it publishes. The
published register carries commitments and a count, and nothing else.*

---

### X3 — The release register with identifiers

Covers action-table rows E11 and E12.

Supervision names citizens. That is the cost of the measure rather than a
defect in it, and §4 of the companion note argues it is parity with the
scrutineers who already watch a marked register on paper. The surface exists
so that the cost can be looked at rather than described.

It says nothing about how anyone voted, and nothing the office holds could.
What it says is who asked for a ballot, which is close to but not the same as
who voted: absence is conclusive, presence is not, and that asymmetry runs the
wrong way for privacy.

See S5 for the control that is missing on this origin, and O1 for why one
operator holds both this and the office it supervises.

**Label:** *Everything here is participation data. Who asked for a ballot —
never how anyone voted, which nothing the office holds can reveal.*

---

### X4 — Published wallet seeds

Formerly A8, moved here when the fourth kind was named: it was always an
exposure rather than an absence, and nothing referenced it under the old
identifier.

`election-data/election.store.json` is committed with every wallet private
seed in the clear, and `vro_token_key.pem` beside it. This is deliberate: one
machine plays a whole electorate, and a reader should be able to open the file
and see exactly what the demo holds on each voter's behalf rather than take
the substitution on trust. `tests/vectors/keys.json` already publishes a
private key on the same reasoning.

A deployment keeps `k_s^(v)` in hardware it never leaves — under eIDAS that is
a regulatory requirement, not a preference — and keeps `k_s^(R)` nowhere a
file can reach. Both files say so about themselves, so neither can be
mistaken for a deployment artefact by anyone who opens it.

The register ships populated with four invented names so that a clone can be
voted in at once. Two carry non-ASCII characters, which exercises the
canonical-JSON agreement the whole wire contract rests on.

**Label:** *Every voter's wallet key is published in this repository. The
voters are fictional; a deployment's keys never leave hardware.*

---

## Not limitations

Listed so that nothing here is put in front of an audience by mistake.

- **Key size.** `demo.py` and `ext_demo.py` run at 3072 bits, the article's
  deployment minimum (§5.1). Only the test suite drops to 2048, for speed.
- **The blind signature itself.** RFC 9474 RSABSSA-SHA384-PSS-Deterministic,
  and the unblinded token verifies under a stock RSA-PSS implementation. Any
  third party can check it with an ordinary library.
- **Device compromise.** Not a demo limitation but a property of the design,
  treated at length in §3.7. The three independent checks are the answer, and
  they are in scope for stage 1.
- **The verifiability–coercion tension.** Not a gap. It is the argument.
