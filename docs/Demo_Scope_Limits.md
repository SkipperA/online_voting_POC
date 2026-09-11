# Demo scope limits

The single list from which two things are derived: the labels shown in the
stage 1 UI, and the scope clauses spoken during a demonstration. They are
written once here so that the screen and the presenter cannot drift apart.

Three kinds of clause, deliberately kept separate. Conflating them is what
makes an audience stop trusting a demonstration, because the honest answer to
"so it doesn't do X?" is different in each case.

| Kind | What it means | The honest answer |
|---|---|---|
| **Substituted** | Deployment has the real thing; the demo stands a stub in its place | "It does, and this is a stand-in for it." |
| **Absent** | The design specifies it; this build omits it | "The design does, this build doesn't, and here is what it would take." |
| **Out of scope** | The proposal does not claim it | "The proposal doesn't settle that, deliberately." |

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
apart from the same address are trivially linkable by timing (§3.9).

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
the implementation does not consume: `close()` is called by an operator, not
scheduled. `election.json` will therefore contain two fields nothing reads.

This touches gap #3 of the action table — the close is treated as a moment,
and the article does not say whether acceptance turns on arrival at the box or
on a published cut, nor who attests that the box stopped. Leave the fields in
the file and label them; removing them would hide the gap.

**Label:** *Opening and closing times are recorded but not enforced. The poll
is closed by an operator action.*

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
