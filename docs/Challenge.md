# The challenge

A generated election, published whole, with an invitation: link a voter to
their vote.

This is the normative text. An actual challenge ships a copy of it with the
digests of that election's files filled in — `tools/publish_challenge.py`
writes the bundle — and the copy in the bundle is the one that binds.

---

## What is published

Four files, and nothing that describes how they were made.

| File | What it is |
|---|---|
| `election.json` | The configuration, byte for byte as it was published. Every client pinned its digest; every signature below names it |
| `ledger.json` | The accepted ballots and the hash chain over them. Each record carries the ad-hoc public key $`k_p^a`$ it was signed under, the selection, the office's token over that key, and the voter's signature |
| `releases.json` | The public release register: one commitment per issued token, the chain over them, and the office's signed head and count |
| `supervision.json` | **The office's own register.** One entry per citizen: their identifier, the opening behind their commitment, and the request they signed — which carries the blinded value $`c`$ they asked the office to sign and their wallet signature over $`\mathrm{hash}([id, c])`$ |

The fourth file is the one that makes this a challenge rather than a
demonstration. A real deployment keeps it behind the supervision perimeter,
because it names every citizen who was issued a token and absence from it is
conclusive proof of non-voting (§3.7). Here it is handed over deliberately:
an attacker gets the identifiers and the blinded values *together*, which is
strictly more than any observer of a real poll ever holds.

Nothing else is published. No generation log, no mapping file, no synthetic
voter table, nothing ordered by how the generator happened to run.

## The claim

> Given all four files, nobody can say which ballot belongs to which citizen.

Precisely: exhibit a mapping from citizen identifiers to ad-hoc public keys
that is correct materially more often than guessing.

With $`N`$ citizens, a blind guess is right one time in $`N`$. A claim may
name as many or as few citizens as you like; it is scored by how far its hit
count sits above the binomial expectation for a claim of that size, and
`tools/score_challenge.py` is the scorer. There is no partial credit and no
appeal to plausibility: a mapping is right about a citizen or it is not.

**Any method counts.** Cryptanalysis, statistics, structure in the dataset,
an implementation mistake, anything. If the generator leaks, that is a
finding worth having and it wins.

## Why it should hold

The only object connecting a citizen to their ballot is the blinding factor
$`r`$. It is generated inside the voting application, used once, and
discarded; the office never sees it and nothing in these four files records
it.

```math
c = \mathrm{enc}(k_p^a)\cdot r^{e_R} \bmod n_R
```

Because $`r`$ ranges over the whole multiplicative group, $`c`$ is uniformly
distributed and independent of $`k_p^a`$: for **every** ad-hoc key in the
ledger there exists an $`r`$ that makes it the preimage of **any** given
$`c`$. The hiding is information-theoretic, not computational. Publishing
$`c`$ for every citizen therefore gives away nothing, and a larger computer
does not help — which is why the supervision register can be published at
all, and why this challenge is about the record rather than about a key
length.

## What is withheld, and committed

The true mapping from citizen to ad-hoc key. One file, written outside every
election directory, served by nothing.

Its SHA-256 is published *with this statement, before the challenge opens*.
A submitted claim is scored against an answer nobody could have moved
afterwards. That is this project's own idiom, the same one the office uses
for a commitment: commit first, disclose on demand.

## Four caveats, all of them load-bearing

**The electorate is synthetic.** No human chose any of these selections, and
the citizens are invented — the identifiers say so on their face. What is
*not* synthetic is any of the cryptography: every blind signature, token,
ballot signature and chain link was produced by the protocol exactly as it
is in any other poll here, which is the only reason attacking this dataset
means anything. Clause S8 carries the disclosure and every surface shows it.

**Ballots under one ad-hoc key are linkable to each other, deliberately.**
Re-voting is the design's answer to coercion, and variant B gives the voter a
handle they control. Finding that two ledger entries share a key is not a
win — it is the design working. Linking either of them to a *citizen* is.

**This dataset has no timestamps, because the ledger has none.** There is no
scheduler and no time in a ballot record. A real deployment leaks through the
network layer — who contacted the ballot box and when — and that is clause A2
and an open problem, not something this dataset models. An attack that
assumes timing is out of scope here and very much in scope for the design.

**The office could link, and does not.** An office that retained $`r`$, or
the order in which it issued, could tie a commitment to a ballot. It retains
neither: the issuance order and the casting order of this election were drawn
independently, so index $`i`$ of one register is not index $`i`$ of the other,
and the registers are not even the same length because some citizens
abstained. A real poll decorrelates the two because citizens choose when to
ask and when to cast; the mitigation a deployment would owe — a random delay
between consent and cast, a ballot box that queues and draws — belongs in the
deployment and is named in `docs/threats.md`.

## Submitting a claim

A claim is one JSON object: citizen identifier to base64url ad-hoc public key,
exactly as `ledger.json` spells them.

```json
{
  "GEN-000042": "k7Qf…",
  "GEN-001337": "9vTa…"
}
```

```
python tools/score_challenge.py answer-key.json claim.json \
    --expect-digest <the SHA-256 published with the dataset>
```

The scorer refuses to run if the answer key does not hash to the published
digest, which is the half of the commitment that protects *you*.
