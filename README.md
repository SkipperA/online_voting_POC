# Anonymous Authenticated Ballot System — proof of concept

A reference implementation of the online voting scheme described in
*Proposal for a Secure, Private, and Coercion-Resistant Online Voting System*
(Ferenc Vágujhelyi, July 2026), with its accompanying policy paper
*Online Voting as an Evolution of Electoral Infrastructure*.

## What this is not

**This is not election software and must not be used in any real election.**
It exists to make a protocol executable and inspectable, and to give an
adversarial test suite something to attack. It has had no independent security
review, it is not constant-time, it has no operational hardening, and several
components the design requires are deliberately absent (see
[docs/threats.md](docs/threats.md)).

Both source papers are explicit that the expert consensus — including the 2018
National Academies study and the joint CISA/EAC/FBI/NIST risk assessment — is
that returning marked ballots over the internet is currently high-risk. Nothing
in this repository disputes that. A working prototype demonstrates tractability,
not sufficiency.

## What it does demonstrate

Running `python demo.py` shows, in one pass:

- a voter proving eligibility through a Digital Identity Wallet without
  revealing anything about their choice;
- the Voter Registration Office certifying that eligibility **blindly**, so that
  it cannot later connect the certificate to the citizen who requested it;
- a ballot published in a public, hash-chained ballot box;
- the voter checking their own recorded choice from an independent device;
- and an outsider — with no privileged access, using only the published ledger
  and the VRO's public key — recomputing the result and getting the same answer.

`tests/test_attacks.py` is the more important half: each attack the design
claims to defeat is named and shown failing. Impersonation, forged tokens,
double token issue, in-flight tampering, token theft, multiplicative forgery
against the blind signature, ledger deletion, and the stolen-identity case that
step 12 of the design is meant to catch.

## Quick start

```bash
pip install -e ".[dev]"
python -m pytest -q     # 24 tests
python demo.py          # narrated end-to-end run
```

Python 3.11+. One dependency: `cryptography`.

## Layout

```
src/ovpoc/
  rsabssa.py    RSA blind signatures (RFC 9474), the cryptographic core
  keys.py       wallet and ad-hoc Ed25519 keys
  messages.py   wire objects and canonical serialisation
  ledger.py     hash-chained append-only log
  vro.py        Voter Registration Office
  ballotbox.py  validation, storage, tally
  voter.py      the voter's whole flow — read this first
tests/          including the adversarial suite
docs/           protocol mapping and threat model
```

Protocol logic is pure Python with no HTTP or database layer. That is
deliberate: the validity rules are testable in isolation, and a web layer added
later cannot quietly change them.

## Verifiability variant

The scheme admits two verification handles, and the choice between them is the
central policy question of the papers:

- **B — implemented.** The voter locates their ballot by the ad-hoc key they
  control. They can verify their choice, and they can also *prove* authorship to
  a third party: to an adjudicator hearing a complaint, and equally to a vote
  buyer.
- **A — not yet implemented.** The voter locates their ballot by an anonymous
  random identifier. Sufficient to check, insufficient to prove. This needs a
  trapdoor-style construction and is the intended novel contribution of the
  forthcoming technical article.

Both rest on the same eligibility and one-vote-per-voter guarantees. Only the
voter's private handle differs — which is exactly why the papers treat the
placement of that balance as a legislative decision rather than a technical one.

## Licence

Not yet chosen. Add one before making the repository public.
