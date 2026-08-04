# Threat model

Two lists. The first is claims the code makes and the test suite backs. The
second is attacks that succeed, or that the implementation does not address —
recorded here so that their absence is deliberate rather than an oversight.

A reviewer should be able to read the second list and find nothing in it that
surprises them.

## Defended, with a test

| Attack | Defence | Test |
|---|---|---|
| Ineligible person votes | VRO checks the electoral register | `test_unregistered_voter_gets_no_token` |
| Voting as someone else, knowing only their `id` | Wallet signature over `hash([id, c])` | `test_impersonation_fails_without_the_wallet_key` |
| Self-minted token | Token is an RSA-PSS signature under the pinned VRO key | `test_forged_token_is_rejected_by_the_ballot_box` |
| One voter, two tokens | Release recorded before signing; one per `id` | `test_a_second_token_request_is_refused` |
| Ballot altered in flight | `s_vote` covers `[i, k_p^a]` | `test_tampering_with_the_selection_breaks_the_signature` |
| Reusing a published token with a fresh key | Token signs `k_p^a` specifically | `test_a_valid_token_cannot_be_reused_with_a_different_key` |
| Forging a third token from two genuine ones | PSS encoding destroys RSA's multiplicative structure | `test_multiplicative_forgery_is_defeated_by_pss_encoding` |
| Coercer's malformed ballot erasing a genuine one | Rejected ballots do not supersede | `test_a_rejected_ballot_does_not_supersede_a_genuine_one` |
| Ballot box dropping or editing a ballot | Hash chain over the ledger | `test_deleting_a_ballot_breaks_the_hash_chain` |
| Token minted in an absent voter's name | Public release log, checkable independently | `test_a_token_minted_without_the_voter_is_detectable` |
| VRO linking its signature to a published ballot | Blinding | `test_the_vro_cannot_link_its_signature_to_a_published_ballot` |

## Not defended

### In the design, and open

**Verifiability transfers to a coercer.** Variant B, which is what this code
implements, gives the voter a handle they control — so a vote buyer can demand
the same proof an adjudicator would accept. Re-voting blunts casual pressure but
not a coercer who controls the final moment before close. This is the tension
the papers hand to legislators; it is not a bug to be fixed here.

**Silent override after the voter's last check.** Because the last ballot wins, a
compromised device holding `k_s^a` can submit a new ballot *after* the voter has
verified. Closing it needs hardware-held keys, or a post-close verification step
anchored out of band (mailed return codes). Neither is implemented.

**Verification uptake.** Every device-compromise defence in this design assumes
the voter actually checks from an independent device. Deployed experience says
few do. No amount of implementation work changes that; it is a design and
communications problem.

**Single point of trust at the VRO.** One office can mint tokens for citizens who
never voted, and those tokens are indistinguishable from genuine ones. The public
release log makes this *detectable by the affected voter*, which is a real
constraint but not a prevention. Threshold issuance across mutually distrusting
bodies is required and not implemented.

**Traffic analysis.** Signing protects integrity, not anonymity. The network
layer sees which wallet contacts the VRO and which address submits which ballot,
and timing correlation can re-link a voter to their ballot. An anonymising
submission channel is assumed by the design and stubbed in the code.

**Availability.** The channel can drop, delay, or selectively block ballots. Not
addressed.

**Coercion at the wallet.** If an attacker controls the voter's wallet, nothing
downstream helps. The design inherits the wallet's security assumptions whole.

### In this implementation specifically

- **Mock wallet.** `keys.py` is software Ed25519, not a secure element. A real
  EUDI wallet would use ECDSA P-256 with hardware key storage and its own
  attestation. The interface is narrow so it can be replaced; the substitution
  has not been done.
- **No persistence.** Everything is in memory. Nothing survives a restart, and
  there is no story about how the published ledger is actually published.
- **Ledger head is not gossiped.** The hash chain makes deletion detectable only
  if someone recorded an earlier head. Publishing the head somewhere the ballot
  box does not control — mirrors, a gossip protocol, print — is what makes the
  chain meaningful, and is not implemented.
- **Not constant-time.** The blinding arithmetic uses plain Python integers.
  Timing side channels are not considered.
- **No rate limiting, no denial-of-service resistance, no logging, no key
  management.** All the operational apparatus a real deployment would need.
- **No independent review.** The most important gap on this page.

## Attacks worth adding to the suite

Ordered roughly by how much a reviewer would want to see them:

1. Ballot box equivocation — two verifiers shown different ledgers.
2. VRO using a per-voter signing key, and the pinned-fingerprint check catching it.
3. Replaying a ballot verbatim (currently accepted and idempotent — confirm that
   is the intended semantics, and document it either way).
4. A voter attempting to obtain two tokens through two wallets.
5. Selection encoded outside the option list but crafted to collide with a valid
   one after serialisation — a canonicalisation attack.
