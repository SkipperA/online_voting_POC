# Threat model

Two lists. The first is claims the code makes and the test suite backs. The
second is attacks that succeed, or that the implementation does not address —
recorded here so that their absence is deliberate rather than an oversight.

A reviewer should be able to read the second list and find nothing in it that
surprises them.

## Defended, with a test

| Attack | Defence | Test |
|---|---|---|
| Ineligible person votes | VRO checks its electoral register | `test_an_identified_person_not_on_the_electoral_register_is_told_so` |
| Voting as someone else, knowing only their `id` | Signature over `hash([id, c])`, verified under the certified key | `test_impersonation_fails_without_the_wallet_key` |
| Probing the electoral roll through the token endpoint | One opaque `NOT_IDENTIFIED` for every pre-identity failure | `test_eligibility_is_never_revealed_before_identity`, `test_an_unknown_id_is_not_identified` |
| Confirming a citizen's certificate status without being them | Revocation and expiry reported only after the signature verifies | `test_a_revoked_certificate_is_reported_only_after_the_signature` |
| Forging an office statement through the blind-signing oracle | Office statements signed under a separate key; the token key signs only tokens | `test_any_voter_can_forge_an_office_statement_under_the_token_key`, `test_release_denials_are_signed_under_a_separate_office_key` |
| A faulted CRT exponentiation leaking the modulus | `s_c^e == c` checked before `s_c` is released | `test_a_faulty_blind_signature_is_not_released` |
| A running result visible during the poll | Records withheld until the close; commitments published meanwhile | `test_no_record_is_published_while_voting_is_open`, `test_a_running_tally_is_published_only_when_configured` |
| A ballot cast after the result is known | Submissions refused once the box is closed | `test_a_ballot_arriving_after_the_close_is_not_recorded` |
| Self-minted token | Token is an RSA-PSS signature under the pinned VRO key | `test_forged_token_is_rejected_by_the_ballot_box` |
| One voter, two tokens | Release recorded before signing; one per `id` | `test_a_second_token_request_is_refused` |
| Ballot altered in flight | `s_vote` covers `[i, k_p^a]` | `test_tampering_with_the_selection_breaks_the_signature` |
| Reusing a published token with a fresh key | Token signs `k_p^a` specifically | `test_a_valid_token_cannot_be_reused_with_a_different_key` |
| Forging a third token from two genuine ones | PSS encoding destroys RSA's multiplicative structure | `test_multiplicative_forgery_is_defeated_by_pss_encoding` |
| Coercer's malformed ballot erasing a genuine one | Rejected ballots do not supersede | `test_a_rejected_ballot_does_not_supersede_a_genuine_one` |
| Ballot box dropping or editing a ballot | Hash chain over the ledger | `test_deleting_a_ballot_breaks_the_hash_chain` |
| Third party learning who registered | Release log publishes commitments; queries need `sig(id)` | `test_the_release_log_publishes_no_voter_identities`, `test_an_unauthenticated_release_query_is_refused` |
| VRO minting tokens *without logging* them | Aggregate audit: distinct ad-hoc keys ≤ tokens released | `test_the_aggregate_audit_bounds_ballots_by_tokens` |
| A voter having to trust the VRO's answer | Nonce discloses the commitment; voter checks the public log | `test_a_voter_can_verify_the_answer_against_the_published_log` |
| VRO linking its signature to a published ballot | Blinding | `test_the_vro_cannot_link_its_signature_to_a_published_ballot` |

## Not defended

### In the design, and open

**Verifiability transfers to a coercer.** Variant B, which is what this code
implements, gives the voter a handle they control — so a vote buyer can demand
the same proof an adjudicator would accept. Re-voting blunts casual pressure but
not a coercer who controls the final moment before close. This is the tension
the papers hand to legislators; it is not a bug to be fixed here.

**A token minted for a citizen who never asked.** ~~Open~~ — narrowed, and
worth recording how far. A corrupt office can write a commitment and a count
for somebody who did not request a token, and no public artefact
distinguishes it from a genuine release: the victim's own check finds it
only if they look, and the count audit finds it only if the office failed to
record it. The release register now carries the citizen's signature over
their own request, which the office cannot manufacture, so a supervisor
reading it finds a fabricated release whether the citizen ever looks or not.
What this does not reach is an office that colludes with a willing citizen,
and it depends on supervisors existing and reading. Distributing the issuing
power remains the answer that prevents rather than detects.

**Eligibility is fixed at a moment, and the moment is not the one you would
guess.** On the qualified-signature route the office answers
`CERTIFICATE_REVOKED` from the revocation material the document carries in its
`/DSS` -- OCSP responses the wallet obtained when it signed, verified here
under their own signatures. It does not fetch at request time, because an
office that reached the certification authority would be telling it which
citizens it was being asked about, from the machine that also holds the
electoral register; and `revocation_mode` is `soft-fail`, so no revocation
information available is not a refusal. Those two together mean "not revoked"
reads as *nothing in evidence said it was*, not *the office confirmed it is
live*.

So the certificate's status is established as of **signing**, not as of the
request arriving. A certificate revoked in between is not seen.

That is not peculiar to this design and it is worth saying so plainly, because
it reads as a weakness only to someone who assumes paper has no equivalent.
Every election fixes eligibility at a cut-off. A paper roll is printed from the
register at some moment before the poll; a voter who dies on the morning of
election day is still on it, and what prevents a ballot being cast in their
name is the identity check at the polling station, not the roll being live. The
question a design must answer is not *is there a gap* but *where is the cut-off,
who chose it, and is it stated*.

Here it is stated nowhere, and that is the real criticism rather than the gap
itself: the cut-off is wherever the wallet's OCSP fetch happened to land. It is
an artefact of the signing software, not a decision anybody took or published.
A deployment should choose it and say so -- either the certificate must not be
revoked as of revocation material the *office* obtained at a stated time, which
keeps the no-fetching property and makes the cut-off auditable the way the trust
anchors are, or the office fetches at request time and accepts what that
discloses to the authority.

Two things narrow the exposure, and one widens it again elsewhere. The harm is
bounded by the commitment: one identifier, one token, so a certificate revoked
after signing yields at most the token that citizen was entitled to anyway, and
the error can only admit a release, never refuse a valid voter. And with a
*remote* QSCD -- which is what DÁP is, the signing key held by the trust service
rather than on the handset -- a revoked certificate cannot produce a new
signature at all, so the only reachable window is sign, then revoke, then hand
in, which is a voter revoking their own certificate after asking rather than an
attack. A wallet holding its key locally on a card has no such protection: a
card whose PIN is known can sign after revocation, and then only a check at
request time catches it.

**Delegated signing — a vote sale that re-voting does not defeat.** Nothing
binds the blinded value to the wallet that signs it. A voter who signs a `c`
generated by somebody else spends *their own* entitlement on an ad-hoc key
*that person* holds, and that person casts the ballot and re-casts it at
will. Observed directly: a request saved from one voter's application,
loaded into a second voter's wallet, signed, and the token collected by the
first.

This is a sale rather than coercion — it needs the seller's cooperation —
but it is cleaner than the receipt-based kind, and it is the case the
design's own remedy misses. The seller never sees the ballot and has
nothing to prove to anybody, so §3.4's answer to a vote buyer does not
arise; and they cannot take it back, because their one token is spent, so
the re-voting of requirement 6 and §3.4 cannot undo it. Every other form of pressure
in this register is blunted by casting again. This one is not.

Two qualifications. It is not special to this design: any scheme that
anonymises eligibility before the ballot exists has the same shape, which is
part of why receipt-freeness and coercion resistance are treated as separate
properties. And on one device the handover is an app-to-app invocation
between two applications the voter controls, so the opportunity does not
arise — the file in the browser demonstration is what makes it reachable
here. The *property* survives the move to a phone; only the convenience
goes.

**Silent override after the voter's last check.** Because the last ballot wins, a
compromised device holding `k_s^a` can submit a new ballot *after* the voter has
verified. Closing it needs hardware-held keys, or a post-close verification step
anchored out of band (mailed return codes). Neither is implemented.

**Verification uptake.** Every device-compromise defence in this design assumes
the voter actually checks from an independent device. Deployed experience says
few do. No amount of implementation work changes that; it is a design and
communications problem.

**Single point of trust at the VRO.** One office can mint tokens for citizens who
never voted, and those tokens are indistinguishable from genuine ones. The
release log constrains this only partly, and it is worth being precise about how
little it does.

A VRO that mints *without* logging is caught by the aggregate audit, since
distinct ad-hoc keys in the ballot box would exceed the number of released
tokens. A VRO that mints *and* logs is not caught by any public check: a logged
release for a citizen who never voted is indistinguishable from a citizen who
took a token and abstained. Detection then depends on that specific
non-participant running a step-12 query — the worst conceivable uptake problem,
since it asks people who did not vote to audit the election.

Worse, the authenticated query gives the VRO the ability to *deny*. A dishonest
office can answer "no token released for you" to a voter whose token it minted,
and the voter cannot disprove it, since they cannot open a commitment whose opening
they were never given. The signed denial makes the lie attributable after the
fact if it is ever contradicted, which is accountability rather than prevention.

Threshold issuance across mutually distrusting bodies is therefore not an
optional hardening step. It is the only real answer, and it is not implemented.

**Ledger position correlates issuance with casting, for whoever already holds
the identities.** Two ordered registers are published: the office's release
register, whose order is load-bearing because the office's signature covers
the chain, and the box's accepted ledger. Index *i* of one against index *i*
of the other relates a release to a submission.

To an outsider this is worth nothing, and the distinction is the whole of the
entry: the release register publishes commitments and names nobody, so the
correlation relates an opaque value to a ballot. It bites for the party that
already knows whose commitment is whose — the office, a supervisor reading
the register, or a single operator holding both roles, which in this build is
clause O1.

**The remedy is a schedule, and the queue was considered and dropped.** The
article now carries the analysis; the short form is that a mixing queue at the
box fails twice. Mixing happens over the submissions resident when one is
drawn — about λT for arrival rate λ and holding time T — so fifty voters over
twelve hours (λ ≈ 4/hour) leave a queue that waits for company holding
nothing, and a shuffle over twenty would need T ≈ 5 hours. The holding time
must scale *inversely* with turnout rate, which makes the remedy weakest
exactly where the channel bites hardest. And the draw must be weighted toward
the oldest entry or an unlucky ballot waits arbitrarily long, which is itself
a reduction in mixing, degenerating to FIFO at the limit. The cost that is
easiest to miss is the receipt: a queued submission has no index yet, so
either the voter cannot check when they care, or the box signs a position it
has not committed to, or the receipt stops naming a position at all — the
third is sound and turns §3.7's immediate confirmation into a deferred one.

What is adopted instead is that **token issuance closes before voting opens**,
so the two orders are drawn over disjoint intervals. It costs no latency and
no cryptography, it defeats a coercer who watched the request — what they saw
during the registration window says nothing about an order established
afterwards — and it is an electoral-process decision a legislator can see.
`election.json` carries both periods so that the arrangement is readable from
the pinned configuration, and clause A4 records that this build consumes
neither. A jurisdiction that will not turn away a late registrant publishes
periods that overlap; the residual risk then falls on late registrants, and
the rarer late registration is the more identifiable they become.

It is recorded here because a *generated* election has to reproduce the
decorrelation deliberately: `service/generate.py` issues every token before
casting any ballot and draws the two orders separately, since a published
dataset carrying a positional channel no real poll has would be testing the
generator rather than the blinding. `docs/Deferred_Decisions.md` §1.8 carries
the amendment the article needs.

**Traffic analysis.** Signing protects integrity, not anonymity. The network
layer sees which wallet contacts the VRO and which address submits which ballot,
and timing correlation can re-link a voter to their ballot. An anonymising
submission channel is assumed by the design and stubbed in the code.

**Availability.** The channel can drop, delay, or selectively block ballots. Not
addressed.

**Coercion at the wallet.** If an attacker controls the voter's wallet, nothing
downstream helps. The design inherits the wallet's security assumptions whole.

**The identity infrastructure is trusted whole.** Eligibility rests on the
population register: a certificate naming the wrong person, or a compromised
certification authority, is not detectable anywhere in this design. That is the
trust boundary the article states plainly in §3.2, and `driver/` exists to keep
it visible in the code. A compromised register does not, however, let anyone
vote *twice* -- the one-token-per-id rule is the office's own.

**The office learns who checked.** Because step-12 queries are answered by the
Registration Office, that office learns which voters audited it, and when: a
record of who is scrutinising it, held by the party being scrutinised. It
discloses nothing about any vote, and a coercer cannot read it without the
office's collusion. It is one more reason to distribute the office's powers.

**Proof of abstention.** Even with commitments, the *count* of released tokens is
public, and a voter can be compelled to run a step-12 query in front of a
coercer and show the result. A token release proves nothing — the voter may have
abstained — but its absence is conclusive proof of non-voting. This serves a
coercer demanding turnout rather than a particular choice, and it is not
addressed. Note that many jurisdictions already publish turnout per elector, so
this is not obviously worse than existing practice; what differs is that the
check is remote, automatic, and free of the friction a records request imposes.

### In this implementation specifically

- **Mock wallet.** `keys.py` is software Ed25519, not a secure element. A real
  EUDI wallet would use ECDSA P-256 with hardware key storage and its own
  attestation. The interface is narrow so it can be replaced; the substitution
  has not been done.
- **Mock population register, and the two routes differ on this.**
  `driver/population_register.py` is a dictionary. Real certificates are X.509
  structures with a chain to a trust anchor, and revocation is an OCSP or CRL
  question rather than a boolean -- so on the wallet route revocation is
  *modelled* rather than checked, and an operator setting that flag is the
  whole of it. On the qualified-signature route it is a real check against the
  OCSP responses the document carries, with the timing caveat recorded above.
  The protocol is unaffected by either; the asymmetry is worth knowing before
  demonstrating a revoked certificate on one route and inferring the other.
- **The wallet relays rather than transmits.** In the article (§5.3) the wallet
  conducts the exchange with the office itself, so that the voting application
  never holds both `id` and `k_p^a`. In this POC one `Voter` object holds both,
  which is a modelling simplification rather than a design change -- and it
  means the code does not demonstrate the property §5.3 argues for.
- **`close()` is reversible.** A real deployment needs closing to be one-way;
  here it is a mutable flag, and the demonstration of a late ballot being
  refused would not survive an operator who simply reopened the box.
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
- **The iOS voting application can open the wallet, and the browser's cannot.**
  On the phone the token request crosses on a URL scheme: the voting
  application hands it over and the wallet opens with a signing question in
  front of the voter. That is a deployment's shape — a relying party invokes
  the wallet, which answers with a consent screen — and it is the thing the
  browser demonstration deliberately does not do, where the only route is a
  file the voter carries.

  What is *not* given up is §5.3's property: only `c` crosses, the identifier
  is added on the wallet's side, and the wallet transmits `[id, c, s]` to the
  office over its own connection. What is given up is the separate property
  that the application cannot provoke a signing question at all. It still
  cannot answer one — the wallet fetches the election's configuration itself
  and refuses a request for another election or a superseded configuration,
  whichever way the request arrived — so what a hostile voting application
  gains is the ability to make a wallet ask, repeatedly, about a request the
  voter can read before consenting.

  Underneath both: two browser origins are separated by the browser, which a
  page cannot talk its way around, while two applications are separated by a
  sandbox enforced by the same system that offers `openURL`. What crosses that
  sandbox is then the wallet's own discipline, and here it is one inbound
  shape carrying the request file's bytes, read by the same reader through the
  same two checks. Nothing in the repository stops a later edit adding a
  second, laxer one; what stops it is this entry, clause A8 and
  `test_only_the_wallet_transmits_and_only_the_voter_app_is_returned_to`. A
  reviewer should check for it rather than assume it.
- **The iOS blinding factor is not recoverable.** `_CryptoExtras` gives its
  blinding inverse no accessor, deliberately, so the voter app cannot persist
  it. An app terminated between blinding and unblinding leaves a token that
  exists, an `s_c` that can still be collected, and nothing that can unblind
  it: the entitlement is spent. The ad-hoc key survives, because its seed is
  bytes; the blinding secret has no representation to keep. Clause A9.
- **No independent review.** The most important gap on this page.

## Attacks worth adding to the suite

Ordered roughly by how much a reviewer would want to see them:

1. Ballot box equivocation — two verifiers shown different ledgers.
2. ~~Replaying a ballot verbatim~~ — settled, and the register had it wrong.
   It was called idempotent; it is idempotent in *content* and not in
   *position*, and supersession reads position, so an operator could re-enter
   a ballot the voter had superseded and make it the last one under that key.
   The ballot now carries a nonce covered by the ad-hoc signature, and the box
   refuses any record already among the accepted entries (§5.7).
3. A voter holding two qualified certificates, and whether the office should
   accept a request signed under either (the article's §3.2 says it must; the
   fixture returns exactly one certificate per `id`, which is enough to run
   the protocol but does not exercise the question). **The wallet route only.**
   On the qualified-signature route the office performs no lookup — the
   certificate arrives with the signature — so it never chooses between a
   citizen's certificates and either will do. The question is absent there
   rather than unexercised, which is clause S2.
4. Selection encoded outside the option list but crafted to collide with a valid
   one after serialisation — a canonicalisation attack.
5. A certificate that is valid, unrevoked, and names a *different* subject than
   the `id` requested — currently impossible by construction, since `lookup`
   is keyed by `id`, but worth an assertion so the invariant is explicit.
