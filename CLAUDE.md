# Project context for Claude

Read this before making changes. It exists so that design decisions and
terminology stay consistent across sessions.

## What this is

A proof-of-concept implementation of the Anonymous Authenticated Ballot System
described in Ferenc Vágujhelyi's paper *Proposal for a Secure, Private, and
Coercion-Resistant Online Voting System* (July 2026) and its policy companion
*Online Voting as an Evolution of Electoral Infrastructure*.

Two purposes, in this order:

1. A **reference implementation** to accompany the technical article — the
   protocol made executable, with an adversarial test suite.
2. A **demonstrator** that can be shown to a non-technical audience.

It is not, and must never be presented as, election-ready software.

## Terminology — use these exact terms

| Use | Not |
|---|---|
| ballot box | urn |
| Voter Registration Office (VRO) | registrar, authority |
| token | certificate, credential |
| ad-hoc key pair | session key, temporary key |
| Digital Identity Wallet | eID, digital ID |
| cast-as-intended verification | vote checking |

## Architecture

Protocol logic is **pure** and lives in `src/ovpoc/`. It has no HTTP, no
database, and no framework dependency. The HTTP layer is `service/` — FastAPI,
one app per origin — and it must contain no protocol decisions. Any rule about
what makes a ballot valid belongs in `ballotbox.py`, never in a route handler.
The test of that claim is that `tools/sabotage.py` still detects every mutation
with the service layer in place.

| Module | Role | Diagram steps |
|---|---|---|
| `rsabssa.py` | RSA blind signatures, RFC 9474 | 2, 6/A, 8 |
| `keys.py` | Wallet and ad-hoc Ed25519 keys | 1/A, 3 |
| `messages.py` | Wire objects, canonical serialisation | 4, 9 |
| `ledger.py` | Hash-chained append-only log | 7, 11/A, 11/B |
| `handles.py` | The verification handle — where the coercion trade-off is set | 13 |
| `vro.py` | Eligibility, token issue, release log | 5, 6, 7, 12 |
| `ballotbox.py` | Acceptance, storage, publication, tally | 10, 11 |
| `voter.py` | The voter's whole flow in one file | 1–4, 8, 9, 13 |
| `pdfrequest.py` | The token request as a signable document, and the rule that reads it back | 3, 4 (second route) |
| `driver/population_register.py` | **Not a component.** External identity service | — |
| `driver/qualified_signature.py` | **Not a component.** Electronic-signature validation | 5 (second route) |

**`driver/` is outside the library deliberately.** The population register
answers `id` with a qualified certificate; the design consults it and does not
build it (§3.2). If a lookup table for identity ever appears inside
`src/ovpoc/`, the code has started contradicting the paper. The *electoral*
register is `VRO.register` — a set of ids, and nothing else.

## Design decisions already settled — do not silently revisit

- **No election-specific registration or binding step.** Under eIDAS a
  qualified certificate already binds the signing key to a named person, so a
  second, election-administered copy of that association would be redundant and
  would add an attack surface (rebinding). The office looks the certificate up
  per request. `VRO.enrol` therefore takes one argument: an id.
- **Two routes, one `_claim`.** The office establishes identity two ways --
  a certificate looked up and an Ed25519 signature over `hash([id, c])`, or
  a qualified signature that arrived with the document -- and must not
  differ by a line in anything afterwards. `VRO._claim` is everything below
  the identity boundary and both routes reach it; `release` is shared too,
  so there is one chain, one released set and one register of openings. The
  reason is requirement 2 and the fact that breaking it would be invisible:
  two commitments for one citizen are indistinguishable from two citizens,
  the aggregate audit still balances, and each voter's own check answers
  truthfully. No observer could see it, so no published artefact can be the
  thing that catches it. `document_route_keeps_its_own_released_set` is the
  mutation that does.
- **On the document route the identifier comes from the certificate, and the
  payload has nowhere to put one.** The schema is exactly
  `blinded_key`, `config_digest`, `election_id`, and `_well_formed` requires
  that set and not a superset. A fourth field would be a field the office
  might one day read, and the first thing anyone would put in it is whose
  request this is -- which would be a document that names its own author.
  Relaxing the check to a subset test is `request_payload_accepts_extra_fields`.
- **Step 5 is a state machine with an identity boundary, and the order is
  load-bearing.** Certificate lookup, then signature verification; both
  failures return the single opaque `Outcome.NOT_IDENTIFIED`. Only below that
  boundary may the office give a reason: revoked, expired, not eligible,
  already issued. Otherwise the token endpoint becomes an electoral-roll
  lookup for anyone who can spell an identifier. The audit log records the true
  reason in every case and is never returned to the requester. Two mutations in
  `tools/sabotage.py` (`eligibility_checked_before_identity`,
  `revocation_reported_before_identity`) exist to catch a refactor that
  reorders this.
- **The office does not ask whether the document changed after it was
  signed, because it does not read the part that changed.** Two of
  pyHanko's defaults refuse every document the real wallet produces, and
  both were found by signing one on a phone rather than by reading
  anything. The strict reader rejects the file outright --
  `XRef stream objects must not be clobbered` -- because the update DÁP
  appends reuses an object number that held a cross-reference stream; and
  `bottom_line` is false for it because that update frees an object, which
  the reject-by-default difference policy calls an unacceptable
  modification, with `trusted` true and nothing whatever wrong with the
  chain. So `driver/qualified_signature.py` reads non-strict and asks
  `trusted` rather than `bottom_line`. What makes that affordable is the
  recomputation rule: the office decides on the prefix it rebuilt from the
  payload and disregards everything past it, so a parser's opinion of the
  file's tidiness cannot make a wrong document acceptable, and a later
  revision cannot change what the document requests.
  `pdf_reader_put_back_in_strict_mode` and
  `validator_inherits_the_modification_verdict` are the mutations, and the
  tests behind them reproduce both conditions synthetically -- the only
  real example is a named citizen's qualified signature, which does not
  belong in this repository.
- **What this office trusts belongs to the deployment, not to the poll, and
  the code has to carry that rather than re-derive it.** The anchors sit
  beside the elections rather than inside one precisely so that minting
  cannot change whose signatures are accepted — and `Deployment.mint` called
  `create` without passing them along, so the new election got
  `create`'s default: a path relative to this repository. Both ways that
  goes wrong are silent. Hosted, where the elections are a mounted volume
  and the repository's `election-data/` is not it, the route turns off the
  first time an operator mints. In a clone that carries the pinned GovCA
  root, an office configured for one certification authority comes back
  trusting another — the exact failure `from_pinned` refuses to let a
  swapped file cause. `minting_does_not_change_whose_signatures_are_accepted`
  is the test; a comment asserting the property is not the property.
- **Three states, and the office must never be in the third silently.** No
  anchors: no qualified-signature route, said plainly. Anchors and the
  `pades` extra: the route is offered and performed. Anchors without the
  extra: `from_pinned` raises `ValidatorUnavailable` and the deployment does
  not start. The alternative is an office that advertises the route and
  meets an `ImportError` inside a citizen's upload, which reaches them as
  their own fault — the same argument that makes a swapped anchor refuse at
  load rather than at the first request. `validate` still imports lazily so
  `driver` stays importable without the extra, so there are two lists of
  module names; `the_load_probe_covers_every_module_the_validator_imports`
  reads `validate`'s own imports with `ast` and is the only thing keeping
  them equal. `deploy/Dockerfile` installs `[service,pades]` for the same
  reason: the operator who pins the anchors and the line that installs the
  validator are in different places, and the image should not be the half
  that is missing.
- **An office that offers no route says which directory it read.** On the
  qualified-signature route "not configured" and "anchors in the wrong
  place" are the same page to a voter and the same page to an operator, and
  the difference between them is a path — on a hosted deployment, the
  difference between `election-data/` in the checkout and
  `deploy/election-data/` in the volume. `GET /back-office/trust` reports
  the state, the path, and the anchors themselves with their digests and
  sources. Publishing them is not a leak: they are public certificates, and
  what an office is willing to believe is the whole of its answer to "who
  are you" — an office whose anchors nobody can read is one nobody can
  check.
- **A `driver` method the office calls must be callable from where the
  office is, and that means off the event loop.** pyHanko's
  `validate_pdf_signature` is a synchronous wrapper around an async
  implementation and calls `asyncio.run` inside itself; the upload endpoint
  is an `async def`, because it streams the request body to cap the size
  before reading it. So on a server every genuinely signed request raised
  `RuntimeError: asyncio.run() cannot be called from a running event loop`
  and was answered `NOT_IDENTIFIED`, while the same validator on the same
  file from a script returned a perfect signer. `_off_the_event_loop` runs
  it in a worker thread — unconditionally, never on a "is a loop running"
  branch, because a branch means the tests take one path and the service the
  other, which is how this survived in the first place. The seam stays
  synchronous and `src/ovpoc` stays free of transport concerns; the fix
  belongs on the driver side of the seam, not in the handler.

  **How a suite with two good halves missed the join.** Every test of the
  validator called it from ordinary synchronous code, and the only test that
  drove a real validator through the HTTP layer posted a document with *no
  signature* — which returns before that line is reached. Each half was
  covered and the join was met first by a citizen. The lesson generalises
  past this bug: when an adapter is exercised in one calling context and the
  transport in another, the thing neither test covers is the context itself.
  `test_a_real_signature_reaches_the_office_through_the_endpoint` is the
  honest test, `test_the_validator_works_from_inside_an_event_loop` the
  sharp one, and `validator_called_on_the_event_loop` the mutation.
- **§3.2 is about what the office *discloses*, never about what it knows,
  and the document route briefly got that wrong.** Everywhere else the
  office records the true reason for every refusal and hands the requester
  an enum. Here the validator returned a bare `None` and `_record` wrote one
  sentence covering every way a signature can fail to establish anybody — so
  the operator's log was as blind as the citizen's answer, and the two states
  an operator most needs to separate, a wrongly pinned anchor and a signer
  this office was right to refuse, were written identically. The fix is
  `pdfrequest.SignatureRefused`: a reason that travels to `_record` and
  nowhere else, with `None` still permitted for a validator with nothing to
  add. `refusal_reason_collapsed_in_the_audit_log` is the mutation, and
  `test_two_routes.py` holds both halves — the reason is in the log and is
  not in the response. The general form, worth keeping in mind for the next
  opaque answer: an outcome that is deliberately uninformative to a stranger
  must be *more* informative to the operator, not less, or the privacy
  property has been paid for twice.
- **The identity boundary runs through the signature validator too, and a
  library will move it if nothing stops it.** On the qualified-signature
  route there is no certificate lookup: the certificate arrives with the
  signature and `driver/qualified_signature.py` reads the subject from it.
  Every validation library reports a revoked or expired certificate as a
  failure, pyHanko included -- `bottom_line` is false for a revoked signer
  exactly as it is for one chaining to nothing trusted. Inheriting that
  verdict whole would collapse revocation into `NOT_IDENTIFIED` and undo the
  decision below, through a dependency rather than a refactor. So those two
  are subtracted from the verdict and reported as fields, and everything
  else that made it false stays a pre-identity failure answered with
  `None`. `revocation_collapsed_into_not_identified` in `tools/sabotage.py`
  is what catches the regression. The signature's own integrity --
  `intact` and `valid` -- is never subtracted from: that is the check that
  establishes there is a signer at all.
- **Revocation is reported *after* the signature verifies, and this diverges
  from the paper on purpose.** A revoked certificate still verifies
  mathematically, so by the time the office can see revocation it already knows
  who it is speaking to. The article's §3.2 and §5.4 enumerate certificate
  validity before signature verification; that order is expository and this one
  is the privacy-preserving one. Do not reconcile them silently in either
  direction.
- **The token key signs nothing but tokens.** A blind signer applies its private
  key to values it cannot inspect, so an ordinary token request is a signing
  oracle: any registered voter can obtain the office's signature over a message
  of their own choosing (§3.3). Office statements — currently step-12 denials —
  are signed under a separate `office_key`. `test_attacks.py` forges a statement
  under the token key to show why.
- **RSA blind signatures per RFC 9474**, PSS-encoded. Never sign `k_p^a`
  directly: raw RSA is multiplicative and forgeable. `test_attacks.py`
  demonstrates the attack failing; keep that test.
- **The VRO public key is pinned.** A VRO free to use a different key per voter
  defeats blinding entirely, since it could later tell which key verifies a
  given ballot. `Voter.build_auth_request` refuses to proceed on a fingerprint
  mismatch. This is load-bearing.
- **The PSS salt is chosen by the client, not the signer.** RFC 9474 puts
  `EMSA-PSS-ENCODE` inside `Blind()`, so the VRO never sees an unencoded
  message and cannot choose the salt. The article's §4.1 said otherwise until
  August 2026 and has been corrected; `docs/blind-signature.md` §2.3 records
  both. If an older PDF of the article is to hand, it is the stale copy.
- **Token release is logged before the signature is returned**, so no token can
  exist outside the public log.
- **Three words, not two: rejected / accepted / valid.** A ballot failing its
  cryptographic checks is *rejected* and supersedes nothing. A ballot passing
  both checks is *accepted* and supersedes the same voter's earlier accepted
  ballot. Within the accepted, a selection in range makes the vote *valid* and
  one outside it makes the vote *invalid* — still accepted, still superseding,
  counted as invalid. So `BallotBox.accepted` names the ledger and
  `tally()["valid"]` a count within it. Conflating rejected with invalid lets a
  coercer erase a genuine vote.
- **Publication is two-phase, and the interval is a dial.** While open the box
  publishes commitments, positions, head and counts; the records are released at
  the close. `published_view()` is the whole of what a citizen sees, and
  `tally_interval` decides whether a running tally exists at all. Left at
  `None` — the article's default — `tally()` refuses until the close, for the
  operator too. The POC's demos use ten accepted ballots; the article's example
  is fifteen minutes, and the substitution is deliberate, since a fake clock
  would demonstrate nothing. The article's remedy for the no-running-tally case
  is to encrypt the selection under a Shamir-shared election key; that is
  deliberately outside the formal model in §5, and no encryption work belongs
  in this POC.
- **`close()` is reversible here.** A real deployment needs it one-way. That is
  an operational property, not a protocol one, and the docstring says so.
- **Protest selections stay unofficial: the system never interprets them.**
  `tally()` reports the exact distribution of out-of-range selections
  (`protest_codes`), not one scalar count — but the system never
  interprets, endorses, or pre-registers what any code means. Two reasons,
  not one: (1) requiring voters to agree on a shared code in advance would
  force organised protest to declare itself before voting opens, which in
  a fragile or locally captured election is when a hostile authority is
  best placed to retaliate; (2) some protest messages — e.g. an extremist
  group signalling numeric strength — are ones no legitimate authority
  could officially register without appearing to endorse them, and Requirement
  7 does not permit content-based rejection of protest ballots. A protest
  selection is a message to the public, never a legally supported choice.
  Coordination on a shared code happens through informal channels the
  system has no visibility into and is never asked to judge. This adds no
  new exposure — each ballot's `selection` was already public in the
  ledger; the change only stops the summary from discarding a distinction
  the ledger exposed all along.
- **The order of `VRO._openings` is load-bearing, and a reload restores it
  from the chain.** `supervision_dump` walks that mapping to build the
  register a supervisor reads, and the office's signature covers the
  *chain* — so the two agree only while the mapping holds the order tokens
  were issued in. It does while the poll runs. It did not across a reload:
  `poll.state.json` is written with `canonical_bytes`, which sorts keys
  because canonical serialisation must, so the openings came back sorted by
  identifier and a reloaded finished poll served a register that could not
  be chained to the head printed beside it. Every commitment recomputed and
  the sequence was somebody else's, which is exactly what tampering looks
  like. The fix is `_in_chain_order`, in `restore_releases`: the ledger is
  the authority on order, being what the signature covers, so the openings
  are threaded back onto it by commitment. Not in the writer — sorted keys
  are what canonical bytes are for. Found only once the supervisor page
  stopped reporting its two checks as one verdict, which is the argument
  for having split them.
- **Supersession is applied at tally time**, not by overwriting. The full
  submission history stays auditable.
- **The release log publishes commitments, not voter ids.** `H(id || opening)`,
  with the opening disclosed only on a step-12 query carrying `sig(id)`. A
  plaintext log would be a public participation register, and while absence of an
  entry does not show how anyone voted, it is conclusive proof of *non*-voting --
  which is what a coercer demanding turnout needs. The published count still
  supports the aggregate `ballots <= tokens` audit, so both properties are kept.
- **Negative answers to step-12 queries are signed.** This does not stop a
  dishonest VRO denying a token it minted; it makes the denial attributable if
  later contradicted. Do not describe it as prevention.
- **Ed25519 for the ad-hoc and wallet keys.** A real wallet would use ECDSA
  P-256 in a secure element; `keys.py` keeps the interface narrow so it can be
  swapped.
- **The browser surfaces share `web/shared/tokens.css`, injected rather than
  linked.** Each origin's own application reads the file and inlines it into
  its own pages (`service/apps.py:_page`). A `<link>` to a stylesheet on 8000
  would make six trust domains share a runtime dependency and would be a
  fourth cross-origin allowance where the surface map permits three. One file
  in the repository, eight copies on the wire. A page opened straight off disk
  is therefore unstyled, as it was already unfilled.
- **Every surface watches the configuration it pinned, and says "reload"
  rather than reloading.** Each page pins the published configuration at
  load -- the fingerprint a token must verify under, the digest the wallet
  refuses a mismatch against, the statement keys the checker and the
  supervisor verify every signature with. The setup console can mint a new
  election over the running one at any moment, and minting replaces all
  three key pairs. Nothing told the open pages, so they went on checking a
  new election's artefacts against an old election's keys and reported,
  accurately, that nothing verified. Every one of those messages names a
  defence doing its job and reads, in a room, as the system being broken:
  the failure was honest and the diagnosis unavailable.
  `web/shared/config-watch.js` is the diagnosis. It watches
  `election.json.sha256`, not the configuration, because the digest moves
  on any change at all and deciding which changes a reader may ignore is
  not this script's to make. It is served by `service/apps.py:_watch`, like
  the band and the tokens, so a surface added later cannot be added without
  one -- and injected rather than linked, which matters more here than for a
  stylesheet: a `<script src>` at 8000 would let the config origin run code
  on six trust domains. The setup console is the one page without it, being
  the author of the change. The bar never navigates on its own: on the voter
  application a reload costs the ad-hoc key and with it the entitlement to
  re-vote, which is the design's own answer to coercion. It collapses rather
  than closes, because the condition is permanent until the page is reloaded
  and a dismissable notice would leave a stale page looking current. It
  stacks with the band rather than covering it -- `--stale-height`, measured
  in the script -- because the band is the only thing on the page that says
  which trust domain the reader is standing in.
- **Hue carries trust-domain identity and nothing else** — never a verdict,
  never decoration. The band colours live on `Origin` in `service/origins.py`
  beside the port, so a surface that moves in code moves on the page. The six
  domains form three families of two: voter side (teal), authority side
  (orange-brown), oversight (violet), with a lightness step between the two
  members of a family. Families rather than six independent hues because an
  audience holds three mappings and not six. The two origins that are not
  trust domains carry no hue, so "not a domain" reads as the absence of
  colour. Red and green are left free to go on meaning danger and verified
  inside the pages; amber is spoken for by the authority family and is
  therefore no longer available to mark a scope limit.
- **The voter app marks the live step, not the finished ones.** `done` used
  to take a green border while the step awaiting the voter took nothing, so a
  page of completed work was outlined and the one box an audience had to look
  at was the only plain one. `current` carries the marking now, and each of
  the three states says itself in words — NOT YET / AWAITING YOU / DONE —
  rather than in colour alone. Nothing is dimmed: the payloads in a finished
  step are the exhibit and stay as readable as they were when it was live.
- **Reduced motion is honoured in the script, not only the stylesheet.** The
  `@media` rule in `tokens.css` reaches CSS animations; it does not reach
  `Element.animate`, and an explicit `behavior: 'smooth'` overrides the CSS
  `scroll-behavior` it would otherwise obey. `main.ts` asks
  `matchMedia` for both.
- **Four kinds of scope clause, four treatments on screen.**
  `docs/Demo_Scope_Limits.md` is the single list; the pages derive their
  labels from it and `test_every_scope_note_names_a_kind_and_a_real_clause`
  is what stops the two drifting. Substituted, Absent and Out of scope share
  a neutral frame and differ by name and by border style — solid, dashed,
  dotted — because amber now belongs to the authority family and a reader who
  cannot separate two colours must still separate two claims. Exposed keeps
  the danger colour: it is the kind an audience misreads as a flaw when it is
  a deliberate disclosure. One aside states one kind; an aside citing clauses
  from two sections is the conflation the document exists to prevent.
- **Three measures, not one.** `--measure` is the page and differs per
  surface because the widest table does. `--measure-prose` holds the running
  text to about sixty-eight characters: the explanatory prose is the
  substance of the demonstration and was inheriting a column set wide for
  base64. `--payload-cols` is 64 `ch`, uniform across every surface, because
  the same token wrapped at 70 characters on the wallet and 95 on the voter
  application and two screens could not be compared by eye; 64 is also what
  base64 looks like in a PEM file. Tables, payload blocks and the
  label/value grids keep the full column.
- **Every surface carries an origin band, served rather than written.**
  `service/apps.py:_band` puts the same element at the top of every page:
  the trust domain's name, its family, whether it is a trust domain, and its
  address, in that domain's own colour. It is injected, so a surface added
  later cannot be added without one. The two origins that are not trust
  domains get the same band with no fill. `_palette` emits every domain's hue
  on every page, not just the serving one, because the config origin draws
  the legend and a legend built from a second copy of the table would be a
  second copy of the table.
- **Every colour has a light value and a dark value.** All eight pages
  declared `color-scheme: light dark` and then set literals, so in dark mode
  the secret-red sat at 2.90:1, the verified-green at 3.74:1 and the
  explanatory prose at 3.26:1, and the wash behind every warning box was a 9%
  alpha over near-black. `test_no_page_declares_a_colour_of_its_own` is what
  keeps a literal from coming back.

- **The build says which code it is, and says what that is worth.** Every
  check for "is the deployment running what I think" was a proxy invented
  per patch: grep a page for a string only that patch introduced, or `exec`
  into the container and read a file. `service/build.py` reports
  `OVPOC_REVISION` on `/health` for every origin and under *This build* on
  the configuration index. It answers which code the operator *meant* to
  deploy; nothing verifies that the running code is that commit, there is
  no signature and no reproducible build, so it is weaker than clause S4,
  which at least publishes a hash. Three decisions inside it. Unset it
  reports `unknown` rather than guessing, because a plausible wrong
  revision would be believed. The environment wins over a `.git` in the
  build context, since that is the container's explicit claim. And it is
  *not* in `election.json`: an image rebuilt with no change to the election
  must not move the digest every voter pinned, and a reader must not
  mistake a software version for something the configuration attests —
  hence two sections on the page, and
  `test_the_revision_is_not_part_of_the_election`. The `ARG` sits last in
  the Dockerfile, because consumed earlier it would put a per-commit value
  in the cache key of every layer below it.
- **The native handover is a file the voter carries, not a URL scheme.** The
  browser wallet grants nothing to anyone and the only thing 8001 can put
  into 8002 is a file; the iOS apps keep that, and it costs them the
  one-tap flow a URL scheme would have bought. The reason is the wallet
  note in `api.py`: a wallet an application can invoke is an API with a
  consent screen painted on it. §5.3's property — no component holding
  both `id` and `k_p^a` with the office's signature over their association
  — would survive a URL scheme, since only `c` would cross; what would not
  survive is the separate property that the application cannot *provoke* a
  signature at all. That second property is the one being kept.
  Consequently *Collect the token* is a button: with no callback there is
  nothing for the application to wait on, and a timer would poll an office
  with no reason to think the answer had changed. One automatic check when
  the app returns to the foreground, because that is when `s_c` may have
  appeared, and the button for everything else. Clause A8 records that what
  is substituted is the *enforcement* — a browser origin is enforced by the
  browser, an app sandbox by the system that also offers `openURL`.
- **The voting application names the office's hand-in page and that is not
  a breach of A8.** What the clause protects is the *inbound* direction:
  the application holds `k_p^a` and `r`, so it must never see the signed
  document, which carries `id`. Telling a person where to take that
  document is not handling it — and a voter told to hand it in themselves
  and not told where is a voter looking for an Upload button, which is how
  the button eventually gets built. So `Origins.handIn` exists, is handed
  to `Link` for the browser to open, and is fetched by nothing. The
  tripwire in `tests/test_native_sources.py` was sharpened to match:
  it forbids the `signed-token-requests` endpoint anywhere native and a
  file picker (`fileImporter`, `UIDocumentPicker`, `NSOpenPanel`, `onDrop`)
  in the voter app, rather than the page's path. A picker is the sharper
  signal in any case — an Upload button needs one, and nothing else in
  that application has any use for one. The same test greps the *wallet*
  for those APIs and requires a hit, because the wallet must import a file
  and a tripwire that matches nothing anywhere cannot be told from a typo.
- **The route is chosen before the one tap, on the first screen.** The two
  routes diverge at the handover and the file is written there, so the
  choice cannot be deferred past `enrol` without writing a file and then
  replacing it. The picker therefore appears in `.fresh` and in no other
  phase, and that is the whole of the enforcement that it is fixed.
- **Two renderers write the token-request document, and CI cannot compile
  one of them.** `src/ovpoc/pdfrequest.py` and
  `ios/OVPOCKit/Sources/OVPOCKit/PDFRequest.swift` must agree byte for
  byte, because the office *rebuilds* a document rather than reading it: a
  renderer one space out does not produce an oddly formatted request, it
  produces one refused as "not as rendered", reported to the citizen as a
  fault in their request. `tests/vectors/pdf-request.json` pins the bytes
  and pins them only where `swift test` runs, which is a Mac. So
  `tests/test_native_sources.py` compares the two sources' *prose* and
  their non-prose constants in Python, reading the sentences out of
  `_lines` with `ast` rather than listing them, and joining Swift's `+`
  concatenations first so that a difference in line wrapping is not
  reported as a difference in the document. It is not a compiler and not a
  substitute for the vector. It catches the thing that actually gets
  edited.
- **The app targets have no tests, so the Python suite balances their
  delimiters.** `swift test` reaches `ios/OVPOCKit` and nothing else:
  `VoterApp` and `WalletApp` are Xcode app targets with no test target, so
  until `tests/test_native_sources.py` the only thing between a malformed
  source file and a broken build was the build. It earned its place
  immediately — a brace dropped while editing `WalletApp/ContentView.swift`
  programmatically left a `struct` unclosed, and Xcode found it rather
  than this suite. It is a delimiter count and nothing semantic: balancing
  is not compiling, and a green run means only that the cheapest mistake
  is absent. `strip()` is written out rather than regexed because the
  regex version failed in the obvious way — removing `//` comments first
  truncates `"https://host"` mid-literal and every quote after it is
  misaligned.
- **A native wallet has no enrolled key, and the name is not the
  credential.** The office checks a token request against the key the
  population register holds for that identifier; this demonstration enrols
  citizens by generating their keys server-side, and the browser wallet
  holds none — it asks origin 8002 to sign. So a wallet application that
  generates its own key signs as nobody the register knows and the office
  answers `NOT_IDENTIFIED`, which is §3.2 working rather than a fault, and
  which no identifier will get past. `Personas.swift` closes it by
  *adopting* one of the demonstration's citizens, key and all, over an
  endpoint that says in its own docstring that no real wallet exposes it.
  The honest version — the wallet generates its key and enrolment records
  the public half, as §3.2 describes — needs `POST /voters` to accept a
  supplied key and a setup console a phone can reach, and the hosted one
  sits behind an address allowance and a password. Clause S1 carries the
  disclosure.
- **The wallet-persona substitution is clause S1, not A3.** Seven places
  cited A3, which is *Browser-delivered code (stage 1 only)*; S1 is *The
  Digital Identity Wallet*. Worth knowing that nothing checks this: the
  suite verifies the clause citations on the *pages* and says nothing
  about the ones in comments, so these drifted silently and were found by
  reading. A3 is also the clause the native client partly discharges — its
  own label says an App Store binary is not supplied by the VRO.
- **The flows live in the package, not the app targets.** `VoterFlow` and
  `WalletFlow` are the native counterpart of `voter.py` — "the voter's
  whole flow in one file" — and they are in `OVPOCKit` so that step order,
  what is held and discarded, the refusal when the configuration moves
  mid-flow, and what `Collect` does when pressed too early are all
  reachable by `swift test` with no simulator and no network. The views
  over them draw a list and three buttons. The seams are four narrow
  protocols (`ElectionReading`, `TokenReplyCollecting`, `BallotSubmitting`,
  `RequestTransmitting`), and their separation is the §3.6 boundary
  expressed in types: `RequestTransmitting` is the wallet's and appears in
  no voter-side type, so a voting application that wanted to transmit
  `[id, c, s]` would have to grow a dependency visible in its initialiser.
- **The native clients share `ios/OVPOCKit`, and it holds no interface.**
  What `src/ovpoc` is to the repository, that package is to `ios/`: the
  protocol, testable with `swift test` on a Mac with no simulator, no
  device and no signing identity. Its one dependency is `apple/swift-crypto`
  pinned `.exact` to 3.12.3 — for `_RSA.BlindSigning`, whose
  `RSABSSA_SHA384_PSS_Deterministic` is the exact counterpart of
  `rsabssa.py`'s variant, so the office serves both clients unchanged.
  Exact rather than a range because the module is underscored, which is
  Apple declaring the API unstable; 3.12.3 rather than the newest because
  4.0 requires `swift-tools-version:6.1` and 5.0 requires 6.2, and the
  blind-signing API is identical across all three.
- **`CanonicalJSON.swift` is written out rather than delegated to
  `JSONEncoder`.** Three silent divergences, each of which would produce
  signatures the Python rejects and only for some inputs: `JSONEncoder`
  escapes the solidus unless told not to and Python never does;
  `.sortedKeys` orders by `String`'s Unicode-aware comparison while
  Python's `sort_keys` orders by code point; and the choice of which
  control characters take a short form is Python's specific one, with
  `\u00xx` in *lower-case* hex for the rest. The
  `characters-that-must-be-escaped` vector was added to
  `tools/golden_vectors.py` for exactly this path, which nothing else
  pinned. A `JSONEncoder` refactor would reintroduce these one at a time,
  so `testTheThreeDivergencesFromAPlatformEncoder` names them one at a
  time.
- **A new vector is added by editing the generator's fallback.**
  `inputs_of` returns the committed inputs unchanged and appends any
  fallback case whose name is not already there. Committed inputs are
  never altered or dropped: a vector's input is what some other
  implementation has already been checked against, and editing one turns a
  conformance file into a moving target whose drift surfaces as the *other*
  implementation failing. Renaming a case retires it and adds a new one,
  which is the honest way to change what a vector tests.
- **swift-crypto's data-based RSA verify hashes with SHA-256.** Handing
  `isValidSignature(_:for:padding:)` a message rather than a digest checks
  a SHA-384 token against a SHA-256 encoding and returns `false` — which
  reads as a blinding fault and is a one-word mistake at the call site.
  Every verify in the Swift passes `SHA384.hash(data:)` explicitly.

## Open, deliberately not yet implemented

- **Variant A — the anonymous random-number tracker.** The current code
  implements variant B: the voter's handle on their ballot is the ad-hoc key
  they control, so authorship is provable to an adjudicator *and* to a vote
  buyer. Variant A binds the ballot to a random identifier instead, which the
  voter can check but cannot use as proof. It requires a trapdoor-style
  construction (compare the Selene line of work) and is the novel contribution
  intended for the technical article. Design it as a pluggable verification
  handle, not a fork.
- **Threshold token issuance** across several mutually distrusting bodies, so no
  single VRO can mint tokens for absent voters.
- **Anonymising submission channel.** Signing protects integrity, not
  anonymity: the network layer sees who contacts the ballot box and when.
- **Post-close verification with out-of-band return codes**, to close the
  silent-override window after a voter's final check.
- **The wallet transmits, rather than the application relaying.** §5.3 has the
  wallet conduct the exchange with the office itself, so that no single
  component holds both `id` and `k_p^a` together with the office's signature
  over their association. One `Voter` object here holds both. It is a modelling
  simplification, but it means the code does not demonstrate the property §5.3
  argues for, and `docs/threats.md` records that.
- **Several certificates per voter.** §3.2 says the office must accept a request
  signed under any valid certificate naming the requester. `lookup` returns
  exactly one, which runs the protocol but does not exercise the question.

## Working style

- Tests alongside code, in the same change. The adversarial suite is the point
  of the project, not an extra.
- Every attack the design claims to defeat gets a test that names it and shows
  it failing. Attacks the design does *not* defeat go in `docs/threats.md`, so
  their absence is deliberate.
- **Add a mutation to `tools/sabotage.py` for every new defence, and re-run it.**
  A passing negative test can pass for the wrong reason; the sabotage run is what
  shows a test actually constrains the check it names. Adding the key-pinning
  mutation is how the missing pinning test was found. `docs/sabotage.md` is
  generated -- never hand-edit it.
- **A mutation defended only by skippable tests is not defended.** The
  report is committed and CI diffs it, so it has to mean the same thing on
  every machine that writes it. It did not, the first time an optional
  extra appeared: the three `driver/qualified_signature.py` mutations came
  back NOT CAUGHT in a virtual environment predating the `pades` extra,
  because the tests that defend them are skipped without it -- true, about
  the environment, and the opposite of what CI would have written. The
  runner now refuses to write a report when the baseline skipped anything,
  and names what was skipped. Install with `pip install -e ".[dev]"` before
  regenerating.

  The rule is about skips and not about extras, which is worth saying
  because the next violation was a different kind: a test that called
  `pytest.skip` when `qpdf` was not on `PATH`, written one patch after this
  note. An extra can be installed; a command-line tool the suite assumes is
  a suite that means something different on two machines, and `pip install`
  cannot fix it. **The test suite depends on what `pyproject.toml`
  declares, and on nothing else.** `tools/` may shell out to whatever is
  useful and say so when it is absent; `tests/` may not.
- Keep `docs/wire-contract.md` in step with the code: it maps every field on
  the wire to the clause it discharges, and ends with two lists worth
  re-reading before any paper edit -- fields with no clause behind them, and
  requirements with no field.
- Keep `docs/protocol.md` in step with the code. It is the only place that maps
  diagram step to paper notation to function, so every rename lands there and
  nowhere else -- `VRO.token_released` sat in that table long after the method
  became `VRO.query_token_release`. `docs/blind-signature.md` is the normative
  reference for the blind-signature core and deliberately names no functions, so
  it does not move when code is renamed.
- Comments explain *why*, especially where a naive implementation would be
  insecure. Assume a reviewer looking for weaknesses.
- Do not add dependencies without asking. The trust story is better the
  shorter the list.

## Markdown and math in `docs/`

GitHub renders math with KaTeX but runs its Markdown pass over the content
first. That pass strips backslash-escapes and pairs `_` and `*` as emphasis, so
plain `$...$` and `$$...$$` corrupt LaTeX *silently*: `\;` arrives as `;`, `\!`
as `!`, `\,` as `,`, and `\{` vanishes into a grouping brace. The equation still
renders, just wrongly -- `S\!(x)` reaches the reader as `S!(x)`, which can be
taken for a factorial.

Use only the protected delimiters, which take their content literally:

- Display: ` ```math ` fenced blocks
- Inline: `` $`...`$ ``

Two further constraints:

- `\operatorname` is blocklisted by KaTeX. Use `\mathrm`.
- Keep `aligned` blocks to two columns. A third annotation column overflows
  GitHub's content width and is clipped without warning.

Do not treat a rendering fault as a content fault. Stripping spacing macros,
avoiding braces, or flattening notation to make something display is fixing the
symptom; the delimiters are the cause.

The protected syntax is GitHub-specific -- `` $`...`$ `` shows literal backticks
in VS Code's preview, Obsidian, and Pandoc. A document that must read well off
GitHub should be compiled, not reformatted.

## Commands

```
pip install -e ".[dev]"
python -m pytest -q          # full suite
python demo.py               # narrated end-to-end run
python ext_demo.py           # narrated end-to-end run with all tests
python tools/sabotage.py     # regenerate docs/sabotage.md
python demo_svr.py           # happy path against a live service
python ext_demo_svr.py       # adversarial scenarios against a live service
cd web/voter-app && npm install && npm run build   # the voter app's bundle.js
cd ios/OVPOCKit && swift test # the native client against the golden vectors
```
