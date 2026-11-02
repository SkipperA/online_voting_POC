# The native surfaces

Two applications and the protocol logic they share. The browser surfaces in
`web/` stay as they are: this is a second client of the same office and the
same ballot box, not a replacement for the first, and the two must agree on
every byte they sign.

```
ios/
  OVPOCKit/        the protocol, as a Swift package. Tested with `swift test`.
  VoterApp/        the voting client. Never reads `id`.
  WalletApp/       the Digital Identity Wallet stand-in. Holds `id`, signs, transmits.
```

The `.xcodeproj` for each app is *not* in the repository — `.gitignore`
excludes it, and the steps below are how it is made. The sources
are, so the thing a reviewer reads is in version control and the thing
Xcode generates is not.

## What the package is for

`OVPOCKit` is to `ios/` what `src/ovpoc/` is to the repository: pure protocol
with no interface in it. A rule about what makes a ballot valid belongs there,
a rule about what a screen shows does not belong there at all, and the test of
that claim is that the package builds and its tests run with no simulator, no
device and no signing identity.

```
cd ios/OVPOCKit
swift test
```

That is the first thing to run, and it is a real gate rather than a formality.
The tests read `tests/vectors/*.json` **in place** — the same files
`tests/test_vectors.py` reads — so a divergence between the Swift and the
Python canonical encoding fails here rather than months later, for one voter
whose identifier carries an accent. `test_vectors.py` says the vectors are a
monologue until a second implementation reads them; this is the second
implementation.

## The dependency

One: `apple/swift-crypto`, pinned to exactly 3.12.3.

It is there for `_RSA.BlindSigning`, which implements RFC 9474 with a named
parameter set — `RSABSSA_SHA384_PSS_Deterministic` — that is the exact
counterpart of what `src/ovpoc/rsabssa.py` implements. SHA-384, PSS, 48-byte
salt, identity preparation. The office needs no change to serve this client.

Two things a reviewer should know about that pin. The module is underscored,
which is Apple declaring the API unstable, so the version is `.exact` rather
than a range: a change to it should arrive as a deliberate bump with a test
run behind it. And 3.12.3 rather than the newest, because from 4.0 the package
requires `swift-tools-version:6.1` and from 5.0 it requires 6.2 — which would
make a current Xcode a precondition for reading this repository. The
blind-signing API is identical across all of them.

The ad-hoc and wallet keys need nothing: `Curve25519.Signing` is in CryptoKit.

## Building the apps

There is no `.xcodeproj` in the repository, on purpose. A generated
`pbxproj` is several hundred lines nobody reviews and that no test covers, and
a broken one fails in ways that look like code problems. Seven steps in Xcode
instead — an `Info.plist` is a source file and *is* committed, for the reason
step 4 gives:

1. **New project**, iOS → App, SwiftUI, name it `VoterApp`, with the
   location set to `ios/` — *not* `ios/OVPOCKit/`, which is the package.
   **Uncheck "Create Git repository on my Mac"**: this repository already
   exists one level up, and a second one nested inside it would quietly
   take the commits. Repeat for `WalletApp`. Xcode produces
   `ios/VoterApp/VoterApp.xcodeproj` with the sources a level down in
   `ios/VoterApp/VoterApp/`.
2. **File → Add Package Dependencies → Add Local**, and choose
   `ios/OVPOCKit`. Add the `OVPOCKit` library to both app targets.
3. **The app sources are in this repository and overwrite the generated
   ones.** `ios/VoterApp/VoterApp/` and `ios/WalletApp/WalletApp/` hold
   the real `ContentView.swift` and `…App.swift`; applying the patch that
   adds them puts them where Xcode is already looking. From Xcode 16
   onward a new project uses a file-system-synchronized folder, so they
   appear in the target by themselves; on an older Xcode, drag them in
   once.

   If you have already *committed* Xcode's generated `ContentView.swift`
   and `…App.swift`, delete them and commit the deletion first — a patch
   that adds a file git already tracks will refuse to apply rather than
   overwrite it.
4. **Point each target at the `Info.plist` this repository carries.** In the
   target's **Build Settings**, set **Packaging → Info.plist File**
   (`INFOPLIST_FILE`) to `Info.plist` — the bare name, for both targets.
   The path is relative to `SRCROOT`, which is the directory holding the
   `.xcodeproj`, so that resolves to `ios/VoterApp/Info.plist` and
   `ios/WalletApp/Info.plist`.

   Leave **Generate Info.plist File** on. Xcode merges the keys it owns —
   display name, launch screen, versions — into the file named here, so
   nothing is lost and the two declarations that matter become reviewable
   and diffable instead of living in a file Xcode generates.

   **The file is beside the project and not among the sources, deliberately.**
   From Xcode 16 a new project uses a file-system-synchronized folder, so
   every file under `VoterApp/VoterApp/` is a member of the target without
   anybody adding it — and an `Info.plist` there is copied as a *resource*
   as well as processed as the bundle's own, which fails the build with

       Multiple commands produce '…/VoterApp.app/Info.plist'

   One level up is outside the synchronized folder and still inside
   `SRCROOT`. If you have already hit that error, this is why, and moving
   the file is the whole fix.

   They are three things, and all three fail quietly if they are wrong:

   - **The URL scheme each app registers**, which is how the other opens it.
     `ovpoc-wallet` on the wallet, `ovpoc-voter` on the voting application —
     `HandOff.walletScheme` and `HandOff.voterScheme` in the package, and
     `test_each_application_registers_the_scheme_the_other_opens_it_with`
     reads the plists with `plistlib` and requires them to agree. This is the
     one thing the voting application can make the wallet do; clause A8 is
     where the trade is written down.
   - **The document type the wallet declares**, `public.json`, which is what
     puts the wallet in the share sheet for `blinded-key.json`. Without it
     the fallback the voting application points at does not exist — the
     share sheet simply never offers the wallet.
   - **The document type the voting application does *not* declare**, which
     is a property rather than an omission. One would put it in *Open with*
     for the signed token request, the single file it must never receive,
     and unlike an Upload button it needs no code at all. The plist comment
     and `test_the_voting_application_declares_no_document_type` are what
     keep it absent.

   Both apps also set `UIFileSharingEnabled` and
   `LSSupportsOpeningDocumentsInPlace`, so the request and the exported
   transcripts are reachable from the Files app — which is what lets a
   cryptographer in the room take the payloads away and check them
   somewhere else.
5. **Delete the apps from the device or simulator before reinstalling, the
   first time.** iOS registers URL schemes and document types when an
   application is installed, and a rebuild over an existing install does not
   always re-register them. A scheme the system has not registered is
   indistinguishable from a wallet that is not installed: nothing opens, and
   nothing says why.

   What *does* say why is the voting application, which now uses `openURL`'s
   completion: if nothing on the device claimed the scheme it answers
   **Nothing on this device opened the wallet**, names this step, and offers
   the request as a file. That is the browser's arrangement on a phone — a
   fine demonstration, as long as nobody believes they are seeing the other
   one.
6. **Build the two apps one at a time, with one project open.** Open
   `VoterApp.xcodeproj`, build and run; close it; open
   `WalletApp.xcodeproj`, build and run with the *same* simulator or
   device as the destination. Both apps install and stay installed, so the
   demonstration — voter app writes the request, wallet reads it, office
   issues, voter app collects — works exactly as designed.

   This is the step that cost an evening, so it is written down as what
   happened rather than as what ought to work. A *local* Swift package can
   be open in one project at a time, and both apps reference
   `ios/OVPOCKit`, so opening the second project gives

       Couldn't load OVPOCKit because it is already opened from
       another project or workspace

   The documented remedy is an Xcode workspace holding both projects, and
   it did not deliver: with both projects added — `contents.xcworkspacedata`
   recording each correctly as a project reference, both `.xcodeproj`
   bundles healthy — the second project would not load, and the wallet
   could be launched only from its own project window. Removing the
   package reference from the projects and hoisting it to the workspace
   did not change that.

   So: one project at a time. It costs a window switch and nothing else.
   If you want to try the workspace anyway, the thing to check is whether
   the *scheme menu* lists both apps; the navigator's appearance is not a
   reliable signal either way.

7. **Check it in one move.** Enrol in the voting application. The wallet
   should come to the front by itself, already knowing whose it is, showing
   the prepared request and asking for a signature. If you see the file
   button instead, the request did not arrive; if you see *Nothing on this
   device opened the wallet*, the scheme did not register and step 5 is
   where to look.
Both apps address the hosted deployment — `config.diw.hu`, `vro.diw.hu`,
`ebb.diw.hu` — so a device works over the internet with nothing configured. A
laptop deployment separates the origins by port, which a phone on another
machine cannot reach.

## Two audiences, one screen

The wallet remembers which citizen it is, so a cold launch from a hand-off
goes straight to the signing question rather than back through the picker;
the picker is still there for playing somebody else, and clause S1 says why
it exists at all.

The policy maker taps *Enrol in election* and watches four steps complete by
themselves — the configuration pinned, the key fingerprint compared, the
ad-hoc key generated, the blinding done — and then the wallet is in front of
them asking for a signature. They consent; they are back here, holding the
token; they choose and submit. Two deliberate acts on the wallet route, and
everything between them automatic. On the qualified-signature route the
handover is a document they sign in their own wallet and hand to the office
themselves, which is more steps on purpose.

The cryptographer opens any step and sees the payloads in full, with a share
action on each and a transcript export at the end. Nothing is hidden and
nothing is in the way; the disclosure is collapsed, not absent.

The wallet route takes no taps at all between *Enrol* and the selection
screen. Blinding finishes, the request goes to the wallet, the wallet opens
and asks for a signature, and on *Consent* it transmits and brings the voting
application back — which collects `s_c` on arrival, because the wallet has
just said the office answered. That is the deployment's shape, and clause A8
says what it trades for.

*Collect* is still there, and still a button rather than a timer. It is what
the voter uses when the wallet is not installed, when the switch back does not
happen, or when the request was carried over by hand — and in those cases the
application has no way to learn that the wallet has consented, so polling
would be an office asked repeatedly by a client with no reason to think the
answer has changed. The app also checks once automatically when it returns to
the foreground, for the same reason it always did: coming back from the wallet
is exactly when `s_c` may have appeared.

This is the same step model as `web/voter-app`, with one difference: there,
each step waits for the voter, because the demonstration *is* the sequence.
Here the steps advance by themselves, because the demonstration is that a
citizen can vote without understanding the sequence — and the sequence is
still there, one tap down, for the people who came to check it.

Each of the three states says itself in words — NOT YET / AWAITING YOU / DONE
— rather than in colour alone, and the live step is the marked one. A page of
completed work that outlines everything except the box the audience must look
at is the mistake `CLAUDE.md` records having made once already.

## What is different from the browser, and recorded as such

Two clauses in `docs/Demo_Scope_Limits.md`, both new with these apps:

- **A8** — the two demonstrations hand the request over two different ways,
  and that is the point rather than an inconsistency. The browser writes a
  file the voter carries, so the boundary is visible and the request can be
  read before anybody signs it; the phone hands it over on a URL scheme and
  the wallet opens by itself, which is the shape a deployment has. What the
  second trades is one property and not §5.3's: only `c` crosses and the
  wallet still transmits to the office itself, but the voting application can
  now *provoke* the signing question. It cannot answer it — the wallet
  fetches the configuration itself and refuses a request for another election
  either way. What is substituted is what *enforces* the separation: a
  browser origin is enforced by the browser, an app sandbox by the system
  that also offers `openURL`, and what crosses it is then the wallet's own
  discipline. The discipline and the single inbound shape are here; a
  mechanism making a laxer one impossible is not.
- **A9** — the blinding factor cannot be persisted, because
  `_CryptoExtras` gives its inverse no accessor. An app terminated between
  blinding and unblinding spends the voter's entitlement. The ad-hoc key
  survives; the blinding secret has no representation to keep.

Neither is a protocol change. Both are substitutions, and both are the sort
that an audience should hear named rather than discover.
