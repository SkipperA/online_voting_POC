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
a broken one fails in ways that look like code problems. Five steps in Xcode
instead:

1. **New project**, iOS → App, SwiftUI, name it `VoterApp`. Repeat for
   `WalletApp`. Put both in `ios/`, so the package sits beside them.
2. **File → Add Package Dependencies → Add Local**, and choose
   `ios/OVPOCKit`. Add the `OVPOCKit` library to both app targets.
3. **Replace the generated `ContentView.swift` and `…App.swift`** with the
   sources in `ios/VoterApp/` and `ios/WalletApp/`.
4. **The wallet declares that it opens token requests.** In the `WalletApp`
   target, Info → Document Types → add one with the extension `ovpocreq` and
   role *Viewer*, so a request file the voter shares can be opened in it. The
   wallet is the destination of a file, not of a call: nothing registers a URL
   scheme, and nothing should.
5. **Both apps allow file sharing.** In each target's `Info.plist` set
   `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` to `YES`, so
   the request and the exported transcripts are reachable from the Files app.
   That is also what lets a cryptographer in the room take the payloads away
   and check them somewhere else.

Both apps address the hosted deployment — `config.diw.hu`, `vro.diw.hu`,
`ebb.diw.hu` — so a device works over the internet with nothing configured. A
laptop deployment separates the origins by port, which a phone on another
machine cannot reach.

## Two audiences, one screen

The policy maker taps *Enrol in election* and watches four steps complete by
themselves — the configuration pinned, the key fingerprint compared, the
ad-hoc key generated, the blinding done — ending in a request file to hand to
the wallet. They come back and press *Collect the token*. Then they choose and
submit. Three deliberate acts, and everything between them automatic.

The cryptographer opens any step and sees the payloads in full, with a share
action on each and a transcript export at the end. Nothing is hidden and
nothing is in the way; the disclosure is collapsed, not absent.

*Collect* is a button rather than a timer, and that follows from the file. The
application has no way to learn that the wallet has consented — no callback
is the point of choosing a file over a URL scheme — so polling would be an
office asked repeatedly by a client that has no reason to think the answer has
changed. The one concession to the one-tap feel: the app checks once
automatically when it returns to the foreground, because coming back from the
wallet is exactly when `s_c` may have appeared. Once per return, and the
button for everything else.

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

- **A8** — the request crosses between the two apps as a file the voter
  carries, exactly as it crosses between the two browser origins, so the
  voting application cannot provoke a signature. What is substituted is what
  *enforces* that: a browser origin is enforced by the browser, an app sandbox
  by the system that also offers `openURL`. The discipline is here; a
  mechanism making the shortcut impossible is not.
- **A9** — the blinding factor cannot be persisted, because
  `_CryptoExtras` gives its inverse no accessor. An app terminated between
  blinding and unblinding spends the voter's entitlement. The ad-hoc key
  survives; the blinding secret has no representation to keep.

Neither is a protocol change. Both are substitutions, and both are the sort
that an audience should hear named rather than discover.
