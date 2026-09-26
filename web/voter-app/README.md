# Voter application (origin 8001)

Static files. Every cryptographic operation runs in the browser: the ad-hoc
key pair, the blinding, the unblinding, and the verification of the token
against the published key. The origin serves bytes and holds nothing — no
session, no cookie, no state in which an identifier could be kept even if one
arrived.

    npm install
    npm run build        # esbuild → static/bundle.js
    python -m service    # from the repository root, then open 127.0.0.1:8001

`static/bundle.js` is generated and not committed; the page reports plainly
when it is missing rather than failing blank.

## Step one

The cryptography, and nothing else: fetch the configuration, import
`k_p^(R)`, recompute its fingerprint, generate an ad-hoc Ed25519 key pair and
blind its public half under RFC 9474 RSABSSA-SHA384-PSS-Deterministic.

No wallet, no ballot, no submission. This is the part that could have failed,
so it is established before anything is built on it.

## What the page says it cannot do

The fingerprint is recomputed in the browser from the published key, which
shows the config origin is internally consistent and nothing more. Real
pinning compares against a value built into the application before the
election; this demo mints the key when the service starts, so there is
nothing to have pinned. The page says so rather than implying otherwise.
