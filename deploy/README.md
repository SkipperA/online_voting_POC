# Serving the demonstration

Stage 1 separates the origins by port. Hosted, they are separated by
hostname instead, and nothing else changes: `OVPOC_DOMAIN` is the whole of
the difference, and every address, every cross-origin allowance and the
startup banner derive from it.

HTTPS is not optional here. The checker and the supervision page verify
Ed25519 statements in the browser through `crypto.subtle`, which exists
only in a secure context — over plain HTTP to a remote host those checks
are unavailable rather than merely warned about.

## Before the first start

Nine names must resolve to this machine, because certificates are issued
over HTTP-01 and a failed attempt counts against the rate limit:

    for n in "" config. voter. wallet. vro. ebb. checker. supervisor. setup.; do
        dig +short "${n}${OVPOC_DOMAIN}"
    done

Then set the two variables and a password hash:

    export OVPOC_DOMAIN=diw.hu
    export OVPOC_ADMIN_CIDRS="203.0.113.4/32"     # your own address
    docker run --rm caddy:2-alpine caddy hash-password --plaintext '…'

Paste the hash into `Caddyfile` in place of both `REPLACE_WITH_A_BCRYPT_HASH`.

## Checking the proxy configuration

Caddy refuses a configuration it cannot parse and then restarts, which in
`docker compose logs` looks like a banner repeating rather than an error.
Ask it directly instead:

    docker run --rm \
      -v "$PWD/deploy/Caddyfile:/etc/caddy/Caddyfile:ro" \
      -e OVPOC_DOMAIN -e OVPOC_ADMIN_CIDRS \
      caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile

Worth doing before the first start, because a proxy that will not parse its
configuration never reaches the point of requesting a certificate.

## Running

    docker compose -f deploy/compose.yaml up -d --build

The elections live in `deploy/election-data/`, mounted into the container,
so rebuilding the image does not discard one. Mint the first from the setup
console once the certificates are up.

## What this does not claim

The gating on `supervisor.` and `setup.` is a perimeter: an address
allowance with a password behind it. It says who may reach those origins,
not who is entitled to act there — the same distinction the supervision
note draws about who may read the register, and it should be described that
way to an audience rather than presented as an authorisation model.

Hosted, the ballot box sees each voter's address, so the anonymising
submission channel of §3.9 is an absence rather than a theoretical gap. And
a restart still loses a poll in progress: the election survives, the poll
does not (clause A7).
