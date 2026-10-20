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

## Updating a running deployment

    git pull --ff-only
    export OVPOC_DOMAIN=diw.hu
    export OVPOC_ADMIN_CIDRS="203.0.113.4/32"     # the same value as before
    docker compose -f deploy/compose.yaml config | grep -A1 OVPOC_ADMIN_CIDRS
    docker compose -f deploy/compose.yaml up -d --build

`--ff-only` so that a commit made on the server stops the pull instead of
being buried in a merge. The local edit this repository *expects* on a
server — the two bcrypt hashes in `Caddyfile` — does not block a pull
unless a change upstream touches that file, in which case the conflict is
the point.

Three things go wrong here more than once.

**`--build` is not optional, and omitting it looks like success.** Without
it Compose recreates the container from the image it already has, so the
service restarts, the banner prints, every page answers, and the code is
the old code. The symptom is a verification below that returns nothing at
all. `docker compose -f deploy/compose.yaml exec ovpoc ls web/shared/`
settles it: if the file a change added is missing there, the image
predates it.

**`OVPOC_ADMIN_CIDRS` fails quietly rather than loudly.** It has a default
of `127.0.0.1/32`, so forgetting to export it does not stop the deploy —
and because Compose recreates a service whose environment changed, Caddy
comes back refusing `supervisor.` and `setup.` from your own address with
a 403. `OVPOC_DOMAIN` is declared `:?` and does error, so only the
allowance can surprise you. The `config | grep` line above is there to be
read before the `up`, not after. Both variables in a `deploy/.env` file is
the better arrangement: a value that depends on which shell you are in is
a value that will one day be absent.

**The rebuild restarts the process, so a poll in progress is lost** —
clause A7, which no change to this repository alters. The election
survives, because the keys and the register are in the mounted volume, and
so does a poll that has already *closed*, through its `poll.state.json`.
An open box does not. Close it first or accept losing it.

Caddy itself is untouched by an update that changes no file under
`deploy/`, and its certificates live in a named volume, so nothing is
re-requested and the rate limit is not approached.

## Checking that an update reached the wire

A deployment can be healthy and stale at once, so the checks worth running
are the ones that name something the update introduced rather than
something every version serves:

    curl -s https://checker.$OVPOC_DOMAIN/ | grep -o 'OVPOC_CONFIG_ORIGIN="[^"]*"'

should print `https://config.` and this domain. An empty result means the
old image is running; a `127.0.0.1` address means `OVPOC_DOMAIN` did not
reach the container.

The two gated origins need the real password, and this is where a
verification run goes wrong: a `curl -su admin:'…'` copied out of a note
with the placeholder still in it gets a 401, and `grep -c` then counts
matches in the word "Unauthorized" and reports a cheerful zero. A check
that cannot fail is not a check.

    curl -su admin:"$PW" https://setup.$OVPOC_DOMAIN/ -o /dev/null -w '%{http_code}\n'

Confirm that says `200` before believing anything grepped from those two
hosts.

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
