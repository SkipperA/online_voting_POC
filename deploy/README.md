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

Then set the domain. Two consumers want it and they read it from
different places, which is worth getting right once rather than meeting as
an error later:

    printf 'OVPOC_DOMAIN=diw.hu\n' > deploy/.env
    export OVPOC_DOMAIN=diw.hu

The file is for **Compose**, which reads `.env` from the directory holding
the compose file, so every `docker compose -f deploy/compose.yaml …` below
picks it up with nothing exported. Without it they stop with *required
variable OVPOC_DOMAIN is missing a value* before doing anything.

The export is for **your shell**, which Compose cannot help with: the `dig`
loop above, the `caddy validate` runs below and every `curl https://…
$OVPOC_DOMAIN/…` are ordinary commands and need the variable in the
environment. A fresh login does not have it.

Both are local files or local state. `deploy/.env` is in `.gitignore`
beside `deploy/election-data/`, so neither follows a `git add -A` into a
commit.

Then generate a password hash:

    docker run --rm caddy:2-alpine caddy hash-password --plaintext '…'

Paste the hash into `Caddyfile` in place of both `REPLACE_WITH_A_BCRYPT_HASH`.
That is the only local edit to a *tracked* file this repository expects, and
it is why an update touching `Caddyfile` has to be applied by hand.

One variable, not two. `OVPOC_ADMIN_CIDRS` used to name the addresses
allowed to reach `supervisor.` and `setup.`; it is gone, and the
`Caddyfile` says why.

## Checking the proxy configuration

Caddy refuses a configuration it cannot parse and then restarts, which in
`docker compose logs` looks like a banner repeating rather than an error.
Ask it directly instead:

    docker run --rm \
      -v "$PWD/deploy/Caddyfile:/etc/caddy/Caddyfile:ro" \
      -e OVPOC_DOMAIN \
      caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile

Worth doing before the first start, because a proxy that will not parse its
configuration never reaches the point of requesting a certificate. Worth
doing before every start, in fact, and `&&` rather than `;` so that a
configuration which does not parse cannot reach the running proxy:

    docker run --rm -v "$PWD/deploy/Caddyfile:/etc/caddy/Caddyfile:ro" \
      -e OVPOC_DOMAIN caddy:2-alpine \
      caddy validate --config /etc/caddy/Caddyfile \
    && docker compose -f deploy/compose.yaml up -d

A Caddy that cannot provision its configuration exits and is restarted by
Compose, forever, and every origin is unreachable for as long as that
lasts. It never reaches ACME in that state, so the certificates and the
rate limit are untouched — the cost is availability, which on a
demonstration day is the whole cost. The symptom in `docker compose logs`
is the startup banner repeating; the cause is on the `error` line between
two of them.

## Running

    docker compose -f deploy/compose.yaml up -d --build

The elections live in `deploy/election-data/`, mounted into the container,
so rebuilding the image does not discard one. Mint the first from the setup
console once the certificates are up.

## Updating a running deployment

    git pull --ff-only
    OVPOC_REVISION=$(git rev-parse --short HEAD) \
      docker compose -f deploy/compose.yaml up -d --build

No `export` here: `deploy/.env` carries the domain for Compose. The
revision stays inline because it must change on every build, which is the
one thing a file of settings is bad at.

`--ff-only` so that a commit made on the server stops the pull instead of
being buried in a merge. The local edit this repository *expects* on a
server — the two bcrypt hashes in `Caddyfile` — does not block a pull
unless a change upstream touches that file, in which case the pull refuses
and the two lines are re-pasted by hand. That is the one file to expect
friction from.

Two things go wrong here more than once.

**`--build` is not optional, and omitting it looks like success.** Without
it Compose recreates the container from the image it already has, so the
service restarts, the banner prints, every page answers, and the code is
the old code. The symptom is a verification below that returns nothing at
all. `docker compose -f deploy/compose.yaml exec ovpoc ls web/shared/`
settles it: if the file a change added is missing there, the image
predates it.

**The rebuild restarts the process, so a poll in progress is lost** —
clause A7, which no change to this repository alters. The election
survives, because the keys and the register are in the mounted volume, and
so does a poll that has already *closed*, through its `poll.state.json`.
An open box does not. Close it first or accept losing it.

Caddy itself is untouched by an update that changes no file under
`deploy/`, and its certificates live in a named volume, so nothing is
re-requested and the rate limit is not approached.

## Telling the office what to trust

Only needed for the qualified-signature route. Without it the office offers
no such route at all, which is the honest state for one that has not been
configured for it -- and is a different thing from an office that offers the
route and refuses every request.

There are two ways, and the first is better. Pin the European trusted list —
**from inside the office's container**, which is where the `pades` extra is
installed and which has the volume mounted as `/data`:

    docker compose -f deploy/compose.yaml exec ovpoc \
        python tools/fetch_trust_anchors.py \
            --into /data/trust-anchors --trusted-list HU

Run on the host instead and it stops with that command rather than a
traceback: pyHanko is in the image, not on the server. It writes as uid 1000
into the mounted volume, so the files land beside the elections owned by you
and survive a rebuild.

That fetches the Union's list-of-the-lists, checks its signature against the
signer certificates pyHanko ships, reads Hungary's own list from the address
the *signed* LOTL gives, and checks that against the certificates the LOTL
names for it. Nothing is trusted because it came from a plausible address.
The office then takes its anchors from that list and can say whether a
signature is *qualified* under Article 3(12) — which an office on a
hand-pinned root cannot, and reports as "no standing to judge" rather than
as "no".

It is read offline, so re-pin before an election rather than after: a service
withdrawn from the list since the snapshot is still trusted by it, and every
surface prints how many days old it is.

The office reads its anchors once, at startup, so it keeps using the old ones
until it is restarted:

    docker compose -f deploy/compose.yaml restart ovpoc

That costs a poll in progress, like any restart (clause A7). `vro.$OVPOC_DOMAIN`
then shows the territory and the pin date under *Qualified-signature route*,
and says it can use the word.

The older way, one root downloaded by hand, still works and is what this
deployment ran before the above existed:

    python tools/fetch_trust_anchors.py --into deploy/election-data/trust-anchors \
        http://qca.hiteles.gov.hu/ecc/cer/govca-ecc-root.cer

**`deploy/election-data/`, not `election-data/`.** That is the mounted
volume — the same directory the elections are in, as above — and the one the
container reads as `/data`. This repository also carries
`election-data/trust-anchors/` at its root, which arrives on a server with
every `git pull` and which the container never sees: it is there so the test
suite and a laptop run have something to pin, and on a server it is a decoy.
Copying it across is enough, and avoids a second download:

    cp -r election-data/trust-anchors deploy/election-data/

The symptom of getting this wrong is an office that answers every upload
with *this office is not accepting signed documents* while the anchors sit
in a directory three lines up in the same checkout. `vro.$OVPOC_DOMAIN`
says which directory it read, under *Qualified-signature route*; compare it
with where the files are before looking anywhere else.

The directory sits beside the elections rather than inside one, so minting a
new election does not silently change whose signatures are accepted, and it
is in the mounted volume, so a rebuild does not discard it.

One certificate is enough, and that is worth knowing rather than assuming: a
document signed by the DAP application carries its own chain in a `/DSS` --
the signer, the issuing authority, the timestamp authority and its issuer --
and none of them is self-signed. Everything reaches `GovCA
Fotanusitvanykiado`, and that root is the one thing the document does not
carry.

**Check the fingerprint the tool prints against something that did not come
down the same wire.** Downloading a root from the authority's own web server
and trusting it is trust on first use, and this office will then believe
whoever that authority vouches for. The authority's published practice
statement or the national trusted list will do; a second download will not.

The manifest records the digest, and the office refuses to start if a file
in that directory no longer matches it, or if a certificate is there that
the manifest does not account for. Verify without starting anything:

    python tools/fetch_trust_anchors.py --into deploy/election-data/trust-anchors --check

A deployment takes its anchors from a signed European trusted list instead,
which is what removes the trust-on-first-use step. That difference is a scope
clause rather than a detail.

## Checking that an update reached the wire

Ask the container which code it is:

    curl -s https://config.$OVPOC_DOMAIN/health

The `revision` in that answer is what `OVPOC_REVISION` was set to at build
time, and `https://config.$OVPOC_DOMAIN/` shows the same value under *This
build*. `unknown` means the image was built without being told, which is
what forgetting the variable above looks like — the field reports it rather
than guessing, since a plausible wrong revision would be believed.

It answers which code the operator *meant* to deploy. Nothing verifies that
the running code is that commit, there is no signature and no reproducible
build, and `service/build.py` says so at length. For the stronger question
there is no answer here yet.

So the checks below remain worth running: they name something a specific
update introduced rather than something every version serves, and unlike
the revision they are evidence rather than a claim.

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

The same trap, in the general form: a placeholder that looks like shell
syntax will eventually be pasted as shell syntax. `<the address>` in a
command reaches a configuration file as `<the`, and an example address in
a document — `203.0.113.4`, reserved by RFC 5737 so that it can never be
real — looks real enough to copy. Both happened here. Where a value must
be typed rather than computed, let the shell ask for it and check what it
got before anything acts on it:

    read -rp 'value: ' V
    [[ "$V" =~ ^[0-9a-fA-F:.]+$ ]] || echo "refused: [$V]"

The brackets are the point. They show the spaces and the angle brackets
that a bare `echo` hides.

## What this does not claim

The gating on `supervisor.` and `setup.` is a password and nothing more.
It says who may reach those origins, not who is entitled to act there —
the same distinction the supervision note draws about who may read the
register, and it should be described that way to an audience rather than
presented as an authorisation model.

It is deliberately weaker than the address allowance it replaced, because
the supervision page is the oversight argument and a page the room cannot
open argues nothing. What that costs is worth stating plainly rather than
discovering: anyone holding the password can mint an election over a
running poll, from any network, and every token already issued stops
verifying. Minting requires naming the election being replaced, which
guards against the accident and not against the act. Choose a password
accordingly, and do not put it on a slide.

A consequence of being publicly reachable: both origins will be scanned.
`basic_auth` verifies at bcrypt cost 14, which is about a second of CPU
per attempt by design — good against guessing, and on a single-core VPS
also a cheap way for a scanner to spend the machine's capacity. It has not
been a problem in practice; it is the sort of thing to recognise rather
than to be surprised by.

Hosted, the ballot box sees each voter's address, so the anonymising
submission channel of §3.9 is an absence rather than a theoretical gap. And
a restart still loses a poll in progress: the election survives, the poll
does not (clause A7).
