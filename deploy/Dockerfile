# The demonstration, served.
#
# Separate from the Dockerfile at the root, which builds a verification
# environment and says of itself that nothing in it is deployable. That one
# runs the test suite; this one runs the origins. Keeping them apart means
# the image a reviewer reproduces results with cannot drift into being the
# image that faces an audience.
#
#   docker compose -f deploy/compose.yaml up -d --build
#
# Binds every origin inside the container only. Nothing is published; the
# proxy reaches them over the compose network.

# The voter application is TypeScript and its bundle is a build artefact,
# deliberately not committed. Built here rather than on the host: the one
# thing a deployment image must not do is require the machine it runs on to
# have a toolchain, and a bundle built by hand is a bundle nobody can say
# the provenance of.
FROM node:20-slim AS voter-app

WORKDIR /build
COPY web/voter-app/package.json web/voter-app/package-lock.json ./
RUN npm ci
COPY web/voter-app/src ./src
RUN npm run build


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
# `pades` as well as `service`, and it is not optional here even though the
# extra is optional in the project. An office with anchors pinned and no
# validator installed refuses to start -- which is the right failure and a
# miserable one to meet on a server, since the thing that pins the anchors
# is an operator on the host and the thing that installs the extra is this
# line. The cost is the image: fifteen distributions, lxml and aiohttp
# among them. An office that will never offer the route pays it anyway,
# which is the trade -- an image that cannot perform a route the operator
# can switch on is worse.
RUN pip install --no-cache-dir -e ".[service,pades]"

COPY service ./service
COPY driver ./driver
COPY web ./web
# The bundle lands beside the page that loads it, exactly where the service
# expects to read it from.
COPY --from=voter-app /build/static/bundle.js ./web/voter-app/static/bundle.js
COPY tools ./tools

# The verifier is downloaded from the checker page, so it has to be in the
# image: an independent check nobody can obtain is not one.
COPY docs ./docs

# Not a security boundary on its own -- but the election directory is a
# mounted volume, and files written into it should not arrive owned by root
# on the host.
RUN useradd --create-home --uid 1000 poc && chown -R poc:poc /app
USER poc

# Every origin on the container's own interface. See the note in
# service/origins.py: loopback here would be reachable by nothing.
ENV OVPOC_BIND=0.0.0.0

# Which code this is, as the builder declares it. See `service/build.py`
# for what that claim is and is not worth -- in short, it answers which
# code the operator meant to deploy, and nothing verifies it.
#
# Last, and deliberately. An `ARG` consumed early would put the revision
# in the cache key of every layer below it, so changing it would rebuild
# the image from that point down -- which for a value that changes on
# every commit means never reusing a layer again. Here it invalidates one.
#
# Defaulted to `unknown` rather than required, because an image built
# without it is a real thing that happens and `unknown` is the honest
# report of it. A plausible-looking wrong revision would be worse, since
# it would be believed.
ARG OVPOC_REVISION=unknown
ENV OVPOC_REVISION=$OVPOC_REVISION

CMD ["python", "-m", "service", "--data", "/data"]
