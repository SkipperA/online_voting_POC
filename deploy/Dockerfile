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

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e "." && pip install --no-cache-dir uvicorn fastapi

COPY service ./service
COPY driver ./driver
COPY web ./web
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

CMD ["python", "-m", "service", "--data", "/data"]
