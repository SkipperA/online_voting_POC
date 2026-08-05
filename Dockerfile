# Reproducible verification environment.
#
# The point of this image is not deployment -- nothing here is deployable. It is
# so that a reviewer of the accompanying article can reproduce the test results
# without installing anything:
#
#     docker build -t ovpoc .
#     docker run --rm ovpoc                      # 33 tests
#     docker run --rm ovpoc python demo.py       # narrated protocol run
#     docker run --rm ovpoc python tools/sabotage.py
#
# Pinned to a specific Python minor version so that "the tests passed" refers to
# a stated environment. The suite is also run on 3.14 during development.

FROM python:3.12-slim

# Do not write .pyc files or buffer output; both only obscure things in a
# throwaway container.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependency layer first, so editing tests does not reinstall cryptography.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e ".[dev]"

COPY tests ./tests
COPY tools ./tools
COPY docs ./docs
COPY demo.py CLAUDE.md ./

# Run as a non-root user. Not a security measure for a test container -- it is
# so that files this image writes (docs/sabotage.md) do not land on a mounted
# host directory owned by root.
RUN useradd --create-home --uid 1000 poc && chown -R poc:poc /app
USER poc

CMD ["python", "-m", "pytest", "-q"]
