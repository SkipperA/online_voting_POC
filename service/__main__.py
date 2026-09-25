"""Run every origin in one process, each on its own port.

One process, seven ports, seven genuine browser origins.  Stage 2 splits the
process rather than redesigning the boundaries, which is the reason the HTTP
layer goes in from the first commit instead of being added once the UI needs
it.

    python -m service                  # every origin
    python -m service --without setup  # the poll must run with 8009 stopped
"""

from __future__ import annotations

import argparse
import asyncio

import uvicorn

from . import origins
from .apps import build_all
from .state import Deployment


async def serve(names: set[str], deployment: Deployment) -> None:
    apps = build_all(deployment)
    servers = [
        uvicorn.Server(
            uvicorn.Config(
                app,
                host=origins.HOST,
                port=origin.port,
                log_level="warning",
                access_log=False,
            )
        )
        for origin, app in apps.items()
        if origin.name in names
    ]
    print(f"election  {deployment.config.election_id}")
    print(f"k_p^(R)   {deployment.config.token_key_fingerprint}")
    print(f"config    sha256 {deployment.config.digest_hex()}")
    for origin in origins.ALL:
        if origin.name in names:
            print(f"  {origin.url}  {origin.name:<10} {origin.serves}")
    await asyncio.gather(*(s.serve() for s in servers))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without", nargs="*", default=[], metavar="ORIGIN",
                        help="origins not to start, by name")
    parser.add_argument("--bits", type=int, default=3072,
                        help="VRO token key size")
    args = parser.parse_args()

    unknown = set(args.without) - set(origins.BY_NAME)
    if unknown:
        parser.error(f"unknown origin(s): {', '.join(sorted(unknown))}")

    names = {o.name for o in origins.ALL} - set(args.without)
    deployment = Deployment.create(bits=args.bits)
    try:
        asyncio.run(serve(names, deployment))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
