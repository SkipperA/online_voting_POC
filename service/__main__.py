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
    parser.add_argument("--choices", type=int, default=None,
                        help="number of options on the ballot")
    parser.add_argument("--tally-interval", type=int, default=None, metavar="SECONDS",
                        help="publication cadence; omit for close-only")
    parser.add_argument("--data", default=None, metavar="DIR",
                        help="the election's durable half (default: election-data)")
    parser.add_argument("--init", action="store_true",
                        help="mint a new election into --data and serve it")
    parser.add_argument("--ephemeral", action="store_true",
                        help="mint an election that is not written anywhere")
    args = parser.parse_args()

    unknown = set(args.without) - set(origins.BY_NAME)
    if unknown:
        parser.error(f"unknown origin(s): {', '.join(sorted(unknown))}")

    names = {o.name for o in origins.ALL} - set(args.without)
    from pathlib import Path

    from .state import DATA_DIR
    from .store import NoElection

    data = Path(args.data) if args.data else DATA_DIR
    kwargs = {"bits": args.bits, "tally_interval_seconds": args.tally_interval}
    if args.choices is not None:
        kwargs["num_choices"] = args.choices

    if args.ephemeral:
        # Used by the tests, which want a fresh election per run and write
        # nothing. Not the default, because a restart that silently invents a
        # new election voids every open page and every issued token.
        deployment = Deployment.create(**kwargs)
    elif args.init:
        if (data / "election.store.json").exists():
            parser.error(
                f"{data} already holds an election. Delete it deliberately, or "
                f"point --data elsewhere. Overwriting would void every token "
                f"already issued under the old key."
            )
        deployment = Deployment.create(**kwargs)
        deployment.data_dir = data
        deployment.save(data)
        print(f"minted a new election in {data}")
    else:
        try:
            deployment = Deployment.load(data)
        except NoElection as exc:
            parser.error(str(exc))
    try:
        asyncio.run(serve(names, deployment))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
