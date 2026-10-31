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
    if deployment.served:
        print(f"election  {deployment.config.election_id}")
        print(f"k_p^(R)   {deployment.config.token_key_fingerprint}")
        print(f"config    sha256 {deployment.config.digest_hex()}")
        if deployment.data_folder is not None:
            print(f"data      {deployment.data_folder}")
    else:
        # The banner is where an operator looks first, so it says the state
        # rather than printing an empty identifier and letting them find out
        # from a 503 on some other origin.
        print(f"election  none yet -- mint the first at {origins.SETUP.url}")
        print(f"data      {deployment.data_dir}")
        print("          every other origin refuses until one exists")
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
                        help="where the elections live, one directory each "
                             "(default: election-data)")
    parser.add_argument("--election", default=None, metavar="NAME",
                        help="serve this directory under --data instead of the "
                             "one `current` names; a past election can be "
                             "served again this way")
    parser.add_argument("--init", action="store_true",
                        help="mint a new election beside the others and serve it")
    parser.add_argument("--ephemeral", action="store_true",
                        help="mint an election that is not written anywhere")
    args = parser.parse_args()

    unknown = set(args.without) - set(origins.BY_NAME)
    if unknown:
        parser.error(f"unknown origin(s): {', '.join(sorted(unknown))}")

    names = {o.name for o in origins.ALL} - set(args.without)
    from pathlib import Path

    from . import store
    from .state import DATA_DIR
    from .store import NoElection, NoElectionYet

    data = Path(args.data) if args.data else DATA_DIR
    kwargs = {"bits": args.bits, "tally_interval_seconds": args.tally_interval}
    if args.choices is not None:
        kwargs["num_choices"] = args.choices

    if args.election:
        # Pointing at a past election is the read-only half of keeping them:
        # its configuration is republished at load, so a ledger downloaded
        # from it can be checked against the keys it was published under.
        if args.init or args.ephemeral:
            parser.error("--election selects an existing election; --init and "
                         "--ephemeral create one")
        chosen = data / args.election
        if not (chosen / "election.store.json").exists():
            held = sorted(d.name for d in data.iterdir() if d.is_dir()) \
                if data.exists() else []
            parser.error(f"{chosen} holds no election. Under {data}: "
                         f"{', '.join(held) or 'nothing'}")
        store.point_at(data, chosen)

    if args.ephemeral:
        # Used by the tests, which want a fresh election per run and write
        # nothing. Not the default, because a restart that silently invents a
        # new election voids every open page and every issued token.
        deployment = Deployment.create(**kwargs)
    elif args.init:
        deployment = Deployment.create(**kwargs)
        deployment.data_dir = data
        folder = deployment.save(data)
        print(f"minted a new election in {folder}")
    else:
        try:
            deployment = Deployment.load(data)
        except NoElectionYet:
            # An empty data directory is a first start, not a failure. The
            # service comes up with the setup console serving and every
            # other origin refusing, which is the only arrangement in which
            # `deploy/README.md`'s "mint the first from the setup console"
            # is a thing an operator can actually do: there is no `--init`
            # to pass to a container, and the console was one of the origins
            # that used to fail to start.
            deployment = Deployment.unfurnished(data_dir=data)
        except NoElection as exc:
            # A pointer naming a directory that holds no election is an
            # operator's mistake, and stays fatal. Treating it as a first
            # start would serve an empty deployment on top of an election
            # still sitting on the disk.
            parser.error(str(exc))
    try:
        asyncio.run(serve(names, deployment))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
