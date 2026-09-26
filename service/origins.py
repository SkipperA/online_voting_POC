"""The seven origins of stage 1, in one table.

Separate ports rather than paths, because a browser origin is scheme, host
*and* port.  Paths under one origin would share a JavaScript context, a CSP
and a fetch policy, and the isolation the design claims would be a diagram
rather than a fact.  See `docs/Stage1_Surface_and_Boundary_Map.md` §1.

Five of the seven are trust domains.  `config` is inert and `setup` is
build-time -- the poll must run with 8009 stopped, which is a test rather
than an intention.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

HOST = "127.0.0.1"

# Added to every port. Lets a test deployment run beside a development one
# instead of fighting it for 8000-8009, without any origin learning that it
# has moved: everything derives its neighbours' addresses from this table.
OFFSET = int(os.environ.get("OVPOC_PORT_OFFSET", "0"))


@dataclass(frozen=True)
class Origin:
    name: str
    base_port: int
    trust_domain: bool
    serves: str

    @property
    def port(self) -> int:
        return self.base_port + OFFSET

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}"


CONFIG = Origin("config", 8000, False, "election.json and its digest, as static files")
VOTER_APP = Origin("voter-app", 8001, True, "the voting client; never reads id")
WALLET = Origin("wallet", 8002, True, "consent page and signing daemon")
VRO = Origin("vro", 8003, True, "token endpoints, release query, back office")
EBB = Origin("ebb", 8004, True, "submission, receipts, published view")
CHECKER = Origin("checker", 8005, True, "the three independent checks of §3.7")
SETUP = Origin("setup", 8009, False, "build-time authoring of election.json")

ALL = (CONFIG, VOTER_APP, WALLET, VRO, EBB, CHECKER, SETUP)
RUNTIME = tuple(o for o in ALL if o is not SETUP)
TRUST_DOMAINS = tuple(o for o in ALL if o.trust_domain)

BY_NAME = {o.name: o for o in ALL}
