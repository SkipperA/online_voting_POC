"""The objects the process holds, created once at startup.

Stage 1 is one process, so this is where the VRO, the ballot box and the
configuration live.  Stage 2 splits the process; at that point each of these
moves behind its own service and this module disappears rather than growing.

Nothing here makes a protocol decision.  It constructs `ovpoc` objects and
hands them to the origins that own them -- which is the whole of what the
service layer is allowed to do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from driver.population_register import PopulationRegister
from ovpoc import keys
from ovpoc.ballotbox import BallotBox
from ovpoc.vro import VRO

from .election import ElectionConfig
from . import store

DOCUMENT_ROOT = Path("/tmp/ovpoc-config")
DATA_DIR = Path("election-data")
DEFAULT_CHOICES = 4


@dataclass
class Deployment:
    vro: VRO
    ebb: BallotBox
    config: ElectionConfig
    population: PopulationRegister
    document_root: Path = field(default=DOCUMENT_ROOT)
    data_dir: Path | None = None       # where the durable half lives, if anywhere

    # Staged signing. Off by default, so every existing caller -- the demos,
    # the scripted runs, the tests -- sees `issue_token` behave as one act.
    # On, the office validates and reserves, and an operator performs the
    # signature as a deliberate act. The reservation state this relies on is
    # not a demo affordance: it is what makes the eligibility check atomic
    # under concurrency (§5.4, register item 1.5).
    manual_release: bool = False
    held_requests: dict[str, object] = field(default_factory=dict)

    # Wallet personas. A real wallet holds one citizen's key in hardware it
    # never leaves; this holds several in memory so one machine can play a
    # whole electorate. Clause A3 in `docs/Demo_Scope_Limits.md` -- the
    # substitution is the wallet, not the boundary, which still holds: the
    # voter application below never reads any of these, nor the ids.
    wallets: dict[str, keys.SigningKeyPair] = field(default_factory=dict)

    # B16. The office holds the reply until the application collects it by
    # presenting `c`. Keyed by the blinded value, which the application
    # generated and which is unguessable, so no other credential is needed
    # and none is invented. Action table gap 5.
    token_replies: dict[bytes, bytes] = field(default_factory=dict)

    def enrol(self, voter_id: str) -> bytes:
        """Build-time only: create a persona and put it on both registers.

        Two registers held by different parties, as the article insists: the
        population register binds a key to a named person and is external
        (§3.2), the electoral register is a set of ids and nothing else.
        """
        wallet = keys.SigningKeyPair.generate()
        self.wallets[voter_id] = wallet
        self.population.enrol(voter_id, wallet.public_bytes)
        self.vro.enrol(voter_id)
        if self.data_dir is not None:
            # Enrolment is Phase A, so it belongs to the durable half. An
            # electorate that vanished on restart would send everyone back
            # to curl, which is how this demo has been used so far.
            self.save(self.data_dir)
        return wallet.public_bytes

    @classmethod
    def create(
        cls,
        election_id: str = "demo-2026",
        num_choices: int = DEFAULT_CHOICES,
        bits: int = 3072,
        document_root: Path = DOCUMENT_ROOT,
    ) -> "Deployment":
        population = PopulationRegister()
        vro = VRO.create(population, bits=bits)
        config = ElectionConfig.build(
            election_id=election_id,
            token_key=vro.public_key,
            statement_key=vro.office_public_key,
            num_choices=num_choices,
            opens="2026-09-25T08:00:00Z",
            closes="2026-09-25T20:00:00Z",
        )
        ebb = BallotBox(vro_public_key=vro.public_key, num_choices=num_choices)
        config.write(document_root)
        return cls(
            vro=vro,
            ebb=ebb,
            config=config,
            population=population,
            document_root=document_root,
        )

    # -- persistence -------------------------------------------------------

    def save(self, path: Path = DATA_DIR) -> Path:
        """Write the durable half. The setup console's act, not the runtime's."""
        store.write(
            path,
            token_private=self.vro.private_key,
            statement_key=self.vro.office_key,
            register=self.vro.register,
            personas=self.wallets,
            election_id=self.config.election_id,
            num_choices=self.ebb.num_choices,
        )
        return path

    @classmethod
    def load(
        cls, path: Path = DATA_DIR, document_root: Path = DOCUMENT_ROOT
    ) -> "Deployment":
        """Restore an election. Raises rather than inventing one.

        The ballot box and the released-token register are *not* restored:
        they are what the poll produced, not what the console authored, and
        the demo says so rather than implying durability it does not have.
        """
        body = store.read(path)
        population = PopulationRegister()
        vro = VRO(
            private_key=body["token_private"],
            public_key=body["token_public"],
            population_register=population,
            office_key=body["statement_key"],
            register=set(body["electoral_register"]),
        )
        wallets = body["wallet_personas"]
        for voter_id, pair in wallets.items():
            population.enrol(voter_id, pair.public_bytes)

        config = ElectionConfig.build(
            election_id=body["election_id"],
            token_key=vro.public_key,
            statement_key=vro.office_public_key,
            num_choices=body["num_choices"],
            opens="2026-09-25T08:00:00Z",
            closes="2026-09-25T20:00:00Z",
        )
        config.write(document_root)
        return cls(
            data_dir=path,
            vro=vro,
            ebb=BallotBox(vro_public_key=vro.public_key,
                          num_choices=body["num_choices"]),
            config=config,
            population=population,
            document_root=document_root,
            wallets=wallets,
        )
