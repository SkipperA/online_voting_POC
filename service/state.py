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
from ovpoc.ballotbox import BallotBox
from ovpoc.vro import VRO

from .election import ElectionConfig

DOCUMENT_ROOT = Path("/tmp/ovpoc-config")
DEFAULT_CHOICES = 4


@dataclass
class Deployment:
    vro: VRO
    ebb: BallotBox
    config: ElectionConfig
    population: PopulationRegister
    document_root: Path = field(default=DOCUMENT_ROOT)

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
