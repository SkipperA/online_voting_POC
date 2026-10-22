"""The objects the process holds, created once at startup.

Stage 1 is one process, so this is where the VRO, the ballot box and the
configuration live.  Stage 2 splits the process; at that point each of these
moves behind its own service and this module disappears rather than growing.

Nothing here makes a protocol decision.  It constructs `ovpoc` objects and
hands them to the origins that own them -- which is the whole of what the
service layer is allowed to do.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from driver.population_register import PopulationRegister
from ovpoc import keys
from ovpoc.ballotbox import BallotBox
from ovpoc.messages import unb64
from ovpoc.vro import VRO, AuditEntry, Outcome

from .election import ElectionConfig
from . import origins, store

# One config root per deployment, keyed by the same offset that gives it its
# ports. The offset exists so a test deployment can run beside a development
# one; sharing a document root means the second one's startup overwrites the
# first one's published configuration. That was survivable while the config
# origin snapshotted its bytes at startup and merely wrong afterwards, since
# the origin now reads the file per request -- which it must, or an election
# minted from the setup console would never reach a page.
_SUFFIX = f"-{origins.OFFSET}" if origins.OFFSET else ""
DOCUMENT_ROOT = Path(f"/tmp/ovpoc-config{_SUFFIX}")
DATA_DIR = Path("election-data")
DEFAULT_ELECTION_ID = "demo-2026"
DEFAULT_CHOICES = 4
DEFAULT_BITS = 3072

# The declared schedule of a freshly minted election, in one place rather
# than two. Recorded, not enforced: the close is an act of the box (E1), so
# these are what the configuration says the poll was meant to be, which a
# reader checks the acts against.
DEFAULT_OPENS = "2026-09-25T08:00:00Z"
DEFAULT_CLOSES = "2026-09-25T20:00:00Z"


@dataclass
class Deployment:
    vro: VRO
    ebb: BallotBox
    config: ElectionConfig
    population: PopulationRegister
    document_root: Path = field(default=DOCUMENT_ROOT)
    #: The parent holding one directory per election, if the election is
    #: durable at all.
    data_dir: Path | None = None
    #: This election's own directory under it. Allocated on the first save
    #: and never reused: minting clears it so that a new election lands
    #: beside the old one rather than on top of it.
    data_folder: Path | None = None

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
    # whole electorate. Clause S1 in `docs/Demo_Scope_Limits.md` -- the
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
        election_id: str = DEFAULT_ELECTION_ID,
        num_choices: int = DEFAULT_CHOICES,
        bits: int = DEFAULT_BITS,
        tally_interval_seconds: int | None = None,
        opens: str = DEFAULT_OPENS,
        closes: str = DEFAULT_CLOSES,
        document_root: Path = DOCUMENT_ROOT,
    ) -> "Deployment":
        population = PopulationRegister()
        vro = VRO.create(population, bits=bits, election_id=election_id)
        ebb = BallotBox(vro_public_key=vro.public_key, num_choices=num_choices,
                        tally_interval_seconds=tally_interval_seconds,
                        election_id=election_id)
        config = ElectionConfig.build(
            election_id=election_id,
            token_key=vro.public_key,
            statement_key=vro.office_public_key,
            box_statement_key=ebb.statement_key.public_bytes,
            num_choices=num_choices,
            tally_interval_seconds=tally_interval_seconds,
            opens=opens,
            closes=closes,
        )
        config.write(document_root)
        return cls(
            vro=vro,
            ebb=ebb,
            config=config,
            population=population,
            document_root=document_root,
        )

    def set_tally_interval(self, seconds: int | None) -> None:
        """A5. Fix the publication cadence, and republish the configuration.

        Three things have to move together or the pinned digest stops
        describing the election: the published configuration, the box that
        obeys the cadence, and the durable store.
        """
        self.ebb.set_publication_interval(seconds)
        self.config = replace(self.config, tally_interval_seconds=seconds)
        self.config.write(self.document_root)
        if self.data_dir is not None:
            self.save(self.data_dir)

    def set_schedule(self, opens: str, closes: str) -> None:
        """A5. The declared opening and closing times.

        The one configuration field that can be corrected without voiding
        anything. Nothing is signed under it and no token depends on it:
        the times are recorded, not enforced, and the close is an act of
        the box (E1) which a reader checks *against* this declaration.
        The digest moves, as it must -- a configuration that changed
        without its digest changing is the thing the digest exists to
        prevent.
        """
        self.config = replace(self.config, opens=opens, closes=closes)
        self.config.write(self.document_root)
        if self.data_dir is not None:
            self.save(self.data_dir)

    def mint(
        self,
        *,
        election_id: str,
        num_choices: int,
        bits: int,
        opens: str,
        closes: str,
        tally_interval_seconds: int | None = None,
        keep_register: bool = True,
    ) -> None:
        """A4-A7 again: author a new election over this one.

        Every key pair is new -- the office's token key, the office's
        statement key, the box's statement key -- so every token already
        issued stops verifying, every receipt already given stops being
        evidence of anything, and the fingerprint a voter pinned is no
        longer the fingerprint of the election they pinned it for. That is
        not damage to be mitigated: it is what a different election *is*,
        and it is why this belongs to an origin the poll runs without
        rather than to any surface that stays up.

        What is not reset is the electoral register, unless asked. The
        register is Phase A material authored outside the system (3.2) and
        its entries name citizens, not keys; carrying it over is the
        demo's convenience and discards nothing the new keys would have
        protected.

        The object is mutated in place rather than replaced because each
        origin's application closed over it when the process started. A
        new `Deployment` would be served by nobody.
        """
        personas = dict(self.wallets) if keep_register else {}
        register = sorted(self.vro.register) if keep_register else []

        fresh = Deployment.create(
            election_id=election_id,
            num_choices=num_choices,
            bits=bits,
            tally_interval_seconds=tally_interval_seconds,
            opens=opens,
            closes=closes,
            document_root=self.document_root,
        )
        for voter_id, wallet in personas.items():
            fresh.wallets[voter_id] = wallet
            fresh.population.enrol(voter_id, wallet.public_bytes)
        for voter_id in register:
            fresh.vro.enrol(voter_id)

        self.vro = fresh.vro
        self.ebb = fresh.ebb
        self.config = fresh.config
        self.population = fresh.population
        self.wallets = fresh.wallets
        # Nothing the old poll was in the middle of survives into the new
        # one: a held request and an uncollected reply both name a key that
        # no longer certifies anything.
        self.held_requests = {}
        self.token_replies = {}
        # A different election gets a different directory. Clearing this is
        # the whole of the protection: the superseded election's token key
        # and register stay on disk, so a ledger downloaded from it can
        # still be checked, and `--election` can serve it again.
        self.data_folder = None
        if self.data_dir is not None:
            self.save(self.data_dir)

    # -- persistence -------------------------------------------------------

    def save(self, path: Path = DATA_DIR) -> Path:
        """Write the durable half. The setup console's act, not the runtime's.

        `path` is the parent. This election goes in its own directory under
        it, and the pointer beside them says which one the service serves.
        An election already on disk is written back where it was found.
        """
        folder = self.data_folder or store.allocate(path, self.config.election_id)
        store.write(
            folder,
            token_private=self.vro.private_key,
            statement_key=self.vro.office_key,
            box_statement_key=self.ebb.statement_key,
            register=self.vro.register,
            personas=self.wallets,
            election_id=self.config.election_id,
            num_choices=self.ebb.num_choices,
            tally_interval_seconds=self.ebb.tally_interval_seconds,
            opens=self.config.opens,
            closes=self.config.closes,
        )
        store.point_at(path, folder)
        self.data_folder = folder
        return folder

    @classmethod
    def load(
        cls, path: Path = DATA_DIR, document_root: Path = DOCUMENT_ROOT
    ) -> "Deployment":
        """Restore an election. Raises rather than inventing one.

        A *finished* poll comes back with it, if this election has one:
        the box shut, the records and chain replayed and re-derived, the
        office's register with its openings. That is the published record
        served again, not a durable ballot box -- a poll interrupted while
        open was never written and is still lost (clause A7).
        """
        folder = store.current(path)
        body = store.read(folder)
        poll = folder / "poll.state.json"
        population = PopulationRegister()
        vro = VRO(
            private_key=body["token_private"],
            public_key=body["token_public"],
            population_register=population,
            office_key=body["statement_key"],
            election_id=body["election_id"],
            register=set(body["electoral_register"]),
        )
        wallets = body["wallet_personas"]
        for voter_id, pair in wallets.items():
            population.enrol(voter_id, pair.public_bytes)

        # A store written before the box had a statement key carries none, so
        # a fresh one is generated. The election is the same election; what
        # changes is the key under which the box signs from now on, and since
        # neither the registry nor the receipts survived the restart either
        # (see above), there is nothing outstanding for the old key to have
        # signed.
        box_statement_key = body["box_statement_key"] or keys.SigningKeyPair.generate()
        ebb = BallotBox(vro_public_key=vro.public_key,
                        num_choices=body["num_choices"],
                        tally_interval_seconds=body["tally_interval_seconds"],
                        statement_key=box_statement_key,
                        election_id=body["election_id"])
        config = ElectionConfig.build(
            election_id=body["election_id"],
            token_key=vro.public_key,
            statement_key=vro.office_public_key,
            box_statement_key=box_statement_key.public_bytes,
            num_choices=body["num_choices"],
            tally_interval_seconds=body["tally_interval_seconds"],
            opens=body["opens"],
            closes=body["closes"],
        )
        config.write(document_root)
        if poll.exists():
            saved = json.loads(poll.read_text(encoding="utf-8"))
            ebb = BallotBox.restore(
                vro_public_key=vro.public_key,
                num_choices=body["num_choices"],
                election_id=body["election_id"],
                statement_key=box_statement_key,
                tally_interval_seconds=body["tally_interval_seconds"],
                accepted=saved["box"]["accepted"],
                rejected=saved["box"]["rejected"],
                acts=[(a["phase"], a["at"], unb64(a["signature"]))
                      for a in saved["box"]["acts"]],
                snapshots=saved["box"]["snapshots"],
                expected_heads={k: unb64(v)
                                for k, v in saved["box"]["heads"].items()},
            )
            vro.restore_releases(
                releases=saved["office"]["releases"],
                released=set(saved["office"]["released"]),
                openings={k: unb64(v)
                          for k, v in saved["office"]["openings"].items()},
                audit=[AuditEntry(voter_id=a["voter_id"],
                                  outcome=Outcome(a["outcome"]),
                                  reason=a["reason"])
                       for a in saved["office"]["audit"]],
                requests={k: (unb64(c), unb64(sig))
                          for k, (c, sig) in saved["office"]["requests"].items()},
                supervisor_downloads=saved["office"]["supervisor_downloads"],
                expected_head=unb64(saved["office"]["head"]),
            )

        return cls(
            data_dir=path,
            data_folder=folder,
            vro=vro,
            ebb=ebb,
            config=config,
            population=population,
            document_root=document_root,
            wallets=wallets,
        )
