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
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from driver.population_register import PopulationRegister
from ovpoc import keys
from ovpoc.ballotbox import BallotBox
from ovpoc.messages import unb64
from ovpoc.vro import VRO, AuditEntry, Outcome, request_from_stored

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

#: Where an operator pins the certificates this office will believe. Beside
#: the elections rather than inside one, because what the office trusts is a
#: property of the deployment and not of a poll: minting a new election must
#: not silently change whose signatures are accepted.
#: `tools/fetch_trust_anchors.py` writes it; absent, the
#: qualified-signature route is simply not offered.
TRUST_ANCHORS = "trust-anchors"
DEFAULT_ELECTION_ID = "demo-2026"
DEFAULT_CHOICES = 4
DEFAULT_BITS = 3072

# The declared schedule of a freshly minted election, in one place rather
# than two. Recorded, not enforced: the close is an act of the box (E1), so
# these are what the configuration says the poll was meant to be, which a
# reader checks the acts against.
DEFAULT_OPENS = "2026-09-25T08:00:00Z"
DEFAULT_CLOSES = "2026-09-25T20:00:00Z"


#: Clause S7. Whether a qualified signature is itself an entitlement to
#: vote, or whether this office administers a roll it was given.
#:
#: An environment variable rather than a setup-console switch, because it
#: is a property of the deployment in the same way the trust anchors are:
#: an election minted over a running one must not quietly change who may
#: ask for a token. Set it in `deploy/.env` beside `OVPOC_DOMAIN`.
OPEN_ENROLMENT = "OVPOC_OPEN_ENROLMENT"


def _open_enrolment(explicit: bool | None = None) -> bool:
    """True for `1`, `true`, `yes`, `on`; false for everything else.

    Deliberately not `bool(os.environ.get(...))`, which makes the string
    `"0"` true and would turn the clause on for an operator who wrote the
    variable down in order to turn it off.

    `explicit` wins over the environment and `None` means "ask it". A
    caller that passes the value is a caller whose behaviour does not
    depend on the shell it was started from -- which is what the tests
    need, and is the same correction `trust_anchors` needed one patch
    after it was introduced, for the same reason and by the same mistake.
    """
    import os

    if explicit is not None:
        return explicit
    return os.environ.get(OPEN_ENROLMENT, "").strip().lower() in {
        "1", "true", "yes", "on"}


def _now() -> str:
    """The moment an election was authored, to the second, in UTC.

    Deployment bookkeeping and nothing more: no protocol object carries a
    timestamp, and this one never reaches `election.json`.
    """
    from datetime import datetime, timezone

    return (datetime.now(timezone.utc)
            .isoformat(timespec="seconds").replace("+00:00", "Z"))


def _signature_validation(anchors: Path | None):
    """The validator, if this deployment has been told what to trust.

    `None` when there are no pinned anchors, and the office then offers no
    qualified-signature route at all -- which is the honest state for an
    office that has not been configured for one. It is *not* an empty
    anchor list: that would be an office which offers the route and refuses
    every request, and the two look identical to a voter and are completely
    different to an operator.

    A directory whose contents disagree with its manifest raises, and the
    deployment does not start. That is deliberate: an office that came up
    having silently trusted a swapped certificate would look like nothing
    at all.

    A pinned European trusted list wins over hand-pinned roots when both
    are there. Not merged: an office trusting the union of a list it can
    justify and a certificate somebody downloaded would be trusting the
    second invisibly, since everything it reports about its anchors would
    be about the first. The operator removes one or the other.
    """
    if anchors is None or not anchors.is_dir():
        return None
    from driver.qualified_signature import QualifiedSignatureValidation
    from driver.trusted_list import load as load_trusted_list

    pinned_list = load_trusted_list(anchors)
    return QualifiedSignatureValidation.from_pinned(
        anchors, trusted_list=pinned_list)


#: What the band says where an election identifier would be. A deployment
#: with nothing authored is a real state -- the first start of an empty
#: volume -- and the one page that works in it is a page carrying a band.
NO_ELECTION = "no election yet"


@dataclass(frozen=True)
class Banner:
    """What every page says about the election it is serving.

    One object rather than a widening list of positional arguments. The
    band takes the election positionally because a keyword with a default
    would let the next page be added without one, and `generated` would
    have made that argument list three long -- after which the fourth
    property is the one somebody forgets.
    """

    name: str
    #: Clause S8. The band says so, and `apps._page` injects the aside.
    generated: bool = False


@dataclass
class Deployment:
    #: `None` until an election is authored. A process that starts against
    #: an empty volume has no keys, no register and no configuration, and
    #: must not invent them: an election that appears because a process
    #: started is not an election. The setup console is how an operator
    #: leaves that state, and `mint` fills this object in place -- which is
    #: the same reason `mint` mutates rather than returning a new one, since
    #: every origin's application closed over it at start-up.
    #:
    #: Nothing dereferences these while they are `None`. Every origin but
    #: the console refuses with 503 before a handler runs
    #: (`apps.build_all`), and the console's own endpoints that need an
    #: election say so.
    vro: VRO | None
    ebb: BallotBox | None
    config: ElectionConfig | None
    population: PopulationRegister
    document_root: Path = field(default=DOCUMENT_ROOT)
    #: The parent holding one directory per election, if the election is
    #: durable at all.
    data_dir: Path | None = None
    #: This election's own directory under it. Allocated on the first save
    #: and never reused: minting clears it so that a new election lands
    #: beside the old one rather than on top of it.
    data_folder: Path | None = None
    #: When this election was authored, ISO 8601 in UTC. It goes to the
    #: store and never to `election.json`: a time in the pinned
    #: configuration would move the digest for a fact about the deployment
    #: rather than about the ballot, which is the argument `build.py` makes
    #: for keeping the revision out of it. `None` for an election stored
    #: before anything recorded it, and the selector prints a dash rather
    #: than the file's modification time -- that moves on every enrolment,
    #: so it would be a plausible wrong answer.
    minted_at: str | None = None
    #: Where this office looked for its anchors, kept whether or not it
    #: found any. An office that offers no qualified-signature route must
    #: be able to say which directory it read, because "not offered" and
    #: "looked in the wrong place" are the same page to an operator and
    #: entirely different problems.
    trust_anchors: Path | None = None
    #: Clause S7, held beside the anchors and for the same reason: who this
    #: office is willing to enrol is a property of the deployment, not of a
    #: poll. It lived only on the office, which was fine while there was
    #: always an office to read it from -- a deployment with no election yet
    #: has none, and the first mint still has to carry the value the process
    #: started with rather than re-reading an environment that may have
    #: moved since.
    open_enrolment: bool = False

    # Staged signing. Off by default, so every existing caller -- the demos,
    # the scripted runs, the tests -- sees `issue_token` behave as one act.
    # On, the office validates and reserves, and an operator performs the
    # signature as a deliberate act. The reservation state this relies on is
    # not a demo affordance: it is what makes the eligibility check atomic
    # under concurrency (§5.4, register item 1.5).
    manual_release: bool = False
    held_requests: dict[str, object] = field(default_factory=dict)

    #: Set while the server is filling a generated election, and left in
    #: place afterwards so the console can report how it went. Every origin
    #: but the console refuses throughout: a half-populated poll is a poll
    #: nobody should see, least of all a voter who could add a ballot to it.
    #: A *finished* report is cleared by either act that replaces the
    #: election, since it would otherwise describe a poll no longer served.
    #: A run still going is not: it spans the mint that started it, because
    #: generating an election is one act that authors it and then fills it.
    populating: object | None = None

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

    @property
    def served(self) -> bool:
        """Whether there is an election here at all."""
        return self.config is not None

    @property
    def election_name(self) -> str:
        """What the band prints. Never raises, because the band never may."""
        return NO_ELECTION if self.config is None else self.config.election_id

    @property
    def banner(self) -> Banner:
        """Everything a page says about the election, in one object."""
        return Banner(
            name=self.election_name,
            generated=self.config is not None and self.config.generated,
        )

    @classmethod
    def unfurnished(
        cls,
        document_root: Path = DOCUMENT_ROOT,
        data_dir: Path | None = None,
        trust_anchors: Path | None = DATA_DIR / TRUST_ANCHORS,
        open_enrolment: bool | None = None,
    ) -> "Deployment":
        """A deployment with no election in it.

        The honest answer to an empty data directory. The alternative this
        replaces was to refuse to start, which was correct about the
        election and wrong about the service: `deploy/README.md` said to
        mint the first election from the setup console, and the setup
        console was one of the origins that had just failed to start. On a
        hosted deployment there is no `--init` to pass, so an empty volume
        could not be brought up at all.

        It mints nothing. What it holds is the deployment's own half --
        where the elections live, which anchors this office was told to
        trust, and whether it enrols on a qualified signature -- all read
        once, here, at start-up, which is the one moment reading the
        environment is the right thing to do.
        """
        return cls(
            vro=None,
            ebb=None,
            config=None,
            population=PopulationRegister(),
            document_root=document_root,
            data_dir=data_dir,
            trust_anchors=trust_anchors,
            open_enrolment=_open_enrolment(open_enrolment),
        )

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
        # What the ballot asks and what it offers by name. Optional, and
        # the office and the box are never told either: the names reach
        # the published configuration and stop there.
        question: str | None = None,
        options: Sequence[str] | None = None,
        # Clause S8, and a parameter rather than something the generator
        # sets afterwards: an election that was briefly unlabelled is an
        # election somebody could have photographed unlabelled.
        generated: bool = False,
        bits: int = DEFAULT_BITS,
        tally_interval_seconds: int | None = None,
        opens: str = DEFAULT_OPENS,
        token_requests_open: str | None = None,
        token_requests_close: str | None = None,
        closes: str = DEFAULT_CLOSES,
        document_root: Path = DOCUMENT_ROOT,
        # Explicit, and defaulted rather than reached for. A deployment that
        # read this out of a module-level path would make the whole suite's
        # behaviour depend on whether a clone happens to carry pinned
        # anchors -- which is the same fault as a test that skips when a
        # tool is missing, arriving through configuration instead.
        trust_anchors: Path | None = DATA_DIR / TRUST_ANCHORS,
        # Explicit for the same reason, and learned the same way: with
        # the variable set in a shell, `test_a_real_signature_reaches_the
        # _office_through_the_endpoint` self-enrolled its citizen and ran
        # on past the eligibility check it exists to stop at. A suite
        # whose result depends on the environment is a suite that means
        # something different on two machines.
        open_enrolment: bool | None = None,
    ) -> "Deployment":
        population = PopulationRegister()
        vro = VRO.create(population, bits=bits, election_id=election_id)
        vro.signature_validation = _signature_validation(trust_anchors)
        vro.enrol_on_qualified_signature = _open_enrolment(open_enrolment)
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
            token_requests_open=token_requests_open,
            token_requests_close=token_requests_close,
            question=question,
            options=options,
            generated=generated,
        )
        config.write(document_root)
        return cls(
            vro=vro,
            ebb=ebb,
            config=config,
            population=population,
            document_root=document_root,
            trust_anchors=trust_anchors,
            # The office's copy and the deployment's are one value computed
            # once, just above. Two readings of the environment would be two
            # answers, which is the fault this field exists to prevent.
            open_enrolment=vro.enrol_on_qualified_signature,
            minted_at=_now(),
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

    def set_schedule(self, opens: str, closes: str,
                     token_requests_open: str | None = None,
                     token_requests_close: str | None = None) -> None:
        """A5. The declared token-request and voting periods.

        The one configuration field that can be corrected without voiding
        anything. Nothing is signed under it and no token depends on it:
        the times are recorded, not enforced, and the close is an act of
        the box (E1) which a reader checks *against* this declaration.
        The digest moves, as it must -- a configuration that changed
        without its digest changing is the thing the digest exists to
        prevent.

        All four are set together and `None` clears a request period
        rather than keeping it. The alternative -- omitted means unchanged
        -- reads better at a call site and is worse where it matters: the
        console posts a form, and a form that lost a field would silently
        withdraw a declaration the administering body had made.
        """
        self.config = replace(self.config, opens=opens, closes=closes,
                              token_requests_open=token_requests_open,
                              token_requests_close=token_requests_close)
        self.config.write(self.document_root)
        if self.data_dir is not None:
            self.save(self.data_dir)

    def mint(
        self,
        *,
        election_id: str,
        num_choices: int,
        question: str | None = None,
        options: Sequence[str] | None = None,
        generated: bool = False,
        bits: int,
        opens: str,
        closes: str,
        token_requests_open: str | None = None,
        token_requests_close: str | None = None,
        tally_interval_seconds: int | None = None,
        keep_register: bool = True,
    ) -> None:
        """A4-A7 again: author a new election over this one, or the first.

        Also the act that furnishes a deployment that had no election at
        all. Nothing in what follows distinguishes the two cases except
        that there is nothing to carry over -- which is why the first mint
        is this method and not a second one beside it.


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

        The question and the option names are not carried, and there is no
        `keep_` for them. They are what this ballot asks, so a new election
        with no names asked for is a numbered ballot and not the previous
        election's candidates under new keys -- which is the reading that
        would be available if they persisted by default.

        The object is mutated in place rather than replaced because each
        origin's application closed over it when the process started. A
        new `Deployment` would be served by nobody.
        """
        # Nothing to carry on a first mint. `keep_register` is about the
        # previous election's register, and a deployment with no election
        # has no office to take one from.
        carry = keep_register and self.vro is not None
        personas = dict(self.wallets) if carry else {}
        register = sorted(self.vro.register) if carry else []

        fresh = Deployment.create(
            election_id=election_id,
            num_choices=num_choices,
            question=question,
            options=options,
            generated=generated,
            bits=bits,
            tally_interval_seconds=tally_interval_seconds,
            opens=opens,
            closes=closes,
            token_requests_open=token_requests_open,
            token_requests_close=token_requests_close,
            document_root=self.document_root,
            # Carried, not re-derived. What this office trusts is a
            # property of the deployment and not of a poll -- the whole
            # reason the anchors sit beside the elections rather than
            # inside one -- and `create`'s default names a directory
            # relative to this repository, which on a hosted deployment is
            # not the directory the office was started with. Minting would
            # then silently turn the qualified-signature route off, or on
            # under anchors nobody chose.
            trust_anchors=self.trust_anchors,
            # Carried, not re-read, exactly as the anchors are. Who this
            # office is willing to enrol is a property of the deployment,
            # and minting an election must not change it -- least of all
            # by picking up an environment that has moved since start-up.
            # From the deployment rather than from the office, because on a
            # first mint there is no office to ask.
            open_enrolment=self.open_enrolment,
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
        self.minted_at = fresh.minted_at
        # Cleared only when it is over. A finished report describes a poll
        # that is no longer served and would be a plain lie over this one.
        # A run still in progress *spans* this mint, because generating an
        # election is one act that authors it and then fills it -- and
        # clearing a live run here would take the refusal off every other
        # origin halfway through, which is the one thing it is for.
        if getattr(self.populating, "finished", True):
            self.populating = None
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
            token_requests_open=self.config.token_requests_open,
            token_requests_close=self.config.token_requests_close,
            # From the configuration and not from the box, because the box
            # does not have them and must not: `num_choices` above comes
            # from the box precisely because that is the figure acceptance
            # turns on, and the names are the half that acceptance never
            # sees.
            question=self.config.question,
            options=self.config.options,
            generated=self.config.generated,
            # Carried rather than stamped here. `save` runs on every
            # enrolment, so a time taken at save time would be the time of
            # the last change and never the time of authorship.
            minted_at=self.minted_at,
        )
        store.point_at(path, folder)
        self.data_folder = folder
        return folder

    @classmethod
    def load(
        cls, path: Path = DATA_DIR, document_root: Path = DOCUMENT_ROOT,
        open_enrolment: bool | None = None,
    ) -> "Deployment":
        """Serve the election the pointer names, at start-up.

        The one place the policy is decided rather than carried: this is
        start-up, which is what reading the environment is for. Everything
        afterwards -- a mint, a switch -- carries what was decided here.
        Raises rather than inventing an election.
        """
        return cls._from_folder(
            store.current(path),
            data_dir=path,
            document_root=document_root,
            trust_anchors=path / TRUST_ANCHORS,
            open_enrolment=_open_enrolment(open_enrolment),
        )

    @classmethod
    def _from_folder(
        cls, folder: Path, *, data_dir: Path | None, document_root: Path,
        trust_anchors: Path | None, open_enrolment: bool,
    ) -> "Deployment":
        """One election's directory, as objects. Reads; decides nothing.

        Shared by `load` and by `switch_to`, and the split is the whole
        point of it: what this office trusts and whom it enrols belong to
        the deployment, so a switch must no more re-derive them than a mint
        does. Both arrive as parameters and neither is read here.

        A *finished* poll comes back with it, if this election has one:
        the box shut, the records and chain replayed and re-derived, the
        office's register with its openings. That is the published record
        served again, not a durable ballot box -- a poll interrupted while
        open was never written and is still lost (clause A7).
        """
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
            signature_validation=_signature_validation(trust_anchors),
            enrol_on_qualified_signature=open_enrolment,
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
            token_requests_open=body["token_requests_open"],
            token_requests_close=body["token_requests_close"],
            question=body["question"],
            options=body["options"],
            generated=body["generated"],
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
                # `request_from_stored` and not a tuple unpack: a signed
                # request is one of two shapes now, and the office is the
                # only thing that gets to know which.
                self_enrolled=saved["office"].get("self_enrolled", []),
                requests={k: request_from_stored(v)
                          for k, v in saved["office"]["requests"].items()},
                supervisor_downloads=saved["office"]["supervisor_downloads"],
                expected_head=unb64(saved["office"]["head"]),
            )

        return cls(
            data_dir=data_dir,
            data_folder=folder,
            vro=vro,
            ebb=ebb,
            config=config,
            population=population,
            document_root=document_root,
            wallets=wallets,
            trust_anchors=trust_anchors,
            open_enrolment=open_enrolment,
            minted_at=body["minted_at"],
        )

    def switch_to(self, folder: Path) -> None:
        """Serve a different election that is already on disk.

        The same problem as `mint` and therefore the same answer: this
        object is what every origin's application closed over at start-up,
        so it is filled in place rather than replaced. A new `Deployment`
        would be served by nobody, and a restart is not available to a
        container that cannot restart itself.

        **Every field moves or is deliberately left.** The ones `mint`
        clears are cleared here for the same reasons -- a held request and
        an uncollected reply both name a key this election never certified
        -- and the ones `mint` carries are carried, because the anchors and
        the enrolment policy belong to the deployment and not to a poll.
        `data_folder` is the one that differs: `mint` clears it so the next
        save allocates a new directory, and a switch sets it to the
        directory it just read, or the first enrolment afterwards would
        write this election's register into a freshly allocated folder.
        `test_switching_and_minting_account_for_every_field` reads both
        methods and is what keeps the next field from being forgotten.

        The pointer moves too, so a restart serves the same election --
        which is what `--election` already does before it starts.

        This voids every page anybody has open: different keys, a different
        `election.json`, a different digest. `config-watch.js` tells every
        reader to reload and is right to. Nothing here is a protocol
        decision, and the rule about *when* an operator may do it lives on
        the console, where an operator can read it.
        """
        fresh = Deployment._from_folder(
            folder,
            data_dir=self.data_dir,
            document_root=self.document_root,
            trust_anchors=self.trust_anchors,
            open_enrolment=self.open_enrolment,
        )
        self.vro = fresh.vro
        self.ebb = fresh.ebb
        self.config = fresh.config
        self.population = fresh.population
        self.wallets = fresh.wallets
        self.minted_at = fresh.minted_at
        self.populating = None
        self.held_requests = {}
        self.token_replies = {}
        self.data_folder = folder
        if self.data_dir is not None:
            store.point_at(self.data_dir, folder)
