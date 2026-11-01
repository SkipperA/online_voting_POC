"""A whole election, generated, with every signature the protocol's own.

The point of generating one is that nothing in it is synthesised. Each
citizen gets an ad-hoc key pair, blinds it, has the stand-in wallet sign the
request, receives the office's blind signature through the same `_claim` and
`release` every other token goes through, unblinds it, signs a ballot under
the ad-hoc key and submits it to the box. The chain, the commitments and the
signatures are the ones the protocol produces, so the checker verifies every
ballot, the chain reaches the published head and the count audit balances.

**Which is exactly why the label matters.** Nothing downstream can tell a
generated election from a real one, because by construction there is nothing
to tell. What is synthetic is the *electorate* and their *preferences* --
no human chose any of these selections -- and that fact exists nowhere in
the data. Clause S8 carries it, and `election.json` carries the flag the
surfaces read, inside the digest every client pins.

**Two independent orders, and that is the whole integrity of the dataset.**
Every token is issued before any ballot is cast, and the casting order is
drawn separately from the issuance order. If the generator ran voter by
voter, index *i* of the release register would be index *i* of the ledger
and anyone holding both could read the answer off two columns with no
cryptography involved at all. In a real poll the two decorrelate because
citizens decide for themselves when to ask and when to cast -- the
qualified-signature route lets them use a different network and a different
device to do the asking -- and a deployment can go further with a random
delay before casting or a queue at the box. None of that is implemented
here; what is implemented is the shape it produces, because a dataset that
leaked position would be testing the generator rather than the blinding.

The shuffles come from `secrets.SystemRandom`. A Mersenne Twister seeded
from the clock is recoverable from its own output, and in a published
challenge the shuffle *is* the answer.

**Only the wallet route.** The qualified-signature route needs a real
certificate and a real signature made in a real wallet, so nobody can
generate a thousand of those. A generated election therefore demonstrates
the protocol at scale and the second route not at all, which is clause S1
applying to every ballot in it.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path

from ovpoc import keys, rsabssa
from ovpoc.messages import b64
from ovpoc.voter import Voter

#: Where the true citizen-to-ballot mapping is written: beside the elections
#: and never inside one. The selector lists election directories and no
#: origin serves this, which is the point -- a challenge whose answer sits
#: in the directory being published is not a challenge.
ANSWER_KEYS = "answer-keys"

#: Obviously invented, and deliberately so. Realism does not improve the
#: challenge -- the question is whether the cryptographic record links a
#: commitment to a ballot, and the shape of an identifier is no part of
#: that -- while a plausible-looking identifier in a public dataset is a
#: liability whether or not it collides with a real one.
PREFIX = "GEN"

#: A handful carry characters outside ASCII on purpose. The canonical-JSON
#: agreement the whole wire contract rests on is pinned by four fixtures in
#: `tests/vectors/`; an election of a few thousand exercises it at scale,
#: which is where a serialisation difference would otherwise first be met
#: by somebody's signature failing to verify.
AWKWARD = ("Ő", "ű", "日本語", "𝔄", "Ágnes")


def identifiers(count: int) -> list[str]:
    """`GEN-000001` and so on, a few of them carrying an accent."""
    out = []
    for i in range(1, count + 1):
        name = f"{PREFIX}-{i:06d}"
        if i <= len(AWKWARD):
            name = f"{name}-{AWKWARD[i - 1]}"
        out.append(name)
    return out


@dataclass
class Distribution:
    """What the finished poll is to look like.

    The counts describe the *final* accepted ballot of each citizen, which
    is what a tally counts. A re-voter's earlier ballot is an extra draw
    from the same distribution and is superseded, so it changes no count --
    it is there because supersession is the design's answer to coercion,
    and a ledger whose submissions outnumber its accepted ballots
    demonstrates that where a sentence only asserts it.
    """

    #: selection in 1..num_choices -> how many citizens end there
    per_option: dict[int, int]
    #: out-of-range selection -> how many. Never named and never
    #: interpreted: a protest ballot is a message to the public, and a
    #: generator that assigned meanings to codes would be the system
    #: registering what somebody meant by one.
    protest: dict[int, int] = field(default_factory=dict)
    #: Citizens who take a token and cast nothing. Realistic, and the case
    #: §3.7 cares most about: absence from the release register is
    #: conclusive, presence is not. They also stop the two registers being
    #: the same length, which is half of why they are here.
    abstentions: int = 0
    #: How many of the casting citizens cast twice.
    revotes: int = 0

    @property
    def casting(self) -> int:
        return sum(self.per_option.values()) + sum(self.protest.values())

    @property
    def citizens(self) -> int:
        return self.casting + self.abstentions

    @property
    def submissions(self) -> int:
        return self.casting + self.revotes

    def selections(self) -> list[int]:
        """One entry per casting citizen, in no particular order yet."""
        out: list[int] = []
        for selection, count in sorted(self.per_option.items()):
            out.extend([selection] * count)
        for selection, count in sorted(self.protest.items()):
            out.extend([selection] * count)
        return out

    def check(self, num_choices: int) -> None:
        """Refuse a plan the ballot cannot carry. Shape only."""
        for selection in self.per_option:
            if not 1 <= selection <= num_choices:
                raise ValueError(
                    f"option {selection} is outside 1..{num_choices}; an "
                    f"out-of-range selection is a protest ballot and belongs "
                    f"in the other list")
        for selection in self.protest:
            if 1 <= selection <= num_choices:
                raise ValueError(
                    f"{selection} is a valid option, not a protest selection")
        if any(count < 0 for count in
               (*self.per_option.values(), *self.protest.values())):
            raise ValueError("a count cannot be negative")
        if self.abstentions < 0 or self.revotes < 0:
            raise ValueError("a count cannot be negative")
        if self.casting < 1:
            raise ValueError("an election with no ballots in it demonstrates nothing")
        if self.revotes > self.casting:
            raise ValueError(
                f"{self.revotes} re-voters among {self.casting} who cast at all")


@dataclass
class Progress:
    """What an operator watches while it runs, and reads when it stops.

    A generated election of a few thousand is minutes of blind signing, and
    an operator who started it needs to know it is still going. Every other
    origin refuses throughout, so there is nothing else to be told.
    """

    election_id: str
    total: int
    done: int = 0
    phase: str = "starting"
    finished: bool = False
    error: str | None = None
    answer_key: str | None = None

    def as_dict(self) -> dict:
        return {
            "election_id": self.election_id,
            "phase": self.phase,
            "done": self.done,
            "total": self.total,
            "finished": self.finished,
            "error": self.error,
            # The path, so an operator can find the file. Its *contents*
            # are never served by anything.
            "answer_key": self.answer_key,
        }


def _enrol_quietly(deployment, voter_ids: list[str]) -> None:
    """The whole electorate, then one save.

    Not `Deployment.enrol`, which writes the store on every citizen: that
    is right for an operator typing names into a console and quadratic for
    a thousand of them, since each write serialises every wallet seed
    already there.
    """
    for voter_id in voter_ids:
        wallet = keys.SigningKeyPair.generate()
        deployment.wallets[voter_id] = wallet
        deployment.population.enrol(voter_id, wallet.public_bytes)
        deployment.vro.enrol(voter_id)
    if deployment.data_dir is not None:
        deployment.save(deployment.data_dir)


def _write_answer_key(deployment, mapping: dict[str, str]) -> Path:
    """The true citizen-to-key mapping, outside every election directory.

    Published nowhere and served by nothing. What *is* published, before
    the challenge opens, is this file's SHA-256 -- so a submitted solution
    can be checked against an answer nobody could have moved afterwards.
    That is this project's own idiom: commit first, disclose on demand.
    """
    folder = deployment.data_dir / ANSWER_KEYS
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "README.md").write_text(
        "# answer keys\n\n"
        "The true mapping from citizen to ad-hoc key for each generated\n"
        "election, one file per election directory.\n\n"
        "**Not part of any election and served by nothing.** These files sit\n"
        "beside the elections rather than inside one so that publishing an\n"
        "election cannot publish its answer. What is published is each\n"
        "file's SHA-256, before the challenge opens.\n",
        encoding="utf-8")
    path = folder / f"{deployment.data_folder.name}.json"
    import json

    path.write_text(
        json.dumps({
            "election_id": deployment.config.election_id,
            "configuration_digest": deployment.config.digest_hex(),
            "note": (
                "The answer to the challenge. Citizen identifier to the "
                "ad-hoc public key that carries their ballot in the ledger. "
                "Published nowhere; its SHA-256 is."),
            "citizen_to_adhoc_key": mapping,
        }, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8")
    return path


def populate(deployment, distribution: Distribution,
             progress: Progress | None = None) -> Path:
    """Fill the served election, then close it. Returns the answer key's path.

    The election must already have been minted -- this does not author one.
    It opens the box, issues every token, casts every ballot, closes the box
    and writes the record, which is one act from the console's side because
    a generated election that could still be voted in would be an election
    nobody could describe afterwards.
    """
    distribution.check(deployment.ebb.num_choices)
    draw = secrets.SystemRandom()
    progress = progress or Progress(deployment.config.election_id,
                                    total=distribution.submissions)

    citizens = identifiers(distribution.citizens)
    progress.phase = "enrolling"
    _enrol_quietly(deployment, citizens)

    deployment.ebb.open()

    # Phase one: every token, in an order of its own. The office learns
    # who asked and when relative to the others, and that order is what
    # the release register publishes.
    progress.phase = "issuing tokens"
    fingerprint = rsabssa.public_key_fingerprint(deployment.vro.public_key)
    issuance = list(citizens)
    draw.shuffle(issuance)
    voters: dict[str, Voter] = {}
    for voter_id in issuance:
        voter = Voter(voter_id, deployment.wallets[voter_id],
                      deployment.vro.public_key, fingerprint)
        response = deployment.vro.issue_token(voter.build_auth_request())
        if not response.issued:                      # pragma: no cover
            raise RuntimeError(
                f"the office refused a generated request: {response.outcome.name}")
        voter.accept_token(response.blind_signature)
        voters[voter_id] = voter

    # Who abstains, and what everybody else ends up choosing -- drawn
    # independently of where anyone sat in the order above. A target
    # distribution filled in sequence is a distribution an attacker reads
    # off without doing any work.
    order_blind = list(citizens)
    draw.shuffle(order_blind)
    abstaining = set(order_blind[:distribution.abstentions])
    casting = [v for v in order_blind if v not in abstaining]
    final = distribution.selections()
    draw.shuffle(final)
    chosen = dict(zip(casting, final))

    # Phase two: the submissions, in a second order drawn separately from
    # the first. A re-voter appears twice; whichever of their entries falls
    # later carries the selection that counts, so supersession is produced
    # by the order rather than imposed on it.
    progress.phase = "casting ballots"
    events = list(casting)
    events.extend(draw.sample(casting, distribution.revotes))
    draw.shuffle(events)
    last_at = {voter_id: i for i, voter_id in enumerate(events)}

    for position, voter_id in enumerate(events):
        selection = (chosen[voter_id] if last_at[voter_id] == position
                     else draw.choice(final))
        result = deployment.ebb.submit(voters[voter_id].cast(selection))
        if not result.accepted:                      # pragma: no cover
            raise RuntimeError(
                f"the box refused a generated ballot: {result.reason}")
        progress.done += 1

    progress.phase = "closing"
    deployment.ebb.close()

    answer = _write_answer_key(deployment, {
        voter_id: b64(voter.adhoc.public_bytes)
        for voter_id, voter in sorted(voters.items())
    })
    progress.answer_key = str(answer)
    # `finished` is the caller's to set, and deliberately not set here. The
    # record of the closed poll is written after this returns, and an origin
    # that started serving while those files were still being written would
    # be serving a poll whose evidence was half there.
    progress.phase = "writing the record"
    return answer
