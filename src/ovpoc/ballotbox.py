"""The Electronic Ballot Box.

Steps 10 - 11 of the design.  `tally` is deliberately something any third
party can reimplement from the published view alone.

THREE LEVELS OF STANDING, NOT TWO
---------------------------------
The article is specific about this, and the code follows it exactly:

  * A **rejected** ballot fails a cryptographic check -- no valid VRO token,
    or a vote signature that does not match the certified ad-hoc key.  It
    cannot be attributed to the holder of that key at all, so it supersedes
    *nothing* and goes to the rejected ledger.

  * An **accepted** ballot passes both checks, and therefore demonstrably
    comes from an eligible voter.  It supersedes any earlier accepted ballot
    under the same ad-hoc key.

  * Among the accepted, a ballot is a **valid vote** if its selection lies in
    1..N and an **invalid vote** if it lies outside -- a deliberate protest,
    or an honest mistake.  Both are accepted, both supersede, and the invalid
    ones are counted as invalid.  "The last vote counts, even if it is an
    invalid but accepted one."

So `accepted` names the ledger, and `valid` names a property of a selection
within it.  Conflating rejected with invalid would let any reader of the box
copy a voter's public ad-hoc key and token, attach a meaningless signature,
and annul that voter's genuine ballot without holding their private key.

PUBLICATION IS TWO-PHASE
------------------------
While voting is open the box publishes commitments, positions, the chain head
and running counts -- not the records.  At the close every record is released
in clear, accepted and rejected alike.  `published_view` is that publication;
reading `accepted.entries` directly is the box's own storage, not something a
citizen can see before the close.

`tally_interval` is the legislator's dial, not a property of the design.
Left at None -- the article's default -- no running tally exists and `tally`
refuses until the box closes, because a continuously visible result would
broadcast a running total and, with re-voting, that somebody reversed a
choice.  Set to a count, a snapshot is published after every that-many
accepted ballots, which is the alternative setting the article describes
(fifteen minutes, in its example).  This POC counts ballots rather than
minutes: a fake clock would add a moving part that demonstrates nothing.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from . import keys, rsabssa
from .ledger import Ledger
from .messages import Ballot, b64

BLANK = 0  # the plain, unaffiliated abstention default -- see tally() for
           # why other out-of-range values are not folded in with this one

BOX_CLOSED = "voting has closed"


class BoxStillOpen(RuntimeError):
    """A full tally was asked for while voting was still open.

    Raised only when no running tally has been configured.  With one
    configured the figures are published anyway, so withholding them from a
    caller would protect nothing.
    """


@dataclass
class SubmissionResult:
    accepted: bool
    reason: str = ""
    ledger_head: bytes = b""
    index: int | None = None      # position of the entry in the registry


@dataclass
class BallotBox:
    vro_public_key: rsa.RSAPublicKey
    num_choices: int
    tally_interval: int | None = None
    accepted: Ledger = field(default_factory=Ledger)
    rejected: Ledger = field(default_factory=Ledger)
    _closed: bool = False
    _snapshots: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Phase
    # ------------------------------------------------------------------
    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Close the poll: submissions stop, records are released in clear.

        A plain mutable flag.  A real deployment needs this to be
        irreversible -- a box that can reopen can accept a ballot after the
        result is known -- and that is an operational property (append-only
        storage, published closing time, several parties holding the head)
        rather than a protocol one.  The POC does not model it, and the
        mutability here is deliberate rather than an oversight.
        """
        self._closed = True

    # ------------------------------------------------------------------
    def submit(self, ballot: Ballot) -> SubmissionResult:
        """Steps 10/1 and 10/2."""
        if self._closed:
            # Not recorded at all: a submission after the close is not a
            # rejected ballot, it is not a ballot.
            return SubmissionResult(False, BOX_CLOSED, self.accepted.head())

        # 10/1 -- is the ad-hoc key certified by the VRO?
        if not rsabssa.verify(self.vro_public_key, ballot.adhoc_public_key, ballot.token):
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": "token not signed by VRO"}
            )
            return SubmissionResult(False, "token not signed by VRO", entry.entry_hash, entry.index)

        # 10/2 -- is the selection authenticated by that key?
        if not keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload()
        ):
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": "vote signature invalid"}
            )
            return SubmissionResult(False, "vote signature invalid", entry.entry_hash, entry.index)

        # 11/A -- accepted.  Appending, not replacing: the supersession rule is
        # applied at tally time, so the full history stays auditable.
        entry = self.accepted.append(ballot.to_dict())

        if self.tally_interval and len(self.accepted) % self.tally_interval == 0:
            self._snapshots.append(
                {"after_accepted": len(self.accepted), **self._count()}
            )

        return SubmissionResult(True, "accepted", entry.entry_hash, entry.index)

    # ------------------------------------------------------------------
    # Publication
    # ------------------------------------------------------------------
    def published_view(self) -> dict:
        """What a citizen can see, and when.

        While voting is open: for every submission, the commitment to the
        entry and its position, plus the chain head and running counts.  The
        commitment discloses nothing about the selection, because every
        record contains a freshly generated ad-hoc public key drawn from a
        space too large to search -- an enquirer who guesses a selection
        cannot confirm the guess without also guessing that key.

        From the close: every record in clear, accepted and rejected alike.

        No row moves backwards.  Nothing available while voting is open is
        withdrawn at the close, and what changes does so only by disclosing
        more.
        """
        view = {
            "phase": "closed" if self._closed else "open",
            "commitments": {
                "accepted": [
                    {"index": e.index, "commitment": e.entry_hash.hex()}
                    for e in self.accepted.entries
                ],
                "rejected": [
                    {"index": e.index, "commitment": e.entry_hash.hex()}
                    for e in self.rejected.entries
                ],
            },
            "heads": {
                "accepted": self.accepted.head().hex(),
                "rejected": self.rejected.head().hex(),
            },
            "counts": {
                "accepted": len(self.accepted),
                "rejected": len(self.rejected),
            },
            "running_tally": list(self._snapshots),
        }
        if self._closed:
            view["records"] = {
                "accepted": [e.payload for e in self.accepted.entries],
                "rejected": [e.payload for e in self.rejected.entries],
            }
        return view

    # ------------------------------------------------------------------
    # Counting
    # ------------------------------------------------------------------
    def effective_ballots(self) -> dict[str, dict]:
        """Last accepted ballot per ad-hoc key, in ledger order."""
        latest: dict[str, dict] = {}
        for entry in self.accepted.entries:
            latest[entry.payload["adhoc_public_key"]] = entry.payload
        return latest

    def _count(self) -> dict:
        """The figures themselves, with no phase check.

        Used both by `tally` and by the running-tally snapshots, so that a
        snapshot cannot drift from the final count.
        """
        counts: Counter = Counter()
        protest_codes: Counter = Counter()
        for payload in self.effective_ballots().values():
            selection = payload["selection"]
            if 1 <= selection <= self.num_choices:
                counts[selection] += 1
            else:
                protest_codes[selection] += 1
        return {
            "counts": {i: counts.get(i, 0) for i in range(1, self.num_choices + 1)},
            "valid": sum(counts.values()),
            "invalid": sum(protest_codes.values()),
            "protest_codes": dict(protest_codes),
            "voters": len(self.effective_ballots()),
            "rejected": len(self.rejected),
            "ledger_head": self.accepted.head().hex(),
        }

    def tally(self) -> dict:
        """Recomputable by anyone from the published view.

        `valid` and `invalid` partition the accepted ballots; `rejected`
        counts submissions that never became anybody's vote.  Distinct
        out-of-range selections are kept apart in `protest_codes` rather than
        merged into one number -- see the module docstring for why.

        Refused while voting is open unless a running tally is configured.
        The operator gets no privileged early sight of the result: with
        `tally_interval` unset there is no tally to be had, for anyone.
        """
        if not self._closed and self.tally_interval is None:
            raise BoxStillOpen(
                "no running tally is published for this election: the full count "
                "is available once the box is closed"
            )
        return self._count()

    def find_ballot(self, adhoc_public_key: bytes) -> dict | None:
        """The voter's own verification: 'is my recorded choice what I intended?'

        Available in both phases.  While voting is open this is the *only*
        way to see a record, and k_p^a is what authenticates the request:
        before the close the key is known to the voter's application and to
        this box and to nobody else, so presenting it is sufficient.  No
        signature is needed, and no private key need leave the voter's device
        to reach the machine the check runs on.
        """
        return self.effective_ballots().get(b64(adhoc_public_key))
