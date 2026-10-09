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

`tally_interval_seconds` is the legislator's dial, not a property of the
design.  There is no "running tally or not": there is a cadence, and the
close is always a publication point, so an interval longer than the poll
simply means the close is the only one.  That is what a small electorate
wants, because what the dial really sets is how many voters stand behind
each published number -- a continuously visible result would broadcast a
running total and, with re-voting, the fact that somebody reversed a
choice.

The trigger is the clock, not the arrival of a ballot.  A real electorate
waits for the periodic report, so it is published at each boundary whether
or not anything has changed; an omitted report would itself say that nobody
voted in that window, only less legibly.  See `_catch_up` for why that needs
no scheduler and no timestamp in the ledger.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import rsa

from . import keys, rsabssa
from .ledger import Ledger
from .messages import Ballot, b64, digest, unb64

BLANK = 0  # the plain, unaffiliated abstention default -- see tally() for
           # why other out-of-range values are not folded in with this one

BOX_CLOSED = "voting has closed"
ALREADY_ACCEPTED = "already accepted"


class BoxStillOpen(RuntimeError):
    """A full tally was asked for before any publication point.

    The close is always a publication point, so this can only be raised
    while voting is open: either no interval is configured, or the first
    boundary has not yet passed.  Past a boundary the figures are published
    anyway, so withholding them from a caller would protect nothing.
    """


def receipt_payload(election_id: str, accepted: bool, reason: str,
                    index: int | None, entry_hash: bytes) -> bytes:
    """The bytes the box signs when it issues a receipt.

    Domain-separated from the head statement, and bound to the election, so
    that a receipt is evidence about one poll rather than about any poll the
    same box ever ran.
    """
    return digest({
        "statement": "ballot-receipt",
        "election_id": election_id,
        "accepted": accepted,
        "reason": reason,
        "index": index,
        "entry_hash": b64(entry_hash),
    })


def head_payload(election_id: str, ledger: str, head: bytes) -> bytes:
    """The bytes the box signs over a published head.

    §3.5 asks for the head to be mirrored through channels the operator does
    not control. An unsigned head carried by a mirror is a string the
    operator can disown; a signed one is the box's own statement, and two
    mirrors holding different signed heads for the same election is
    equivocation nobody has to take on trust.
    """
    return digest({
        "statement": "registry-head",
        "election_id": election_id,
        "ledger": ledger,
        "head": b64(head),
    })


def verify_receipt(statement_public_key: bytes, election_id: str, receipt: dict,
                   signature: bytes) -> bool:
    """Check a receipt against the box's *published statement key*.

    `receipt` is the wire form: accepted, reason, index, entry_hash (b64).
    """
    return keys.verify_signature(
        statement_public_key, signature,
        receipt_payload(election_id, receipt["accepted"], receipt["reason"],
                        receipt["index"], unb64(receipt["entry_hash"])),
    )


def verify_head(statement_public_key: bytes, election_id: str, ledger: str,
                head: bytes, signature: bytes) -> bool:
    return keys.verify_signature(
        statement_public_key, signature, head_payload(election_id, ledger, head))


@dataclass
class SubmissionResult:
    """The receipt. §3.4 calls it the voter's evidence, so it is signed.

    `entry_hash`, not a head: it is the hash of this entry, which covers the
    record, its position and every entry before it. For an accepted ballot
    that is also the head of the accepted chain at that moment, because the
    entry had just been appended -- but for a rejected one it is the head of
    the *rejected* chain, and a voter comparing it against the published
    accepted head would find a discrepancy that is not one. The old name
    was accidentally right in one case out of two.
    """

    accepted: bool
    reason: str = ""
    entry_hash: bytes = b""
    index: int | None = None      # position of the entry in the registry
    signature: bytes = b""        # under the box's statement key


@dataclass
class BallotBox:
    vro_public_key: rsa.RSAPublicKey
    num_choices: int
    tally_interval_seconds: int | None = None
    accepted: Ledger = field(default_factory=Ledger)
    rejected: Ledger = field(default_factory=Ledger)
    _closed: bool = False
    _snapshots: list[dict] = field(default_factory=list)

    # The box's statement key, on the VRO's pattern (§3.3): it signs what the
    # box asserts -- receipts and published heads -- and nothing else. Unlike
    # the office's token key it is no oracle, since the box never applies it
    # to a value it cannot read; the one-key-one-purpose rule still holds.
    #
    # Signing prevents nothing. A box can equivocate under its own key as
    # easily as without one. What it changes is that the voter's receipt
    # stops being a string they could have typed themselves: a published
    # registry that fails to reproduce a signed receipt is a discrepancy
    # the box cannot disown, which is what §3.5 claims and what an unsigned
    # receipt does not support.
    statement_key: keys.SigningKeyPair = field(
        default_factory=keys.SigningKeyPair.generate)

    # Bound into every statement, so a receipt is evidence about this poll
    # and not about any poll this box ever ran.
    election_id: str = ""

    # Content hashes of the accepted records, for the replay test in
    # `submit`.  Not the entry hashes: those cover the index and the
    # previous hash, so two identical ballots at different positions hash
    # differently, which is the opposite of what is needed here.
    _accepted_records: set[bytes] = field(default_factory=set)

    # The clock, injectable so that tests can drive the cadence, and the
    # instant the cadence counts from.  Stage 1 anchors at construction,
    # because creating the deployment is the poll beginning; an explicit
    # opening act would own this instant instead.
    now: Callable[[], float] = time.time
    _anchor: float = 0.0
    _next_boundary: float = 0.0

    def __post_init__(self) -> None:
        # Floored to the second: a published boundary is a time the public
        # is told to expect, not the microsecond this process happened to
        # start at.
        self._anchor = float(int(self.now()))
        self._next_boundary = self._anchor + (self.tally_interval_seconds or 0)

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

        The close is always a publication point: any boundary the clock has
        passed is filled in first, and the final figures are published last,
        so an interval longer than the poll is not a special case -- it just
        means the close is the only point in the series.
        """
        self._catch_up()
        # Floored like every other boundary: the close is a publication point
        # and its label should look like one, not carry the microsecond the
        # operator's click happened to land on.
        self._publish(float(int(self.now())))
        self._closed = True

    # ------------------------------------------------------------------
    def submit(self, ballot: Ballot) -> SubmissionResult:
        """Steps 10/1 and 10/2."""
        self._catch_up()      # before the append: see _catch_up
        if self._closed:
            # Not recorded at all: a submission after the close is not a
            # rejected ballot, it is not a ballot.
            return SubmissionResult(
                False, BOX_CLOSED, b"", None,
                self.statement_key.sign(receipt_payload(
                    self.election_id, False, BOX_CLOSED, None, b"")),
            )

        # 10/1 -- is the ad-hoc key certified by the VRO?
        if not rsabssa.verify(self.vro_public_key, ballot.adhoc_public_key, ballot.token):
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": "token not signed by VRO"}
            )
            return self._receipt(False, "token not signed by VRO", entry)

        # 10/2 -- is the selection authenticated by that key?
        if not keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload()
        ):
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": "vote signature invalid"}
            )
            return self._receipt(False, "vote signature invalid", entry)

        # 10/2 -- is this record already among the accepted entries?
        #
        # A replay is not a forgery and no signature can catch it: a ballot
        # delivered a second time carries a valid signature because it is
        # genuine.  Without this test an operator could re-enter a ballot the
        # voter had already superseded, and it would count as the last one
        # under that key -- and the voter could not disown it, since the
        # record carries their own signature and "I did not submit this
        # twice" is not something a signature can express.  The nonce is what
        # makes two honest ballots for the same selection differ, so that a
        # replay can be told from a re-vote.
        #
        # Against the accepted entries alone: a duplicate of a *rejected*
        # submission supersedes nothing and is harmless.
        record = digest(ballot.to_dict())
        if record in self._accepted_records:
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": ALREADY_ACCEPTED}
            )
            return self._receipt(False, ALREADY_ACCEPTED, entry)

        # 11/A -- accepted.  Appending, not replacing: the supersession rule is
        # applied at tally time, so the full history stays auditable.
        entry = self.accepted.append(ballot.to_dict())
        self._accepted_records.add(record)

        return self._receipt(True, "accepted", entry)

    # ------------------------------------------------------------------
    # The publication cadence
    # ------------------------------------------------------------------
    def set_publication_interval(self, seconds: int | None) -> None:
        """Choose the cadence.  Build-time only.

        Refused once anything has been submitted: the interval decides what
        the public is shown and when, so a poll that can be re-timed while
        it runs is one whose operator chooses how much of the result to
        reveal and to whom.  An explicit opening act would make this a
        consequence of the box being open rather than of the ledger being
        non-empty.
        """
        if len(self.accepted) or len(self.rejected):
            raise RuntimeError(
                "the publication interval is fixed once a submission has been processed"
            )
        self.tally_interval_seconds = seconds
        self._anchor = float(int(self.now()))
        self._next_boundary = self._anchor + (seconds or 0)

    def _receipt(self, accepted: bool, reason: str, entry) -> SubmissionResult:
        """One place where a receipt is made, so none can be made unsigned."""
        return SubmissionResult(
            accepted=accepted,
            reason=reason,
            entry_hash=entry.entry_hash,
            index=entry.index,
            signature=self.statement_key.sign(receipt_payload(
                self.election_id, accepted, reason, entry.index, entry.entry_hash)),
        )

    def _publish(self, at: float) -> None:
        """Record one publication point, labelled with the instant it is for."""
        self._snapshots.append({
            "at": datetime.fromtimestamp(at, tz=timezone.utc)
                          .isoformat().replace("+00:00", "Z"),
            "after_accepted": len(self.accepted),
            **self._count(),
        })

    def _catch_up(self) -> None:
        """Publish every boundary the clock has passed.

        The trigger is the time, not the arrival of a ballot: in a real
        election the public waits for the periodic report, so it goes out
        at each boundary whether or not anything has changed.  A boundary
        that passes with no ballots therefore republishes the previous
        figures, which is the point rather than a defect.

        No scheduler is needed, and none belongs here.  The ledger changes
        only in `submit`, and `submit` rolls the boundaries forward *before*
        it appends, so a boundary noticed late is still filled in with the
        figures that were correct at the time -- nothing was added in
        between.  Materialising on read is therefore indistinguishable from
        a timer, because reading is the only way to see a snapshot.

        The label is the boundary, never the moment the gap was noticed.
        Labelling it with the triggering ballot's arrival would publish one
        voter's submission time per interval, which is the traffic exposure
        of Section 3.8 written into the public record.
        """
        if self._closed or not self.tally_interval_seconds:
            return
        now = self.now()
        while now >= self._next_boundary:
            self._publish(self._next_boundary)
            self._next_boundary += self.tally_interval_seconds

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
        self._catch_up()
        heads = {"accepted": self.accepted.head(), "rejected": self.rejected.head()}
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
                "accepted": heads["accepted"].hex(),
                "rejected": heads["rejected"].hex(),
            },
            # Signed so that a mirror carries the box's own statement rather
            # than a string it could have invented, and so that two mirrors
            # disagreeing is equivocation nobody has to take on trust (§3.5).
            "head_signatures": {
                name: b64(self.statement_key.sign(
                    head_payload(self.election_id, name, head)))
                for name, head in heads.items()
            },
            "statement_key": b64(self.statement_key.public_bytes),
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

        While voting is open this returns the last *published* figures, not
        the live count, so the endpoint cannot be used to read around the
        publication cadence.  The operator gets no privileged early sight of
        the result: before the first boundary there is no tally to be had,
        for anyone, and after it there is one the public has too.
        """
        if self._closed:
            return self._count()
        self._catch_up()
        if not self._snapshots:
            raise BoxStillOpen(self._no_publication_yet())
        return dict(self._snapshots[-1])

    def _no_publication_yet(self) -> str:
        if not self.tally_interval_seconds:
            return ("no publication interval is configured for this election: "
                    "the full count is available once the box is closed")
        due = datetime.fromtimestamp(self._next_boundary, tz=timezone.utc)
        return ("no publication point has been reached yet: the first falls at "
                f"{due.isoformat().replace('+00:00', 'Z')}")

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
