"""The Electronic Ballot Box.

Steps 10 - 11 of the design.  Everything it stores is public; the `tally`
function below is deliberately something any third party can reimplement from
the published ledgers alone.

One distinction in here is easy to get wrong, and the paper is specific about
it.  There are two different senses of "invalid":

  * A **rejected** ballot fails its cryptographic checks -- no valid VRO token,
    or a vote signature that does not match.  It goes to the rejected ledger
    and does *not* supersede an earlier ballot, because we cannot attribute it
    to the holder of the ad-hoc key at all.

  * An **invalid vote** is properly authenticated but carries a selection
    outside the list of options -- a deliberate protest ballot.  It is valid in
    the cryptographic sense, it is counted as invalid in the political sense,
    and it *does* supersede an earlier ballot.  "The last vote counts, even if
    it is an invalid one."

Conflating the two would let a coercer's malformed submission wipe out a
voter's genuine earlier ballot.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from . import keys, rsabssa
from .ledger import Ledger
from .messages import Ballot, b64

BLANK = 0  # a deliberately blank / protest ballot


@dataclass
class SubmissionResult:
    accepted: bool
    reason: str = ""
    ledger_head: bytes = b""


@dataclass
class BallotBox:
    vro_public_key: rsa.RSAPublicKey
    num_choices: int
    valid: Ledger = field(default_factory=Ledger)
    rejected: Ledger = field(default_factory=Ledger)

    def submit(self, ballot: Ballot) -> SubmissionResult:
        """Steps 10/1 and 10/2."""
        # 10/1 -- is the ad-hoc key certified by the VRO?  ("valid voter?")
        if not rsabssa.verify(self.vro_public_key, ballot.adhoc_public_key, ballot.token):
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": "token not signed by VRO"}
            )
            return SubmissionResult(False, "token not signed by VRO", entry.entry_hash)

        # 10/2 -- is the selection authenticated by that key?
        if not keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload()
        ):
            entry = self.rejected.append(
                {**ballot.to_dict(), "reason": "vote signature invalid"}
            )
            return SubmissionResult(False, "vote signature invalid", entry.entry_hash)

        # 11/A -- accepted.  Appending, not replacing: the supersession rule is
        # applied at tally time, so the full history stays auditable.
        entry = self.valid.append(ballot.to_dict())
        return SubmissionResult(True, "accepted", entry.entry_hash)

    # ------------------------------------------------------------------
    def effective_ballots(self) -> dict[str, dict]:
        """Last valid ballot per ad-hoc key, in ledger order."""
        latest: dict[str, dict] = {}
        for entry in self.valid.entries:
            latest[entry.payload["adhoc_public_key"]] = entry.payload
        return latest

    def tally(self) -> dict:
        """Recomputable by anyone from the public ledger.

        Returns counts per option plus the number of invalid (protest) ballots.
        """
        counts = Counter()
        invalid = 0
        for payload in self.effective_ballots().values():
            selection = payload["selection"]
            if 1 <= selection <= self.num_choices:
                counts[selection] += 1
            else:
                invalid += 1
        return {
            "counts": {i: counts.get(i, 0) for i in range(1, self.num_choices + 1)},
            "invalid": invalid,
            "voters": len(self.effective_ballots()),
            "rejected": len(self.rejected),
            "ledger_head": self.valid.head().hex(),
        }

    def find_ballot(self, adhoc_public_key: bytes) -> dict | None:
        """The voter's own verification: 'is my recorded choice what I intended?'"""
        return self.effective_ballots().get(b64(adhoc_public_key))
