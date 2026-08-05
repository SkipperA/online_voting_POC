"""Where the verifiability/coercion balance is actually set.

The papers treat the placement of that balance as a legislative decision rather
than a technical fact. This module is the single place in the code where the
decision is expressed, so that it is visible rather than diffused through
`voter.py` and `ballotbox.py`.

A *verification handle* is how a voter locates their own ballot in the public
box. Only one is implemented -- `AdHocKeyHandle`, variant B of the papers.

## Why there is no variant A here

It is tempting to think variant A is the same design with a different handle:
the voter writes down a random number, finds their ballot by that number
instead of by `k_p^a`, and is thereby unable to prove authorship. That is
wrong, and `tests/test_provability.py` demonstrates it failing.

Provability does not live in the index a voter uses. It lives in the ballot's
structure. Every published ballot carries `k_p^a`, and the voter retains
`k_s^a` -- necessarily, since that key authenticates the selection and makes
re-voting possible. A coercer therefore need only say "sign this nonce", and
verify the result against the `k_p^a` sitting in the published ballot. The
random number proves nothing; the key proves everything. Note also that the
coercer chooses the demand, so offering voters a choice of handle protects
nobody.

A genuine variant A is a different system, not a different handle:

  * ballots encrypted rather than published in clear, so a tracker refers to a
    ciphertext;
  * trackers assigned through a trapdoor, so a coerced voter can point at
    someone else's tracker and be believed -- the mechanism is deniability, not
    anonymity;
  * a verifiable tally over ciphertexts, meaning threshold decryption and
    mixing, which costs the property that any third party can recompute the
    result with a standard library.

Compare Selene (Ryan et al.) for the trapdoor-tracker line of work. Treat it as
a research spike, not an extension of this code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from . import keys
from .ballotbox import BallotBox


@runtime_checkable
class VerificationHandle(Protocol):
    """A voter's private means of finding and checking their own ballot."""

    #: Whether the holder can convince a third party that the ballot is theirs.
    #: `True` places the system at the provable, and hence coercible, end.
    transferable: bool

    def locate(self, box: BallotBox) -> dict | None:
        """Return the voter's effective ballot, or None if absent."""
        ...

    def confirms(self, box: BallotBox, expected_selection: int) -> bool:
        """Cast-as-intended check: is the recorded choice the intended one?"""
        ...


@dataclass
class AdHocKeyHandle:
    """Variant B: the handle is the ad-hoc key pair the voter controls.

    The voter can check their recorded ballot, and can also prove authorship to
    an adjudicator hearing a complaint -- and, unavoidably, just as well to a
    vote buyer. `prove_authorship` exists to make that consequence executable
    rather than a remark in a comment.
    """

    adhoc: keys.SigningKeyPair
    transferable: bool = True

    def locate(self, box: BallotBox) -> dict | None:
        return box.find_ballot(self.adhoc.public_bytes)

    def confirms(self, box: BallotBox, expected_selection: int) -> bool:
        recorded = self.locate(box)
        return recorded is not None and recorded["selection"] == expected_selection

    def prove_authorship(self, challenge: bytes) -> bytes:
        """Produce a transferable proof of authorship over an arbitrary challenge.

        Anyone holding the published ballot can verify this against `k_p^a`.
        That is the whole content of the trade-off the papers hand to
        legislators: this method is useful to a complainant and equally useful
        to a coercer, and no choice of lookup index changes that.
        """
        return self.adhoc.sign(challenge)
