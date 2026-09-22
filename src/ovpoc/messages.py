"""The wire objects of the protocol, with canonical serialisation.

Canonical serialisation is not a detail.  A signature is over *bytes*, so if
two implementations serialise the same logical ballot differently, signatures
verify on one and fail on the other.  Everything signed here goes through
`canonical_bytes`, which produces JSON with sorted keys, no whitespace,
non-ASCII characters left as UTF-8, and base64url for binary fields.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of a dict, for signing and hashing.

    `ensure_ascii=False` is load-bearing, not cosmetic.  Python's default
    escapes every non-ASCII character as \\uXXXX; JavaScript's JSON.stringify,
    Swift's JSONEncoder and RFC 8785 all emit the character as UTF-8.  With the
    default, a voter_id carrying an accent serialises to different bytes on
    either side of the wire, so a signature made by one implementation fails to
    verify under the other -- and it fails only for those identifiers, which no
    single-implementation test can reveal.  See `docs/wire-contract.md`.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(obj: dict[str, Any]) -> bytes:
    return hashlib.sha256(canonical_bytes(obj)).digest()


# --------------------------------------------------------------------------

@dataclass
class AuthRequest:
    """Steps 3-4: the authentication request package [id, c, s].

    `voter_id` is the public wallet identifier, `blinded_key` is c, and
    `wallet_signature` is s = sig_{k_s^(v)}(hash([id, c])).
    """

    voter_id: str
    blinded_key: bytes
    wallet_signature: bytes

    def signed_payload(self) -> bytes:
        """Exactly the bytes the wallet signs -- hash([id, c])."""
        return digest({"voter_id": self.voter_id, "blinded_key": b64(self.blinded_key)})

    def to_dict(self) -> dict[str, Any]:
        return {
            "voter_id": self.voter_id,
            "blinded_key": b64(self.blinded_key),
            "wallet_signature": b64(self.wallet_signature),
        }


@dataclass
class Ballot:
    """Step 9: the ballot package [i, k_p^a, s_{k_p^a}, s_vote].

    Note what is *absent*: nothing here identifies the voter.  The link to
    eligibility runs only through `token`, the VRO's blind signature over
    `adhoc_public_key`.
    """

    selection: int              # i -- the chosen option, or 0 for a deliberately blank ballot
    adhoc_public_key: bytes     # k_p^a
    token: bytes                # s_{k_p^a} -- VRO blind signature over k_p^a
    vote_signature: bytes       # s_vote

    def signed_payload(self) -> bytes:
        """Exactly the bytes the ad-hoc key signs -- hash([i, k_p^a])."""
        return digest(
            {"selection": self.selection, "adhoc_public_key": b64(self.adhoc_public_key)}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "selection": self.selection,
            "adhoc_public_key": b64(self.adhoc_public_key),
            "token": b64(self.token),
            "vote_signature": b64(self.vote_signature),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Ballot":
        return cls(
            selection=d["selection"],
            adhoc_public_key=unb64(d["adhoc_public_key"]),
            token=unb64(d["token"]),
            vote_signature=unb64(d["vote_signature"]),
        )
