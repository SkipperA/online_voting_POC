"""The Voter Registration Office (VRO).

Steps 5 - 7 and 12 of the design.  No HTTP here on purpose: this is the
protocol logic, which the FastAPI layer will wrap later.  Keeping them apart
means the adversarial tests exercise the real decisions rather than a web
framework.

The VRO's power, and its limits, are worth stating plainly.  Because it signs
blindly, it cannot see or later recognise the ad-hoc key it certifies -- that
is the anonymity guarantee.  But by the same token nothing cryptographic stops
it from issuing a token for a voter who never asked.  Only two things do: the
one-token-per-id rule, and the *public* token-release log that lets a voter
detect a token minted in their name.  In a real deployment the signing power
must additionally be split across several mutually distrusting bodies, which
this POC does not yet implement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from . import keys, rsabssa
from .ledger import Ledger
from .messages import AuthRequest


class RegistrationError(Exception):
    """Step 6/B -- the request is rejected, with a reason."""


@dataclass
class VRO:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    roll: dict[str, bytes] = field(default_factory=dict)   # voter_id -> wallet public key
    release_log: Ledger = field(default_factory=Ledger)
    _released: set[str] = field(default_factory=set)

    @classmethod
    def create(cls, bits: int = rsabssa.DEFAULT_MODULUS_BITS) -> "VRO":
        priv, pub = rsabssa.generate_vro_keypair(bits)
        return cls(private_key=priv, public_key=pub)

    def register_voter(self, voter_id: str, wallet_public_key: bytes) -> None:
        """Populate the electoral register (out of band, before the election)."""
        self.roll[voter_id] = wallet_public_key

    # ------------------------------------------------------------------
    def issue_token(self, request: AuthRequest) -> bytes:
        """Steps 5 -> 6/A -> 7.  Returns the blind signature s_c.

        Note the order: the release is logged *before* the signature is
        returned.  If it were logged afterwards, a crash or a malicious VRO
        could hand out a token that never appears in the public log.
        """
        # 5/1 -- is this id on the register and eligible?
        wallet_key = self.roll.get(request.voter_id)
        if wallet_key is None:
            raise RegistrationError("id not valid or not eligible to vote")

        # 5/2 -- is the request signed by the wallet belonging to this id?
        if not keys.verify_signature(
            wallet_key, request.wallet_signature, request.signed_payload()
        ):
            raise RegistrationError("signature is not from the wallet belonging to this id")

        # Equality: at most one token per voter.
        if request.voter_id in self._released:
            raise RegistrationError("a token has already been released for this id")

        # 7 -- record the release publicly, then sign.
        self._released.add(request.voter_id)
        self.release_log.append({"voter_id": request.voter_id})

        # 6/A -- blind signature over the blinded ad-hoc key.
        return rsabssa.blind_sign(self.private_key, request.blinded_key)

    # ------------------------------------------------------------------
    def token_released(self, voter_id: str) -> bool:
        """Step 12: the independent check, runnable from any device.

        A voter asks 'was a token ever released in my name?'.  A 'yes' they did
        not cause means their wallet identity was used without their knowledge.
        This is the POC's answer to the stolen-identity attack, and it works
        only because the release log is public.
        """
        return any(e.payload.get("voter_id") == voter_id for e in self.release_log.entries)
