"""Key material other than the VRO's blind-signing key.

Two distinct roles, deliberately kept apart:

  * The **wallet key** (k_s^(v), k_p^(v)) is the voter's long-term, identified
    key.  In a real deployment this lives in an EUDI Digital Identity Wallet
    and would typically be ECDSA P-256 inside a secure element.  Here it is a
    software Ed25519 key behind the same interface, so `wallet_mock` can later
    be swapped for a real wallet without touching anything else.

  * The **ad-hoc key** (k_s^a, k_p^a) is generated fresh per election on the
    voter's device, is never shown to the VRO in the clear, and is what the
    VRO blind-signs.  It is the voter's anonymous handle on their own ballot.

The whole anonymity argument rests on these two never being linkable.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def _pub_bytes(pk: ed25519.Ed25519PublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass
class SigningKeyPair:
    """An Ed25519 key pair with raw-bytes public encoding (32 bytes)."""

    private: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "SigningKeyPair":
        return cls(private=ed25519.Ed25519PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        return _pub_bytes(self.private.public_key())

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def verify_signature(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature given the 32-byte raw public key."""
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except Exception:
        return False


def generate_adhoc_keypair() -> SigningKeyPair:
    """Step 1/A: the voter's one-time, election-specific key pair."""
    return SigningKeyPair.generate()
