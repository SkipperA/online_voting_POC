"""Tests for the blind signature core.

The interesting assertions here are the negative ones: what the VRO does *not*
learn, and what a voter cannot do with the material they hold.
"""

import secrets

import pytest

from ovpoc import rsabssa
from ovpoc.rsabssa import BlindSignatureError


def test_round_trip_produces_a_valid_signature(vro_keypair):
    priv, pub = vro_keypair
    msg = secrets.token_bytes(32)

    blinded, state = rsabssa.blind(pub, msg)
    blind_sig = rsabssa.blind_sign(priv, blinded)
    signature = rsabssa.finalize(pub, msg, blind_sig, state)

    assert rsabssa.verify(pub, msg, signature)


def test_unblinded_signature_is_ordinary_rsa_pss(vro_keypair):
    """The whole point: the token needs no special verifier.

    `rsabssa.verify` is a thin wrapper over the standard library's PSS verify.
    If this passes, any third party can check tokens with off-the-shelf tools.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    priv, pub = vro_keypair
    msg = secrets.token_bytes(32)
    blinded, state = rsabssa.blind(pub, msg)
    signature = rsabssa.finalize(pub, msg, rsabssa.blind_sign(priv, blinded), state)

    # No exception == valid.  Called directly, bypassing our own helper.
    pub.verify(
        signature,
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
        hashes.SHA384(),
    )


def test_the_vro_never_sees_the_message(vro_keypair):
    """The blinded value must not equal, or reveal, the message."""
    _, pub = vro_keypair
    msg = secrets.token_bytes(32)
    blinded, _ = rsabssa.blind(pub, msg)
    assert msg not in blinded


def test_blinding_the_same_key_twice_is_unlinkable(vro_keypair):
    """Two blindings of one message look unrelated.

    This is the property that stops the VRO from correlating the value it
    signed with the ad-hoc key that later appears in the ballot box.
    """
    _, pub = vro_keypair
    msg = secrets.token_bytes(32)
    first, _ = rsabssa.blind(pub, msg)
    second, _ = rsabssa.blind(pub, msg)
    assert first != second


def test_signature_does_not_transfer_to_another_message(vro_keypair):
    priv, pub = vro_keypair
    signed, other = secrets.token_bytes(32), secrets.token_bytes(32)

    blinded, state = rsabssa.blind(pub, signed)
    signature = rsabssa.finalize(pub, signed, rsabssa.blind_sign(priv, blinded), state)

    assert not rsabssa.verify(pub, other, signature)


def test_finalize_rejects_a_dishonest_vro_response(vro_keypair):
    """A wrong or malicious blind signature is caught on the voter's device."""
    priv, pub = vro_keypair
    msg = secrets.token_bytes(32)
    blinded, state = rsabssa.blind(pub, msg)

    corrupted = bytearray(rsabssa.blind_sign(priv, blinded))
    corrupted[0] ^= 0xFF

    with pytest.raises(BlindSignatureError):
        rsabssa.finalize(pub, msg, bytes(corrupted), state)


def test_blind_sign_rejects_out_of_range_input(vro_keypair):
    priv, pub = vro_keypair
    n = pub.public_numbers().n
    k = (n.bit_length() + 7) // 8
    with pytest.raises(BlindSignatureError):
        rsabssa.blind_sign(priv, (n + 1).to_bytes(k, "big"))


def test_fingerprint_pins_a_single_vro_key(vro_keypair):
    """Distinct VRO keys must have distinct fingerprints.

    If a VRO could quietly use a different key per voter, blinding would
    protect nothing -- see the note in rsabssa.public_key_fingerprint.
    """
    _, pub = vro_keypair
    _, other_pub = rsabssa.generate_vro_keypair(2048)
    assert rsabssa.public_key_fingerprint(pub) != rsabssa.public_key_fingerprint(other_pub)
