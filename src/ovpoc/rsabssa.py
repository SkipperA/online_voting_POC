"""RSA Blind Signatures -- RFC 9474, variant RSABSSA-SHA384-PSS-Deterministic.

This module is the cryptographic heart of the scheme.  It maps onto the
notation of the paper as follows:

    k_p^a            the message to be blind-signed: the voter's ad-hoc
                     public key
    enc(.)           the padded encoding (EMSA-PSS with SHA-384), applied by
                     the voter before blinding
    r                the voter's secret blinding factor, fresh per election
    S(x) = x^d_R     the raw private-key operation, distinct from signing:
                     sig_{k_s}(m) = S(enc(m))

    blind      ->    c         = enc(k_p^a) * r^e_R  mod n_R
    blind_sign ->    s_c       = S(c)                mod n_R
    finalize   ->    s_{k_p^a} = s_c * r^-1          mod n_R

Note that `blind_sign` applies S and NOT the full signature scheme.  The value
c already contains the encoding the voter applied; encoding it a second time
would destroy the blinding, since enc is not multiplicative.

The property the construction relies on is the multiplicativity of S:

    S(enc(m) * r^e_R)  ==  S(enc(m)) * r    (mod n_R)

because (r^e_R)^d_R = r.  So blinding multiplies by r^e_R while unblinding
divides by r: the two do not cancel, and the factor is transformed by passing
through the exponentiation.  Reading them as inverse mappings is the mistake
that makes the false identity S(f_d(f_e(m))) = S(m) look plausible.

Multiplying by r^-1 leaves an *ordinary* RSASSA-PSS signature over k_p^a.  That
is load-bearing for this project: the independent verifier needs no bespoke
cryptography, only a standard RSA-PSS verify.

Why PSS encoding rather than signing k_p^a directly: raw RSA is multiplicative,
so a voter given signatures on two keys could derive one on their product
without the VRO.  PSS encoding destroys that structure.  See
tests/test_attacks.py::test_multiplicative_forgery_is_defeated_by_pss_encoding,
which exercises the attack and shows it failing.

SECURITY NOTE.  This is proof-of-concept code written to demonstrate a
protocol, not hardened production code.  It is not constant-time, it has had
no independent review, and it must not be used in a real election.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# RFC 9474 RSABSSA-SHA384-PSS-Deterministic parameters
HASH = hashlib.sha384
H_LEN = 48
SALT_LEN = 48
_CRYPTO_HASH = hashes.SHA384()

DEFAULT_MODULUS_BITS = 3072


class BlindSignatureError(Exception):
    """Raised when a blind-signature operation fails its own sanity checks."""


# --------------------------------------------------------------------------
# VRO key management
# --------------------------------------------------------------------------

def generate_vro_keypair(bits: int = DEFAULT_MODULUS_BITS):
    """Generate the VRO's long-term signing key pair (k_s^(R), k_p^(R))."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private_key, private_key.public_key()


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Stable fingerprint of the VRO public key, for pinning.

    This matters more than it looks.  If the VRO were free to use a different
    signing key per voter, blinding would buy nothing: the VRO could later
    tell which of its keys verifies a given ballot and so de-anonymise the
    voter.  The defence is that there is exactly one published VRO key and
    every client checks it against a pinned fingerprint before submitting.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# EMSA-PSS encoding (RFC 8017 §9.1.1)
# --------------------------------------------------------------------------

def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += HASH(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def emsa_pss_encode(msg: bytes, em_bits: int, salt: bytes | None = None) -> bytes:
    """EMSA-PSS-ENCODE.  Returns the encoded message EM of em_len bytes."""
    em_len = (em_bits + 7) // 8
    if em_len < H_LEN + SALT_LEN + 2:
        raise BlindSignatureError("modulus too small for these PSS parameters")

    m_hash = HASH(msg).digest()
    if salt is None:
        salt = secrets.token_bytes(SALT_LEN)

    m_prime = b"\x00" * 8 + m_hash + salt
    h = HASH(m_prime).digest()

    ps = b"\x00" * (em_len - SALT_LEN - H_LEN - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h, em_len - H_LEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # Zero the leftmost (8*em_len - em_bits) bits so that OS2IP(EM) < n.
    zero_bits = 8 * em_len - em_bits
    if zero_bits:
        masked_db = bytes([masked_db[0] & (0xFF >> zero_bits)]) + masked_db[1:]

    return masked_db + h + b"\xbc"


# --------------------------------------------------------------------------
# The blind signature protocol
# --------------------------------------------------------------------------

@dataclass
class BlindState:
    """Secret state the voter keeps between blinding and finalising.

    In the paper's notation this holds k_d (as r_inv) together with the
    encoded message, which must not leave the voter's device.
    """

    r_inv: int
    encoded_msg: bytes
    modulus: int


def blind(public_key: rsa.RSAPublicKey, msg: bytes) -> tuple[bytes, BlindState]:
    """Voter side, step 1/B + 2: produce c = PSS(msg) * r^e mod n.

    Returns (blinded_msg, state).  `blinded_msg` is what travels to the VRO;
    it reveals nothing about `msg`.
    """
    numbers = public_key.public_numbers()
    n, e = numbers.n, numbers.e
    k = (n.bit_length() + 7) // 8

    encoded = emsa_pss_encode(msg, n.bit_length() - 1)
    m_int = int.from_bytes(encoded, "big")
    if m_int >= n:
        raise BlindSignatureError("encoded message not reduced mod n")

    while True:
        r = secrets.randbelow(n - 1) + 1
        try:
            r_inv = pow(r, -1, n)
        except ValueError:
            continue  # r not invertible; vanishingly rare, retry
        break

    blinded = (m_int * pow(r, e, n)) % n
    return blinded.to_bytes(k, "big"), BlindState(r_inv=r_inv, encoded_msg=encoded, modulus=n)


def blind_sign(private_key: rsa.RSAPrivateKey, blinded_msg: bytes) -> bytes:
    """VRO side, step 6/A: s_c = c^d mod n.

    The VRO learns nothing about the message it is signing.  It is therefore
    the VRO's *policy* checks -- eligibility, and one token per id -- that do
    all the work of limiting what this signature means.  There is no
    cryptographic backstop here.
    """
    numbers = private_key.private_numbers()
    n = numbers.public_numbers.n
    d = numbers.d
    k = (n.bit_length() + 7) // 8

    if len(blinded_msg) != k:
        raise BlindSignatureError("blinded message has wrong length")
    c = int.from_bytes(blinded_msg, "big")
    if c >= n:
        raise BlindSignatureError("blinded message out of range")

    return pow(c, d, n).to_bytes(k, "big")


def finalize(
    public_key: rsa.RSAPublicKey,
    msg: bytes,
    blind_sig: bytes,
    state: BlindState,
) -> bytes:
    """Voter side, step 8: s_{k_p^a} = s_c * r^{-1} mod n.

    The result is a plain RSASSA-PSS signature over `msg`.  Per RFC 9474 we
    verify it before returning, so a malformed or malicious VRO response is
    caught on the voter's device rather than at the ballot box.
    """
    n = state.modulus
    k = (n.bit_length() + 7) // 8
    if len(blind_sig) != k:
        raise BlindSignatureError("blind signature has wrong length")

    z = int.from_bytes(blind_sig, "big")
    sig = ((z * state.r_inv) % n).to_bytes(k, "big")

    if not verify(public_key, msg, sig):
        raise BlindSignatureError("VRO returned a signature that does not verify")
    return sig


def verify(public_key: rsa.RSAPublicKey, msg: bytes, signature: bytes) -> bool:
    """Standard RSASSA-PSS verification -- no blind-signature logic needed.

    Anyone can run this: the ballot box, the independent verifier, a
    journalist with a Python interpreter.
    """
    try:
        public_key.verify(
            signature,
            msg,
            padding.PSS(mgf=padding.MGF1(_CRYPTO_HASH), salt_length=SALT_LEN),
            _CRYPTO_HASH,
        )
        return True
    except Exception:
        return False
