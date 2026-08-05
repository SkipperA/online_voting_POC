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

import hashlib
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import keys, rsabssa
from .ledger import Ledger
from .messages import AuthRequest, b64, canonical_bytes, digest


def commit(voter_id: str, nonce: bytes) -> bytes:
    """Commitment published in place of the voter id: H(id || nonce).

    Hiding: without the nonce, a third party cannot test a guessed id, even
    though wallet identifiers are low-entropy and enumerable.
    Binding: the VRO cannot later open the same commitment to a different id.
    """
    return hashlib.sha256(voter_id.encode("utf-8") + nonce).digest()


def release_query_payload(voter_id: str) -> bytes:
    """The bytes a voter signs to authenticate a step-12 query.

    Domain-separated from the registration request, so a signature captured
    from one cannot be replayed as the other.
    """
    return digest({"query": "token-release", "voter_id": voter_id})


@dataclass
class ReleaseAnswer:
    """The VRO's answer to an authenticated step-12 query."""

    released: bool
    nonce: bytes | None = None
    index: int | None = None
    signed_denial: bytes | None = None


def verify_release_answer(
    published_log: list[dict], voter_id: str, answer: ReleaseAnswer
) -> bool:
    """Run by the voter, on any device, against the published log.

    Confirms that the disclosed nonce really does open the commitment at the
    stated position -- so the answer rests on the public log, not on trust in
    the VRO's reply.
    """
    if not answer.released or answer.nonce is None or answer.index is None:
        return False
    if not 0 <= answer.index < len(published_log):
        return False
    return published_log[answer.index]["commitment"] == b64(commit(voter_id, answer.nonce))


class RegistrationError(Exception):
    """Step 6/B -- the request is rejected, with a reason."""


@dataclass
class VRO:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    roll: dict[str, bytes] = field(default_factory=dict)   # voter_id -> wallet public key
    release_log: Ledger = field(default_factory=Ledger)    # commitments only
    _released: set[str] = field(default_factory=set)
    _nonces: dict[str, bytes] = field(default_factory=dict)

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
        #
        # The published entry is a *commitment* to the id, not the id itself.
        # This keeps two properties that a plaintext log cannot hold together:
        #
        #   * anyone can count entries, which is what makes the aggregate audit
        #     "published ballots <= tokens released" possible for a third party;
        #   * nobody but the voter can learn whether a particular id appears,
        #     because the nonce is disclosed only on an authenticated query.
        #
        # The second matters because absence of a release is proof of
        # non-voting, which is exactly what a coercer demanding turnout wants.
        nonce = secrets.token_bytes(32)
        self._nonces[request.voter_id] = nonce
        self._released.add(request.voter_id)
        self.release_log.append({"commitment": b64(commit(request.voter_id, nonce))})

        # 6/A -- blind signature over the blinded ad-hoc key.
        return rsabssa.blind_sign(self.private_key, request.blinded_key)

    # ------------------------------------------------------------------
    # Step 12 -- the independent check, runnable from any device
    # ------------------------------------------------------------------
    def query_token_release(self, voter_id: str, signature: bytes) -> ReleaseAnswer:
        """Answer 'was a token released for this id?', to the voter only.

        The query must carry `sig(id)` under the wallet key, per step 12 of the
        design: an unauthenticated lookup would turn the log into a public
        register of who did and did not register.

        An affirmative answer discloses the nonce, so the voter can verify the
        commitment against the published log themselves rather than taking the
        VRO's word for it. A negative answer is *signed*, which does not prevent
        a dishonest VRO from denying a token it minted, but does leave evidence
        of the denial: a signed 'no' that later proves false is attributable.
        """
        wallet_key = self.roll.get(voter_id)
        if wallet_key is None:
            raise RegistrationError("id not on the electoral register")
        if not keys.verify_signature(wallet_key, signature, release_query_payload(voter_id)):
            raise RegistrationError("query not signed by the wallet belonging to this id")

        nonce = self._nonces.get(voter_id)
        if nonce is None:
            denial = {"voter_id": voter_id, "released": False}
            return ReleaseAnswer(
                released=False,
                signed_denial=self.private_key.sign(
                    canonical_bytes(denial),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
                    hashes.SHA384(),
                ),
            )

        target = b64(commit(voter_id, nonce))
        index = next(
            i for i, e in enumerate(self.release_log.entries)
            if e.payload["commitment"] == target
        )
        return ReleaseAnswer(released=True, nonce=nonce, index=index)

    def release_count(self) -> int:
        """Public: how many tokens were released in total.

        Enough for the aggregate audit, and it names nobody.
        """
        return len(self.release_log)
