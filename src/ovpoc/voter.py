"""The voter's side of the protocol -- steps 1 to 4, 8, 9 and the checks.

Read this file first if you want to understand the scheme: it is the only place
where the whole sequence appears in one piece.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import rsa

from . import keys, rsabssa
from .ballotbox import BallotBox
from .handles import AdHocKeyHandle, VerificationHandle
from .messages import Ballot, AuthRequest, b64


@dataclass
class Voter:
    voter_id: str
    wallet: keys.SigningKeyPair                       # the identified wallet key
    vro_public_key: rsa.RSAPublicKey
    pinned_vro_fingerprint: str

    adhoc: keys.SigningKeyPair | None = None          # k_s^a, k_p^a
    token: bytes | None = None                        # s_{k_p^a}
    _blind_state: rsabssa.BlindState | None = None
    recorded_heads: list[bytes] = field(default_factory=list)

    # ---- steps 1-4 ---------------------------------------------------
    def build_auth_request(self) -> AuthRequest:
        """Generate the ad-hoc key, blind it, and sign the request with the wallet."""
        if rsabssa.public_key_fingerprint(self.vro_public_key) != self.pinned_vro_fingerprint:
            raise ValueError(
                "VRO public key does not match the pinned fingerprint -- refusing to "
                "proceed (a per-voter VRO key would destroy anonymity)"
            )

        self.adhoc = keys.generate_adhoc_keypair()
        blinded, state = rsabssa.blind(self.vro_public_key, self.adhoc.public_bytes)
        self._blind_state = state

        request = AuthRequest(
            voter_id=self.voter_id, blinded_key=blinded, wallet_signature=b""
        )
        request.wallet_signature = self.wallet.sign(request.signed_payload())
        return request

    # ---- step 8 ------------------------------------------------------
    def accept_token(self, blind_sig: bytes) -> None:
        """Unblind the VRO's response to obtain s_{k_p^a}."""
        assert self.adhoc and self._blind_state
        self.token = rsabssa.finalize(
            self.vro_public_key, self.adhoc.public_bytes, blind_sig, self._blind_state
        )
        self._blind_state = None  # the blinding secret has served its purpose

    # ---- step 9 ------------------------------------------------------
    def cast(self, selection: int) -> Ballot:
        assert self.adhoc and self.token
        ballot = Ballot(
            selection=selection,
            adhoc_public_key=self.adhoc.public_bytes,
            token=self.token,
            vote_signature=b"",
        )
        ballot.vote_signature = self.adhoc.sign(ballot.signed_payload())
        return ballot

    # ---- verification ------------------------------------------------
    @property
    def handle(self) -> VerificationHandle:
        """The voter's private means of finding their own ballot.

        See `handles.py` for why only variant B exists, and why an anonymous
        lookup index would not by itself make the ballot unprovable.
        """
        assert self.adhoc, "no ad-hoc key yet -- call build_auth_request first"
        return AdHocKeyHandle(self.adhoc)

    def verify_recorded_ballot(self, box: BallotBox, expected: int) -> bool:
        """The cast-as-intended check, performed from an independent device."""
        return self.handle.confirms(box, expected)

    def record_head(self, head: bytes) -> None:
        """Keep the ledger head seen at submission time, to detect later deletion."""
        self.recorded_heads.append(head)
