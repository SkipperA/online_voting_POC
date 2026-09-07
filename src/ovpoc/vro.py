"""The Voter Registration Office (VRO).

Steps 5 - 7 and 12 of the design.  No HTTP here on purpose: this is the
protocol logic, which the FastAPI layer will wrap later.  Keeping them apart
means the adversarial tests exercise the real decisions rather than a web
framework.

The VRO's power, and its limits, are worth stating plainly.  Because it signs
blindly, it cannot see or later recognise the ad-hoc key it certifies -- that
is the anonymity guarantee.  But by the same token nothing cryptographic stops
it from issuing a token for a voter who never asked.  Only two things do: the
one-token-per-id rule, and the token-release log that lets a voter detect a
token minted in their name.  In a real deployment the signing power must
additionally be split across several mutually distrusting bodies, which this
POC does not yet implement.

WHAT THE OFFICE HOLDS, AND WHAT IT ASKS SOMEBODY ELSE
-----------------------------------------------------
The office administers the **electoral register**: `register`, a set of ids
naming entitled citizens, and nothing more (§5.1).  It does *not* hold the
signature keys those citizens sign with.  Those live in qualified
certificates maintained by the certification authority, which the office
consults per request through `population_register` -- an external dependency
implemented in `driver/`, outside this package, because it is infrastructure
the design assumes rather than builds (§3.2).

There is no election-specific registration or binding step.  Nothing has to
be established between the office and a voter before the poll opens.

THE STATE MACHINE, AND WHY THE ORDER IS LOAD-BEARING
----------------------------------------------------
    1. cert = population_register.lookup(id)
         absent  -> NOT_IDENTIFIED
    2. verify s over hash([id, c]) under cert.public_key
         fails   -> NOT_IDENTIFIED
    ---- the identity boundary: below here the office knows who it is
         talking to, and may say why it is refusing ----
    3. cert.revoked        -> CERTIFICATE_REVOKED
       cert expired        -> CERTIFICATE_EXPIRED
    4. id not in register  -> NOT_ELIGIBLE
    5. id already released -> TOKEN_ALREADY_ISSUED
    6. record the release, sign, check the signature, return it

`NOT_IDENTIFIED` is one opaque outcome covering both pre-boundary failures,
and that opacity is the point: an unauthenticated party must not be able to
use the token endpoint to discover whether a named citizen holds a
certificate or appears on the electoral roll.  Every specific reason sits
below the boundary, reachable only by someone who has already proved, with a
signature, that they are the person they claim to be.

Two consequences are easy to undo by accident:

  * The eligibility check is *local* to this office, so nothing structural
    stops a later edit from testing `id in self.register` first.  That edit
    would leak roll membership to anybody who can spell an id.  It is the
    mutation `eligibility_checked_before_identity` in `tools/sabotage.py`.

  * Revocation sits *below* the boundary, which can read like an oversight.
    It is not: a revoked certificate still verifies mathematically, so by the
    time the office can see revocation it has already established identity
    and may as well say so.  The article's §3.2 and §5.4 enumerate
    certificate validity before signature verification; that order is
    expository, and this one is the privacy-preserving one.  Do not
    reconcile them silently in either direction.

The audit log records the true reason in every case, including which of the
pre-boundary situations occurred.  It is never returned to the requester.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import rsa

from . import keys, rsabssa
from .ledger import Ledger
from .messages import AuthRequest, b64, digest


# --------------------------------------------------------------------------
# What the office depends on, declared as the shape it needs
# --------------------------------------------------------------------------

@runtime_checkable
class Certificate(Protocol):
    """A qualified certificate, as far as this office is concerned.

    Declared structurally so that the implementation can live outside the
    library -- see `driver/population_register.py`.
    """

    subject: str
    public_key: bytes
    revoked: bool

    def is_expired(self, now: datetime | None = None) -> bool: ...


@runtime_checkable
class CertificateLookup(Protocol):
    """The external identity service: `id` in, certificate or nothing out."""

    def lookup(self, person_id: str) -> Certificate | None: ...


# --------------------------------------------------------------------------
# Outcomes
# --------------------------------------------------------------------------

class Outcome(Enum):
    """The result of a token request, as reported *to the requester*."""

    ISSUED = "issued"
    NOT_IDENTIFIED = "not_identified"
    CERTIFICATE_REVOKED = "certificate_revoked"
    CERTIFICATE_EXPIRED = "certificate_expired"
    NOT_ELIGIBLE = "not_eligible"
    TOKEN_ALREADY_ISSUED = "token_already_issued"


#: Outcomes that may only be reported once identity has been established.
POST_IDENTITY_OUTCOMES = frozenset(
    {
        Outcome.CERTIFICATE_REVOKED,
        Outcome.CERTIFICATE_EXPIRED,
        Outcome.NOT_ELIGIBLE,
        Outcome.TOKEN_ALREADY_ISSUED,
        Outcome.ISSUED,
    }
)


@dataclass
class TokenResponse:
    """Step 6/A or 6/B.  Carries the blind signature only on success."""

    outcome: Outcome
    blind_signature: bytes | None = None

    @property
    def issued(self) -> bool:
        return self.outcome is Outcome.ISSUED


@dataclass(frozen=True)
class AuditEntry:
    """One line of the office's private log.

    `reason` is the truth, including which pre-boundary situation produced a
    `NOT_IDENTIFIED`.  It is never returned to a requester.
    """

    voter_id: str
    outcome: Outcome
    reason: str


class ReleaseOutcome(Enum):
    """The result of a step-12 release query."""

    RELEASED = "released"
    NOT_RELEASED = "not_released"
    NOT_IDENTIFIED = "not_identified"


class FaultDetected(Exception):
    """The office's own signing arithmetic failed its self-check.

    Not a protocol outcome: it says the hardware misbehaved, and it must not
    be reported to the requester as a reason for refusal.
    """


# --------------------------------------------------------------------------
# Commitments and query payloads
# --------------------------------------------------------------------------

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


def denial_payload(voter_id: str) -> bytes:
    """The bytes the office signs when denying a release.

    Domain-separated from both the registration request and the query, so no
    signature can be carried across.
    """
    return digest({"statement": "no-token-released", "voter_id": voter_id})


def verify_denial(office_public_key: bytes, voter_id: str, signature: bytes) -> bool:
    """Check a signed denial against the office's *published statement key*.

    Deliberately not the token key.  See `VRO.office_key`.
    """
    return keys.verify_signature(office_public_key, signature, denial_payload(voter_id))


@dataclass
class ReleaseAnswer:
    """The office's answer to a step-12 query."""

    outcome: ReleaseOutcome
    nonce: bytes | None = None
    index: int | None = None
    signed_denial: bytes | None = None

    @property
    def released(self) -> bool:
        return self.outcome is ReleaseOutcome.RELEASED


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


# --------------------------------------------------------------------------
# The office
# --------------------------------------------------------------------------

@dataclass
class VRO:
    private_key: rsa.RSAPrivateKey                          # k_s^(R), tokens only
    public_key: rsa.RSAPublicKey                            # k_p^(R), published
    population_register: CertificateLookup                  # external (driver/)
    office_key: keys.SigningKeyPair                         # office statements
    register: set[str] = field(default_factory=set)         # electoral register: ids
    release_log: Ledger = field(default_factory=Ledger)     # commitments only
    _released: set[str] = field(default_factory=set)
    _nonces: dict[str, bytes] = field(default_factory=dict)
    _audit: list[AuditEntry] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        population_register: CertificateLookup,
        bits: int = rsabssa.DEFAULT_MODULUS_BITS,
    ) -> "VRO":
        priv, pub = rsabssa.generate_vro_keypair(bits)
        return cls(
            private_key=priv,
            public_key=pub,
            population_register=population_register,
            office_key=keys.SigningKeyPair.generate(),
        )

    # -- the electoral register ----------------------------------------
    def enrol(self, voter_id: str) -> None:
        """Add an id to the electoral register.

        One argument, and one only.  An enrolment that also recorded a
        signature key would be the wallet-binding step §3.2 removes: a second,
        election-administered copy of an association the certification
        authority already maintains.
        """
        self.register.add(voter_id)

    @property
    def office_public_key(self) -> bytes:
        """Published alongside k_p^(R), and distinct from it.

        The token key is a blind-signing oracle: it applies the raw private
        operation to values the office cannot inspect, so any registered voter
        can obtain the office's signature over a message of their choosing
        through an ordinary token request.  Using it for anything else -- a
        signed denial, a transport certificate, an authenticated statement --
        means those things are forgeable by any voter (§3.3).  Office
        statements are therefore signed under a separate key that never
        touches a blinded value.
        """
        return self.office_key.public_bytes

    @property
    def audit_log(self) -> tuple[AuditEntry, ...]:
        """The office's private log.  Never returned to a requester."""
        return tuple(self._audit)

    def _record(self, voter_id: str, outcome: Outcome, reason: str) -> TokenResponse:
        self._audit.append(AuditEntry(voter_id=voter_id, outcome=outcome, reason=reason))
        return TokenResponse(outcome=outcome)

    # ------------------------------------------------------------------
    def issue_token(
        self, request: AuthRequest, now: datetime | None = None
    ) -> TokenResponse:
        """Steps 5 -> 6/A -> 7.  The state machine is in the module docstring."""
        # ---- before the identity boundary: one opaque outcome, no detail ----
        cert = self.population_register.lookup(request.voter_id)
        if cert is None:
            return self._record(
                request.voter_id,
                Outcome.NOT_IDENTIFIED,
                "no entry for this id in the population register",
            )

        if not keys.verify_signature(
            cert.public_key, request.wallet_signature, request.signed_payload()
        ):
            return self._record(
                request.voter_id,
                Outcome.NOT_IDENTIFIED,
                "request signature does not verify under the certified key",
            )

        # ==== THE IDENTITY BOUNDARY ====
        # Nothing above this line may report a specific reason, and nothing
        # below it may be reached without a verified signature.  Moving a
        # check across it is a privacy regression, not a refactor.
        if cert.revoked:
            return self._record(
                request.voter_id, Outcome.CERTIFICATE_REVOKED, "certificate revoked"
            )

        if cert.is_expired(now):
            return self._record(
                request.voter_id, Outcome.CERTIFICATE_EXPIRED, "certificate expired"
            )

        if request.voter_id not in self.register:
            return self._record(
                request.voter_id, Outcome.NOT_ELIGIBLE, "not on the electoral register"
            )

        if request.voter_id in self._released:
            return self._record(
                request.voter_id,
                Outcome.TOKEN_ALREADY_ISSUED,
                "a token has already been released for this id",
            )

        # ---- step 7: record the release, then sign ----
        #
        # The order is not incidental.  Were s_c returned before the
        # commitment was recorded, an interruption between the two would leave
        # a token in circulation that the log does not account for: the
        # aggregate audit of §3.5 would understate the tokens issued, and the
        # voter's own step-12 check would report -- truthfully according to the
        # log, and falsely in fact -- that no token had been released in their
        # name.  Recording first fails in the harmless direction, since a
        # logged release that never completed appears only as a token that was
        # never used.
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

        # ---- step 6/A: the blind signature ----
        blind_sig = rsabssa.blind_sign(self.private_key, request.blinded_key)

        if not rsabssa.check_blind_signature(
            self.public_key, request.blinded_key, blind_sig
        ):
            raise FaultDetected(
                "s_c does not satisfy s_c^e == c: the signing operation faulted"
            )

        self._audit.append(
            AuditEntry(request.voter_id, Outcome.ISSUED, "token released")
        )
        return TokenResponse(outcome=Outcome.ISSUED, blind_signature=blind_sig)

    # ------------------------------------------------------------------
    # Step 12 -- the independent check, runnable from any device
    # ------------------------------------------------------------------
    def query_token_release(self, voter_id: str, signature: bytes) -> ReleaseAnswer:
        """Answer 'was a token released for this id?', to the voter only.

        The query must carry `sig(id)` under the certified wallet key: an
        unauthenticated lookup would turn the log into a public register of
        who did and did not register, and absence of an entry is conclusive
        evidence of non-voting.

        The same identity boundary applies as in `issue_token`, for the same
        reason.  An unknown id and a bad signature both return
        `NOT_IDENTIFIED`, so this endpoint cannot be used to probe either
        register either.

        An affirmative answer discloses the nonce, so the voter can verify the
        commitment against the published log themselves rather than taking the
        office's word for it.  A negative answer is *signed* -- under the
        office statement key, never the token key -- which does not prevent a
        dishonest office from denying a token it minted, but does leave
        evidence of the denial: a signed 'no' that later proves false is
        attributable.
        """
        cert = self.population_register.lookup(voter_id)
        if cert is None:
            return ReleaseAnswer(ReleaseOutcome.NOT_IDENTIFIED)

        if not keys.verify_signature(
            cert.public_key, signature, release_query_payload(voter_id)
        ):
            return ReleaseAnswer(ReleaseOutcome.NOT_IDENTIFIED)

        # ==== identity established ====
        nonce = self._nonces.get(voter_id)
        if nonce is None:
            return ReleaseAnswer(
                ReleaseOutcome.NOT_RELEASED,
                signed_denial=self.office_key.sign(denial_payload(voter_id)),
            )

        target = b64(commit(voter_id, nonce))
        index = next(
            i for i, e in enumerate(self.release_log.entries)
            if e.payload["commitment"] == target
        )
        return ReleaseAnswer(ReleaseOutcome.RELEASED, nonce=nonce, index=index)

    def release_count(self) -> int:
        """Public: how many tokens were released in total.

        Enough for the aggregate audit, and it names nobody.
        """
        return len(self.release_log)
