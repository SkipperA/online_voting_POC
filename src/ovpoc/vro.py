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

from . import keys, pdfrequest, rsabssa
from .ledger import Ledger
from .messages import AuthRequest, b64, digest, unb64


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
    #: Validated and reserved, but not signed. Distinct from ISSUED because
    #: it is a different thing to have been told: no token exists, nothing is
    #: published, and the claim can still be cancelled. Overloading ISSUED
    #: here would make the office's audit log misreport what it disclosed,
    #: which is the one column that must not lie.
    RESERVED = "reserved"
    #: A request for this id has been validated and is awaiting release.
    #: Distinct from TOKEN_ALREADY_ISSUED because the facts differ: nothing
    #: has been published, no token exists, and the reservation can be
    #: cancelled. The office knows which, so it says which.
    REQUEST_PENDING = "request_pending"
    #: The qualified-signature route only. The signature is good and the
    #: signer is known; the document they signed is not what any token
    #: request renders to. Reported with a reason because it is below the
    #: identity boundary -- a qualified signature has already established
    #: who is being told -- and because a citizen whose document was
    #: refused can do nothing about it unless they are told.
    DOCUMENT_REFUSED = "document_refused"


#: Outcomes that may only be reported once identity has been established.
POST_IDENTITY_OUTCOMES = frozenset(
    {
        Outcome.DOCUMENT_REFUSED,
        Outcome.CERTIFICATE_REVOKED,
        Outcome.CERTIFICATE_EXPIRED,
        Outcome.NOT_ELIGIBLE,
        Outcome.TOKEN_ALREADY_ISSUED,
        Outcome.REQUEST_PENDING,
        Outcome.RESERVED,
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
class SignedRequest:
    """The one object in the exchange the office cannot manufacture.

    Kept, not discarded once checked, because a release the office minted
    for somebody who never asked has none to show -- which is how a
    supervisor finds a fabricated release for every citizen at once,
    including the ones who abstain and never perform their own check.

    The two routes produce different objects and the argument is the same
    for both.  On the wallet route it is `s`, the citizen's Ed25519
    signature over `hash([id, c])`, verifiable against the key the
    population register holds.  On the qualified-signature route it is the
    signed document itself, verifiable by anybody against the European
    trust lists without this office's cooperation -- which is a stronger
    thing to hold and, for the same reason, a heavier one. See
    `docs/threats.md` on what that changes.

    Exactly one of the two is present. A `SignedRequest` with both would
    be a release claiming to have been asked for twice, and with neither
    would be the thing this class exists to make impossible.
    """

    blinded_key: bytes
    #: Route 1: sig_{k_s^(v)}(hash([id, c])).
    wallet_signature: bytes | None = None
    #: Route 2: the whole signed PDF, which is what a third party would
    #: have to re-validate. Its digest is what the supervision register
    #: publishes; the document is served separately or not at all.
    document: bytes | None = None
    #: Route 2 only: whether the office established, against a pinned
    #: European trusted list, that this is a *qualified* electronic
    #: signature under Article 3(12). `None` means it did not look -- an
    #: office on hand-pinned roots has no standing to judge, and that is
    #: not the same answer as `False`.
    #:
    #: Recorded and never acted on. Whether a deployment should *require*
    #: a qualified signature is a question of electoral law rather than of
    #: this protocol: the certificate established who is speaking either
    #: way, and the word is about the legal effect of the signature rather
    #: than about the strength of the identification. An office that
    #: refused an advanced signature would be making that decision in
    #: `vro.py`, where no legislator can see it.
    qualified: bool | None = None

    def __post_init__(self) -> None:
        if (self.wallet_signature is None) == (self.document is None):
            raise ValueError(
                "a signed request carries exactly one of a wallet signature "
                "and a signed document"
            )

    @property
    def route(self) -> str:
        return "wallet" if self.wallet_signature is not None else "document"


@dataclass(frozen=True)
class DocumentRequest:
    """A validated signed document, reduced to what `_claim` needs.

    The counterpart of `AuthRequest` on the qualified-signature route, and
    the same three attributes -- `voter_id`, `blinded_key`, `evidence` --
    because `_claim` must not be able to tell which route it is serving.

    `revoked` and `expired` ride along because on this route they are
    findings of the signature validator rather than fields of a looked-up
    certificate, and they are still reported below the identity boundary
    and never above it.
    """

    voter_id: str
    blinded_key: bytes
    document: bytes
    revoked: bool = False
    expired: bool = False
    #: Carried, not consulted. See `SignedRequest.qualified`.
    qualified: bool | None = None

    @property
    def evidence(self) -> "SignedRequest":
        return SignedRequest(blinded_key=self.blinded_key, document=self.document,
                             qualified=self.qualified)


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

def commit(voter_id: str, opening: bytes) -> bytes:
    """Commitment published in place of the voter id: H(id || opening).

    Hiding: without the opening value, a third party cannot test a guessed id, even
    though wallet identifiers are low-entropy and enumerable.
    Binding: the VRO cannot later open the same commitment to a different id.
    """
    return hashlib.sha256(voter_id.encode("utf-8") + opening).digest()


def _in_chain_order(
    release_log: Ledger, openings: dict[str, bytes]
) -> dict[str, bytes]:
    """The openings, rearranged to the order the release chain was built in.

    `supervision_dump` walks `_openings` to build the register a supervisor
    reads, and the office's signature covers the *chain* -- so the two agree
    only while the mapping holds the order tokens were issued in. A reload
    does not preserve it: the poll is written with `canonical_bytes`, which
    sorts keys, as canonical serialisation must.

    So the chain is asked instead. Each entry carries one commitment; the
    opening that produces it names the citizen that entry is about. An
    opening the chain does not account for, or an entry no opening reaches,
    is a stored register that contradicts itself -- it is put at the end
    rather than dropped, because a supervisor who cannot chain the register
    must still be able to see every name in it.
    """
    by_commitment = {b64(commit(voter_id, opening)): voter_id
                     for voter_id, opening in openings.items()}
    ordered: dict[str, bytes] = {}
    for entry in release_log.entries:
        voter_id = by_commitment.get(entry.payload.get("commitment"))
        if voter_id is not None and voter_id not in ordered:
            ordered[voter_id] = openings[voter_id]
    for voter_id, opening in openings.items():
        ordered.setdefault(voter_id, opening)
    return ordered


def _request_to_stored(request: SignedRequest) -> dict:
    """A signed request as `poll.state.json` holds it."""
    if request.wallet_signature is not None:
        return {"blinded_key": b64(request.blinded_key),
                "wallet_signature": b64(request.wallet_signature)}
    return {"blinded_key": b64(request.blinded_key),
            "document": b64(request.document),
            "qualified": request.qualified}


def request_from_stored(stored) -> SignedRequest:
    """The inverse, tolerant of the two-element list older polls were written as."""
    if isinstance(stored, (list, tuple)):
        return SignedRequest(blinded_key=unb64(stored[0]),
                             wallet_signature=unb64(stored[1]))
    document = stored.get("document")
    signature = stored.get("wallet_signature")
    return SignedRequest(
        blinded_key=unb64(stored["blinded_key"]),
        wallet_signature=unb64(signature) if signature is not None else None,
        document=unb64(document) if document is not None else None,
        # Absent from a poll written before the office could establish it,
        # and absent is exactly `None`: that office did not look.
        qualified=stored.get("qualified"))


def _request_for_supervision(request: SignedRequest) -> dict:
    """What a supervisor is shown about the citizen's own request.

    The wallet route publishes the signature itself: it is 64 bytes and a
    supervisor can check it against the key the population register holds.

    The qualified-signature route publishes the document's digest and its
    length, and not the document. Two reasons, and the second is the one
    that matters. A signed request is some tens of kilobytes, so a register
    of a few thousand releases would be a download nobody performs -- and a
    supervision surface nobody opens supervises nothing. But also: that
    document is verifiable by anyone against the European trust lists,
    without this office's cooperation, which makes it a far more portable
    proof that a named citizen took part than anything the first route
    produces. Publishing it to whoever can reach the supervision origin
    would hand out exactly the artefact §3.7 spends a page keeping out of
    circulation. The digest is enough to tie a release to a document the
    supervisor has obtained by some other route, and not enough to be one.
    """
    if request.wallet_signature is not None:
        return {"blinded_key": b64(request.blinded_key),
                "request_signature": b64(request.wallet_signature),
                "route": request.route}
    return {"blinded_key": b64(request.blinded_key),
            "request_document_sha256": hashlib.sha256(request.document).hexdigest(),
            "request_document_bytes": len(request.document),
            # The finding, published because it is the whole point of
            # reading a trusted list and because a supervisor cannot
            # reach it themselves from here -- they are not given the
            # document. `None` is this office saying it had no standing
            # to judge, which a surface must not round to "no".
            "request_qualified": request.qualified,
            "route": request.route}


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


def release_count_payload(election_id: str, count: int) -> bytes:
    """The bytes the office signs over its published count.

    The count audit is the strongest check a third party can run without
    the records: the number of distinct tokens used by the ballots in the
    box cannot exceed the number of tokens issued.  One of those two figures
    comes from the box, which signs what it publishes; the other came from
    the office unsigned, so the audit rested on an unattributable claim at
    exactly the point where an office with something to hide would want to
    understate.  Bound to the election, like every other statement here.
    """
    return digest({
        "statement": "tokens-released",
        "election_id": election_id,
        "count": count,
    })


def release_head_payload(election_id: str, head: bytes) -> bytes:
    """The bytes the office signs over the head of its release register.

    The box signs the heads it publishes so that a mirror carries its
    statement rather than a string it could have invented.  The office's
    register is a chain on the same terms and was published without one, so
    a downloaded copy of it stood on nothing: the commitments are opaque by
    construction, and a reader who cannot attribute the head cannot tell a
    register with an entry removed from one without.
    """
    return digest({
        "statement": "release-register-head",
        "election_id": election_id,
        "head": b64(head),
    })


def verify_release_head(office_public_key: bytes, election_id: str,
                        head: bytes, signature: bytes) -> bool:
    return keys.verify_signature(
        office_public_key, signature, release_head_payload(election_id, head))


def verify_release_count(office_public_key: bytes, election_id: str, count: int,
                         signature: bytes) -> bool:
    """Check a published count against the office's *published statement key*."""
    return keys.verify_signature(
        office_public_key, signature, release_count_payload(election_id, count))


def verify_denial(office_public_key: bytes, voter_id: str, signature: bytes) -> bool:
    """Check a signed denial against the office's *published statement key*.

    Deliberately not the token key.  See `VRO.office_key`.
    """
    return keys.verify_signature(office_public_key, signature, denial_payload(voter_id))


@dataclass
class ReleaseAnswer:
    """The office's answer to a step-12 query."""

    outcome: ReleaseOutcome
    opening: bytes | None = None
    index: int | None = None
    signed_denial: bytes | None = None

    @property
    def released(self) -> bool:
        return self.outcome is ReleaseOutcome.RELEASED


def verify_release_answer(
    published_log: list[dict], voter_id: str, answer: ReleaseAnswer
) -> bool:
    """Run by the voter, on any device, against the published log.

    Confirms that the disclosed value really does open the commitment at the
    stated position -- so the answer rests on the public log, not on trust in
    the VRO's reply.
    """
    if not answer.released or answer.opening is None or answer.index is None:
        return False
    if not 0 <= answer.index < len(published_log):
        return False
    return published_log[answer.index]["commitment"] == b64(commit(voter_id, answer.opening))


# --------------------------------------------------------------------------
# The office
# --------------------------------------------------------------------------

@dataclass
class VRO:
    private_key: rsa.RSAPrivateKey                          # k_s^(R), tokens only
    public_key: rsa.RSAPublicKey                            # k_p^(R), published
    population_register: CertificateLookup                  # external (driver/)
    office_key: keys.SigningKeyPair                         # office statements
    #: The qualified-signature route's counterpart to
    #: `population_register`, and on that route its replacement: there is
    #: no lookup, because the certificate arrives with the signature.
    #: External infrastructure, injected, implemented in `driver/`. `None`
    #: in an office that does not offer the route.
    signature_validation: "pdfrequest.SignatureValidation | None" = None
    #: Bound into the office's statements, so a figure is about one poll.
    election_id: str = ""
    register: set[str] = field(default_factory=set)         # electoral register: ids
    #: Whether a qualified signature is itself an entitlement to vote.
    #:
    #: Off, and the article's design is the off case: the electoral
    #: register is Phase A material authored outside the system (§3.2),
    #: derived from civil registration, and the office administers it
    #: rather than populating it.
    #:
    #: On, an identifier the office has never heard of is added to the
    #: register on the strength of its own qualified signature, and then
    #: everything proceeds unchanged. The argument for allowing it is that
    #: a qualified certificate is an attestation by a trust service that
    #: this person exists and is who the signature says -- which is most
    #: of what a roll is consulted for -- and the mapping from civil
    #: registration to a DÁP identifier does not exist, so the alternative
    #: is an operator typing identifiers in by hand.
    #:
    #: The argument against is why this is a scope clause and not a
    #: feature. A DÁP certificate carries no age, no citizenship and no
    #: address, registration opens at fourteen, and the register's scope
    #: reaches residents who are not citizens -- so "holds a qualified
    #: certificate" is not "may vote", and in a real election the gap is
    #: closed by an attribute attestation rather than by assuming. It also
    #: changes what the supervision register *means*: an office that
    #: enrolled a citizen because they asked cannot be checked against its
    #: own roll, and every surface has to say so. Clause S7.
    #:
    #: Never on the wallet route, and that asymmetry is the point rather
    #: than an omission: those certificates are invented by this
    #: demonstration, so enrolling from them would be the office enrolling
    #: from its own fixture.
    enrol_on_qualified_signature: bool = False
    #: Identifiers this office added itself, in the order it added them.
    #: Published, because a supervisor comparing releases against a roll
    #: from the citizen registry must know which entries that roll was
    #: never asked about.
    _self_enrolled: list[str] = field(default_factory=list)
    release_log: Ledger = field(default_factory=Ledger)     # commitments only
    _released: set[str] = field(default_factory=set)
    #: voter_id -> the opening value behind that citizen's commitment.
    #:
    #: **Its order is load-bearing.** `supervision_dump` walks this
    #: mapping to build the release list, and the supervisor's page chains
    #: those commitments from the genesis hash to the head the office
    #: signed. The head covers the order tokens were issued in, so this
    #: has to hold that order and nothing else. It does, while the poll
    #: runs, because entries are added as tokens are released -- but a
    #: dict's order is not a property anything was checking, and
    #: `restore_releases` lost it for a whole release of the project.
    _openings: dict[str, bytes] = field(default_factory=dict)
    _audit: list[AuditEntry] = field(default_factory=list)
    #: voter_id -> (c, s), the blinded value and the citizen's signature
    #: over hash([id, c]). Supervision material; never published.
    _requests: dict[str, SignedRequest] = field(default_factory=dict)
    _supervisor_downloads: int = 0
    #: id -> the blinded value it was reserved for. Internal; never published.
    _reserved: dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        population_register: CertificateLookup,
        bits: int = rsabssa.DEFAULT_MODULUS_BITS,
        election_id: str = "",
    ) -> "VRO":
        priv, pub = rsabssa.generate_vro_keypair(bits)
        return cls(
            private_key=priv,
            public_key=pub,
            population_register=population_register,
            office_key=keys.SigningKeyPair.generate(),
            election_id=election_id,
        )

    # -- the electoral register ----------------------------------------
    def stored_state(self) -> dict:
        """What `restore_releases` needs, taken without side effects.

        Not `supervision_dump()`, which counts itself: that method
        increments the published download figure, and an archive that
        called it would record a supervisor who never read anything.
        """
        return {
            "releases": [e.payload for e in self.release_log.entries],
            "head": b64(self.release_log.head()),
            "released": sorted(self._released),
            "openings": {k: b64(v) for k, v in self._openings.items()},
            "audit": [{"voter_id": a.voter_id, "outcome": a.outcome.value,
                       "reason": a.reason} for a in self._audit],
            "requests": {k: _request_to_stored(r)
                         for k, r in self._requests.items()},
            "self_enrolled": list(self._self_enrolled),
            "supervisor_downloads": self._supervisor_downloads,
        }

    def restore_releases(
        self,
        *,
        releases: list[dict],
        released: set[str],
        openings: dict[str, bytes],
        audit: list[AuditEntry],
        requests: dict[str, SignedRequest],
        supervisor_downloads: int,
        expected_head: bytes,
        self_enrolled: list[str] | None = None,
    ) -> None:
        """The office's register of a finished poll, rebuilt from storage.

        The commitments are replayed through `append`, so the chain is
        recomputed here rather than trusted, and the head that results must
        equal the head the office signed. A register that does not
        reproduce it is refused rather than served, for the same reason the
        box refuses an altered ledger: a surface that displays a record the
        signing party cannot stand behind is worse than one that displays
        nothing.

        The openings and the citizens' signed requests come back with it.
        They are supervision material and are never published (§3.7); what
        they make possible on a reloaded election is the voter's own
        token-request check and the supervisor's reading of the register,
        both of which are answers about a poll that has finished.

        **The openings are reordered onto the chain, not taken as given.**
        `_openings` is walked by `supervision_dump` to build the release
        list, and the head the office signed covers the order tokens were
        issued in -- so the mapping has to come back in that order. It did
        not. The poll is written with `canonical_bytes`, which sorts keys
        because canonical serialisation must; the openings came back
        sorted by identifier, and a supervisor reloading a finished poll
        was served a register that could not be chained to the head
        printed beside it. Every commitment recomputed and the sequence
        was somebody else's, which reads exactly like evidence of
        tampering and was a demonstration artefact.

        The fix belongs here rather than in the writer: sorted keys are
        what canonical bytes are *for*, and a serialisation that preserved
        insertion order to keep one consumer happy would be a worse thing
        than this loop. The ledger is the authority on order -- it is what
        the signature covers -- so the openings are threaded back onto it
        by commitment.
        """
        for payload in releases:
            self.release_log.append(payload)
        if self.release_log.head() != expected_head:
            raise ValueError(
                "the stored commitments do not reproduce the head the office "
                "signed; the release register has been altered"
            )
        self._released = set(released)
        self._openings = _in_chain_order(self.release_log, openings)
        self._audit = list(audit)
        self._requests = dict(requests)
        # Defaulted, because a poll written before clause S7 existed had
        # no such entries -- and an empty list is the truthful answer for
        # an office whose roll came entirely from outside it.
        self._self_enrolled = list(self_enrolled or [])
        self._supervisor_downloads = supervisor_downloads

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
        """Steps 5 -> 6/A -> 7, as one act.

        A composition of `reserve` and `release`, retained because that is
        what every caller outside an operator console wants: validate and
        sign with nothing in between.
        """
        reserved = self.reserve(request, now)
        if reserved.outcome is not Outcome.RESERVED:
            return reserved
        return self.release(request)

    def reserve(
        self, request: AuthRequest, now: datetime | None = None
    ) -> TokenResponse:
        """Step 5: validate, and claim the identifier.

        The claim is the point. Checking `_released` and then writing to it
        are two steps, and nothing between them is atomic: two requests for
        one identifier arriving together can both pass the check before
        either records, and both receive a token. Requirement 2 is then
        broken with nothing in the published artefacts to show it, because
        two commitments for one citizen are indistinguishable from two
        citizens — the aggregate audit still balances and the voter's own
        check still answers truthfully. There is no observer who could see
        it.

        So the identifier is claimed here, before anything else can claim
        it, and only the winner reaches `release`.

        **The reservation publishes nothing.** No commitment, no increment to
        the count, until the release itself. Were the pause visible in the
        published artefacts, a third party could tell an office that is
        deliberating from one that is not — a property the design does not
        offer and should not acquire by accident.

        Returns RESERVED on success, never ISSUED: no token exists yet, and
        saying otherwise would be false to the requester and false in the
        audit log.
        """
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
        return self._claim(request, revoked=cert.revoked,
                           expired=cert.is_expired(now))

    def _claim(
        self, request, *, revoked: bool, expired: bool
    ) -> TokenResponse:
        """Everything below the identity boundary, shared by both routes.

        Split out when the qualified-signature route arrived, and the split
        is the point rather than tidiness.  The two routes establish
        identity differently -- one looks a certificate up and checks an
        Ed25519 signature over `hash([id, c])`, the other reads the subject
        out of a qualified signature that arrived with the document -- and
        they must not differ by so much as a line in what they do
        afterwards.

        Requirement 2 is the reason.  One citizen gets one token, and if
        the second route kept its own `_released` set, a citizen could take
        a token by each and the published artefacts would show two
        commitments that no observer could tell from two citizens: the
        aggregate audit still balances, and each voter's own check answers
        truthfully.  There is no observer who could see it.  So the
        register, the released set and the reservations are reached through
        here and through nothing else.

        `revoked` and `expired` are passed rather than read, because the
        two routes learn them from different places and neither is this
        method's business.  What is its business is that they are reported
        *here*, below the boundary, and never above it.

        `request` needs only `voter_id`, `blinded_key` and `evidence`.
        Declared structurally for the same reason `CertificateLookup` is.
        """
        if revoked:
            return self._record(
                request.voter_id, Outcome.CERTIFICATE_REVOKED, "certificate revoked"
            )

        if expired:
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

        if request.voter_id in self._reserved:
            return self._record(
                request.voter_id,
                Outcome.REQUEST_PENDING,
                "a validated request for this id is awaiting release",
            )

        # The claim. Everything above is a check; this is the act that makes
        # the checks mean something under concurrency.
        self._reserved[request.voter_id] = request.blinded_key
        self._audit.append(
            AuditEntry(request.voter_id, Outcome.RESERVED, "validated and reserved")
        )
        return TokenResponse(outcome=Outcome.RESERVED, blind_signature=None)

    # ------------------------------------------------------------------
    # The qualified-signature route
    # ------------------------------------------------------------------
    def interpret_signed_document(
        self, document: bytes
    ) -> tuple[DocumentRequest | None, TokenResponse | None]:
        """Step 5, as far as identity and the request go. Entitlement is `_claim`.

        The same state machine as `reserve`, with the first two steps
        answered by a different service:

            1. validate the signature against the trust anchors
                 fails    -> NOT_IDENTIFIED
            2. read the subject, and compose the identifier from it
                 nothing  -> NOT_IDENTIFIED
            ---- the identity boundary ----
            3. the document is what its payload renders to, and the
               signature covers all of it
                 fails    -> DOCUMENT_REFUSED, with the reason

        Both pre-boundary failures collapse into one opaque outcome, for
        the reason they do on the other route: an unauthenticated party
        must not learn from this endpoint whether a certificate is known,
        and here they must not learn whether one is *trusted* either.

        **The document check sits below the boundary and above
        eligibility**, which is an order with an argument behind it. A
        qualified signature has already established who is being spoken to,
        so saying "that is not a token request" costs nothing and a citizen
        who is told nothing can do nothing. And it answers *what was
        asked* before the office begins deciding whether to grant it: a
        file that is not a token request is not a request this office has
        received, whatever the sender may be entitled to.

        What it does **not** do is read the document to find out who sent
        it. The identifier comes from the signing certificate and never
        from a field in the payload; a document saying whose it is would
        be a document anyone could write. See
        `identity_taken_from_the_document` in `tools/sabotage.py`.
        """
        if self.signature_validation is None:
            raise RuntimeError(
                "this office offers no qualified-signature route: nothing "
                "was injected to validate a signature with"
            )

        found = self.signature_validation.validate(document)
        if not isinstance(found, pdfrequest.ValidatedSignature):
            # One answer to the requester, the true reason in the log. The
            # office records why for every other refusal it makes and this
            # one was the exception: a single sentence covering every way a
            # signature can fail to establish anybody, which left the
            # operator's own log as blind as the citizen's answer. §3.2 is
            # about what is *disclosed*; it never asked the office to stop
            # knowing. See `pdfrequest.SignatureRefused`.
            return None, self._record(
                "", Outcome.NOT_IDENTIFIED,
                found.reason if found is not None else
                "no valid signature over this document, or none that chains "
                "to a trusted anchor — the validator gave no further detail",
            )
        if not found.identifier:
            return None, self._record(
                "", Outcome.NOT_IDENTIFIED,
                "the signing certificate carries nothing that identifies its "
                "subject to this office",
            )

        # ==== THE IDENTITY BOUNDARY ====
        # Nothing above this line may report a specific reason, and nothing
        # below it may be reached without a signature that verified and
        # chained. Moving a check across it is a privacy regression, not a
        # refactor -- the same sentence as in `reserve`, and the same rule.
        checked = pdfrequest.check(
            document, covered_prefix_length=found.covered_prefix_length)
        if not checked.accepted:
            return None, self._record(
                found.identifier, Outcome.DOCUMENT_REFUSED,
                f"the signed document was refused: {checked.refusal.value}",
            )

        return DocumentRequest(
            voter_id=found.identifier,
            blinded_key=unb64(checked.payload["blinded_key"]),
            document=document,
            revoked=bool(found.revoked),
            expired=bool(found.expired),
            # Not `bool(...)`: `None` has to survive as `None`, because an
            # office with no trusted list did not look and must not be
            # recorded as having found the signature unqualified.
            qualified=found.qualified,
        ), None

    def reserve_signed_document(
        self, document: bytes
    ) -> tuple[TokenResponse, DocumentRequest | None]:
        """Step 5 on the second route: validate, and claim the identifier.

        Returns the request alongside the outcome because `release` needs
        it, exactly as the caller on the other route holds the
        `AuthRequest` it built.
        """
        request, refusal = self.interpret_signed_document(document)
        if request is None:
            return refusal, None
        self._enrol_on_signature(request)
        return self._claim(request, revoked=request.revoked,
                           expired=request.expired), request

    def _enrol_on_signature(self, request: "DocumentRequest") -> None:
        """Clause S7. Before `_claim`, and deliberately not inside it.

        `_claim` is everything below the identity boundary and must not
        differ by a line between the two routes -- so this runs *before*
        it, adds the identifier, and leaves `_claim` to find a citizen on
        the register exactly as it would have found one an operator put
        there. Every check afterwards is the same check: one token per
        identifier, one commitment, one chain.

        Recorded as it happens. An office that quietly grew its own
        electoral register would be the single most consequential thing on
        this page to leave unsaid.
        """
        if not self.enrol_on_qualified_signature:
            return
        if request.voter_id in self.register:
            return
        self.register.add(request.voter_id)
        self._self_enrolled.append(request.voter_id)
        self._audit.append(AuditEntry(
            request.voter_id, Outcome.RESERVED,
            "enrolled on the strength of their own qualified signature "
            "(clause S7); this office was not given a roll naming them"))

    def issue_token_for_signed_document(self, document: bytes) -> TokenResponse:
        """Steps 5 -> 6/A -> 7 on the second route, as one act.

        The counterpart of `issue_token`, and it reaches the same
        `release`: one hash chain, one released set, one register of
        openings. A citizen who has taken a token by either route has taken
        their token.
        """
        reserved, request = self.reserve_signed_document(document)
        if reserved.outcome is not Outcome.RESERVED:
            return reserved
        return self.release(request)

    def cancel_reservation(self, voter_id: str) -> bool:
        """Release a claim that will never complete.

        In a console an operator abandons a request; in production the gap is
        closed by a crash. Either way a citizen is left reserved with nothing
        published, no token, and no way to ask again. §5.5 already requires a
        documented re-issuance path with an audit trail for the case where
        the voter's own verification fails; this is the second caller for it.
        """
        if voter_id not in self._reserved:
            return False
        del self._reserved[voter_id]
        self._audit.append(
            AuditEntry(voter_id, Outcome.RESERVED, "reservation cancelled")
        )
        return True

    @property
    def pending(self) -> tuple[str, ...]:
        """Identifiers validated and awaiting release. Never published."""
        return tuple(sorted(self._reserved))

    def release(self, request: AuthRequest) -> TokenResponse:
        """Steps 7 and 6/A: record the release, then sign.

        Only reachable for an identifier this office has reserved.
        """
        if self._reserved.get(request.voter_id) != request.blinded_key:
            return self._record(
                request.voter_id,
                Outcome.NOT_ELIGIBLE,
                "no matching reservation for this id and blinded value",
            )
        del self._reserved[request.voter_id]

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
        #     because the opening value is disclosed only on an authenticated query.
        #
        # The second matters because absence of a release is proof of
        # non-voting, which is exactly what a coercer demanding turnout wants.
        opening = secrets.token_bytes(32)
        self._openings[request.voter_id] = opening
        self._released.add(request.voter_id)

        # The request itself is kept, not discarded once it has been checked.
        #
        # It is the one object in the whole exchange the office cannot
        # manufacture: `s` is the citizen's own signature, under a key a
        # certification authority binds to them. A release the office minted
        # for somebody who never asked has no `s` to show, and a supervisor
        # reading this record finds that out for every citizen at once --
        # including the ones who abstain and never perform their own check,
        # which is the only case the published artefacts cannot reach.
        #
        # What is kept is larger than what is published. The commitment says
        # a token was released for an identifier; the signature says that
        # citizen asked for it, non-repudiably and permanently. It discloses
        # no more about the ballot: the blinding means nothing here reveals
        # whether the token was ever used, let alone for what. Absence from
        # this register is conclusive; presence is not (Section 3.7).
        self._requests[request.voter_id] = request.evidence
        self.release_log.append({"commitment": b64(commit(request.voter_id, opening))})

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

        An affirmative answer discloses the opening value, so the voter can verify the
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
        opening = self._openings.get(voter_id)
        if opening is None:
            return ReleaseAnswer(
                ReleaseOutcome.NOT_RELEASED,
                signed_denial=self.office_key.sign(denial_payload(voter_id)),
            )

        target = b64(commit(voter_id, opening))
        index = next(
            i for i, e in enumerate(self.release_log.entries)
            if e.payload["commitment"] == target
        )
        return ReleaseAnswer(ReleaseOutcome.RELEASED, opening=opening, index=index)

    def release_count(self) -> int:
        """Public: how many tokens were released in total.

        Enough for the aggregate audit, and it names nobody.
        """
        return len(self.release_log)

    def supervision_dump(self) -> dict:
        """The register with the identifiers in it.

        No supervisor list, no signature, no nonce. The protection is the
        perimeter: this is served on an origin reachable only from inside
        the operator's network, and whoever can reach it is a supervisor by
        construction. That is both how it would be deployed and the only
        honest thing to build for a demonstration -- a registry and a
        signature scheme here would have been protecting a proof of concept
        from nobody.

        What it catches, and the limits decide which remedy answers which
        failure:

          * a release naming somebody not entitled to vote -- invisible in
            the published artefacts, which carry opaque commitments alone;
          * two releases for one identifier, which is the atomicity failure
            of Section 5.4. Still not preventable and still invisible to the
            public, but demonstrable afterwards to somebody.

          * a release with no signed request behind it. The register
            retains the citizen's own signature over `hash([id, c])`, which
            is the one object in the exchange the office cannot
            manufacture, so a release nobody asked for can be exhibited as
            such -- for every citizen at once, and whether or not any of
            them performs the check of Section 3.7.

        What it does not catch is a release a citizen genuinely asked for
        and then handed on. The request is real, the signature is real, the
        commitment is real, and nothing that inspects records will find a
        transaction the records faithfully describe. That residual is a
        vote sale rather than a dishonest office, it does not require the
        office at all, and no scheme certifying eligibility before the
        ballot exists is free of it.

        The electoral register is not in here. A supervisor comparing these
        identifiers against a roll this office supplied would be comparing
        the office against its own copy; the roll comes from the citizen
        registry, with current eligibility, or the comparison is worth
        nothing.
        """
        self._supervisor_downloads += 1
        head, head_signature = self.signed_release_head()
        count, count_signature = self.signed_release_count()
        self_enrolled = set(self._self_enrolled)
        return {
            # Clause S7, published rather than inferred. A supervisor
            # comparing this register against a roll from the citizen
            # registry has to know which entries that roll was never asked
            # about -- otherwise the check reads as a mismatch in the
            # roll, which is exactly backwards.
            "enrol_on_qualified_signature": self.enrol_on_qualified_signature,
            "self_enrolled": sorted(self_enrolled),
            "releases": [
                {"index": i, "voter_id": voter_id, "opening": b64(opening),
                 "commitment": b64(commit(voter_id, opening)),
                 "self_enrolled": voter_id in self_enrolled,
                 **_request_for_supervision(self._requests[voter_id])}
                if voter_id in self._requests else
                {"index": i, "voter_id": voter_id, "opening": b64(opening),
                 "commitment": b64(commit(voter_id, opening)),
                 "self_enrolled": voter_id in self_enrolled}
                for i, (voter_id, opening) in enumerate(self._openings.items())
            ],
            "audit": [
                {"voter_id": e.voter_id, "outcome": e.outcome.name,
                 "reason": e.reason}
                for e in self._audit
            ],
            "head": head.hex(),
            "head_signature": b64(head_signature),
            "count": count,
            "count_signature": b64(count_signature),
        }

    @property
    def supervisor_downloads(self) -> int:
        """Published, so the office cannot hand the register out quietly."""
        return self._supervisor_downloads

    def signed_release_head(self) -> tuple[bytes, bytes]:
        """The head of the release register, and the office's statement on it."""
        head = self.release_log.head()
        return head, self.office_key.sign(
            release_head_payload(self.election_id, head))

    def signed_release_count(self) -> tuple[int, bytes]:
        """The count, and the office's statement that it is the count."""
        count = self.release_count()
        return count, self.office_key.sign(
            release_count_payload(self.election_id, count))
