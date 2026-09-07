"""The population register -- an external identity service, not a component.

Under eIDAS a citizen's qualified certificate already binds their signature
key to them as a named person, and that binding is maintained by a
certification authority.  The Voter Registration Office is therefore an
ordinary relying party: it looks a certificate up, and it verifies a signature
against the key that certificate attests.  It stores no copy of that
association, which is what keeps the register schema at `[id]` alone (§5.1).

Two roles that are easy to conflate, and which the code keeps apart:

  * the **population register** -- this module -- answers "who is this `id`,
    and under which key do they sign?"  It is identity infrastructure, shared
    with every other e-government service, and it knows nothing about
    elections;

  * the **electoral register** -- `VRO.register` -- answers "may this person
    vote?"  It is the election authority's own list, and the VRO administers
    it (§3.2).

The certificate is returned whole rather than as a bare public key, so that
revocation status and subject identity travel with it.  The office has to
check both, and a service that returned only a key would leave it unable to.

WHAT THIS IS NOT.  A real lookup would go to a national directory or answer
against published trust lists, the certificate would be an X.509 structure
with a chain to a trust anchor, and revocation would be an OCSP or CRL
question rather than a boolean.  None of that changes the protocol, and all of
it would obscure the part that matters here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Certificate:
    """A qualified certificate, reduced to the four fields the VRO consults.

    `subject` is the person the certificate names, `public_key` the raw
    Ed25519 key it attests (k_p^(v)), `not_after` its expiry, and `revoked`
    whether the certification authority has withdrawn it.

    Note that a revoked certificate still *verifies* mathematically: the key
    is unchanged, and a signature under it is as valid as it ever was.  That
    is why revocation cannot be treated as an identity failure, and why the
    VRO may report it only after the signature has verified -- by then the
    office does know who it is speaking to.  See `vro.issue_token`.
    """

    subject: str
    public_key: bytes
    not_after: datetime
    revoked: bool = False

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or _now()) >= self.not_after


@dataclass
class PopulationRegister:
    """A stand-in for the national identity service.

    `lookup` is the whole of the interface the VRO uses; everything else on
    this class exists so that a test or a demo can arrange the world.
    """

    _entries: dict[str, Certificate] = field(default_factory=dict)

    # -- the interface the VRO depends on ------------------------------
    def lookup(self, person_id: str) -> Certificate | None:
        """Return the certificate for `person_id`, or None if there is none.

        A single opaque None for every failure: no such person, no
        certificate on file, a withdrawn enrolment.  The office cannot
        distinguish them and has no business doing so -- it has not yet
        established that it is talking to anybody at all.
        """
        return self._entries.get(person_id)

    # -- arranging the world, for tests and demos ----------------------
    def enrol(
        self,
        person_id: str,
        public_key: bytes,
        *,
        valid_for: timedelta = timedelta(days=365),
        revoked: bool = False,
        not_after: datetime | None = None,
    ) -> Certificate:
        cert = Certificate(
            subject=person_id,
            public_key=public_key,
            not_after=not_after or (_now() + valid_for),
            revoked=revoked,
        )
        self._entries[person_id] = cert
        return cert

    def revoke(self, person_id: str) -> Certificate:
        """Withdraw a certificate, leaving its key intact."""
        cert = self._entries[person_id]
        replacement = Certificate(
            subject=cert.subject,
            public_key=cert.public_key,
            not_after=cert.not_after,
            revoked=True,
        )
        self._entries[person_id] = replacement
        return replacement

    def expire(self, person_id: str) -> Certificate:
        """Backdate a certificate's expiry, leaving its key intact."""
        cert = self._entries[person_id]
        replacement = Certificate(
            subject=cert.subject,
            public_key=cert.public_key,
            not_after=_now() - timedelta(days=1),
            revoked=cert.revoked,
        )
        self._entries[person_id] = replacement
        return replacement

    def withdraw(self, person_id: str) -> None:
        """Remove the entry entirely -- the person becomes unidentifiable."""
        self._entries.pop(person_id, None)
