"""Validating a qualified electronic signature -- infrastructure, not design.

The second occupant of `driver/`, and it is here for the reason the first one
is.  `population_register.py` answers "who is this id, and under which key do
they sign?"; this answers "who signed these bytes, and may that signature be
believed?".  Both are services that exist in law and are operated by somebody
else, and §3.2 keeps what the design *builds* distinct from what it *assumes*.

On the qualified-signature route this module **replaces** the population
register rather than joining it.  There is no lookup: the certificate arrives
with the signature, and the office reads the subject from it.  That is closer
to §3.2 than the first route manages, because the office stops consulting a
directory about a name somebody claimed and starts reading the name out of
the credential that did the signing.

WHY THIS IS NOT WRITTEN BY HAND
-------------------------------
The settled position is that validating the signature is EU infrastructure
and mandatory to use.  Doing it here would mean CMS SignedData, signed
attributes, the ESS signing-certificate binding, timestamp tokens, path
building and trust-list parsing -- and hand-rolled CMS verification is a
well-known way to produce something that verifies everything, forgeries
included.  So pyHanko does it, behind the one-method seam
`ovpoc.pdfrequest.SignatureValidation`, and a fake implementing that seam is
all the test suite needs for everything upstream of here.

**What this library is trusted for is narrower than it looks.**  It answers
four questions: does a signature cover bytes 0 to n, does it verify, does the
certificate chain to a trust anchor, and who signed.  It is *not* trusted for
what the document says -- `pdfrequest.check` recomputes the document from the
payload it recovered and compares bytes, so a parsing bug upstream can cause
a wrong refusal and never a wrong acceptance.  That is the whole reason a
dependency of this size was acceptable.

THE IDENTITY BOUNDARY, WHICH THIS MODULE MUST NOT MOVE
-------------------------------------------------------
`vro.py` sets out why revocation is reported *after* the signature verifies
and not before, and `tools/sabotage.py` carries two mutations to catch a
refactor that reorders it.  The same boundary runs through here, and a
validator is exactly the place it would be lost by accident, because every
validation library in existence reports "revoked" as a failure.

It is not a failure for this office.  A revoked certificate still verifies
mathematically; the signature is as valid as it ever was and it still names
its signer.  So:

  * the signature does not verify, or chains to nothing trusted
        -> `None`, which the office reports as one opaque refusal;
  * the signature verifies and the certificate is revoked or expired
        -> a `ValidatedSignature` saying so, which the office may disclose
           because by then it knows who it is talking to.

Observed, not assumed: pyHanko reports a revoked signer with `intact=True`,
`valid=True`, `bottom_line=False` and `revocation_details` populated.  The
discriminator below is `revocation_details`, not `bottom_line`.

TRUST ANCHORS
-------------
Supplied at construction, never fetched during validation.  pyHanko splits
`eutl_fetch` from `eutl_parse` precisely so that obtaining the European trust
list can be an operator action producing a dated file, and validation can
then run offline against it.  That is also the better demonstration artefact:
a reader can see which list was pinned and when, which a live fetch would not
show them.

It is affordable because of what the wallet turned out to do.  Every document
DAP signs carries a `/DSS` with the certificates and OCSP responses in it, so
the revocation material travels in the file and the office does not have to
reach the certification authority at validation time.  The DSS is itself
unsigned -- there is no document timestamp over it -- so it is a convenience
and not evidence: the OCSP responses carry their own signatures and are
verified, never trusted for being present.

WHAT IS NOT HERE
----------------
No network, by default.  `allow_fetching` exists and is off, and an office
that turns it on is reaching the certification authority from a machine that
also holds the electoral register.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ovpoc.pdfrequest import ValidatedSignature

#: The subject attributes this office reads, in the form `asn1crypto` names
#: them.  Everything else in a distinguished name is left alone.
SUBJECT_FIELDS = ("country_name", "serial_number", "common_name",
                  "given_name", "surname", "organization_name")


def subject_identifier(subject: dict[str, str]) -> str | None:
    """The `id` the office will look for on its electoral register.

    **The serial number, never the common name.**  Names collide, are not
    identifiers, and change; a certificate's `serialNumber` attribute is the
    field the certification authority allocates for exactly this purpose.

    Qualified by country, because the serial is not globally unique.  A real
    DAP certificate carries a bare nine-digit number rather than the
    semantic form of ETSI EN 319 412-1 -- there is no `PNOHU-` prefix on it --
    so it is scoped to the issuing scheme and means nothing on its own.
    `HU-471570820` is this project's composition of the two, and it is a
    decision rather than a standard.

    It also leaves a question open that the fixture register never posed,
    because the fixture invented both sides of it: the electoral register
    derives from civil registration under the law of the jurisdiction, and
    nothing here maps a civil record to one of these identifiers.  The first
    route never met the problem -- it looked an id up and got a key back. See
    the gaps list in `docs/wire-contract.md`.
    """
    serial = subject.get("serial_number")
    country = subject.get("country_name")
    if not serial or not country:
        return None
    return f"{country}-{serial}"


@dataclass
class QualifiedSignatureValidation:
    """pyHanko, behind `ovpoc.pdfrequest.SignatureValidation`.

    `trust_roots` are DER-encoded certificates: the anchors a signature must
    chain to.  In a demonstration they come from a dated snapshot of the
    European trust list; in a test they are one invented certification
    authority.  An empty list trusts nothing and every signature is
    unidentified, which is the correct behaviour for an office that has not
    been told what to trust and is better than a default that trusts the
    host's certificate store.
    """

    trust_roots: tuple[bytes, ...] = ()
    #: Off. An office that turns this on reaches the certification authority
    #: from the machine that holds the electoral register, and reveals to it
    #: which certificates it is asking about.
    allow_fetching: bool = False
    #: Extra revocation material, DER-encoded, for a deployment that has
    #: fetched it out of band. The DSS inside a signed document is used
    #: whether or not this is supplied.
    crls: tuple[bytes, ...] = ()

    @classmethod
    def from_directory(cls, path: Path, **kwargs) -> "QualifiedSignatureValidation":
        """Every `.cer`/`.crt`/`.der` under a pinned trust-list directory.

        The directory is the artefact an operator produces out of band and
        the office then reads offline. Its name and date are what a reader
        inspects to see what this office was willing to believe.
        """
        roots = tuple(
            p.read_bytes()
            for p in sorted(path.iterdir())
            if p.suffix.lower() in (".cer", ".crt", ".der")
        )
        return cls(trust_roots=roots, **kwargs)

    # ------------------------------------------------------------------
    def validate(self, document: bytes) -> ValidatedSignature | None:
        # Imported here rather than at module scope so that `driver` stays
        # importable without the `pades` extra. The office that does not use
        # this route should not need a PDF library installed to start.
        import io

        from asn1crypto import crl as asn1_crl, x509 as asn1_x509
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext

        try:
            # `strict=False`, and the reason is the whole of the note below
            # on what this office does and does not ask. A real DÁP-signed
            # document is refused outright by the strict reader --
            # `PdfStrictReadError: XRef stream objects must not be clobbered`
            # -- because the update the wallet appends after signing reuses
            # an object number that held a cross-reference stream. Every
            # genuine request would be answered NOT_IDENTIFIED, and the
            # office would have been refusing the only wallet it is built
            # for.
            reader = PdfFileReader(io.BytesIO(document), strict=False)
            signatures = reader.embedded_signatures
        except Exception:  # noqa: BLE001
            # Anything a malformed file can throw is the same answer. The
            # office does not owe a parse error to an unidentified party,
            # and `pdfrequest.check` will not have been reached.
            return None
        if not signatures:
            return None

        # The first signature in the file, which is the one that signed the
        # document the citizen was shown. A later one signs that plus
        # whatever the first signer appended, and is somebody else's
        # statement about a document this office never rendered.
        embedded = signatures[0]

        context = ValidationContext(
            trust_roots=[asn1_x509.Certificate.load(r) for r in self.trust_roots],
            crls=[asn1_crl.CertificateList.load(c) for c in self.crls] or None,
            allow_fetching=self.allow_fetching,
            # Soft, deliberately. Hard-fail turns "no revocation information
            # was available" into a refusal, and this office reports what it
            # found rather than refusing for what it could not look up. What
            # it *did* find is reported below and is not softened.
            revocation_mode="soft-fail",
        )
        try:
            status = validate_pdf_signature(embedded,
                                            signer_validation_context=context)
        except Exception:  # noqa: BLE001
            return None

        # ---- above the identity boundary: one answer, no detail ----
        #
        # `intact` is the document's digest; `valid` is the signature over
        # it. Either failing means nobody has been identified at all.
        if not (status.intact and status.valid):
            return None

        revoked = status.revocation_details is not None
        expired = _expired(status)

        # Trust, and `trusted` rather than `bottom_line`. The difference is
        # one question: `bottom_line` also folds in the modification
        # analysis -- were the changes made *after* signing acceptable? --
        # and this office does not ask it, because it does not read them.
        # It decides on the prefix it recomputed and disregards everything
        # past it, so what a later revision did to the document cannot
        # change what the document requests.
        #
        # Not a theoretical allowance. The update DÁP appends after signing
        # frees an object, and pyHanko's reject-by-default diff policy
        # returns `bottom_line=False` for it with `trusted=True` and
        # `trust_problem_indic=None` -- the chain is perfect and the
        # verdict is about the wallet's own housekeeping. Inheriting it
        # would refuse every genuine request.
        #
        # Revocation and expiry are subtracted for the separate reason at
        # the top of this module. Anything else that made `trusted` false
        # -- no path to an anchor, an untrusted root, a broken chain -- is
        # a pre-identity failure and gets the opaque answer.
        if not status.trusted and not (revoked or expired):
            return None

        subject = {k: str(v) for k, v in
                   dict(status.signing_cert.subject.native).items()
                   if k in SUBJECT_FIELDS}
        return ValidatedSignature(
            subject=subject,
            identifier=subject_identifier(subject),
            covered_prefix_length=_covered_prefix(embedded),
            signing_time=_signing_time(status),
            revoked=revoked,
            expired=expired,
            # Only a trust list can answer this, and only pyHanko's
            # incubating ETSI support reads one. Absent that, `None` --
            # the office does not get to use the word on its own authority.
            qualified=(None if status.qualification_result is None
                       else bool(status.qualification_result.qualified)),
        )


def _covered_prefix(embedded) -> int:
    """How many bytes from the start of the file the signature covers.

    A PAdES `/ByteRange` is `[0, a, b, c]`: the signature cannot cover its
    own `/Contents`, so the gap between `a` and `b` is the hole where it
    sits. What the office needs is `a` -- the length of the unbroken run
    from byte zero -- because that is what it compares against the document
    it rebuilt.

    A range that does not start at zero covers none of the prefix, and zero
    is the honest number for it rather than an exception: the office's own
    rule will then refuse, and it refuses for the reason that is true.
    """
    try:
        byte_range = [int(n) for n in embedded.byte_range]
    except (TypeError, ValueError):
        return 0
    if len(byte_range) < 2 or byte_range[0] != 0:
        return 0
    return byte_range[1]


def _signing_time(status) -> datetime | None:
    """The timestamp's time, and the signer's claim only if there is no timestamp.

    A time the signer asserts is a time the signer chose. DAP attaches a
    qualified timestamp, so the honest value is almost always available;
    where it is not, the claim is returned and the caller can see from the
    absence of a timestamp what it is worth.
    """
    timestamp = status.timestamp_validity
    if timestamp is not None and timestamp.timestamp is not None:
        return timestamp.timestamp
    return status.signer_reported_dt


def _expired(status) -> bool:
    """Whether the signing certificate had expired when it was used.

    Computed here rather than read off the verdict, because the verdict
    folds expiry together with half a dozen other reasons a path can fail
    and this office has to tell them apart.

    Against the signing time where there is one, because that is the
    question that matters: a certificate valid when it signed does not
    become invalid later, which is what timestamps are for.
    """
    cert = status.signing_cert
    not_before = cert['tbs_certificate']['validity']['not_before'].native
    not_after = cert['tbs_certificate']['validity']['not_after'].native
    at = _signing_time(status) or datetime.now(timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return not (not_before <= at <= not_after)
