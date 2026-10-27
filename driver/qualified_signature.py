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

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from datetime import datetime, timezone
from pathlib import Path

from ovpoc.pdfrequest import SignatureRefused, ValidatedSignature

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


def _off_the_event_loop(call, /, *args, **kwargs):
    """Run something that calls `asyncio.run()` inside itself.

    pyHanko's `validate_pdf_signature` is a thin synchronous wrapper
    around an async implementation, and `asyncio.run` refuses to start a
    loop when one is already running. The office's upload endpoint is an
    `async def` -- it has to be, it streams the request body to cap the
    size before reading it -- so on a server every real upload met
    `RuntimeError: asyncio.run() cannot be called from a running event
    loop` and was answered NOT_IDENTIFIED, while the same validator run
    from a script on the same file returned a perfectly good signer.

    The seam is declared synchronous and `src/ovpoc` must stay free of
    transport concerns, so the fix belongs on this side of it: a method
    this office calls has to be callable from wherever the office is,
    and a worker thread with no loop of its own is what makes that true.

    Unconditionally, rather than only when a loop is running. A branch
    would mean the tests take one path and the service the other, which
    is precisely how this survived a suite that tested both halves of
    the join and never the join.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(partial(call, *args, **kwargs)).result()


class TrustAnchorsRefused(Exception):
    """The pinned anchors are not the ones the manifest records.

    Not a protocol outcome and never reported to a requester: it says the
    office's own configuration has been altered, which is an operator's
    problem and nobody else's business.
    """


class ValidatorUnavailable(RuntimeError):
    """Anchors are pinned and nothing installed here can act on them.

    An office is in one of three states and only two of them are honest.
    With no anchors it offers no qualified-signature route, and says so.
    With anchors and the `pades` extra it offers the route and performs
    it. With anchors and no extra it would offer a route it cannot carry
    out -- and the failure would arrive as an unhandled import error in
    the middle of a citizen's upload, after the office had told them the
    route was open.

    So it is raised at load. A deployment configured for something it
    cannot do should not start, for the same reason a swapped anchor
    should not: an office that comes up wrong looks like an office.
    """


#: The top-level distributions the `pades` extra provides. Probed at load
#: so a misconfigured office fails there; imported for real inside
#: `validate`, which is the only thing that needs them.
#: `test_qualified_signature.py` reads `validate`'s own imports and
#: requires this tuple to cover them, so the two cannot drift apart.
PADES_MODULES = ("asn1crypto", "pyhanko", "pyhanko_certvalidator")


def require_validator() -> None:
    """Fail now if the extra is missing. See `ValidatorUnavailable`."""
    import importlib

    for name in PADES_MODULES:
        try:
            importlib.import_module(name)
        except ImportError as exc:
            raise ValidatorUnavailable(
                "this office has pinned trust anchors and nothing to "
                f"validate a signature with: {name} is not installed. "
                'Install the extra -- pip install -e ".[pades]" -- or '
                "remove the anchor directory, which turns the "
                "qualified-signature route off rather than breaking it."
            ) from exc


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

    #: The manifest naming every anchor and its digest.
    MANIFEST = "MANIFEST.json"
    SUFFIXES = (".cer", ".crt", ".der")

    trust_roots: tuple[bytes, ...] = ()
    #: Off. An office that turns this on reaches the certification authority
    #: from the machine that holds the electoral register, and reveals to it
    #: which certificates it is asking about.
    allow_fetching: bool = False
    #: Extra revocation material, DER-encoded, for a deployment that has
    #: fetched it out of band. The DSS inside a signed document is used
    #: whether or not this is supplied.
    crls: tuple[bytes, ...] = ()

    #: What the manifest said about each anchor, kept so the office can be
    #: asked what it is willing to believe. Public certificates, their
    #: digests and where they were fetched from: there is nothing here to
    #: withhold, and an office whose anchors cannot be read is an office
    #: nobody can check. Empty when the validator was built directly, as
    #: the tests build it.
    anchors: tuple[dict, ...] = ()
    #: The directory they were read from, and the day the operator pinned
    #: them. Reported as configuration, not as evidence.
    pinned_from: str = ""
    pinned_on: str = ""

    @classmethod
    def from_pinned(cls, path: Path, **kwargs) -> "QualifiedSignatureValidation":
        """The anchors an operator pinned, checked against their manifest.

        The directory is the artefact an operator produces out of band --
        `tools/fetch_trust_anchors.py` writes it -- and the office then
        reads offline.  What it contains is the whole of what this office
        is willing to believe about who signed a request, so it is the
        shortest and most consequential configuration file in the project.

        **The digests are checked and a mismatch refuses to load.**  An
        anchor directory is a folder of certificates on a server, and a
        certificate quietly added or swapped there is an office that will
        accept signatures from a new authority without anybody noticing:
        nothing downstream would look wrong, because a signature under a
        trusted anchor is exactly what a valid request looks like. The
        manifest is what makes a change visible, and it is worth nothing
        unless loading enforces it.

        Failing here rather than later is deliberate. An office that
        started up and then refused every request would look like a broken
        wallet; an office that started up having silently trusted an
        unverified anchor would look like nothing at all. The same
        argument is why the `pades` extra is probed here rather than met
        on a citizen's first upload -- see `ValidatorUnavailable`.
        """
        require_validator()
        manifest_path = path / cls.MANIFEST
        if not manifest_path.exists():
            raise TrustAnchorsRefused(
                f"{path} has no {cls.MANIFEST}: an anchor directory without "
                f"one is a folder of certificates nobody has vouched for"
            )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        roots: list[bytes] = []
        for entry in manifest.get("anchors", []):
            anchor = path / entry["file"]
            if not anchor.exists():
                raise TrustAnchorsRefused(
                    f"{entry['file']} is in {cls.MANIFEST} and not in {path}")
            der = anchor.read_bytes()
            actual = hashlib.sha256(der).hexdigest()
            if actual != entry["sha256"]:
                raise TrustAnchorsRefused(
                    f"{entry['file']} is not the certificate this office "
                    f"pinned: the manifest says {entry['sha256'][:16]}… and "
                    f"the file is {actual[:16]}…"
                )
            roots.append(der)

        # Named in the manifest and absent from it are different, and so
        # are a stray file and a swapped one. A certificate nobody recorded
        # is not an anchor this office pinned.
        recorded = {e["file"] for e in manifest.get("anchors", [])}
        stray = sorted(p.name for p in path.iterdir()
                       if p.suffix.lower() in cls.SUFFIXES and p.name not in recorded)
        if stray:
            raise TrustAnchorsRefused(
                f"{path} holds certificates no manifest entry accounts for: "
                f"{', '.join(stray)}"
            )
        return cls(
            trust_roots=tuple(roots),
            anchors=tuple(manifest.get("anchors", [])),
            pinned_from=str(path),
            pinned_on=str(manifest.get("pinned", "")),
            **kwargs,
        )

    # ------------------------------------------------------------------
    def validate(
        self, document: bytes
    ) -> ValidatedSignature | SignatureRefused:
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
        except Exception as exc:  # noqa: BLE001
            # Anything a malformed file can throw is the same answer. The
            # office does not owe a parse error to an unidentified party,
            # and `pdfrequest.check` will not have been reached. It owes
            # the operator one, which is what the refusal carries.
            return SignatureRefused(
                f"the file could not be read as a PDF: "
                f"{type(exc).__name__}: {exc}")
        if not signatures:
            return SignatureRefused(
                "the file is a readable PDF and carries no signature at all")

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
            status = _off_the_event_loop(
                validate_pdf_signature, embedded,
                signer_validation_context=context)
        except Exception as exc:  # noqa: BLE001
            return SignatureRefused(
                f"the validator raised while checking the signature: "
                f"{type(exc).__name__}: {exc}")

        # ---- above the identity boundary: one answer, no detail ----
        #
        # `intact` is the document's digest; `valid` is the signature over
        # it. Either failing means nobody has been identified at all.
        if not (status.intact and status.valid):
            return SignatureRefused(
                "the bytes the signature covers have changed since it was "
                "made" if not status.intact else
                "the signature does not verify under the certificate it "
                "names")

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
            # `trust_problem_indic` is pyHanko's own word for what went
            # wrong on the path, and it is the single most useful line an
            # operator can be given: it separates "this office pinned the
            # wrong root" from "this citizen's certificate is not one we
            # were ever meant to accept".
            return SignatureRefused(
                "the signing certificate does not chain to any anchor this "
                f"office has pinned ({status.trust_problem_indic}); the "
                f"office trusts {len(self.trust_roots)} root(s) from "
                f"{self.pinned_from or 'an unrecorded directory'}")

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
