"""The validator in `driver/`, and the boundary it must not move.

Everything here is about one decision: which failures are *refusals* and
which are *findings*. `vro.py` argues it at length for the first route --
a revoked certificate still verifies mathematically, so by the time anyone
can see revocation they already know who they are speaking to, and reporting
it before identity would turn the office's endpoint into an electoral-roll
lookup for anyone who can spell an identifier. Two mutations in
`tools/sabotage.py` exist to catch a refactor that reorders it.

A signature validator is the likeliest place in the project to lose that
boundary by accident, because every validation library reports "revoked" as
a failure and pyHanko is no exception: it returns `bottom_line=False` for a
revoked signer exactly as it does for one that chains to nothing. Subtracting
revocation and expiry from that verdict, and nothing else, is the whole of
what `QualifiedSignatureValidation.validate` adds to the library, so it is
the bulk of what is tested here.

The certificates are invented and so is the authority that issued them. They
are built in-process rather than committed, because a committed CRL has a
`next_update` and would become a test that fails on a date nobody chose.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import logging
import re

import pytest

from ovpoc import pdfrequest
from ovpoc.pdfrequest import (
    SignatureRefused, SignatureValidation, ValidatedSignature)

pyhanko = pytest.importorskip(
    "pyhanko", reason="the pades extra is not installed")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from driver.qualified_signature import (  # noqa: E402
    QualifiedSignatureValidation, subject_identifier,
)

# pyHanko logs every path failure at ERROR, and three of the tests below
# cause one on purpose. Quieted so that a real failure is visible.
logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)

SERIAL = "471570820"
DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM


def _c() -> bytes:
    out = b""
    while len(out) < 384:
        out += hashlib.sha512(b"c" + str(len(out)).encode()).digest()
    return out[:384]


@pytest.fixture(scope="module")
def unsigned() -> bytes:
    return pdfrequest.render(
        pdfrequest.payload_of("demo-2026", "a" * 64, _c()))


def _name(**parts) -> x509.Name:
    oids = {"cn": NameOID.COMMON_NAME, "serial": NameOID.SERIAL_NUMBER,
            "country": NameOID.COUNTRY_NAME, "given": NameOID.GIVEN_NAME,
            "surname": NameOID.SURNAME}
    return x509.Name([x509.NameAttribute(oids[k], v) for k, v in parts.items()])


def _issue(subject, *, issuer=None, issuer_key=None, ca=False,
           not_before=None, not_after=None, crl_url=None):
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer or subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (now - datetime.timedelta(days=30)))
        .not_valid_after(not_after or (now + datetime.timedelta(days=900)))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
        # `content_commitment` — non-repudiation — and not
        # `digital_signature`, because that is what a real DÁP signing
        # certificate carries and what pyHanko requires of one. Issued the
        # other way round, every signature below is refused for a reason
        # that has nothing to do with what is being tested.
        .add_extension(
            x509.KeyUsage(False, not ca, False, False, False, ca, ca,
                          False, False),
            critical=True)
    )
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    return key, builder.sign(issuer_key or key, hashes.SHA384())


@pytest.fixture(scope="module")
def authority():
    return _issue(_name(country="HU", cn="OVPOC TEST CA"), ca=True)


def _sign(unsigned: bytes, key, cert, ca_cert, tmp_path_factory) -> bytes:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers

    directory = tmp_path_factory.mktemp("signer")
    (directory / "k.pem").write_bytes(key.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "c.pem").write_bytes(cert.public_bytes(PEM))
    (directory / "ca.pem").write_bytes(ca_cert.public_bytes(PEM))

    signer = signers.SimpleSigner.load(
        str(directory / "k.pem"), str(directory / "c.pem"),
        ca_chain_files=(str(directory / "ca.pem"),))
    out = signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(unsigned)),
        signers.PdfSignatureMetadata(
            field_name="Signature1",
            subfilter=fields.SigSeedSubFilter.PADES,
            md_algorithm="sha384"),
        signer=signer)
    return out.getvalue()


@pytest.fixture(scope="module")
def citizen(authority, unsigned, tmp_path_factory):
    ca_key, ca_cert = authority
    key, cert = _issue(
        _name(cn="TESZT POLGAR", given="TESZT", surname="POLGAR",
              serial=SERIAL, country="HU"),
        issuer=ca_cert.subject, issuer_key=ca_key)
    return cert, _sign(unsigned, key, cert, ca_cert, tmp_path_factory)


@pytest.fixture(scope="module")
def trusted(authority) -> QualifiedSignatureValidation:
    _ca_key, ca_cert = authority
    return QualifiedSignatureValidation(trust_roots=(ca_cert.public_bytes(DER),))


# --------------------------------------------------------------------------
# The seam
# --------------------------------------------------------------------------

def assert_identifies_nobody(found, *, saying: str | None = None) -> None:
    """No signer established, and the office told why in its own log.

    Both halves matter and they pull against each other, which is the
    point. Nothing identified means the office answers `NOT_IDENTIFIED`
    and distinguishes nothing for the requester (§3.2). A reason means
    the *operator* can still tell a wrongly pinned root from a forged
    signature, which the office used to make impossible by recording one
    sentence for every refusal. `test_two_routes.py` holds the other
    half: the reason never reaches a response.
    """
    assert not isinstance(found, ValidatedSignature), f"identified {found}"
    assert isinstance(found, SignatureRefused), (
        "a validator in a deployment should say why it refused, so that "
        "the office's log is not as blind as the answer it gives")
    assert found.reason
    if saying is not None:
        assert saying in found.reason, found.reason


def test_the_validator_satisfies_the_seam_the_protocol_declares(trusted):
    """Structural, like `CertificateLookup`, so the implementation can live here."""
    assert isinstance(trusted, SignatureValidation)


def test_a_good_signature_is_reported_whole(trusted, citizen, unsigned):
    _cert, signed = citizen
    found = trusted.validate(signed)
    assert isinstance(found, ValidatedSignature)
    assert found.subject["serial_number"] == SERIAL
    assert found.subject["country_name"] == "HU"
    assert found.covered_prefix_length >= len(unsigned)
    assert found.revoked is False
    assert found.expired is False
    # No trust list was consulted, so the word is not available.
    assert found.qualified is None


def test_the_identifier_is_the_serial_number_and_not_the_name(trusted, citizen):
    """Names collide, are not identifiers, and change."""
    _cert, signed = citizen
    found = trusted.validate(signed)
    assert subject_identifier(found.subject) == f"HU-{SERIAL}"
    assert "TESZT" not in subject_identifier(found.subject)


def test_a_subject_with_no_serial_number_yields_no_identifier():
    assert subject_identifier({"common_name": "A", "country_name": "HU"}) is None
    assert subject_identifier({"serial_number": "1"}) is None


# --------------------------------------------------------------------------
# Above the identity boundary: one answer, no detail
# --------------------------------------------------------------------------

def test_a_tampered_document_identifies_nobody(trusted, citizen, unsigned):
    """The digest no longer matches, so there is no signature over these bytes."""
    _cert, signed = citizen
    altered = bytearray(signed)
    altered[len(unsigned) // 2] ^= 0xFF
    assert_identifies_nobody(trusted.validate(bytes(altered)),
                             saying="have changed since")


def test_a_signature_chaining_to_nothing_trusted_identifies_nobody(citizen):
    """Not a different message from a tampered file. Deliberately."""
    _cert, signed = citizen
    refused = QualifiedSignatureValidation(trust_roots=()).validate(signed)
    assert_identifies_nobody(refused, saying="does not chain")


def test_an_unsigned_document_identifies_nobody(trusted, unsigned):
    assert_identifies_nobody(trusted.validate(unsigned),
                             saying="no signature at all")


def test_rubbish_identifies_nobody_rather_than_raising(trusted):
    """A malformed file is an answer, not an exception.

    The office owes an unidentified party no parse error, and a traceback
    escaping into a route handler would be one.
    """
    for rubbish in (b"", b"not a pdf at all", b"%PDF-1.7\nbroken", b"\x00" * 500):
        assert_identifies_nobody(trusted.validate(rubbish))


# --------------------------------------------------------------------------
# Below it: findings, not refusals
# --------------------------------------------------------------------------

def test_a_revoked_certificate_still_identifies_its_signer(
    authority, unsigned, tmp_path_factory
):
    """The decision this module exists to get right.

    pyHanko reports a revoked signer with `bottom_line=False`, exactly as it
    reports one that chains to nothing. Inheriting that verdict would
    collapse revocation into `NOT_IDENTIFIED` and move the check back above
    the identity boundary -- which is the privacy regression `vro.py`
    describes, arriving through a library rather than through a refactor.
    """
    ca_key, ca_cert = authority
    key, cert = _issue(
        _name(cn="TESZT POLGAR", serial=SERIAL, country="HU"),
        issuer=ca_cert.subject, issuer_key=ca_key,
        crl_url="http://example.invalid/ca.crl")
    signed = _sign(unsigned, key, cert, ca_cert, tmp_path_factory)

    now = datetime.datetime.now(datetime.timezone.utc)
    crl = (x509.CertificateRevocationListBuilder()
           .issuer_name(ca_cert.subject)
           .last_update(now - datetime.timedelta(hours=1))
           .next_update(now + datetime.timedelta(days=30))
           .add_revoked_certificate(
               x509.RevokedCertificateBuilder()
               .serial_number(cert.serial_number)
               .revocation_date(now - datetime.timedelta(days=1)).build())
           .sign(ca_key, hashes.SHA384()))

    validator = QualifiedSignatureValidation(
        trust_roots=(ca_cert.public_bytes(DER),),
        crls=(crl.public_bytes(DER),))
    found = validator.validate(signed)

    assert found is not None, "revocation was collapsed into NOT_IDENTIFIED"
    assert found.revoked is True
    assert found.subject["serial_number"] == SERIAL
    assert found.covered_prefix_length >= len(unsigned)


def test_an_expired_certificate_still_identifies_its_signer(
    authority, unsigned, tmp_path_factory
):
    """Same argument as revocation, and the same mistake available.

    A certificate that has run out still verifies the signature it made.
    The office may refuse the request afterwards -- and says so, because by
    then it knows whom it is refusing.
    """
    ca_key, ca_cert = authority
    now = datetime.datetime.now(datetime.timezone.utc)
    key, cert = _issue(
        _name(cn="TESZT POLGAR", serial=SERIAL, country="HU"),
        issuer=ca_cert.subject, issuer_key=ca_key,
        not_before=now - datetime.timedelta(days=400),
        not_after=now - datetime.timedelta(days=1))
    signed = _sign(unsigned, key, cert, ca_cert, tmp_path_factory)

    found = QualifiedSignatureValidation(
        trust_roots=(ca_cert.public_bytes(DER),)).validate(signed)

    assert found is not None, "expiry was collapsed into NOT_IDENTIFIED"
    assert found.expired is True
    assert found.subject["serial_number"] == SERIAL


# --------------------------------------------------------------------------
# What the wallet does to the document after signing it
# --------------------------------------------------------------------------
#
# Both tests below reproduce, synthetically, a condition observed in a
# document signed by the real DÁP application. Neither is hypothetical and
# neither could be found by reading documentation: the first file that came
# back from a phone was refused by this validator for both reasons at once,
# and would have been answered NOT_IDENTIFIED by an office built on the
# library's defaults.
#
# They are built here rather than committed, because the only real example
# is a named citizen's qualified signature and that does not belong in a
# public repository.

def _append_revision(signed: bytes, body: bytes) -> bytes:
    """An incremental update, chained to the revision before it."""
    previous = int(re.search(rb"startxref\s+(\d+)\s*%%EOF\s*$",
                             signed, re.S).group(1))
    return signed + body(len(signed), previous)


def test_a_later_revision_that_frees_an_object_still_identifies_the_signer(
    trusted, citizen, unsigned
):
    """What DÁP's own `/DSS` update does, and what pyHanko makes of it.

    The wallet appends a second revision carrying certificates and OCSP
    responses, and in doing so frees an object. pyHanko's reject-by-default
    difference policy calls that an unacceptable modification, so
    `bottom_line` comes back false -- with `trusted` true and
    `trust_problem_indic` None, because nothing is wrong with the chain.

    The office does not ask whether later modifications were acceptable.
    It decides on the prefix it recomputed and disregards everything past
    it, so a later revision cannot change what the document requests. An
    office that inherited the verdict would refuse every genuine request.
    """
    _cert, signed = citizen

    def freeing(start: int, previous: int) -> bytes:
        table = (b"xref\n0 1\n0000000000 65535 f \n"
                 b"10 1\n0000000000 00001 f \n")
        return (table + b"trailer\n<< /Size 20 /Root 1 0 R /Prev "
                + str(previous).encode() + b" >>\nstartxref\n"
                + str(start).encode() + b"\n%%EOF\n")

    found = trusted.validate(_append_revision(signed, freeing))
    assert found is not None, "the modification verdict was inherited"
    assert found.subject["serial_number"] == SERIAL
    assert found.covered_prefix_length >= len(unsigned)


def test_a_later_revision_clobbering_an_xref_stream_is_still_read(
    authority, unsigned, tmp_path_factory
):
    """The strict reader refuses a real DÁP document before validation begins.

    `PdfStrictReadError: XRef stream objects must not be clobbered in
    strict mode` -- because the update the wallet appends reuses an object
    number that held a cross-reference stream. Strictness about structure
    buys this office nothing it does not already have: the meaning of the
    document comes from bytes it recomputed itself, so a parser's opinion
    of the file's tidiness cannot make a wrong document acceptable.
    """
    ca_key, ca_cert = authority
    key, cert = _issue(_name(cn="TESZT POLGAR", serial=SERIAL, country="HU"),
                       issuer=ca_cert.subject, issuer_key=ca_key)

    # Rewritten with cross-reference streams, which is what the real file
    # has and what `render` deliberately does not produce. Through
    # pyHanko's own writer rather than an external tool: a test that skips
    # when some command is missing defends nothing, and the runner now
    # refuses to write a report at all when the baseline skipped anything.
    # That rule arrived one patch before this test, and this test broke it.
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.writer import copy_into_new_writer

    out = io.BytesIO()
    copy_into_new_writer(
        PdfFileReader(io.BytesIO(unsigned)),
        writer_kwargs={"stream_xrefs": True},
    ).write(out)
    signed = _sign(out.getvalue(), key, cert, ca_cert, tmp_path_factory)

    xref_objects = [int(m.group(1)) for m in re.finditer(
        rb"(?<![0-9])(\d+) 0 obj\s*<<[^>]*?/Type\s*/XRef", signed, re.S)]
    assert xref_objects, "this test needs a document with cross-reference streams"
    target = xref_objects[0]

    # The catalogue's own object number, carried over rather than guessed:
    # qpdf renumbers, so a trailer naming `1 0 R` would point `/Root` at
    # whatever happened to land there and the reader would find no
    # signature — a test failing for a reason of its own making.
    root = int(re.findall(rb"/Root (\d+) 0 R", signed)[-1])

    def clobbering(start: int, previous: int) -> bytes:
        # An inert object, not a replacement catalogue: what trips the
        # strict reader is the object number having held a cross-reference
        # stream, and a destructive body would make the test fail for the
        # wrong reason.
        body = (str(target).encode() + b" 0 obj\n<< >>\nendobj\n")
        table = (b"xref\n0 1\n0000000000 65535 f \n" + str(target).encode()
                 + b" 1\n" + f"{start:010d}".encode() + b" 00000 n \n")
        return (body + table + b"trailer\n<< /Size 999 /Root "
                + str(root).encode() + b" 0 R /Prev "
                + str(previous).encode() + b" >>\nstartxref\n"
                + str(start + len(body)).encode() + b"\n%%EOF\n")

    clobbered = _append_revision(signed, clobbering)
    validator = QualifiedSignatureValidation(
        trust_roots=(ca_cert.public_bytes(DER),))
    found = validator.validate(clobbered)
    assert found is not None, "the strict reader refused the document"
    assert found.subject["serial_number"] == SERIAL


# --------------------------------------------------------------------------
# What the signature covers
# --------------------------------------------------------------------------

def test_the_covered_prefix_is_the_run_from_byte_zero(trusted, citizen, unsigned):
    _cert, signed = citizen
    found = trusted.validate(signed)
    assert signed[:found.covered_prefix_length] == \
        signed[:found.covered_prefix_length]
    assert found.covered_prefix_length >= len(unsigned)
    assert found.covered_prefix_length < len(signed)


def test_a_dss_appended_after_signing_does_not_shorten_it(
    trusted, authority, citizen, unsigned
):
    """Every DÁP signature has one, and it is outside the signature's coverage.

    The wallet appends a second incremental update carrying a `/DSS` with
    certificates and OCSP responses. An office whose coverage number shrank
    because of it, or which required the signature to cover the whole file,
    would refuse every genuine request.

    Built with pyHanko's own DSS writer rather than by appending bytes: a
    tail of rubbish is not an incremental update, and a test that used one
    would be checking that the file is unreadable rather than that the
    coverage number holds.
    """
    from pyhanko.sign.validation.dss import DocumentSecurityStore

    _ca_key, ca_cert = authority
    cert, signed = citizen
    before = trusted.validate(signed)

    out = io.BytesIO(signed)
    DocumentSecurityStore.add_dss(
        output_stream=out,
        sig_contents=None,
        certs=[__import__("asn1crypto").x509.Certificate.load(c.public_bytes(DER))
               for c in (cert, ca_cert)],
        embed_roots=True,
    )
    augmented = out.getvalue()
    assert len(augmented) > len(signed), "the DSS should have been appended"
    assert augmented[:len(signed)] == signed, "and appended, not rewritten"

    after = trusted.validate(augmented)
    assert after is not None
    assert after.covered_prefix_length == before.covered_prefix_length
    assert after.covered_prefix_length < len(augmented)


def test_a_range_not_starting_at_zero_covers_none_of_the_prefix():
    """Zero rather than an exception: the office's own rule then refuses."""
    from driver.qualified_signature import _covered_prefix

    class Stub:
        def __init__(self, r):
            self.byte_range = r

    assert _covered_prefix(Stub([0, 4939, 9000, 500])) == 4939
    assert _covered_prefix(Stub([16, 4939, 9000, 500])) == 0
    assert _covered_prefix(Stub([0])) == 0
    assert _covered_prefix(Stub(None)) == 0


# --------------------------------------------------------------------------
# The two halves together
# --------------------------------------------------------------------------

def test_the_office_can_decide_a_real_signed_request(trusted, citizen, unsigned):
    """The whole route, minus the office's own eligibility rules.

    The validator says who signed and how much they signed; `pdfrequest`
    rebuilds the document and compares. Neither is trusted with the other's
    question, and this is the only test where both answers meet.
    """
    _cert, signed = citizen
    found = trusted.validate(signed)
    assert found is not None

    result = pdfrequest.check(
        signed, covered_prefix_length=found.covered_prefix_length)
    assert result.accepted is True
    assert result.payload["election_id"] == "demo-2026"
    assert result.rendered_bytes == len(unsigned)
    assert subject_identifier(found.subject) == f"HU-{SERIAL}"


def test_a_signed_document_whose_page_was_altered_is_refused_by_the_rule(
    authority, unsigned, tmp_path_factory
):
    """Signed, genuinely, and still not a token request.

    The attack the route has to survive: a hostile application renders a
    plausible page and embeds somebody else's `c`. Every signature here is
    real and the validator reports an identified signer. The refusal comes
    from the office rebuilding the document, which is the point of doing it
    that way.
    """
    ca_key, ca_cert = authority
    key, cert = _issue(_name(cn="TESZT POLGAR", serial=SERIAL, country="HU"),
                       issuer=ca_cert.subject, issuer_key=ca_key)

    payload = pdfrequest.payload_of("demo-2026", "a" * 64, _c())
    visible = payload["blinded_key"][:64].encode("ascii")
    altered = pdfrequest.render(payload).replace(
        b"(" + visible + b") Tj", b"(" + b"X" * 64 + b") Tj", 1)
    signed = _sign(altered, key, cert, ca_cert, tmp_path_factory)

    found = QualifiedSignatureValidation(
        trust_roots=(ca_cert.public_bytes(DER),)).validate(signed)
    assert found is not None, "the signature itself is perfectly good"

    result = pdfrequest.check(
        signed, covered_prefix_length=found.covered_prefix_length)
    assert result.accepted is False
    assert result.refusal is pdfrequest.Refusal.NOT_AS_RENDERED
