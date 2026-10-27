"""The word *qualified*, and who is entitled to use it.

Clause S6 said the office accepts a signature because an operator pinned
a certificate by hand, and that a deployment takes its anchors from the
European trusted list instead -- "which is also what would let it say
your signature is *qualified*, a word this build does not use because it
cannot establish it". These tests are that clause being discharged.

Two things the list does that a root certificate cannot, and they are
the same thing twice. It says *whose* certificates count, service by
service, with the dates each service was granted and withdrawn. And
because it says that, it can answer Article 3(12): whether a signature
made at a particular moment, under a particular service, is a qualified
electronic signature. A flat set of trust anchors answers the first
question badly and the second not at all.

The trusted lists here are built in-process rather than committed. A
real one is a megabyte of XML with a XAdES signature over it and an
expiry, so a committed copy would be a test that fails on a date nobody
chose -- the same reason `test_qualified_signature.py` invents its
certificates. What is *not* exercised here is the parse of a real
member state's list and the two signature checks over it, because that
needs the Union's servers; `tools/fetch_trust_anchors.py --trusted-list`
is where an operator does that, and `driver/trusted_list.py` validates
both signatures when they do.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("pyhanko", reason="the pades extra is not installed")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID, ObjectIdentifier  # noqa: E402

from ovpoc import pdfrequest  # noqa: E402

from driver import trusted_list as tl  # noqa: E402
from driver.qualified_signature import (  # noqa: E402
    QualifiedSignatureValidation,
)

DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM
SERIAL = "471570820"

#: ETSI EN 319 412-5. The statements a qualified certificate for
#: electronic signatures carries, and which the DÁP certificate carries:
#: compliance, a key held in a QSCD, and the type.
QC_STATEMENTS = ObjectIdentifier("1.3.6.1.5.5.7.1.3")
QC_COMPLIANCE = "0.4.0.1862.1.1"
QC_SSCD = "0.4.0.1862.1.4"
QC_TYPE = "0.4.0.1862.1.6"
QC_TYPE_ESIGN = "0.4.0.1862.1.6.1"


# --------------------------------------------------------------------------
# DER by hand, because `cryptography` has no builder for qcStatements
# --------------------------------------------------------------------------

def _der_oid(dotted: str) -> bytes:
    first, second, *rest = (int(part) for part in dotted.split("."))
    body = bytes([40 * first + second])
    for number in rest:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append((number & 0x7F) | 0x80)
            number >>= 7
        body += bytes(reversed(chunk))
    return bytes([0x06, len(body)]) + body


def _der_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    assert len(body) < 128, "the fixtures here are small by construction"
    return bytes([0x30, len(body)]) + body


def _qc_statements() -> bytes:
    return _der_seq(
        _der_seq(_der_oid(QC_COMPLIANCE)),
        _der_seq(_der_oid(QC_SSCD)),
        _der_seq(_der_oid(QC_TYPE), _der_seq(_der_oid(QC_TYPE_ESIGN))),
    )


# --------------------------------------------------------------------------
# An authority, a citizen, a signed request
# --------------------------------------------------------------------------

def _name(**parts) -> x509.Name:
    oids = {"cn": NameOID.COMMON_NAME, "serial": NameOID.SERIAL_NUMBER,
            "country": NameOID.COUNTRY_NAME, "given": NameOID.GIVEN_NAME,
            "surname": NameOID.SURNAME}
    return x509.Name([x509.NameAttribute(oids[k], v) for k, v in parts.items()])


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _issue(subject, *, issuer=None, issuer_key=None, ca=False, qualified=False):
    key = ec.generate_private_key(ec.SECP384R1())
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer or subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=900))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
        # `content_commitment`, as a real signing certificate carries and
        # as pyHanko requires of one -- see the note in
        # `test_qualified_signature.py`.
        .add_extension(
            x509.KeyUsage(False, not ca, False, False, False, ca, ca,
                          False, False),
            critical=True)
    )
    if qualified:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(QC_STATEMENTS, _qc_statements()),
            critical=False)
    return key, builder.sign(issuer_key or key, hashes.SHA384())


@pytest.fixture(scope="module")
def authority():
    return _issue(_name(country="HU", cn="OVPOC TEST QTSP"), ca=True)


@pytest.fixture(scope="module")
def unsigned() -> bytes:
    blinded = bytes(range(256))
    return pdfrequest.render(
        pdfrequest.payload_of("demo-2026", "a" * 64, blinded))


def _sign(unsigned: bytes, key, cert, ca_cert, directory) -> bytes:
    import io

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers

    (directory / "k.pem").write_bytes(key.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "c.pem").write_bytes(cert.public_bytes(PEM))
    (directory / "ca.pem").write_bytes(ca_cert.public_bytes(PEM))
    signer = signers.SimpleSigner.load(
        str(directory / "k.pem"), str(directory / "c.pem"),
        ca_chain_files=(str(directory / "ca.pem"),))
    return signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(unsigned)),
        signers.PdfSignatureMetadata(
            field_name="Signature1",
            subfilter=fields.SigSeedSubFilter.PADES,
            md_algorithm="sha384"),
        signer=signer).getvalue()


@pytest.fixture(scope="module")
def citizen(authority, unsigned, tmp_path_factory):
    """A certificate carrying the qcStatements a real qualified one does."""
    ca_key, ca_cert = authority
    key, cert = _issue(
        _name(cn="TESZT POLGAR", given="TESZT", surname="POLGAR",
              serial=SERIAL, country="HU"),
        issuer=ca_cert.subject, issuer_key=ca_key, qualified=True)
    return cert, _sign(unsigned, key, cert, ca_cert,
                       tmp_path_factory.mktemp("signer"))


# --------------------------------------------------------------------------
# A trusted list, as a registry
# --------------------------------------------------------------------------

def _listing(ca_cert, *, granted_from=None, service_type=None):
    """One certification authority, granted for qualified signatures.

    What a member state's list says about one entry, in the shape
    pyHanko parses one into -- so that these tests exercise the office's
    use of a list rather than pyHanko's XML reader.
    """
    from asn1crypto import x509 as asn1_x509
    from pyhanko.sign.validation.qualified.tsp import (
        CA_QC_URI, BaseServiceInformation, CAServiceInformation, QcCertType,
        TSPRegistry)

    base = BaseServiceInformation(
        service_type=service_type or CA_QC_URI,
        service_name="OVPOC TEST QTSP — qualified certificates",
        valid_from=granted_from or (_now() - datetime.timedelta(days=365)),
        valid_until=None,
        provider_certs=(asn1_x509.Certificate.load(ca_cert.public_bytes(DER)),),
        additional_info_certificate_type=frozenset({QcCertType.QC_ESIGN}),
        other_additional_info=frozenset())
    registry = TSPRegistry()
    registry.register_ca(CAServiceInformation(
        base_info=base, qualifications=frozenset(),
        expired_certs_revocation_info=None))
    return registry


def _pinned(registry, *, territory="HU", pinned_on=None) -> tl.PinnedTrustedList:
    return tl.PinnedTrustedList(
        territory=territory,
        pinned_on=(pinned_on or datetime.date.today()).isoformat()
        if not isinstance(pinned_on, str) else pinned_on,
        location="https://example.invalid/tl.xml",
        registry=registry)


# --------------------------------------------------------------------------
# The word
# --------------------------------------------------------------------------

def test_an_office_with_a_trusted_list_can_say_qualified(authority, citizen):
    """Article 3(12), established rather than assumed.

    The certificate carries the qcStatements, the list says the service
    that issued it was granted for qualified electronic signatures on the
    day it was used, and only both together are an answer.
    """
    _ca_key, ca_cert = authority
    _cert, signed = citizen
    office = QualifiedSignatureValidation(
        trusted_list=_pinned(_listing(ca_cert)))

    found = office.validate(signed)
    assert found.identifier == f"HU-{SERIAL}"
    assert found.qualified is True


def test_an_office_with_a_pinned_root_says_nothing_at_all(authority, citizen):
    """`None` is not "no". It is this office having no standing to judge.

    The same signature, the same certificate, the same qcStatements —
    and a validator told only that one root is to be believed. It can
    establish who signed, and cannot establish that the authority behind
    them is one the Union recognises, because a certificate downloaded
    from that authority's own web server is not evidence about the
    authority.
    """
    _ca_key, ca_cert = authority
    _cert, signed = citizen
    office = QualifiedSignatureValidation(
        trust_roots=(ca_cert.public_bytes(DER),))

    found = office.validate(signed)
    assert found.identifier == f"HU-{SERIAL}"
    assert found.qualified is None


def test_a_certificate_without_the_statements_is_not_qualified(
        authority, unsigned, tmp_path):
    """A signature the list's authority made, and that is not a QES.

    The authority is granted; this particular certificate does not claim
    compliance. An office that read the list and answered `True` for
    everything under a listed root would be reporting the authority's
    status as the signature's.
    """
    ca_key, ca_cert = authority
    key, cert = _issue(
        _name(cn="TESZT POLGAR", serial=SERIAL, country="HU"),
        issuer=ca_cert.subject, issuer_key=ca_key, qualified=False)
    signed = _sign(unsigned, key, cert, ca_cert, tmp_path)

    found = QualifiedSignatureValidation(
        trusted_list=_pinned(_listing(ca_cert))).validate(signed)
    assert found.identifier == f"HU-{SERIAL}"
    assert found.qualified is False


def test_an_authority_the_list_does_not_name_identifies_nobody(citizen, unsigned,
                                                               tmp_path):
    """The list is the anchors, not merely a commentary on them.

    A second authority, with a perfectly good certificate and a perfectly
    good signature, absent from the list. The office must not identify
    its signer at all -- if the list only decided the *word* and some
    other set of roots decided trust, then the office would be accepting
    signatures it cannot account for.
    """
    listed_key, listed_cert = _issue(
        _name(country="HU", cn="LISTED QTSP"), ca=True)
    other_key, other_cert = _issue(
        _name(country="HU", cn="UNLISTED QTSP"), ca=True)
    key, cert = _issue(_name(cn="SOMEBODY", serial="1", country="HU"),
                       issuer=other_cert.subject, issuer_key=other_key,
                       qualified=True)
    signed = _sign(unsigned, key, cert, other_cert, tmp_path)

    office = QualifiedSignatureValidation(
        trusted_list=_pinned(_listing(listed_cert)))
    found = office.validate(signed)
    assert not hasattr(found, "identifier"), found
    assert "does not chain" in found.reason


# --------------------------------------------------------------------------
# The snapshot on disk
# --------------------------------------------------------------------------

def _write_manifest(directory, section) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / tl.MANIFEST).write_text(
        json.dumps({"anchors": [], "trusted_list": section}, indent=2) + "\n",
        encoding="utf-8")


def test_a_directory_with_no_trusted_list_section_loads_as_none(tmp_path):
    """An ordinary configuration, not an error.

    A directory holding only hand-pinned roots is what this repository
    ships and what the hosted demonstration runs. `None` is the office
    falling back to them.
    """
    (tmp_path / tl.MANIFEST).write_text('{"anchors": []}', encoding="utf-8")
    assert tl.load(tmp_path) is None
    assert tl.describe(tmp_path) is None


def test_a_trusted_list_whose_digest_moved_refuses_to_load(tmp_path):
    """The same rule as a swapped anchor, for a much larger file.

    A trusted list is the whole of what the office will believe about
    who may sign. A copy edited on a server is an office trusting
    whoever edited it, and nothing downstream would look wrong.
    """
    (tmp_path / "eu-lotl.xml").write_text("<lotl/>", encoding="utf-8")
    (tmp_path / "hu-tl.xml").write_text("<tl/>", encoding="utf-8")
    _write_manifest(tmp_path, {
        "territory": "HU", "location": "https://example.invalid/tl.xml",
        "lotl": {"file": "eu-lotl.xml", "sha256": "00" * 32},
        "list": {"file": "hu-tl.xml", "sha256": "11" * 32},
        "tlso_certs": ["AA=="], "pinned": "2026-10-27"})

    with pytest.raises(tl.TrustedListRefused) as refused:
        tl.load(tmp_path)
    assert "eu-lotl.xml" in str(refused.value)


def test_a_trusted_list_with_no_signer_refuses_to_load(tmp_path):
    """Pinned bytes with nothing to check them against.

    The digest says the file has not changed since it was pinned; the
    signer certificates say it was the member state's list when it was.
    Without the second, a list pinned from the wrong place stays wrong
    for ever and the manifest agrees with it.
    """
    import hashlib

    (tmp_path / "eu-lotl.xml").write_text("<lotl/>", encoding="utf-8")
    (tmp_path / "hu-tl.xml").write_text("<tl/>", encoding="utf-8")
    digest = {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
              for name in ("eu-lotl.xml", "hu-tl.xml")}
    _write_manifest(tmp_path, {
        "territory": "HU", "location": "https://example.invalid/tl.xml",
        "lotl": {"file": "eu-lotl.xml", "sha256": digest["eu-lotl.xml"]},
        "list": {"file": "hu-tl.xml", "sha256": digest["hu-tl.xml"]},
        "tlso_certs": [], "pinned": "2026-10-27"})

    with pytest.raises(tl.TrustedListRefused) as refused:
        tl.load(tmp_path)
    assert "may sign it" in str(refused.value)


def test_describe_reads_the_section_without_the_parser(tmp_path):
    """For `--check`, which runs where an operator is.

    An operator verifying their own configuration should not have to
    install a PDF library to be told whether the files on disk are the
    files the manifest records.
    """
    (tmp_path / "eu-lotl.xml").write_text("<lotl/>", encoding="utf-8")
    _write_manifest(tmp_path, {
        "territory": "HU", "location": "https://example.invalid/tl.xml",
        "lotl": {"file": "eu-lotl.xml", "sha256": "00" * 32},
        "list": {"file": "hu-tl.xml", "sha256": "11" * 32},
        "tlso_certs": ["AA=="], "pinned": "2026-10-27"})

    described = tl.describe(tmp_path)
    assert described["territory"] == "HU"
    assert described["signers"] == 1
    # One digest wrong, one file missing, and it says both.
    assert len(described["problems"]) == 2


def test_the_snapshot_says_how_old_it_is():
    """Read offline, so a service withdrawn since is still trusted here.

    That is the cost of not reaching the Union's servers while a poll
    runs, which is the same cost `allow_fetching=False` buys elsewhere
    and for the same reason. A page can only say it if the object knows.
    """
    pinned = _pinned(None, pinned_on="2026-10-01")
    assert pinned.age_in_days(datetime.date(2026, 10, 27)) == 26
