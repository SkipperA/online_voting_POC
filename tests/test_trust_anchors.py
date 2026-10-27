"""The shortest configuration file in the project, and what guards it.

An anchor directory is a folder of certificates on a server. A certificate
quietly added or swapped there is an office that accepts signatures from a
new authority, and nothing downstream looks wrong: a signature under a
trusted anchor is exactly what a valid request looks like, so there is no
later check that could notice. The manifest is what makes a change visible
and it is worth nothing unless loading enforces it.

So these tests are mostly one assertion in several costumes -- the office
refuses to start rather than start having silently trusted something. An
office that started and then refused every request would look like a broken
wallet; an office that started on an unverified anchor would look like
nothing at all.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import fetch_trust_anchors as pinner  # noqa: E402

pytest.importorskip("pyhanko", reason="the pades extra is not installed")

from driver.qualified_signature import (  # noqa: E402
    QualifiedSignatureValidation, TrustAnchorsRefused, ValidatorUnavailable,
)

DER = serialization.Encoding.DER


def _authority(name: str = "OVPOC TEST CA") -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "HU"),
                         x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3000))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA384())).public_bytes(DER)


@pytest.fixture
def pinned(tmp_path) -> pathlib.Path:
    pinner.add(tmp_path, _authority(), "root.cer", "file:test")
    return tmp_path


# --------------------------------------------------------------------------
# Pinning
# --------------------------------------------------------------------------

def test_pinning_records_what_was_pinned(tmp_path):
    """The manifest is the artefact a reader inspects, so it has to say things."""
    der = _authority()
    described = pinner.add(tmp_path, der, "root.cer", "http://example.invalid/r.cer")

    manifest = json.loads((tmp_path / "MANIFEST.json").read_text())
    entry, = manifest["anchors"]
    assert entry["sha256"] == hashlib.sha256(der).hexdigest() == described["sha256"]
    assert entry["source"] == "http://example.invalid/r.cer"
    assert entry["self_signed"] is True
    assert "OVPOC TEST CA" in entry["subject"]
    assert manifest["pinned"] == datetime.date.today().isoformat()


def test_a_pem_certificate_is_stored_as_der(tmp_path):
    """Authorities publish both and the extension says nothing reliable."""
    der = _authority()
    pem = x509.load_der_x509_certificate(der).public_bytes(
        serialization.Encoding.PEM)
    pinner.add(tmp_path, pinner._as_der(pem), "root.cer", "file:test")
    assert (tmp_path / "root.cer").read_bytes() == der


def test_pinning_the_same_file_twice_leaves_one_entry(tmp_path):
    pinner.add(tmp_path, _authority(), "root.cer", "first")
    second = _authority("ANOTHER CA")
    pinner.add(tmp_path, second, "root.cer", "second")

    manifest = json.loads((tmp_path / "MANIFEST.json").read_text())
    entry, = manifest["anchors"]
    assert entry["source"] == "second"
    assert entry["sha256"] == hashlib.sha256(second).hexdigest()


# --------------------------------------------------------------------------
# Loading, and refusing to
# --------------------------------------------------------------------------

def test_a_pinned_directory_loads(pinned):
    validator = QualifiedSignatureValidation.from_pinned(pinned)
    assert len(validator.trust_roots) == 1


def test_a_swapped_certificate_refuses_to_load(pinned):
    """The case the manifest exists for.

    Same filename, different authority, and the office would otherwise
    accept requests signed by whoever that one vouches for.
    """
    (pinned / "root.cer").write_bytes(_authority("AN AUTHORITY NOBODY PINNED"))
    with pytest.raises(TrustAnchorsRefused, match="not the certificate"):
        QualifiedSignatureValidation.from_pinned(pinned)


def test_a_certificate_nobody_recorded_refuses_to_load(pinned):
    """Adding is as good as swapping, and quieter.

    A file dropped into the directory needs no edit to anything the
    operator reads.
    """
    (pinned / "extra.cer").write_bytes(_authority("UNINVITED CA"))
    with pytest.raises(TrustAnchorsRefused, match="no manifest entry"):
        QualifiedSignatureValidation.from_pinned(pinned)


def test_a_manifest_entry_with_no_file_refuses_to_load(pinned):
    (pinned / "root.cer").unlink()
    with pytest.raises(TrustAnchorsRefused, match="not in"):
        QualifiedSignatureValidation.from_pinned(pinned)


def test_a_directory_with_no_manifest_refuses_to_load(tmp_path):
    (tmp_path / "root.cer").write_bytes(_authority())
    with pytest.raises(TrustAnchorsRefused, match="no MANIFEST"):
        QualifiedSignatureValidation.from_pinned(tmp_path)


def test_an_empty_manifest_trusts_nothing_and_says_so_by_refusing_everyone(tmp_path):
    """Not an error. An office told to trust nothing identifies nobody,
    which is the right answer and not a crash."""
    (tmp_path / "MANIFEST.json").write_text('{"anchors": []}')
    validator = QualifiedSignatureValidation.from_pinned(tmp_path)
    assert validator.trust_roots == ()
    assert validator.validate(b"%PDF-1.7\nnot signed\n%%EOF\n") is None


# --------------------------------------------------------------------------
# The operator's own check, which must agree with the office's
# --------------------------------------------------------------------------

def test_the_check_command_reports_what_loading_would_refuse(pinned):
    """Two implementations of one rule, so they get one test.

    `--check` is duplicated in the tool on purpose: it runs on an
    operator's machine, which may not have the `pades` extra, and somebody
    verifying their anchors should not have to install a PDF library. The
    duplication is only safe while the two agree.
    """
    assert pinner.check(pinned) == []

    (pinned / "root.cer").write_bytes(_authority("SOMEBODY ELSE"))
    problems = pinner.check(pinned)
    assert len(problems) == 1 and "root.cer" in problems[0]
    with pytest.raises(TrustAnchorsRefused):
        QualifiedSignatureValidation.from_pinned(pinned)


def test_the_check_command_notices_a_file_nobody_recorded(pinned):
    (pinned / "extra.cer").write_bytes(_authority("UNINVITED"))
    problems = pinner.check(pinned)
    assert len(problems) == 1 and "extra.cer" in problems[0]
    with pytest.raises(TrustAnchorsRefused):
        QualifiedSignatureValidation.from_pinned(pinned)


# --------------------------------------------------------------------------
# Configured for a route this office cannot perform
# --------------------------------------------------------------------------

def test_anchors_without_the_validator_refuse_to_load(pinned, monkeypatch):
    """The third state an office can be in, and the only dishonest one.

    No anchors: no qualified-signature route, and the office says so.
    Anchors and the `pades` extra: the route is offered and performed.
    Anchors without the extra: an office that advertises the route and
    then meets an `ImportError` in the middle of a citizen's upload,
    after having told them the route was open. That is the one failure
    here that reaches a voter looking like their fault.

    So it is refused at load, for the same reason a swapped certificate
    is. An office that comes up wrong looks like an office.
    """
    import importlib
    real = importlib.import_module

    def missing(name, *args, **kwargs):
        if name == "pyhanko":
            raise ImportError("no module named pyhanko")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", missing)
    with pytest.raises(ValidatorUnavailable) as refused:
        QualifiedSignatureValidation.from_pinned(pinned)
    # The message has to name the way out, because the person reading it
    # is on a server and the fix is one install away.
    assert "pades" in str(refused.value)


def test_the_load_probe_covers_every_module_the_validator_imports():
    """Two import lists, and nothing but this keeps them the same.

    `validate` imports its dependencies lazily so that `driver` stays
    importable without the extra; `require_validator` probes for them at
    load so a misconfigured office fails there rather than mid-upload.
    Those are two lists of names in two places, and the failure mode of
    them drifting apart is silent: a probe that passes and a `validate`
    that raises is exactly the state the probe exists to prevent.
    """
    import ast
    import inspect
    import sys as _sys
    import textwrap

    from driver import qualified_signature as module

    tree = ast.parse(textwrap.dedent(
        inspect.getsource(QualifiedSignatureValidation.validate)))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            roots.add(node.module.split(".")[0])

    missing = roots - set(_sys.stdlib_module_names) - set(module.PADES_MODULES)
    assert not missing, (
        "`validate` imports these and `require_validator` does not probe "
        f"for them: {sorted(missing)} -- an office with anchors pinned and "
        "one of them missing would start and then fail on a citizen's "
        "upload, which is what PADES_MODULES exists to prevent")
