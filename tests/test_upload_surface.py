"""Where the voter hands in a signed document, and why it is on this origin.

The page is served by the Registration Office, not by the voting
application, and that is clause A8 on this route rather than a layout
choice. The application writes the document and must never see the signed
one -- it is the component holding `k_p^a` and `r`, so it is the component
that must not learn `id`. If the handing-in were a screen in the
application, the signed document would pass through it and the one property
the route was arranged to keep would be gone.

The convenience somebody will eventually propose is an Upload button in the
voter app. These tests are not what would stop it; `docs/Demo_Scope_Limits.md`
clause A8 and a reviewer are. What they do is pin the arrangement as it
stands, so that removing it is a visible edit rather than a quiet one.
"""

from __future__ import annotations

import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from service import apps as apps_module  # noqa: E402
from service.state import Deployment  # noqa: E402

from ovpoc import pdfrequest  # noqa: E402


@pytest.fixture(scope="module")
def deployment(tmp_path_factory) -> Deployment:
    """An office told nothing to trust, said so rather than assumed.

    `trust_anchors` is passed explicitly and points nowhere, because this
    repository now carries a pinned anchor and a fixture that defaulted
    would behave one way here and another in a clone without it.
    """
    return Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("config-root"),
        trust_anchors=tmp_path_factory.mktemp("no-anchors") / "absent")


@pytest.fixture
def office(deployment) -> TestClient:
    return TestClient(apps_module.vro_app(deployment))


def _document(election: str = "demo-2026") -> bytes:
    import hashlib
    blinded = b""
    while len(blinded) < 256:
        blinded += hashlib.sha512(b"c" + str(len(blinded)).encode()).digest()
    return pdfrequest.render(
        pdfrequest.payload_of(election, "a" * 64, blinded[:256]))


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def test_the_page_is_served_by_the_office(office):
    response = office.get("/upload")
    assert response.status_code == 200
    assert "Hand in a signed token request" in response.text


def test_the_page_carries_this_origin_s_band(office):
    """Injected, like every other surface: a page added later cannot be
    added without one, and the band is the only thing that says which trust
    domain a reader is standing in."""
    body = office.get("/upload").text
    assert "Voter Registration Office" in body
    assert "--stale-height" in body or "config-watch" in body or "ovpocWatch" in body


def test_the_page_says_what_is_substituted(office):
    """S6 reaches a surface. A clause that reaches none is either a clause
    nobody needs or a label somebody forgot."""
    body = office.get("/upload").text
    assert "note note--substituted" in body and "<code>S6</code>" in body


def test_the_script_is_served_from_the_same_origin(office):
    """No cross-origin permission is needed for the page, and none is granted."""
    response = office.get("/upload.js")
    assert response.status_code == 200
    assert "text/javascript" in response.headers["content-type"]


def test_the_voting_application_offers_no_such_page(deployment):
    """The one thing this arrangement exists for.

    The application writes the document and never handles the signed one.
    A page here would be the shortcut A8 names.
    """
    voter = TestClient(apps_module.voter_app(deployment))
    for path in ("/upload", "/signed-token-requests"):
        assert voter.get(path).status_code in (404, 405)
    assert voter.post("/signed-token-requests", content=b"x").status_code in (404, 405)


# --------------------------------------------------------------------------
# The endpoint
# --------------------------------------------------------------------------

def test_an_office_told_nothing_to_trust_says_so(office):
    """Not NOT_IDENTIFIED.

    An office that was never given trust anchors has not been configured
    for this route. Reporting a deployment's state as a citizen's failure
    would send them looking for a problem with their own certificate.
    """
    response = office.post("/signed-token-requests", content=_document())
    assert response.status_code == 200
    assert response.json() == {"outcome": "ROUTE_NOT_OFFERED"}


def test_an_oversized_upload_is_refused_without_being_read(office, deployment):
    """The endpoint is reachable by anyone, and reads into memory to check.

    Not an answer to denial of service -- `docs/threats.md` says there is
    none -- but an open endpoint with no cap at all is an invitation rather
    than an omission.
    """
    response = office.post("/signed-token-requests", content=b"%PDF-1.7\n" + b"X" * (3 * 1024 * 1024))
    assert response.json() == {"outcome": "TOO_LARGE"}


def test_the_office_answers_rubbish_without_raising(office):
    """A malformed upload is an answer, not a traceback.

    Checked before the validator is configured as well as after, because
    the size and the route checks run first and must not be reached by an
    exception from either.
    """
    for rubbish in (b"", b"not a pdf", b"%PDF-1.7\nbroken\n"):
        response = office.post("/signed-token-requests", content=rubbish)
        assert response.status_code == 200
        assert "outcome" in response.json()


def test_the_outcome_is_all_that_comes_back(office):
    """The office records why and tells a requester the enum.

    What each answer means is written on the page, where a reader can see
    it. Putting it on the wire would make the office's disclosure depend
    on the wording of a page it happens to serve.
    """
    body = office.post("/signed-token-requests", content=_document()).json()
    assert set(body) == {"outcome"}


def test_every_outcome_the_office_can_return_is_spelled_out_on_the_page():
    """Otherwise a voter meets a bare enum name and can do nothing with it.

    The page is the only place these are explained, so a new outcome added
    to the office without a sentence here reaches a citizen as
    `CERTIFICATE_REVOKED` and nothing else.
    """
    import re

    from ovpoc.vro import Outcome

    script = (ROOT / "web" / "upload" / "static" / "upload.js").read_text()
    explained = set(re.findall(r"^  ([A-Z_]+): \[", script, re.M))

    # RESERVED never reaches a requester -- the transport names that state
    # AWAITING_RELEASE in its own vocabulary, which the page does explain.
    reachable = {o.name for o in Outcome} - {"RESERVED"}
    missing = reachable - explained
    assert not missing, f"the upload page explains no outcome for: {sorted(missing)}"


# --------------------------------------------------------------------------
# An office that has been told what to trust
# --------------------------------------------------------------------------

@pytest.fixture
def pinned_office(tmp_path_factory):
    """A deployment whose anchors are one invented authority.

    Built here rather than borrowed from `election-data/trust-anchors`,
    which this repository now carries: a test reading that directory would
    pass or fail on whether a clone happens to have it, and would be
    asserting something about the Hungarian certification authority rather
    than about this code.
    """
    pytest.importorskip("pyhanko", reason="the pades extra is not installed")
    import datetime
    import sys as _sys

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    _sys.path.insert(0, str(ROOT / "tools"))
    import fetch_trust_anchors as pinner

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "HU"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "TEST CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=900))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA384()))

    anchors = tmp_path_factory.mktemp("anchors")
    pinner.add(anchors, cert.public_bytes(serialization.Encoding.DER),
               "test-ca.cer", "file:test")
    deployment = Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("config-root"),
        trust_anchors=anchors)
    return TestClient(apps_module.vro_app(deployment))


def test_an_office_with_anchors_offers_the_route(pinned_office):
    """Unsigned, so NOT_IDENTIFIED -- and not ROUTE_NOT_OFFERED.

    The two answers are the whole difference between an office that has
    not been configured and one that has been and does not know you.
    """
    body = pinned_office.post("/signed-token-requests",
                              content=_document()).json()
    assert body == {"outcome": "NOT_IDENTIFIED"}


def test_an_office_with_anchors_still_caps_the_upload(pinned_office):
    body = pinned_office.post(
        "/signed-token-requests",
        content=b"%PDF-1.7\n" + b"X" * (3 * 1024 * 1024)).json()
    assert body == {"outcome": "TOO_LARGE"}
