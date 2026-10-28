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


def test_an_office_offering_no_route_says_which_directory_it_read(
        office, deployment):
    """The question an operator has, answered where an operator looks.

    Without this the only way to find out that an office is not offering
    the route is to be a voter refused by it -- and that answer is about
    the office's state, deliberately, not about the configuration behind
    it. Reporting the path is the point: on a hosted deployment the
    elections are a mounted volume, so the directory the office reads is
    not the one in a clone of this repository, and anchors in the wrong
    place look from every other angle exactly like no anchors at all.
    """
    body = office.get("/back-office/trust").json()
    assert body["offered"] is False
    assert body["looked_in"] == str(deployment.trust_anchors)
    assert str(deployment.trust_anchors) in body["why"]


def test_the_office_s_own_page_is_where_that_is_reported(office):
    """And wired up, which is not a given.

    `office.js` fills the whole page in one pass, so a container it reads
    and the page does not define is not a missing section: it is a
    `null` dereference that stops the audit table and the release
    register filling too. The feature this patch adds is a diagnostic,
    and a diagnostic that takes the page down with it is worse than none.
    """
    page = office.get("/").text
    assert 'id="trust"' in page
    script = (ROOT / "web" / "office" / "static" / "office.js").read_text()
    assert "/back-office/trust" in script


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
def pinned_office(pinned_deployment) -> TestClient:
    return TestClient(apps_module.vro_app(pinned_deployment))


@pytest.fixture
def pinned_deployment(tmp_path_factory):
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
    return Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("config-root"),
        trust_anchors=anchors)


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


def test_an_office_publishes_the_anchors_it_will_believe(pinned_office):
    """What the office trusts is the whole of its answer to "who are you".

    Public certificates, their digests and where each was fetched from.
    Withholding them would make the one configuration that decides whose
    signatures this office accepts the one thing nobody outside it can
    read, which is the opposite of what the route is for.
    """
    body = pinned_office.get("/back-office/trust").json()
    assert body["offered"] is True
    assert body["pinned_on"]
    assert [a["subject"] for a in body["anchors"]] == ["CN=TEST CA,C=HU"]
    assert body["anchors"][0]["sha256"]
    assert body["anchors"][0]["source"] == "file:test"


def test_minting_does_not_change_whose_signatures_are_accepted(pinned_deployment):
    """The reason the anchors sit beside the elections and not inside one.

    `Deployment.create`'s default names a directory relative to this
    repository, so a mint that let it default gives the new election
    whatever anchors a clone happens to carry. Both ways it goes wrong
    are silent. On a hosted deployment, where the elections are a mounted
    volume and the repository's own `election-data/` is not it, the route
    turns off the first time an operator mints. In a clone that carries
    the pinned GovCA root -- this one does -- an office configured to
    trust one certification authority comes back trusting a different
    one, which is the failure `from_pinned` refuses to let a swapped file
    cause and which a mint would cause anyway.

    Nothing published shows either, and no voter can tell the first from
    an office that never offered the route.
    """
    before = pinned_deployment.vro.signature_validation
    assert before is not None

    pinned_deployment.mint(
        election_id="demo-2027", num_choices=4, bits=2048,
        opens="2027-09-25T08:00:00Z", closes="2027-09-25T20:00:00Z")

    after = pinned_deployment.vro.signature_validation
    assert after is not None, "minting turned the qualified-signature route off"
    assert after.trust_roots == before.trust_roots


# --------------------------------------------------------------------------
# The policy is the caller's, never the shell's
# --------------------------------------------------------------------------

def test_a_deployment_told_its_policy_ignores_the_environment(
        monkeypatch, tmp_path_factory):
    """Clause S7, and the correction `trust_anchors` already needed.

    `OVPOC_OPEN_ENROLMENT` is how an operator configures a server, and a
    caller that passes the value must not inherit the shell the process
    happened to start in. Both directions, because a default that
    silently won either way would be a configuration nobody could
    override.
    """
    monkeypatch.setenv("OVPOC_OPEN_ENROLMENT", "1")
    told_no = Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("a"),
        trust_anchors=None, open_enrolment=False)
    assert told_no.vro.enrol_on_qualified_signature is False

    monkeypatch.setenv("OVPOC_OPEN_ENROLMENT", "0")
    told_yes = Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("b"),
        trust_anchors=None, open_enrolment=True)
    assert told_yes.vro.enrol_on_qualified_signature is True


def test_the_word_is_read_as_a_word(monkeypatch):
    """`OVPOC_OPEN_ENROLMENT=0` turns it off.

    `bool(os.environ.get(...))` is true for the string `"0"`, so an
    operator writing the variable down in order to disable the clause
    would have enabled it. Worth a test because the bug is invisible:
    the office works, and admits everybody.
    """
    from service.state import _open_enrolment

    for value, expected in (("1", True), ("true", True), ("YES", True),
                            ("on", True), ("0", False), ("false", False),
                            ("", False), ("no", False)):
        monkeypatch.setenv("OVPOC_OPEN_ENROLMENT", value)
        assert _open_enrolment() is expected, value

    monkeypatch.delenv("OVPOC_OPEN_ENROLMENT")
    assert _open_enrolment() is False


def test_minting_does_not_change_who_may_ask(tmp_path_factory):
    """The same rule as the trust anchors, and the same way of getting it
    wrong: `create`'s default would re-read the environment, so an
    election minted after the variable changed would quietly admit a
    different set of people than the one before it.
    """
    deployment = Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("config-root"),
        trust_anchors=None, open_enrolment=True)
    deployment.mint(election_id="demo-2027", num_choices=4, bits=2048,
                    opens="2027-09-25T08:00:00Z", closes="2027-09-25T20:00:00Z")
    assert deployment.vro.enrol_on_qualified_signature is True
