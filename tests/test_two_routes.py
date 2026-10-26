"""Where the two routes meet, which is the only place they are allowed to.

A citizen may ask for a token with their wallet or with a qualified
signature over a document. They establish identity differently and they
must not differ by a line in anything afterwards -- which is easy to say
and easy to lose, because the second route is a second entry point into
the same office and a second entry point is where a second copy of the
rules gets written.

Requirement 2 is what is at stake. If the document route kept its own
released set, one citizen could take a token by each, and nothing
published would show it: two commitments are indistinguishable from two
citizens, the aggregate audit still balances, and each voter's own check
answers truthfully. There is no observer who could see it. So most of what
follows is one assertion in several costumes -- the register, the released
set and the reservations are reached through `_claim` and through nothing
else.

The validator is a fake. What `driver/qualified_signature.py` does with
pyHanko is tested against real signatures in `test_qualified_signature.py`;
what the *office* does with its answers has no business needing a PDF
library to find out, which is the whole reason the seam is a protocol.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from driver.population_register import PopulationRegister
from ovpoc import keys, pdfrequest, rsabssa
from ovpoc.messages import AuthRequest, b64, unb64
from ovpoc.pdfrequest import ValidatedSignature
from ovpoc.vro import VRO, Outcome, SignedRequest

ELECTION = "demo-2026"
DIGEST = "a" * 64
WALLET_ID = "HU-1970-0442"
DOCUMENT_ID = "HU-471570820"


# --------------------------------------------------------------------------
# A validator that answers from a table
# --------------------------------------------------------------------------

@dataclass
class FakeValidation:
    """Whatever the test says, for whichever document the test hands over.

    Keyed by the document's digest rather than by its content, so that a
    test can arrange an answer for a document it has not built yet and so
    that nothing here has to parse a PDF.
    """

    answers: dict[str, ValidatedSignature | None]

    def validate(self, document: bytes) -> ValidatedSignature | None:
        return self.answers.get(hashlib.sha256(document).hexdigest())

    def says(self, document: bytes, answer: ValidatedSignature | None) -> bytes:
        self.answers[hashlib.sha256(document).hexdigest()] = answer
        return document


#: The office here is 2048-bit, for speed, so a blinded value is 256 bytes.
#: `rsabssa.blind_sign` refuses anything else, and a stand-in `c` of the
#: wrong length fails inside the signer rather than anywhere interesting.
C_BYTES = 256


def _c(seed: bytes) -> bytes:
    out = bytearray()
    while len(out) < C_BYTES:
        out += hashlib.sha512(seed + str(len(out)).encode()).digest()
    # Top bit cleared, so the value is below any 2048-bit modulus. A real
    # `c` comes out of `rsabssa.blind` and is in range by construction;
    # these are stand-ins and a quarter of them would not be.
    out[0] &= 0x7F
    return bytes(out[:C_BYTES])


def _document(blinded: bytes, election: str = ELECTION) -> bytes:
    return pdfrequest.render(
        pdfrequest.payload_of(election, DIGEST, blinded))


def _identified(document: bytes, identifier: str = DOCUMENT_ID,
                **kwargs) -> ValidatedSignature:
    """A validator answer that identifies somebody and covers the document."""
    return ValidatedSignature(
        subject={"country_name": "HU", "serial_number": identifier.split("-")[-1]},
        identifier=identifier,
        covered_prefix_length=kwargs.pop("covered", len(document)),
        **kwargs)


@pytest.fixture
def world():
    """One office, one wallet citizen, one document citizen, both enrolled."""
    register = PopulationRegister()
    wallet = keys.SigningKeyPair.generate()
    register.enrol(WALLET_ID, wallet.public_bytes)

    office = VRO.create(register, bits=2048, election_id=ELECTION)
    office.enrol(WALLET_ID)
    office.enrol(DOCUMENT_ID)
    office.signature_validation = FakeValidation(answers={})
    return office, wallet


def _wallet_request(wallet, blinded: bytes, voter_id: str = WALLET_ID):
    unsigned = AuthRequest(voter_id=voter_id, blinded_key=blinded,
                           wallet_signature=b"")
    return AuthRequest(voter_id=voter_id, blinded_key=blinded,
                       wallet_signature=wallet.sign(unsigned.signed_payload()))


# --------------------------------------------------------------------------
# One office, one released set
# --------------------------------------------------------------------------

def test_both_routes_issue_a_token_and_share_one_chain(world):
    office, wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(document, _identified(document))

    first = office.issue_token(_wallet_request(wallet, _c(b"wallet")))
    second = office.issue_token_for_signed_document(document)

    assert first.outcome is Outcome.ISSUED
    assert second.outcome is Outcome.ISSUED
    assert office.release_count() == 2
    assert office.release_log.verify_chain()
    assert set(office._released) == {WALLET_ID, DOCUMENT_ID}


def test_a_citizen_who_took_a_token_by_one_route_cannot_take_another(world):
    """Requirement 2, across the seam that could lose it.

    Nothing published would show the failure: two commitments for one
    citizen look exactly like two citizens, the count audit still
    balances, and the voter's own check still answers truthfully.
    """
    office, wallet = world
    register = office.population_register
    register.enrol(DOCUMENT_ID, keys.SigningKeyPair.generate().public_bytes)

    document = _document(_c(b"doc"))
    office.signature_validation.says(document, _identified(document))
    assert office.issue_token_for_signed_document(document).outcome is Outcome.ISSUED

    again = _document(_c(b"doc-again"))
    office.signature_validation.says(again, _identified(again))
    assert office.issue_token_for_signed_document(again).outcome is \
        Outcome.TOKEN_ALREADY_ISSUED
    assert office.release_count() == 1


def test_a_reservation_on_one_route_blocks_the_other(world):
    """The claim is the point, and it is one claim for one citizen."""
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(document, _identified(document))

    first, _request = office.reserve_signed_document(document)
    assert first.outcome is Outcome.RESERVED

    other = _document(_c(b"other"))
    office.signature_validation.says(other, _identified(other))
    second, _ = office.reserve_signed_document(other)
    assert second.outcome is Outcome.REQUEST_PENDING


def test_a_token_from_the_document_route_is_an_ordinary_token(world):
    """Nothing about the route survives into the ballot.

    If it did, the blinding would be leaking the thing it exists to hide.
    """
    office, _wallet = world
    adhoc = keys.SigningKeyPair.generate()
    blinded, inverse = rsabssa.blind(office.public_key, adhoc.public_bytes)

    document = _document(blinded)
    office.signature_validation.says(document, _identified(document))
    response = office.issue_token_for_signed_document(document)

    token = rsabssa.finalize(office.public_key, adhoc.public_bytes,
                             response.blind_signature, inverse)
    assert rsabssa.verify(office.public_key, adhoc.public_bytes, token)


# --------------------------------------------------------------------------
# The identity boundary, on the second route
# --------------------------------------------------------------------------

def test_an_unvalidatable_signature_is_not_identified(world):
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(document, None)

    response = office.issue_token_for_signed_document(document)
    assert response.outcome is Outcome.NOT_IDENTIFIED
    assert office.release_count() == 0


def test_a_certificate_naming_nobody_this_office_knows_is_not_identified(world):
    """No identifier composed means no identity, not an empty one."""
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(
        document, ValidatedSignature(subject={"common_name": "A"},
                                     identifier=None,
                                     covered_prefix_length=len(document)))
    assert office.issue_token_for_signed_document(document).outcome is \
        Outcome.NOT_IDENTIFIED


def test_eligibility_is_never_revealed_before_identity_on_this_route(world):
    """An unidentified party learns nothing about the electoral register.

    Both an unknown signer and an ineligible one must come back the same
    when the signature does not validate, or the upload endpoint becomes a
    roll lookup for anyone who can address the origin.
    """
    office, _wallet = world
    enrolled = _document(_c(b"enrolled"))
    stranger = _document(_c(b"stranger"))
    office.signature_validation.says(enrolled, None)
    office.signature_validation.says(stranger, None)

    assert office.issue_token_for_signed_document(enrolled).outcome is \
        office.issue_token_for_signed_document(stranger).outcome is \
        Outcome.NOT_IDENTIFIED


@pytest.mark.parametrize("field", ["revoked", "expired"])
def test_certificate_status_is_reported_only_after_identity(world, field):
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(
        document, _identified(document, **{field: True}))

    response = office.issue_token_for_signed_document(document)
    assert response.outcome is (Outcome.CERTIFICATE_REVOKED if field == "revoked"
                                else Outcome.CERTIFICATE_EXPIRED)
    assert office.release_count() == 0


def test_an_identified_signer_not_on_the_register_is_told_so(world):
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(
        document, _identified(document, identifier="HU-999999999"))
    assert office.issue_token_for_signed_document(document).outcome is \
        Outcome.NOT_ELIGIBLE


# --------------------------------------------------------------------------
# The document itself
# --------------------------------------------------------------------------

def test_a_document_that_is_not_what_its_payload_renders_to_is_refused(world):
    """The theft case reaching the office, with a genuine signature on it."""
    office, _wallet = world
    blinded = _c(b"doc")
    payload = pdfrequest.payload_of(ELECTION, DIGEST, blinded)
    visible = payload["blinded_key"][:64].encode("ascii")
    altered = pdfrequest.render(payload).replace(
        b"(" + visible + b") Tj", b"(" + b"X" * 64 + b") Tj", 1)
    office.signature_validation.says(altered, _identified(altered))

    response = office.issue_token_for_signed_document(altered)
    assert response.outcome is Outcome.DOCUMENT_REFUSED
    assert office.release_count() == 0
    # Below the boundary, so the audit log and the requester agree.
    assert "not_as_rendered" in office.audit_log[-1].reason


def test_a_signature_covering_less_than_the_document_is_refused(world):
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(
        document, _identified(document, covered=len(document) - 1))
    assert office.issue_token_for_signed_document(document).outcome is \
        Outcome.DOCUMENT_REFUSED


def test_the_identifier_never_comes_from_the_document(world):
    """A document saying whose it is would be a document anyone could write.

    Here the payload is perfectly good and the certificate names somebody
    not on the register. The office must follow the certificate.
    """
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(
        document, _identified(document, identifier="HU-000000001"))
    assert office.issue_token_for_signed_document(document).outcome is \
        Outcome.NOT_ELIGIBLE


def test_a_payload_claiming_an_identifier_is_not_a_token_request(world):
    """There is nowhere in the payload for a document to name anybody.

    The schema is exactly three fields, and that is the defence: a fourth
    would be a field the office might one day read, and the first thing
    anybody would put in it is whose request this is. The carrier here is
    edited to add one, which makes the file stop being a token request
    rather than making it somebody else's.

    Weaker as a test than it looks unless the strictness is pinned too --
    `request_payload_accepts_extra_fields` in `tools/sabotage.py` is the
    mutation that keeps `_well_formed` from being relaxed to a subset
    check by a later tidy-up.
    """
    office, _wallet = world
    blinded = _c(b"doc")
    document = _document(blinded)
    honest = pdfrequest.canonical_bytes(
        pdfrequest.payload_of(ELECTION, DIGEST, blinded))
    lying = pdfrequest.canonical_bytes({
        **pdfrequest.payload_of(ELECTION, DIGEST, blinded),
        "voter_id": WALLET_ID,
    })
    tampered = document.replace(honest, lying)
    assert tampered != document
    office.signature_validation.says(tampered, _identified(tampered))

    response = office.issue_token_for_signed_document(tampered)
    assert response.outcome is Outcome.DOCUMENT_REFUSED
    assert office.release_count() == 0


def test_an_office_with_no_validator_refuses_to_pretend(world):
    """Not a protocol outcome. An office that was never given a validator
    has not been configured for this route, and answering NOT_IDENTIFIED
    would report a deployment mistake as a citizen's problem."""
    office, _wallet = world
    office.signature_validation = None
    with pytest.raises(RuntimeError, match="no qualified-signature route"):
        office.issue_token_for_signed_document(_document(_c(b"doc")))


# --------------------------------------------------------------------------
# What the office keeps
# --------------------------------------------------------------------------

def test_the_office_keeps_the_signed_document_as_the_citizens_own_request(world):
    office, _wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(document, _identified(document))
    office.issue_token_for_signed_document(document)

    kept = office._requests[DOCUMENT_ID]
    assert kept.document == document
    assert kept.wallet_signature is None
    assert kept.route == "document"


def test_supervision_shows_the_digest_and_not_the_document(world):
    """A signed request is third-party verifiable without this office.

    Publishing it to whoever can reach the supervision origin would hand
    out a portable proof that a named citizen took part -- which is the
    artefact §3.7 spends a page keeping out of circulation. The digest
    ties a release to a document somebody already has; it is not one.
    """
    office, wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(document, _identified(document))
    office.issue_token_for_signed_document(document)
    office.issue_token(_wallet_request(wallet, _c(b"wallet")))

    dump = office.supervision_dump()
    by_id = {r["voter_id"]: r for r in dump["releases"]}

    document_row = by_id[DOCUMENT_ID]
    assert document_row["route"] == "document"
    assert document_row["request_document_sha256"] == \
        hashlib.sha256(document).hexdigest()
    assert document_row["request_document_bytes"] == len(document)
    assert b64(document) not in str(dump)

    wallet_row = by_id[WALLET_ID]
    assert wallet_row["route"] == "wallet"
    assert "request_signature" in wallet_row


def test_a_signed_request_carries_exactly_one_kind_of_evidence():
    """Both would be a release claiming to have been asked for twice."""
    for bad in ({}, {"wallet_signature": b"s", "document": b"d"}):
        with pytest.raises(ValueError):
            SignedRequest(blinded_key=b"c", **bad)


def test_a_poll_with_both_routes_survives_being_written_and_read_back(world):
    """`poll.state.json` holds two shapes of evidence now.

    The reload re-derives the chain and refuses anything that does not
    reproduce the head the office signed, so a register that lost the
    document half would not come back at all.
    """
    from ovpoc.vro import request_from_stored

    office, wallet = world
    document = _document(_c(b"doc"))
    office.signature_validation.says(document, _identified(document))
    office.issue_token_for_signed_document(document)
    office.issue_token(_wallet_request(wallet, _c(b"wallet")))

    stored = office.stored_state()
    restored = VRO.create(office.population_register, bits=2048,
                          election_id=ELECTION)
    restored.office_key = office.office_key
    restored.restore_releases(
        releases=stored["releases"],
        released=set(stored["released"]),
        openings={k: unb64(v) for k, v in stored["openings"].items()},
        audit=[],
        requests={k: request_from_stored(v)
                  for k, v in stored["requests"].items()},
        supervisor_downloads=stored["supervisor_downloads"],
        expected_head=unb64(stored["head"]),
    )
    assert restored._requests[DOCUMENT_ID].document == document
    assert restored._requests[WALLET_ID].wallet_signature is not None
    assert restored.release_count() == 2
