"""The token-request document, and the rule the office applies to it.

Three groups. The first pins `render` as a pure function, because everything
else depends on the office being able to reproduce a document it did not
write. The second covers recovering a payload back out, which is allowed to
be crude. The third is the rule itself, and is where the attacks live.

The attack worth keeping in mind while reading the third group: a hostile
voting application shows the citizen a plausible request and embeds somebody
else's `c`. The citizen signs under a qualified certificate and spends their
entitlement on a ballot they never see. Nothing downstream can detect it,
because every signature involved is genuine. The office refusing a document
that is not what its payload renders to is the whole of the defence, and on
this route it replaces a check the wallet used to perform (`WalletFlow.load`)
and a real wallet does not.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from ovpoc import pdfrequest
from ovpoc.messages import b64, canonical_bytes, unb64
from ovpoc.pdfrequest import DocumentCheck, Refusal, check, extract, render

ELECTION = "demo-2026"
DIGEST = "a" * 64


def _c(seed: bytes = b"c") -> bytes:
    """384 bytes, the length a 3072-bit modulus gives — the article's minimum."""
    out = b""
    while len(out) < 384:
        out += hashlib.sha512(seed + str(len(out)).encode()).digest()
    return out[:384]


@pytest.fixture
def blinded() -> bytes:
    return _c()


@pytest.fixture
def payload(blinded) -> dict:
    return pdfrequest.payload_of(ELECTION, DIGEST, blinded)


@pytest.fixture
def document(payload) -> bytes:
    return render(payload)


def signed_like(document: bytes, tail: bytes = b"") -> bytes:
    """A document with an incremental update appended, as a wallet leaves it."""
    return document + (tail or b"\n% the wallet's incremental update\n%%EOF\n")


# --------------------------------------------------------------------------
# render is a function of its payload
# --------------------------------------------------------------------------

def test_two_renders_of_one_payload_are_byte_identical(payload):
    """The property the whole route stands on.

    If the renderer draws anything it cannot recompute — a creation time read
    from a clock, a random identifier — the office cannot rebuild a citizen's
    document and the rule collapses back to parsing.
    """
    assert render(payload) == render(payload)


def test_a_different_payload_renders_differently(payload, blinded):
    for other in (dict(payload, election_id="demo-2027"),
                  dict(payload, config_digest="b" * 64),
                  pdfrequest.payload_of(ELECTION, DIGEST, _c(b"other"))):
        assert render(other) != render(payload)


def test_the_document_states_its_payload_where_a_person_can_read_it(payload, document):
    """Not a formatting assertion: this text is the citizen's only check."""
    page = _page_text(document)
    assert payload["election_id"] in page
    assert payload["config_digest"] in page
    assert pdfrequest.fingerprint(unb64(payload["blinded_key"])) in page
    for i in range(0, len(payload["blinded_key"]), 64):
        assert payload["blinded_key"][i:i + 64] in page


def test_the_document_carries_the_payload_in_both_machine_readable_places(
    payload, document
):
    body = canonical_bytes(payload)
    assert pdfrequest._from_embedded(document) == body
    assert pdfrequest._from_marker(document) == body


def test_an_info_dictionary_is_written(document):
    """Established by experiment, and the experiment cost a round trip.

    The DÁP application refuses a document with no `/Info` outright, before
    any signature is attempted, as a file with "content problems". Nothing
    else in this module would notice if a later tidy-up dropped it, and the
    failure would appear on a phone rather than here.
    """
    assert b"/Info " in document
    assert b"/CreationDate" in document


def test_the_info_dates_are_not_read_from_a_clock(payload):
    """A producer that times itself is not a function of its payload."""
    assert render(payload).count(pdfrequest._INFO_DATE.encode()) == 2


def test_non_ascii_is_refused_rather_than_transliterated(blinded):
    """`ő` is outside WinAnsiEncoding and rendering it as `ö` is a lie.

    The document is the only thing the citizen can check, so a renderer that
    quietly changes what it says is the one failure this design cannot
    tolerate. Refusing is the honest answer until a font is embedded.
    """
    bad = pdfrequest.payload_of("előválasztás", DIGEST, blinded)
    with pytest.raises(ValueError):
        render(bad)


def test_a_payload_with_the_wrong_fields_is_refused(payload):
    for bad in (dict(payload, extra="x"),
                {k: v for k, v in payload.items() if k != "election_id"},
                dict(payload, blinded_key="not base64!!")):
        with pytest.raises(ValueError):
            render(bad)


def test_the_document_is_a_well_formed_pdf(document):
    """A malformed file is refused by the wallet, which reads as a design fault."""
    assert document.startswith(b"%PDF-1.7\n")
    assert document.rstrip().endswith(b"%%EOF")

    table = document.split(b"xref\n", 1)[1]
    rows = re.findall(rb"(\d{10}) (\d{5}) ([nf]) \n", table)
    assert rows
    numbers = []
    for offset, _generation, kind in rows:
        if kind == b"f":
            continue
        header = re.match(rb"(\d+) 0 obj\n", document[int(offset):int(offset) + 32])
        assert header, f"offset {int(offset)} does not land on an object"
        numbers.append(int(header.group(1)))
    assert numbers == list(range(1, len(numbers) + 1))

    for match in re.finditer(rb"/Length (\d+) >>\nstream\n", document):
        declared = int(match.group(1))
        stop = document.index(b"\nendstream", match.end())
        assert stop - match.end() == declared


def _page_text(document: bytes) -> str:
    at = document.index(b"BT /")
    stop = document.index(b"\nendstream", at)
    return document[at:stop].decode("latin-1")


# --------------------------------------------------------------------------
# Recovering a candidate
# --------------------------------------------------------------------------

def test_a_payload_is_recovered_from_the_document(payload, document):
    candidate, where, refusal = extract(document)
    assert candidate == payload
    assert where == "embedded file"
    assert refusal is None


def test_the_marker_alone_is_enough(payload, document):
    stripped = document.replace(b"/Type /EmbeddedFile", b"/Type /Something", 1)
    candidate, where, refusal = extract(stripped)
    assert candidate == payload
    assert where == "marker comment"


def test_carriers_that_disagree_are_refused_rather_than_resolved(payload, document):
    """Preferring one would make the choice of carrier an attacker's lever.

    A document that cannot say one thing about itself was edited after it
    was rendered. The office has no basis for deciding which copy is the
    real one and must not invent one.
    """
    lie = canonical_bytes(pdfrequest.payload_of(ELECTION, "b" * 64, _c(b"lie")))
    tampered = document.replace(
        pdfrequest.MARKER + canonical_bytes(payload),
        pdfrequest.MARKER + lie, 1)
    assert tampered != document

    candidate, where, refusal = extract(tampered)
    assert candidate is None
    assert refusal is Refusal.CARRIERS_DISAGREE


def test_a_document_with_no_payload_in_it_is_not_a_request():
    candidate, _where, refusal = extract(b"%PDF-1.7\nnothing here\n%%EOF\n")
    assert candidate is None
    assert refusal is Refusal.NOT_A_REQUEST_DOCUMENT


def test_a_carrier_holding_rubbish_is_not_a_request():
    for rubbish in (b"{not json", b'{"blinded_key": 1}', b'["a"]', b"{}"):
        document = b"%PDF-1.7\n" + pdfrequest.MARKER + rubbish + b"\n%%EOF\n"
        candidate, _where, refusal = extract(document)
        assert candidate is None
        assert refusal is Refusal.NOT_A_REQUEST_DOCUMENT


# --------------------------------------------------------------------------
# The rule
# --------------------------------------------------------------------------

def test_a_signed_request_is_accepted(payload, document):
    signed = signed_like(document)
    result = check(signed, covered_prefix_length=len(document))
    assert result == DocumentCheck(
        accepted=True, payload=payload, recovered_from="embedded file",
        rendered_bytes=len(document))


def test_the_unsigned_tail_a_wallet_appends_does_not_matter(payload, document):
    """DÁP appends a `/DSS` outside the first signature's coverage.

    Every document it signs has unsigned bytes at the end, so an office
    requiring the signature to cover the whole file would refuse all of
    them. The rule asks for coverage of the prefix and disregards the rest.
    """
    signed = document + b"X" * 9000
    result = check(signed, covered_prefix_length=len(document))
    assert result.accepted is True


def test_a_document_that_is_not_what_its_payload_renders_to_is_refused(
    payload, document
):
    """The theft case, and the reason the rule recomputes instead of reading.

    Here every machine-readable copy says one thing and the page says
    another — which is what a hostile application would produce to make a
    citizen sign a request for somebody else's `c`. Recovery succeeds; the
    rebuild does not match; the document is refused.
    """
    visible = payload["blinded_key"][:64].encode("ascii")
    altered = document.replace(b"(" + visible + b") Tj",
                               b"(" + b"X" * 64 + b") Tj", 1)
    assert altered != document

    result = check(signed_like(altered), covered_prefix_length=len(altered))
    assert result.accepted is False
    assert result.refusal is Refusal.NOT_AS_RENDERED


def test_a_swapped_payload_cannot_produce_a_false_accept(payload, document):
    """Why extraction is allowed to be crude.

    Both carriers are replaced with a consistent lie, so nothing disagrees
    and recovery succeeds. The document was rendered from a different
    payload, so the rebuild differs and the prefix check refuses. A wrong
    recovery costs a refusal, never an acceptance.
    """
    lie = canonical_bytes(pdfrequest.payload_of(ELECTION, "c" * 64, _c(b"lie")))
    tampered = document.replace(canonical_bytes(payload), lie)

    candidate, _where, refusal = extract(tampered)
    assert candidate is not None and refusal is None

    result = check(tampered, covered_prefix_length=len(tampered))
    assert result.accepted is False
    assert result.refusal is Refusal.NOT_AS_RENDERED


def test_a_signature_that_stops_short_of_the_document_is_refused(payload, document):
    result = check(signed_like(document),
                   covered_prefix_length=len(document) - 1)
    assert result.accepted is False
    assert result.refusal is Refusal.SIGNATURE_DOES_NOT_COVER_IT


def test_a_refusal_hands_back_no_payload(document):
    """A candidate that failed the rebuild is a guess that turned out wrong.

    Returning it would invite a caller to use it, which is the whole
    attack wearing a different hat.
    """
    for result in (
        check(signed_like(document), covered_prefix_length=0),
        check(b"%PDF-1.7\nnothing\n%%EOF\n", covered_prefix_length=99),
    ):
        assert result.accepted is False
        assert result.payload is None


def test_the_rule_says_nothing_about_who_signed(payload, document):
    """It cannot: no identity is reachable from these bytes.

    Stated as a test because the temptation on this route is to let a PDF
    reader answer an identity question, and the identity boundary in
    `vro.py` is where that has to be decided instead.
    """
    result = check(signed_like(document), covered_prefix_length=len(document))
    assert not hasattr(result, "subject")
    assert set(result.payload) == set(pdfrequest.FIELDS)


# --------------------------------------------------------------------------
# The vector, consumed here as well as in test_vectors.py
# --------------------------------------------------------------------------

def test_the_committed_vector_still_describes_this_renderer():
    import pathlib
    body = json.loads(
        (pathlib.Path(__file__).resolve().parent / "vectors" / "pdf-request.json")
        .read_text())
    for vector in body["vectors"]:
        i, e = vector["input"], vector["expected"]
        payload = pdfrequest.payload_of(
            i["election_id"], i["config_digest"], unb64(i["blinded_key_b64url"]))
        document = render(payload)
        assert b64(document) == e["document_b64"], vector["name"]
        assert hashlib.sha256(document).hexdigest() == e["document_sha256"]
        assert len(document) == e["document_bytes"]
