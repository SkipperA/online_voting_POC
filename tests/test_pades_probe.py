"""The probe, and the inspector that has to be believed when it says "gone".

`tools/pades_probe.py` writes one document carrying its payload four times
over; `tools/pades_inspect.py` reads a signed copy back and reports which
copies survived.  The report is the whole product -- it is what decides
whether the office can recompute a document rather than parse it -- and it has
a failure mode that would send the investigation the wrong way without anyone
noticing.  "The wallet stripped the embedded file" and "the inspector cannot
see an embedded file" produce the same line.

So each carrier is removed in turn from a known-good document and the
inspector is required to notice, which is `tools/sabotage.py`'s argument
applied to a diagnostic: a check that cannot fail is not a check.  The
remaining tests pin the two properties the office's rule would stand on -- that
the document is a pure function of its payload, and that appending to it
leaves the prefix intact while rewriting it does not.

Nothing here tests a defence, because the probe is not one.  It is deleted or
promoted once the signed file comes back.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from ovpoc.messages import canonical_bytes, unb64  # noqa: E402

import pades_inspect  # noqa: E402
import pades_probe  # noqa: E402


ELECTION = "demo-2026"


@pytest.fixture
def blinded() -> bytes:
    return pades_probe.fixture_blinded_key(ELECTION)


@pytest.fixture
def payload(blinded: bytes) -> dict:
    return pades_probe.payload_of(ELECTION, "a" * 64, blinded)


@pytest.fixture
def document(payload: dict, blinded: bytes) -> bytes:
    return pades_probe.probe_document(payload, blinded)


# --------------------------------------------------------------------------
# The document is a function of its payload
# --------------------------------------------------------------------------

def test_two_builds_of_one_payload_are_byte_identical(payload, blinded):
    """The property the office's rule depends on, asserted directly.

    If the renderer draws anything it cannot recompute -- a creation date, a
    random identifier -- the office cannot rebuild a citizen's document and
    the whole approach collapses to parsing.
    """
    first = pades_probe.probe_document(payload, blinded)
    second = pades_probe.probe_document(payload, blinded)
    assert first == second
    assert len(first) > 1000


def test_a_different_payload_produces_a_different_document(payload, blinded, document):
    other = dict(payload, election_id="demo-2027")
    assert pades_probe.probe_document(other, blinded) != document


def test_the_document_carries_the_payload_four_times(document, payload):
    canonical = canonical_bytes(payload)
    assert pades_inspect.carrier_embedded(document) == canonical
    assert pades_inspect.carrier_marker(document) == canonical
    assert pades_inspect.carrier_xmp(document) == canonical
    visible = pades_inspect.carrier_visible(document, payload)
    assert visible["every_line_of_c"]
    assert visible["election_id"] and visible["config_digest"]


def test_the_rendered_text_is_ascii_so_nothing_is_transliterated(payload, blinded):
    """A non-ASCII string must raise rather than reach WinAnsiEncoding.

    `o-double-acute` is not in WinAnsi, and a document that renders it as
    `o-diaeresis` is the dishonest rendering this route exists to prevent.
    """
    with pytest.raises(ValueError):
        pades_probe.probe_document(
            dict(payload, election_id="előválasztás"), blinded)


@pytest.mark.parametrize("variant", pades_probe.LADDER, ids=lambda v: v.name)
def test_every_rung_is_structurally_sound(variant, payload, blinded):
    """Not pedantry: a malformed file is a wasted trip to the phone.

    The ladder is about to be carried to a wallet that has already refused
    one document without saying why. A rung with a wrong offset would be
    refused too, and would be read as evidence about the feature it was
    built to test.
    """
    document = pades_probe.probe_document(payload, blinded, variant)
    assert document.startswith(b"%PDF-1.7\n")
    assert document.rstrip().endswith(b"%%EOF")

    table = document.split(b"xref\n", 1)[1]
    rows = re.findall(rb"(\d{10}) (\d{5}) ([nf]) \n", table)
    assert rows, "no cross-reference table"
    numbers = set()
    for offset, _generation, kind in rows:
        if kind == b"f":
            continue
        header = re.match(rb"(\d+) 0 obj\n", document[int(offset):int(offset) + 32])
        assert header, f"offset {int(offset)} does not land on an object header"
        numbers.add(int(header.group(1)))
    # Contiguous from 1: a variant that reserved a number for an object it
    # does not have would leave a hole, and the hole would be what the
    # wallet objected to.
    assert numbers == set(range(1, len(numbers) + 1))


@pytest.mark.parametrize("variant", pades_probe.LADDER, ids=lambda v: v.name)
def test_every_rung_carries_exactly_what_it_declares(variant, payload, blinded):
    """The ladder's whole value is that one rung differs from the last by one thing."""
    document = pades_probe.probe_document(payload, blinded, variant)
    canonical = canonical_bytes(payload)

    assert (pades_inspect.carrier_marker(document) == canonical) is variant.marker
    assert (pades_inspect.carrier_xmp(document) == canonical) is variant.xmp
    assert (pades_inspect.carrier_embedded(document) == canonical) is variant.attachment
    assert (b"/Info " in document) is variant.info


def test_every_rung_renders_the_same_page(payload, blinded):
    """Otherwise a refusal would have two candidate causes again.

    The documents differ in structure and metadata. What a reader sees must
    not vary, or the experiment stops being single-variable.
    """
    pages = {
        v.name: pades_inspect.content_streams(
            pades_probe.probe_document(payload, blinded, v))[0]
        for v in pades_probe.LADDER
    }
    assert len(set(pages.values())) == 1, (
        "these rungs do not render identically: "
        + ", ".join(sorted(pages))
    )


def test_the_rungs_are_distinct_documents(payload, blinded):
    built = [pades_probe.probe_document(payload, blinded, v)
             for v in pades_probe.LADDER]
    assert len(set(built)) == len(built)


def test_the_cross_reference_offsets_point_at_their_objects(document):
    """The full document specifically, as the single-file mode writes it."""
    table = document.split(b"xref\n", 1)[1]
    rows = re.findall(rb"(\d{10}) (\d{5}) ([nf]) \n", table)
    assert rows, "no cross-reference table"
    for offset, _generation, kind in rows:
        if kind == b"f":
            continue
        at = int(offset)
        assert re.match(rb"\d+ 0 obj\n", document[at:at + 32]), \
            f"offset {at} does not land on an object header"


def test_every_declared_stream_length_is_the_true_length(document):
    for obj in pades_inspect.objects(document):
        if obj["stream"] is None:
            continue
        declared = re.search(rb"/Length\s+(\d+)", obj["header"])
        assert declared, f"object {obj['number']} has a stream and no /Length"
        assert len(obj["stream"]) == int(declared.group(1)), \
            f"object {obj['number']} declares the wrong /Length"


# --------------------------------------------------------------------------
# The inspector has to notice a carrier that is gone
# --------------------------------------------------------------------------

def _cut_object(data: bytes, number: int) -> bytes:
    match = re.search(rb"\n" + str(number).encode("ascii") + rb" 0 obj\b", data)
    assert match, f"object {number} not in the document"
    end = data.index(b"endobj\n", match.end()) + len(b"endobj\n")
    return data[:match.start() + 1] + data[end:]


def _object_number_of(data: bytes, needle: bytes) -> int:
    for obj in pades_inspect.objects(data):
        if needle in obj["header"]:
            return obj["number"]
    raise AssertionError(f"no object containing {needle!r}")


def test_a_stripped_embedded_file_is_reported_as_gone(document, payload):
    # `/Type /EmbeddedFile`, because the catalogue's name tree is called
    # `/EmbeddedFiles` and cutting the catalogue would prove nothing.
    number = _object_number_of(document, b"/Type /EmbeddedFile")
    stripped = _cut_object(document, number)
    report = pades_inspect.inspect(stripped, None, payload)
    assert report["carriers"]["embedded_file"]["present"] is False
    # And the others are still found, so the report distinguishes one loss
    # from a detector that has stopped working altogether.
    assert report["carriers"]["marker_comment"]["present"] is True
    assert report["carriers"]["xmp"]["present"] is True


def test_a_stripped_marker_comment_is_reported_as_gone(document, payload):
    stripped = pades_inspect.MARKER_RE.sub(b"", document, count=1)
    report = pades_inspect.inspect(stripped, None, payload)
    assert report["carriers"]["marker_comment"]["present"] is False
    assert report["carriers"]["embedded_file"]["present"] is True


def test_a_stripped_xmp_packet_is_reported_as_gone(document, payload):
    number = _object_number_of(document, b"/Type /Metadata")
    stripped = _cut_object(document, number)
    report = pades_inspect.inspect(stripped, None, payload)
    assert report["carriers"]["xmp"]["present"] is False
    assert report["carriers"]["embedded_file"]["present"] is True


def test_rewritten_page_text_is_reported_as_missing(document, payload):
    """The case that matters most and is hardest to see.

    A wallet that re-renders the page could leave every machine-readable copy
    intact and change what the page says, which is the disagreement the whole
    design refuses to tolerate.
    """
    blinded = payload["blinded_key"].encode("ascii")
    # The text operator specifically. A bare replace would hit the marker
    # comment at the top of the file, which is a different carrier and would
    # leave the page untouched — the test would then pass for the wrong reason.
    altered = document.replace(
        b"(" + blinded[:64] + b") Tj", b"(" + b"X" * 64 + b") Tj", 1)
    assert altered != document
    report = pades_inspect.inspect(altered, None, payload)
    assert report["carriers"]["visible_text"]["every_line_of_c"] is False
    assert report["carriers"]["visible_text"]["first_line_of_c"] is False


def test_a_carrier_that_disagrees_is_reported_as_disagreeing(document, payload, blinded):
    """Present and wrong is a different finding from absent, and worse."""
    other = canonical_bytes(pades_probe.payload_of(ELECTION, "b" * 64, blinded))
    tampered = document.replace(canonical_bytes(payload), other, 1)
    report = pades_inspect.inspect(tampered, None, payload)
    present = [c for c in ("embedded_file", "marker_comment", "xmp")
               if report["carriers"][c]["present"]]
    assert any(report["carriers"][c]["agrees_with_payload"] is False for c in present)


# --------------------------------------------------------------------------
# The prefix rule, under the two things a wallet might do
# --------------------------------------------------------------------------

def test_an_incremental_update_leaves_the_prefix_intact(document, payload):
    """What a PAdES signer is expected to do, simulated.

    The appended bytes are nonsense; that is the point. The office reads the
    prefix it recomputed and disregards everything after it, so what the
    wallet appends cannot change the decision.
    """
    signed = document + b"\n% an incremental update would go here\n%%EOF\n"
    report = pades_inspect.inspect(signed, document, payload)
    assert report["prefix"]["holds"] is True


def test_a_rewritten_document_fails_the_prefix_check(document, payload, blinded):
    """And the report says where, so the failure can be read rather than guessed."""
    rewritten = pades_probe.probe_document(
        dict(payload, config_digest="c" * 64), blinded)
    report = pades_inspect.inspect(rewritten, document, payload)
    assert report["prefix"]["holds"] is False
    assert report["prefix"]["first_difference_at"] > 0


def test_the_prefix_is_checked_against_a_rebuild_when_the_original_is_lost(
    document, payload
):
    """The office's own position: it holds no original, only the payload.

    This is the rule as the office would run it -- recover a candidate, rebuild
    the document from it, compare -- and it has to give the same answer as the
    comparison against the file we kept.
    """
    signed = document + b"\n%%EOF\n"
    report = pades_inspect.inspect(signed, None, None)
    assert report["prefix"]["checked_against"] == "rebuilt"
    assert report["prefix"]["holds"] is True
    assert report["payload"] == payload


def test_a_misrecovered_payload_cannot_produce_a_false_accept(document, payload, blinded):
    """The reason extraction is allowed to be fragile.

    Here every machine-readable copy says one thing and the document was
    rendered from another. Recovery succeeds, the rebuild differs, and the
    prefix check refuses -- which is the property that lets the carrier be a
    hint rather than evidence.
    """
    lie = canonical_bytes(pades_probe.payload_of(ELECTION, "d" * 64, blinded))
    tampered = document.replace(canonical_bytes(payload), lie)
    report = pades_inspect.inspect(tampered, None, None)
    assert report["payload"] is not None
    assert report["prefix"]["holds"] is False


@pytest.mark.parametrize("eol", [b"\n", b"\r\n", b"\r", b""])
def test_a_revision_ends_after_the_end_of_line_that_follows_eof(document, eol):
    """One byte, and getting it wrong looks exactly like a wallet rewriting the file.

    Cutting a signed document at the end of the `%%EOF` token alone yields a
    prefix one byte short of the original, whose digest then disagrees with
    the citizen's own copy — which is indistinguishable, to a reader of the
    report, from the wallet having re-saved the document. It happened. The
    terminator varies, so all four forms are pinned here.
    """
    original = document.rstrip(b"\r\n") + eol
    signed = original + b"7 0 obj\n<< >>\nendobj\nstartxref\n0\n%%EOF\n"
    ends = pades_inspect.revisions(signed)
    assert ends[0] == len(original)
    assert signed[:ends[0]] == original
    assert pades_inspect.looks_like_a_whole_pdf(signed[:ends[0]])


def _with_signature(document: bytes) -> bytes:
    """An incremental update carrying something shaped like a signature."""
    return (document + b"7 0 obj\n<< /Type /Sig /ByteRange [0 "
            + str(len(document)).encode("ascii")
            + b" 999 10] /Contents <00> >>\nendobj\nstartxref\n0\n%%EOF\n")


def test_the_signed_document_is_reported_with_a_digest_to_compare(document, payload):
    updates = pades_inspect.inspect(_with_signature(document), None, payload)["updates"]
    assert updates["signed_document_bytes"] == len(document)
    assert updates["signed_document_sha256"] == hashlib.sha256(document).hexdigest()


def test_an_early_eof_in_a_linearised_file_is_not_taken_for_the_document():
    """The failure this rule exists to avoid, in the shape it actually took.

    A linearised PDF ends its first-page cross-reference with `%%EOF` a few
    hundred bytes in. That prefix starts with `%PDF-`, contains `startxref`
    and ends with `%%EOF`, so every cheap shape check passes — and a tool
    that reported the first such boundary would report a four-hundred-byte
    document and sound certain about it.
    """
    head = (b"%PDF-1.6\n16 0 obj\n<</Linearized 1/L 900>>\nendobj\n"
            b"startxref\n0\n%%EOF\n")
    body = b"1 0 obj\n<< /Type /Catalog >>\nendobj\nstartxref\n9\n%%EOF\n"
    original = head + body
    signed = _with_signature(original)

    updates = pades_inspect.inspect(signed, None, None)["updates"]
    assert updates["linearized"] is True
    # All three boundaries pass the shape check — the linearisation header,
    # the document, and the update that signed it. That is the point: the
    # shape check cannot choose between them and the signature can.
    assert updates["complete_revisions"] == [len(head), len(original), len(signed)]
    assert updates["signed_document_bytes"] == len(original)


def test_an_eof_inside_a_stream_is_not_taken_for_a_revision(payload, blinded):
    """`%%EOF` is five ordinary bytes, and a document may contain them."""
    forged = (b"%PDF-1.7\n1 0 obj\n<< /Length 9 >>\nstream\n%%EOF\n...\n"
              b"endstream\nendobj\nstartxref\n9\n%%EOF\n")
    ends = pades_inspect.revisions(forged)
    whole = [e for e in ends if pades_inspect.looks_like_a_whole_pdf(forged[:e])]
    assert len(ends) == 2
    assert whole == [len(forged)]


def test_the_coverage_arithmetic_separates_the_hole_from_appended_bytes():
    """Two different numbers that are easy to conflate, and only one is a finding.

    A `/ByteRange` leaves a gap because a signature cannot cover itself, and
    that gap is expected. Bytes beyond the *second* run are appended and
    unsigned, and on an ordinary signed file there are none. Reporting the
    hole as though it were unsigned trailing content would make every signed
    file look alarming, which is the fastest way to make the report ignored.
    """
    data = b"%PDF-1.7\n9 0 obj\n<< /ByteRange [0 100 400 60] >>\nendobj\n" + b"x" * 500
    coverage = pades_inspect.inspect(data, None, None)["coverage"]
    assert coverage["starts_at_zero"] is True
    assert coverage["contents_hole_bytes"] == 300
    assert coverage["unsigned_bytes_at_the_end"] == len(data) - 460


# --------------------------------------------------------------------------
# The script as a whole
# --------------------------------------------------------------------------

def test_build_writes_both_files_and_a_usable_sidecar(tmp_path):
    sidecar = pades_probe.build(tmp_path, ELECTION, None)
    pdf = (tmp_path / "pades-probe.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-1.7\n")
    assert pdf.rstrip().endswith(b"%%EOF")

    stored = json.loads((tmp_path / "pades-probe.json").read_text(encoding="utf-8"))
    assert stored == sidecar
    rebuilt = pades_probe.probe_document(
        stored["payload"], unb64(stored["payload"]["blinded_key"]))
    assert rebuilt == pdf


def test_the_ladder_writes_every_rung_and_a_legend(tmp_path):
    legend = pades_probe.build_ladder(tmp_path, ELECTION, None)
    for rung in legend["rungs"]:
        assert (tmp_path / rung["file"]).read_bytes()
        assert rung["note"], f"{rung['file']} does not say what a refusal would mean"
    names = [r["file"] for r in legend["rungs"]]
    assert names[:len(pades_probe.LADDER)] == [
        f"{v.name}.pdf" for v in pades_probe.LADDER]


def test_the_fingerprint_is_four_groups_of_four_hex_digits(blinded):
    assert re.fullmatch(r"[0-9a-f]{4}(-[0-9a-f]{4}){3}",
                        pades_probe.fingerprint(blinded))


def test_c_is_the_length_a_3072_bit_modulus_gives(blinded, payload):
    """512 base64url characters, which is eight lines of the 64 every surface uses."""
    assert len(blinded) == 384
    assert len(payload["blinded_key"]) == 512
