"""Build one probe document, so that a real wallet can be asked what it does to it.

WHY THIS EXISTS, AND WHY IT COMES BEFORE ANY PROTOCOL CODE
-----------------------------------------------------------
The qualified-signature route has the voting application write an unsigned PDF,
the citizen sign it in their own wallet -- the European Digital Identity
Wallet, and in Hungary the DAP application -- and the office read `c` back out
of the signed file.  The office must be able to say, of a document it did not
write, that the thing the citizen saw is the thing the citizen signed.  A
document whose visible text and embedded data could disagree is worse than one
with neither, because on this route no software checks the request on the
voter's behalf: the present wallet implementations fetch the election
configuration themselves and refuse a mismatch (`WalletFlow.load`,
`web/wallet/static/wallet.js`), and a real wallet does no such thing.  It signs
what it is handed and shows a rendering.  The rendering is the whole of the
voter's protection.

The way to make that protection real is to stop treating the document as
something to be parsed and start treating it as something to be *recomputed*:
the document is a deterministic function of its payload, the office rebuilds it
from the payload it recovered, and compares.  Extraction then cannot cause a
wrong acceptance -- a misread payload rebuilds to different bytes and the
comparison fails -- and a document whose rendering disagrees with its payload
is not refused by a check so much as unconstructable.

All of which rests on one unpublished fact: **does the wallet add its signature
as an incremental update, leaving the original bytes intact as a prefix of the
signed file?**  That is what PAdES signers do in practice, and what the PDF
specification requires when signing a document that is already signed, but it
is not guaranteed by the standard for a first signature on an unsigned file.
Nothing the DAP service publishes answers it.  Its PKI Disclosure Statement
gives the profile -- PAdES-B-T, SHA-384 computed on the device, the key in a
qualified HSM it never leaves, a qualified timestamp, private individuals only
-- and says nothing whatever about what survives a save.

So this script writes one document carrying the same payload four times over,
in four carriers of different fragility, and `tools/pades_inspect.py` reads the
signed file back and reports which of them survived and whether the original
bytes are still there.  One signature on a phone decides the carrier, confirms
or kills the recomputation rule, and says whether the wallet touches the page.

It is deliberately a *probe* and not the final renderer.  No protocol code
depends on it, nothing here is a defence, and the office does not import it.
What it is, is the shape the renderer would take if the answers come back the
way they are expected to: deterministic, dependency-free, and built from the
same `canonical_bytes` the rest of the wire contract rests on.

WHAT EACH ANSWER WOULD MEAN
---------------------------
* **The signed file begins with these bytes, verbatim.**  The recomputation
  rule is available, the carrier question becomes a question about hints rather
  than evidence, and a PDF library is never trusted for what the document says.
* **It does not.**  The wallet re-saved the document, the rule is unavailable,
  and the route needs a different answer -- a semantic comparison between the
  payload and the rendered page, which needs text extraction and is the fragile
  thing this design was avoiding.  That is a conversation, not a fallback.
* **The embedded file survived.**  Use it; it is the proper mechanism and has
  precedent, a human-readable document carrying its own machine-readable
  original being exactly what PDF/A-3 invoices do.
* **The marker comment survived.**  Keep it as a second carrier: it costs one
  line to write and one line to read, and needs no PDF parsing at all.
* **XMP or `/Info` survived unchanged.**  Mildly interesting and still not
  worth using.  Both are the parts of a PDF a signer is most likely to rewrite,
  and a carrier the wallet quietly edits turns every honest request into a
  refusal.
* **The page content stream is unchanged, and a visible signature arrived as an
  annotation.**  Expected, and harmless: the office reads the prefix and
  disregards everything after it.
* **The page content stream changed.**  The wallet flattened its appearance
  into the page.  The prefix rule has already failed by then; this says why.

THE FOUR CARRIERS
-----------------
Each holds the same payload, which is `canonical_bytes` of the three fields the
present handover file carries -- `blinded_key`, `config_digest`, `election_id`
-- so that nothing new about serialisation has to be agreed:

1. an embedded file stream, reached through `/Names /EmbeddedFiles` and flagged
   `/AFRelationship /Source`;
2. a `%OVPOC-REQUEST` marker comment in the raw bytes, ahead of the first
   object;
3. an XMP metadata packet under a private namespace;
4. the visible text of the page itself.

Nothing in the file is compressed, and that is a decision rather than an
oversight.  A reader should be able to open the document in a text editor and
find all four copies, in the same spirit as the X-clauses of
`docs/Demo_Scope_Limits.md`: the demonstration shows what a deployment would
have no reason to show, so that it can be looked at rather than taken on trust.
It also makes the inspector's work honest, since a carrier it fails to find is
then a carrier that is not there.

DETERMINISM
-----------
The document contains nothing its recipient could not recompute.  No creation
date, no modification date, no producer version, no device identifier, and an
`/ID` derived from the payload rather than drawn at random.  Byte offsets in
the cross-reference table are computed, line endings are `\\n` throughout, and
the fonts are three of the standard fourteen, so no font binary is a second
artefact to keep identical across implementations.

The consequence is that the document's prose is ASCII and so are its fields.
That rules out rendering a free-text election name: `o-double-acute` and
`u-double-acute` are outside WinAnsiEncoding, `election.store.json` ships
non-ASCII names on purpose (clause X4), and a document that silently renders
*Elovalasztas* for *Előválasztás* is precisely the dishonest rendering the
route exists to prevent.  The election is named here by its identifier and the
digest of its configuration, which is what the voter can check against their
application in any case.  A deployment-grade document embeds a font.

THE FIRST ANSWER CAME BACK A REFUSAL
------------------------------------
The DAP application declined to sign the first probe at all, before any
signature was attempted: *"Problemas fajlok -- az alabbi fajlokkal tartalmi
problemak vannak, a biztonsagod erdekeben nem lehetseges az alairasuk, ezert
eltavolitjuk oket."*  Content problems; for your security these cannot be
signed, so we are removing them.

That is a finding and not a setback, but it is an undifferentiated one: the
first document varied six things from an ordinary PDF at once, and the refusal
names none of them.  The wording is worth reading closely, though.  *For your
security* is what a service says about content it considers active or
dangerous, rather than about a file it could not parse -- which points at the
embedded file stream first, attachments inside a PDF being the thing such a
scan exists to find.  It is a suspicion and not a conclusion, and the way to
settle it is to vary one thing at a time.

Hence `--variants`, which writes a ladder of documents differing from their
predecessor in exactly one respect.  The page text is byte-identical in all of
them, deliberately: if the rendering varied too, a refusal would have two
candidate causes again.

    v1-bare      the page, and nothing else at all
    v2-info      + a document information dictionary
    v3-marker    + the %OVPOC-REQUEST comment
    v4-xmp       + the XMP metadata packet
    v5-attach    + the embedded file, /Names and /AF
    v6-all       + all three carriers together (the original probe, with /Info)
    v7-qpdf      v6 rewritten by qpdf, if qpdf is on PATH

The last one is the control that matters most if the first six are all
refused: qpdf is a mainstream producer, so `v7` carries this document's content
in somebody else's bytes.  Refused as well, and the problem is what the
document *contains*; accepted, and the problem is that we wrote it ourselves.

**Sign them as one batch.**  The wallet takes several documents at once and
its refusal screen lists the ones it rejected by name, so a single pass gives
both halves of the experiment: the list of what was refused, and signed copies
of everything that was not -- which `tools/pades_inspect.py` can then be run
over for the prefix question the ladder was built to reach.

One consequence of `/Info` worth recording before it is forgotten.  A document
information dictionary conventionally carries `/CreationDate` and `/ModDate`,
and a renderer that writes the current time is no longer a pure function of
its payload, which is the property the office's rule depends on.  The dates
here are fixed constants.  If it turns out that `/Info` is required, a
deployment has to derive them from the election rather than from a clock.

USAGE
-----
    python tools/pades_probe.py                       # writes build/pades-probe/
    python tools/pades_probe.py --variants            # the whole ladder
    python tools/pades_probe.py --out DIR
    python tools/pades_probe.py --election-id demo-2026 --config-digest abc...

Then: move the documents to the phone, sign them in the wallet, bring back
whatever was signed, and

    python tools/pades_inspect.py SIGNED.pdf --original build/pades-probe/v6-all.pdf
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ovpoc.messages import b64, canonical_bytes  # noqa: E402

#: The marker the inspector looks for, and the cheapest carrier of the four.
MARKER = b"%OVPOC-REQUEST "

#: A private namespace for the XMP copy.  Not registered anywhere and not
#: meant to be: it exists so the inspector can tell its own packet from one
#: the wallet wrote.
XMP_NS = "https://diw.hu/ns/ovpoc/1.0/"

#: The name the embedded file is given inside the document.
EMBEDDED_NAME = "ovpoc-request.json"

#: A4, in points.
PAGE_W, PAGE_H = 595, 842
MARGIN = 56

#: Fixture values, chosen so that a run with no arguments is reproducible and
#: so that `c` is the length a 3072-bit modulus produces -- the article's
#: deployment minimum, and 512 base64url characters exactly, which is eight
#: lines of the 64 every surface already wraps a payload at.
FIXTURE_ELECTION_ID = "demo-2026"
FIXTURE_C_BYTES = 384

#: Fixed, because a renderer that reads a clock is not a function of its
#: payload.  See the note on `/Info` in the module docstring.
FIXED_DATE = "D:20260101000000Z"


@dataclass(frozen=True)
class Variant:
    """One rung of the ladder: what this document has that the last one did not.

    `note` is what a refusal of *this* document and acceptance of the one
    before it would establish.  It is carried here rather than in a table
    somewhere else so that the reason a file exists travels with the file.
    """

    name: str
    adds: str
    note: str
    info: bool = False
    marker: bool = False
    xmp: bool = False
    attachment: bool = False


#: Each rung differs from the one above it in exactly one respect, and every
#: rung renders the same page.  A ladder rather than a matrix: six documents
#: answer the question if the cause is a single feature, and if it is a
#: combination then no batch small enough to sign would have found it anyway.
LADDER: tuple[Variant, ...] = (
    Variant(
        "v1-bare", "nothing — one page and three fonts",
        "refused here and the objection is to the document itself: hand-written "
        "bytes, standard-14 fonts, or the absence of everything a producer "
        "normally writes.",
    ),
    Variant(
        "v2-info", "a document information dictionary",
        "accepted here and refused at v1 would mean the service requires the "
        "metadata an ordinary producer writes.",
        info=True,
    ),
    Variant(
        "v3-marker", "the %OVPOC-REQUEST comment",
        "refused here and the objection is to unrecognised bytes ahead of the "
        "first object, which would be a surprise: a comment is legal anywhere.",
        info=True, marker=True,
    ),
    Variant(
        "v4-xmp", "the XMP metadata packet",
        "refused here and the objection is to metadata under a namespace the "
        "service does not know.",
        info=True, xmp=True,
    ),
    Variant(
        "v5-attach", "the embedded file, /Names and /AF",
        "the one to watch. Refused here and the objection is to a PDF carrying "
        "an attachment, which is what a content scan exists to find and what "
        "'for your security' most likely means. It would close off the carrier "
        "with the best precedent and leave the marker comment doing the work.",
        info=True, attachment=True,
    ),
    Variant(
        "v6-all", "all three carriers at once",
        "the original probe with /Info added. Refused while v3, v4 and v5 are "
        "each accepted would mean the objection is to the combination, which "
        "no single-variable ladder can localise further.",
        info=True, marker=True, xmp=True, attachment=True,
    ),
)

#: What `probe_document` builds when nothing says otherwise: everything.
FULL = LADDER[-1]


# --------------------------------------------------------------------------
# The payload
# --------------------------------------------------------------------------

def fixture_blinded_key(election_id: str, size: int = FIXTURE_C_BYTES) -> bytes:
    """A stand-in for `c`, derived rather than drawn.

    A real `c` would come from `Voter.build_auth_request`.  The probe needs a
    value of the right shape and does not need it to be a genuine blinded key,
    since nothing here verifies anything -- but it does need the same bytes on
    every run, or two probes could not be compared with each other.
    """
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(
            b"ovpoc-pades-probe/" + election_id.encode("utf-8")
            + b"/" + str(counter).encode("ascii")
        ).digest()
        counter += 1
    return bytes(out[:size])


def payload_of(election_id: str, config_digest: str, blinded_key: bytes) -> dict:
    """The three fields, and no fourth.

    The same set the present handover file carries, minus its `_transport`
    note: the note is prose for a reader of that file, and this document says
    the same thing on its face where a reader will actually meet it.
    """
    return {
        "blinded_key": b64(blinded_key),
        "config_digest": config_digest,
        "election_id": election_id,
    }


def fingerprint(blinded_key: bytes) -> str:
    """The sixty-four bits of `c` a person is asked to compare.

    The base64 of `c` is 512 characters and nobody checks that by eye.  What
    the voter compares is this, shown identically here and in the application:
    four groups of four hex digits.  Sixty-four bits is ample, because the
    attack it has to resist is a targeted second preimage -- an adversary
    producing a *different* `c` with this same fingerprint -- and not a
    birthday collision between two values of their own choosing.
    """
    short = hashlib.sha256(blinded_key).digest()[:8].hex()
    return "-".join(short[i:i + 4] for i in range(0, 16, 4))


# --------------------------------------------------------------------------
# A very small, very deterministic PDF writer
# --------------------------------------------------------------------------

def _pdf_text(text: str) -> bytes:
    """A PDF literal string.

    ASCII only, by the rule above.  Three characters have to be escaped, and
    a non-ASCII one is a programming error here rather than something to
    transliterate quietly.
    """
    if not text.isascii():
        raise ValueError(f"non-ASCII text would not render honestly: {text!r}")
    out = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return b"(" + out.encode("ascii") + b")"


def _xml_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _content_stream(lines: list[tuple[str, int, float, float, str]]) -> bytes:
    """One `BT ... ET` block per line, each positioned absolutely.

    Positioned rather than led, because a renderer that is a pure function of
    its payload is easier to argue about when every line's position is written
    down than when it is accumulated.
    """
    out = bytearray()
    for font, size, x, y, text in lines:
        out += b"BT /" + font.encode("ascii") + f" {size} Tf ".encode("ascii")
        out += f"{x:g} {y:g} Td ".encode("ascii") + _pdf_text(text) + b" Tj ET\n"
    return bytes(out)


def _page_lines(payload: dict, blinded_key: bytes) -> list[tuple[str, int, float, float, str]]:
    """What the document says, which is the only part of it a voter can check."""
    x = float(MARGIN)
    lines: list[tuple[str, int, float, float, str]] = []
    y = PAGE_H - 72.0

    lines.append(("F3", 16, x, y, "TOKEN REQUEST"))
    y -= 20
    lines.append(("F1", 9, x, y, "Anonymous Authenticated Ballot System - proof of concept. This is not a ballot."))

    y -= 30
    for label, value in (
        ("election", payload["election_id"]),
        ("configuration", payload["config_digest"]),
        ("fingerprint of c", fingerprint(blinded_key)),
    ):
        lines.append(("F2", 9, x, y, f"{label:<20}{value}"))
        y -= 13

    y -= 16
    for sentence in (
        "By signing this document I request one ballot token for the election named",
        "above. The document does not record, and cannot record, how I will vote: the",
        "value below conceals the key that will carry my ballot, and the office that",
        "signs the token never sees that key. The fingerprint above is of that value,",
        "and should match the one shown by the application that produced this file.",
    ):
        lines.append(("F1", 9, x, y, sentence))
        y -= 12

    y -= 16
    lines.append(("F1", 9, x, y, "c - the blinded ad-hoc public key, base64url, 64 characters to the line:"))
    y -= 16
    text = payload["blinded_key"]
    for i in range(0, len(text), 64):
        lines.append(("F2", 8, x, y, text[i:i + 64]))
        y -= 10

    y -= 18
    lines.append(("F1", 8, x, y, "This document carries the same three values in an embedded file, in a marker"))
    y -= 10
    lines.append(("F1", 8, x, y, "comment and in its metadata. The office rebuilds the document from them and"))
    y -= 10
    lines.append(("F1", 8, x, y, "refuses the file if what it rebuilds is not what it was given."))
    return lines


def _xmp_packet(payload_json: bytes) -> bytes:
    """A metadata copy, present so that the probe can find out whether it survives.

    It carries no `xmp:CreateDate` and no `xmp:ModifyDate`, because the
    document has to be recomputable; a wallet that adds them is telling us
    something, and the inspector will say so.
    """
    body = _xml_text(payload_json.decode("utf-8"))
    return (
        '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
        ' <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        f'  <rdf:Description rdf:about="" xmlns:ovpoc="{XMP_NS}">\n'
        f"   <ovpoc:request>{body}</ovpoc:request>\n"
        "  </rdf:Description>\n"
        " </rdf:RDF>\n"
        "</x:xmpmeta>\n"
        '<?xpacket end="w"?>\n'
    ).encode("utf-8")


def probe_document(payload: dict, blinded_key: bytes,
                   variant: Variant = FULL) -> bytes:
    """The whole file, as a pure function of the payload and the variant.

    Object order is fixed, offsets are computed, and there is no value in here
    that a holder of the payload could not reproduce.  That is the property the
    office's rule would depend on, so the probe has it too -- a probe that was
    not reproducible would answer a different question from the one being
    asked.

    Object *numbers* are assigned to whichever objects this variant has, in a
    fixed order, rather than reserved and left dangling.  A variant with a hole
    in its cross-reference table would be testing the hole and not the feature.
    """
    payload_json = canonical_bytes(payload)
    content = _content_stream(_page_lines(payload, blinded_key))
    xmp = _xmp_packet(payload_json) if variant.xmp else b""

    # The identifier, derived.  A random /ID is the commonest reason two runs
    # of a PDF writer disagree, and the trailer is inside the signed bytes.
    ident = hashlib.sha256(payload_json + variant.name.encode("ascii")) \
        .hexdigest()[:32].upper()

    present = ["catalog", "pages", "page", "f1", "f2", "f3", "content"]
    if variant.attachment:
        present += ["filespec", "embedded"]
    if variant.xmp:
        present += ["metadata"]
    if variant.info:
        present += ["info"]
    n = {name: i + 1 for i, name in enumerate(present)}

    def ref(name: str) -> bytes:
        return str(n[name]).encode("ascii") + b" 0 R"

    catalog = b"<< /Type /Catalog /Pages " + ref("pages")
    if variant.attachment:
        catalog += (
            b" /AF [ " + ref("filespec") + b" ] /Names << /EmbeddedFiles << "
            b"/Names [ (" + EMBEDDED_NAME.encode("ascii") + b") "
            + ref("filespec") + b" ] >> >>"
        )
    if variant.xmp:
        catalog += b" /Metadata " + ref("metadata")
    catalog += b" >>"

    bodies: dict[str, bytes] = {
        "catalog": catalog,
        "pages": b"<< /Type /Pages /Kids [ " + ref("page") + b" ] /Count 1 >>",
        "page": (
            b"<< /Type /Page /Parent " + ref("pages") + b" /MediaBox [ 0 0 "
            + f"{PAGE_W} {PAGE_H}".encode("ascii")
            + b" ] /Resources << /Font << /F1 " + ref("f1") + b" /F2 " + ref("f2")
            + b" /F3 " + ref("f3") + b" >> >> /Contents " + ref("content") + b" >>"
        ),
        # Three of the standard fourteen, so that no font binary becomes a
        # second artefact to keep byte-identical across implementations.
        "f1": b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        "f2": b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
        "f3": b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        # Every stream here is written `stream\n DATA \nendstream` with
        # /Length counting DATA alone: the end-of-line before `endstream` is
        # the separator the specification allows and not part of the data, and
        # writing all of them the same way keeps a reader's arithmetic simple.
        "content": (
            b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n"
            + content + b"\nendstream"
        ),
    }

    # Built only where the variant has them: these bodies reference object
    # numbers that do not exist on the lower rungs.
    if variant.attachment:
        bodies["filespec"] = (
            b"<< /Type /Filespec /F (" + EMBEDDED_NAME.encode("ascii") + b") /UF ("
            + EMBEDDED_NAME.encode("ascii") + b") /AFRelationship /Source "
            b"/Desc (The three values this document states, as canonical JSON.) "
            b"/EF << /F " + ref("embedded") + b" >> >>"
        )
        # Uncompressed, so that a reader can find it with an editor.
        bodies["embedded"] = (
            b"<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length "
            + str(len(payload_json)).encode("ascii")
            + b" /Params << /Size " + str(len(payload_json)).encode("ascii")
            + b" >> >>\nstream\n" + payload_json + b"\nendstream"
        )
    if variant.xmp:
        bodies["metadata"] = (
            b"<< /Type /Metadata /Subtype /XML /Length "
            + str(len(xmp)).encode("ascii") + b" >>\nstream\n" + xmp + b"\nendstream"
        )
    if variant.info:
        # Fixed dates. See the note in the module docstring: a producer that
        # writes the current time is not a function of its payload.
        bodies["info"] = (
            b"<< /Title (Token request) /Subject (Anonymous Authenticated Ballot System) "
            b"/Producer (ovpoc pades probe) /Creator (ovpoc pades probe) "
            b"/CreationDate (" + FIXED_DATE.encode("ascii") + b") "
            b"/ModDate (" + FIXED_DATE.encode("ascii") + b") >>"
        )

    out = bytearray()
    out += b"%PDF-1.7\n"
    # The conventional binary comment, so that a transport which guesses at
    # text or binary guesses right.
    out += b"%\xe2\xe3\xcf\xd3\n"
    if variant.marker:
        # Ahead of the first object, where a reader with nothing but `grep`
        # can find it.
        out += MARKER + payload_json + b"\n"

    offsets: list[int] = []
    for name in present:
        offsets.append(len(out))
        out += (str(n[name]).encode("ascii") + b" 0 obj\n" + bodies[name]
                + b"\nendobj\n")

    startxref = len(out)
    out += b"xref\n0 " + str(len(present) + 1).encode("ascii") + b"\n"
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    trailer = (
        b"trailer\n<< /Size " + str(len(present) + 1).encode("ascii")
        + b" /Root " + ref("catalog")
    )
    if variant.info:
        trailer += b" /Info " + ref("info")
    trailer += (b" /ID [ <" + ident.encode("ascii") + b"> <"
                + ident.encode("ascii") + b"> ] >>\n")
    out += trailer
    out += b"startxref\n" + str(startxref).encode("ascii") + b"\n%%EOF\n"
    return bytes(out)


# --------------------------------------------------------------------------

def _payload_for(election_id: str, config_digest: str | None) -> tuple[dict, bytes]:
    blinded_key = fixture_blinded_key(election_id)
    if config_digest is None:
        # Derived, so that a run with no arguments is reproducible.  A real one
        # is the digest of `election.json`.
        config_digest = hashlib.sha256(
            b"ovpoc-pades-probe-config/" + election_id.encode("utf-8")
        ).hexdigest()
    return payload_of(election_id, config_digest, blinded_key), blinded_key


def _sidecar(payload: dict, blinded_key: bytes, document: bytes) -> dict:
    return {
        "payload": payload,
        "fingerprint": fingerprint(blinded_key),
        "document_sha256": hashlib.sha256(document).hexdigest(),
        "document_bytes": len(document),
    }


def build(out_dir: Path, election_id: str, config_digest: str | None) -> dict:
    """The single full document, as before the ladder existed."""
    payload, blinded_key = _payload_for(election_id, config_digest)
    document = probe_document(payload, blinded_key, FULL)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pades-probe.pdf").write_bytes(document)

    # A sidecar, so that the inspector can still do its work if the unsigned
    # original is lost between the laptop and the phone -- which is exactly the
    # journey it is about to make.
    sidecar = _sidecar(payload, blinded_key, document)
    (out_dir / "pades-probe.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return sidecar


def _rewrite_with_qpdf(source: Path, target: Path) -> str:
    """The same content in somebody else's bytes.

    The control for the case where every hand-written rung is refused: qpdf is
    a mainstream producer, and it writes object streams, compressed content and
    a cross-reference stream where this script writes none of those.  Refused
    as well and the objection is to what the document contains; accepted and
    the objection was to our writing it ourselves.

    A command-line tool rather than a library, deliberately: nothing is added
    to what this repository installs, and a machine without qpdf gets a stated
    omission instead of a missing rung it might not notice.
    """
    if shutil.which("qpdf") is None:
        return "skipped: qpdf is not on PATH"
    try:
        subprocess.run(
            ["qpdf", "--object-streams=generate", "--compress-streams=y",
             "--deterministic-id", str(source), str(target)],
            check=True, capture_output=True, timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return f"failed: {exc}"
    return "written"


def graft_ladder(base: Path, out_dir: Path, payload: dict) -> dict:
    """The other ladder: a document the wallet already accepted, plus one carrier.

    The hand-written ladder asks whether a deterministic document can be
    signed at all.  This one asks a different question and asks it better:
    taking a file the wallet has *already* signed, and adding one carrier to
    it, removes "we wrote the bytes ourselves" as a variable entirely.  Four
    rungs, each differing from the last in one respect:

        w1-base      the accepted document, untouched
        w2-qpdf      the same, rewritten by qpdf and otherwise unchanged
        w3-attach    w2 plus an embedded file
        w4-marker    w2 plus the %OVPOC-REQUEST comment

    `w2` is not padding.  Without it, `w3` would differ from `w1` by both the
    attachment and the rewrite, and a refusal would not say which.

    The marker is inserted through qpdf's own QDF mode, which writes a
    normalised file with a classic cross-reference table, and `--fix-qdf`,
    which recomputes every offset afterwards.  Editing a linearised file by
    hand and leaving its offsets wrong would test the broken offsets.
    """
    missing = [t for t in ("qpdf", "fix-qdf") if shutil.which(t) is None]
    if missing:
        return {"error": f"the graft ladder needs {' and '.join(missing)} on PATH"}

    out_dir.mkdir(parents=True, exist_ok=True)
    payload_json = canonical_bytes(payload)
    rungs: list[dict] = []

    def record(name: str, path: Path, adds: str, note: str) -> None:
        data = path.read_bytes()
        rungs.append({"file": path.name, "adds": adds, "note": note,
                      "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()})

    w1 = out_dir / "w1-base.pdf"
    w1.write_bytes(base.read_bytes())
    record("w1", w1, "nothing — the accepted document as it was",
           "refused here and something other than the document changed between "
           "the run that worked and this one.")

    w2 = out_dir / "w2-qpdf.pdf"
    subprocess.run(["qpdf", "--deterministic-id", str(base), str(w2)],
                   check=True, capture_output=True, timeout=60)
    record("w2", w2, "a qpdf rewrite, and no other change",
           "refused here and the objection is to being rewritten at all, which "
           "would make every rung below it unreadable.")

    with tempfile.TemporaryDirectory() as tmp:
        attachment = Path(tmp) / EMBEDDED_NAME
        attachment.write_bytes(payload_json)
        w3 = out_dir / "w3-attach.pdf"
        subprocess.run(
            ["qpdf", "--deterministic-id", str(w2), str(w3),
             "--add-attachment", str(attachment),
             "--mimetype=application/json", "--"],
            check=True, capture_output=True, timeout=60,
        )
    record("w3", w3, "an embedded file",
           "the one to watch. Refused here while w2 is accepted and the "
           "objection is to a PDF carrying an attachment, whatever wrote it.")

    with tempfile.TemporaryDirectory() as tmp:
        qdf = Path(tmp) / "qdf.pdf"
        subprocess.run(["qpdf", "--qdf", "--deterministic-id", str(w2), str(qdf)],
                       check=True, capture_output=True, timeout=60)
        # After the three header lines, not before them: QDF mode marks the
        # file with `%QDF-1.0` on the third line and `fix-qdf` looks for it
        # there. Pushing it down by one leaves a file nothing will repair.
        lines = qdf.read_bytes().split(b"\n")
        spliced = b"\n".join(
            lines[:3] + [MARKER + payload_json] + lines[3:])
        marked = Path(tmp) / "marked.pdf"
        marked.write_bytes(spliced)
        # `fix-qdf` is its own program, not a qpdf option. It recomputes every
        # offset and the cross-reference table after an edit of this kind.
        fixed = subprocess.run(["fix-qdf", str(marked)],
                               check=True, capture_output=True, timeout=60)
        w4 = out_dir / "w4-marker.pdf"
        w4.write_bytes(fixed.stdout)
    record("w4", w4, "the %OVPOC-REQUEST comment",
           "refused here and the objection is to unrecognised bytes ahead of "
           "the first object.")

    legend = {"base": str(base), "payload": payload, "rungs": rungs}
    (out_dir / "graft.json").write_text(
        json.dumps(legend, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return legend


def _surviving_carriers(document: bytes, payload_json: bytes) -> dict:
    """Which copies of the payload are still in these bytes, and still right.

    Used on anything that has been through another producer. Written here
    rather than imported from `pades_inspect` so that the generator stays
    free of the inspector: the two are run at different moments, on different
    machines, and a circular import between them would be the kind of
    convenience that makes a diagnostic harder to trust.
    """
    found = {}
    found["marker"] = (MARKER + payload_json) in document
    found["xmp"] = XMP_NS.encode("ascii") in document and payload_json in document
    found["embedded"] = (b"/Type /EmbeddedFile" in document
                         or b"/Type/EmbeddedFile" in document)
    return found


def build_ladder(out_dir: Path, election_id: str, config_digest: str | None) -> dict:
    """Every rung, plus a legend naming what each one would establish."""
    payload, blinded_key = _payload_for(election_id, config_digest)
    payload_json = canonical_bytes(payload)
    out_dir.mkdir(parents=True, exist_ok=True)

    rungs = []
    for variant in LADDER:
        document = probe_document(payload, blinded_key, variant)
        (out_dir / f"{variant.name}.pdf").write_bytes(document)
        rungs.append({
            "file": f"{variant.name}.pdf",
            "adds": variant.adds,
            "note": variant.note,
            "bytes": len(document),
            "sha256": hashlib.sha256(document).hexdigest(),
        })

    qpdf_status = _rewrite_with_qpdf(
        out_dir / f"{FULL.name}.pdf", out_dir / "v7-qpdf.pdf")
    if qpdf_status == "written":
        written = (out_dir / "v7-qpdf.pdf").read_bytes()
        rungs.append({
            "file": "v7-qpdf.pdf",
            "adds": "nothing — v6 rewritten by a mainstream producer",
            "note": "refused here as well and the objection is to what the "
                    "document contains; accepted and the objection was to our "
                    "writing the bytes ourselves.",
            # Which carriers a rewrite leaves behind is a finding of its own,
            # and it is recorded rather than assumed: a producer that drops a
            # carrier has ruled it out whatever the wallet then says.
            "carriers_surviving_the_rewrite": _surviving_carriers(
                written, payload_json),
            "bytes": len(written),
            "sha256": hashlib.sha256(written).hexdigest(),
        })

    legend = {
        "payload": payload,
        "fingerprint": fingerprint(blinded_key),
        "qpdf": qpdf_status,
        "rungs": rungs,
    }
    (out_dir / "variants.json").write_text(
        json.dumps(legend, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return legend


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the PAdES probe document.")
    parser.add_argument("--out", type=Path, default=ROOT / "build" / "pades-probe")
    parser.add_argument("--election-id", default=FIXTURE_ELECTION_ID)
    parser.add_argument(
        "--config-digest", default=None,
        help="the digest of election.json; derived from the election id if omitted",
    )
    parser.add_argument(
        "--variants", action="store_true",
        help="write the whole ladder, one feature to a rung, for one batch",
    )
    parser.add_argument(
        "--graft", type=Path, default=None,
        help="a PDF the wallet is known to accept; add one carrier at a time to it",
    )
    args = parser.parse_args()

    if args.graft is not None:
        payload, _ = _payload_for(args.election_id, args.config_digest)
        legend = graft_ladder(args.graft, args.out, payload)
        if "error" in legend:
            print(legend["error"])
            return 1
        print(f"grafted {len(legend['rungs'])} documents onto {args.graft}")
        print()
        for rung in legend["rungs"]:
            print(f"  {rung['file']:<16} {rung['bytes']:>7}  adds {rung['adds']}")
        return 0

    if args.variants:
        legend = build_ladder(args.out, args.election_id, args.config_digest)
        print(f"wrote {len(legend['rungs'])} documents to {args.out}")
        print(f"  qpdf control: {legend['qpdf']}")
        print()
        for rung in legend["rungs"]:
            print(f"  {rung['file']:<16} {rung['bytes']:>6}  adds {rung['adds']}")
        print()
        print("  fingerprint   " + legend["fingerprint"])
        print()
        print("Sign them as ONE batch. The refusal screen lists what it would")
        print("not take; bring back both that list and whatever it did sign.")
        return 0

    sidecar = build(args.out, args.election_id, args.config_digest)
    print(f"wrote {args.out / 'pades-probe.pdf'}  ({sidecar['document_bytes']} bytes)")
    print(f"      {args.out / 'pades-probe.json'}")
    print()
    print(f"  election      {sidecar['payload']['election_id']}")
    print(f"  configuration {sidecar['payload']['config_digest']}")
    print(f"  fingerprint   {sidecar['fingerprint']}")
    print(f"  sha256        {sidecar['document_sha256']}")
    print()
    print("Sign it in the wallet, bring the signed file back, then:")
    print(f"  python tools/pades_inspect.py SIGNED.pdf "
          f"--original {args.out / 'pades-probe.pdf'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
