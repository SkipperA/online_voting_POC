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

USAGE
-----
    python tools/pades_probe.py                       # writes build/pades-probe/
    python tools/pades_probe.py --out DIR
    python tools/pades_probe.py --election-id demo-2026 --config-digest abc...

Then: move `pades-probe.pdf` to the phone, sign it in the wallet, bring the
signed file back, and

    python tools/pades_inspect.py SIGNED.pdf --original build/pades-probe/pades-probe.pdf
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
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


def probe_document(payload: dict, blinded_key: bytes) -> bytes:
    """The whole file, as a pure function of the payload.

    Object order is fixed, offsets are computed, and there is no value in here
    that a holder of the payload could not reproduce.  That is the property the
    office's rule would depend on, so the probe has it too -- a probe that was
    not reproducible would answer a different question from the one being
    asked.
    """
    payload_json = canonical_bytes(payload)
    content = _content_stream(_page_lines(payload, blinded_key))
    xmp = _xmp_packet(payload_json)

    # The identifier, derived.  A random /ID is the commonest reason two runs
    # of a PDF writer disagree, and the trailer is inside the signed bytes.
    ident = hashlib.sha256(payload_json).hexdigest()[:32].upper()

    objects: list[bytes] = [
        # 1: catalogue.  /Names carries the embedded file, /AF marks it as an
        # associated file of the document, /Metadata the XMP packet.
        b"<< /Type /Catalog /Pages 2 0 R /AF [ 7 0 R ] /Metadata 9 0 R "
        b"/Names << /EmbeddedFiles << /Names [ (" + EMBEDDED_NAME.encode("ascii")
        + b") 7 0 R ] >> >> >>",
        # 2
        b"<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
        # 3
        b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 "
        + f"{PAGE_W} {PAGE_H}".encode("ascii")
        + b" ] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 10 0 R >> >> "
        b"/Contents 6 0 R >>",
        # 4, 5, 10: three of the standard fourteen, so no font is embedded.
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
        # 6: the page content, uncompressed on purpose.  Every stream here is
        # written `stream\n DATA \nendstream` with /Length counting DATA
        # alone: the end-of-line before `endstream` is the separator the
        # specification allows and not part of the data, and writing all three
        # the same way is what keeps a reader's length arithmetic simple.
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n"
        + content + b"\nendstream",
        # 7: the file specification for the embedded copy.
        b"<< /Type /Filespec /F (" + EMBEDDED_NAME.encode("ascii") + b") /UF ("
        + EMBEDDED_NAME.encode("ascii") + b") /AFRelationship /Source "
        b"/Desc (The three values this document states, as canonical JSON.) "
        b"/EF << /F 8 0 R >> >>",
        # 8: the embedded copy itself, uncompressed so a reader can find it.
        b"<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length "
        + str(len(payload_json)).encode("ascii")
        + b" /Params << /Size " + str(len(payload_json)).encode("ascii")
        + b" >> >>\nstream\n" + payload_json + b"\nendstream",
        # 9: the XMP packet.
        b"<< /Type /Metadata /Subtype /XML /Length " + str(len(xmp)).encode("ascii")
        + b" >>\nstream\n" + xmp + b"\nendstream",
        # 10
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    ]

    out = bytearray()
    out += b"%PDF-1.7\n"
    # The conventional binary comment, so that a transport which guesses at
    # text or binary guesses right.
    out += b"%\xe2\xe3\xcf\xd3\n"
    # Carrier 2.  Ahead of the first object, where it can be found by a reader
    # with nothing but `grep`.
    out += MARKER + payload_json + b"\n"

    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += str(number).encode("ascii") + b" 0 obj\n" + body + b"\nendobj\n"

    startxref = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n"
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        b"trailer\n<< /Size " + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R /ID [ <" + ident.encode("ascii") + b"> <"
        + ident.encode("ascii") + b"> ] >>\n"
    )
    out += b"startxref\n" + str(startxref).encode("ascii") + b"\n%%EOF\n"
    return bytes(out)


# --------------------------------------------------------------------------

def build(out_dir: Path, election_id: str, config_digest: str | None) -> dict:
    blinded_key = fixture_blinded_key(election_id)
    if config_digest is None:
        # Derived, so that a run with no arguments is reproducible.  A real one
        # is the digest of `election.json`.
        config_digest = hashlib.sha256(
            b"ovpoc-pades-probe-config/" + election_id.encode("utf-8")
        ).hexdigest()

    payload = payload_of(election_id, config_digest, blinded_key)
    document = probe_document(payload, blinded_key)

    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / "pades-probe.pdf"
    pdf_path.write_bytes(document)

    # A sidecar, so that the inspector can still do its work if the unsigned
    # original is lost between the laptop and the phone -- which is exactly the
    # journey it is about to make.
    sidecar = {
        "payload": payload,
        "fingerprint": fingerprint(blinded_key),
        "document_sha256": hashlib.sha256(document).hexdigest(),
        "document_bytes": len(document),
    }
    (out_dir / "pades-probe.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return sidecar


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the PAdES probe document.")
    parser.add_argument("--out", type=Path, default=ROOT / "build" / "pades-probe")
    parser.add_argument("--election-id", default=FIXTURE_ELECTION_ID)
    parser.add_argument(
        "--config-digest", default=None,
        help="the digest of election.json; derived from the election id if omitted",
    )
    args = parser.parse_args()

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
