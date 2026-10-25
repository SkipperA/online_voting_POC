"""Read a signed probe back, and report what the wallet did to it.

The companion to `tools/pades_probe.py`, and the half that produces the
evidence.  It answers, of a file a real wallet has signed, the questions the
qualified-signature route turns on:

  * **Do the original bytes survive as a prefix of the signed file?**  This is
    the one that decides the design.  If they do, the office can recompute the
    document from the payload it recovered and compare byte for byte, and an
    extraction error can then cause a wrong refusal but never a wrong
    acceptance.  If they do not, the wallet re-saved the document and the rule
    is unavailable.
  * Which of the four carriers survived, and does each still hold the same
    payload.
  * What the signature covers, and whether a visible appearance arrived as an
    annotation -- harmless, since the office reads only the prefix -- or was
    flattened into the page content, which would mean the first answer was no.
  * What the signature is: profile, algorithms, whether a timestamp token and
    the CAdES attributes are present.

WHAT THIS IS NOT
----------------
It is not a validator and must never grow into one.  It verifies nothing, it
trusts nothing it reads, and no protocol code imports it.  Signature validation
is EU infrastructure, it is mandatory to use, and it will arrive behind a
narrow seam in `driver/` -- not as a parser written here.  Everything below is
a byte scan over a file whose structure is already known, because the probe
wrote it uncompressed on purpose.

That is also why the structural reports are honest about their method.  The
`cms` section in particular does not parse: it looks for the DER encodings of
specific object identifiers in the signature blob and says which it found.  A
found OID is evidence that something is present; an absent one is weaker, and
is reported as "not seen" rather than "absent".

A detector that silently fails to find a carrier would send this whole
investigation the wrong way -- "the wallet stripped it" and "the inspector
cannot see it" look identical in a report.  So `tests/test_pades_probe.py`
removes each carrier in turn from a known-good document and requires this
inspector to notice, in the same spirit as `tools/sabotage.py`: a check that
cannot fail is not a check.

USAGE
-----
    python tools/pades_inspect.py SIGNED.pdf --original build/pades-probe/pades-probe.pdf
    python tools/pades_inspect.py SIGNED.pdf --sidecar build/pades-probe/pades-probe.json
    python tools/pades_inspect.py SIGNED.pdf --json

With neither `--original` nor `--sidecar`, the payload is recovered from the
signed file and the document rebuilt from it, which is exactly the rule the
office would apply and the stronger of the two tests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from ovpoc.messages import canonical_bytes, unb64  # noqa: E402

from pades_probe import MARKER, XMP_NS, probe_document  # noqa: E402

OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
STREAM_RE = re.compile(rb"stream\r?\n")
BYTERANGE_RE = re.compile(rb"/ByteRange\s*\[([^\]]*)\]")
MARKER_RE = re.compile(re.escape(MARKER) + rb"(\{.*?\})\s*\n")
XMP_REQUEST_RE = re.compile(rb"<ovpoc:request>(.*?)</ovpoc:request>", re.S)


# --------------------------------------------------------------------------
# Enough structure to find things, and no more
# --------------------------------------------------------------------------

def objects(data: bytes) -> list[dict]:
    """Every `N G obj ... endobj` in the file, with its stream if it has one.

    Object numbers repeat across incremental updates, which is the normal
    state of a signed PDF and not an error: every occurrence is reported, in
    file order, so that a later definition of an object can be seen to be a
    later one.
    """
    found: list[dict] = []
    for match in OBJ_RE.finditer(data):
        end = data.find(b"endobj", match.end())
        if end == -1:
            end = len(data)
        body = data[match.end():end]
        stream = None
        marker = STREAM_RE.search(body)
        if marker:
            stop = body.find(b"endstream", marker.end())
            if stop != -1:
                stream = body[marker.end():stop]
                if stream.endswith(b"\n"):
                    stream = stream[:-1]
                if stream.endswith(b"\r"):
                    stream = stream[:-1]
        found.append({
            "number": int(match.group(1)),
            "offset": match.start(),
            "header": body[:marker.start()] if marker else body,
            "stream": stream,
        })
    return found


def _inflate(header: bytes, stream: bytes | None) -> bytes | None:
    if stream is None:
        return None
    if b"/FlateDecode" not in header:
        return stream
    try:
        return zlib.decompress(stream)
    except zlib.error:
        try:
            return zlib.decompressobj().decompress(stream)
        except zlib.error:
            return None


def _oid_der(dotted: str) -> bytes:
    """The DER encoding of an object identifier, computed rather than tabulated.

    Written out so that the table below reads as the identifiers it names
    instead of as hex somebody once pasted in.
    """
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(reversed(chunk))
    return bytes([0x06, len(body)]) + bytes(body)


#: Identifiers worth looking for in the signature blob.  Presence is evidence;
#: absence is a weaker claim, and is reported as such.
OIDS = {
    "id-signedData": "1.2.840.113549.1.7.2",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "rsaEncryption": "1.2.840.113549.1.1.1",
    "RSASSA-PSS": "1.2.840.113549.1.1.10",
    "ecdsa-with-SHA256": "1.2.840.10045.4.3.2",
    "ecdsa-with-SHA384": "1.2.840.10045.4.3.3",
    "signingCertificateV2": "1.2.840.113549.1.9.16.2.47",
    "signatureTimeStampToken": "1.2.840.113549.1.9.16.2.14",
    "revocationValues": "1.2.840.113549.1.9.16.2.24",
    "id-ct-TSTInfo": "1.2.840.113549.1.9.16.1.4",
    "qcStatements": "1.3.6.1.5.5.7.1.3",
    "qcCompliance": "0.4.0.1862.1.1",
    "qcSSCD": "0.4.0.1862.1.4",
}


# --------------------------------------------------------------------------
# The carriers
# --------------------------------------------------------------------------

def carrier_marker(data: bytes) -> bytes | None:
    match = MARKER_RE.search(data)
    return match.group(1) if match else None


def carrier_embedded(data: bytes) -> bytes | None:
    for obj in objects(data):
        # `/Type /EmbeddedFile` and not a bare `/EmbeddedFile`: the catalogue
        # carries `/EmbeddedFiles` as the name of its name tree, and matching
        # that would find the wrong object.
        if b"/Type /EmbeddedFile" in obj["header"]:
            body = _inflate(obj["header"], obj["stream"])
            if body is not None:
                return body.strip()
    return None


def carrier_xmp(data: bytes) -> bytes | None:
    if XMP_NS.encode("ascii") not in data:
        return None
    match = XMP_REQUEST_RE.search(data)
    if not match:
        return None
    text = match.group(1).decode("utf-8", "replace")
    text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return text.strip().encode("utf-8")


def content_streams(data: bytes) -> list[bytes]:
    """Every stream that looks like page content, inflated.

    Identified by carrying a font operator rather than by walking the page
    tree: the probe is one page and the point here is to find what a reader
    sees, including in a page some wallet appended.
    """
    out: list[bytes] = []
    for obj in objects(data):
        header, stream = obj["header"], obj["stream"]
        if stream is None:
            continue
        if b"/Type /EmbeddedFile" in header or b"/Type /Metadata" in header:
            continue
        body = _inflate(header, stream)
        if body is not None and b" Tf " in body:
            out.append(body)
    return out


def carrier_visible(data: bytes, payload: dict | None) -> dict:
    """What the *page* still says — searched in the content streams alone.

    Searching the whole file would be wrong in the one direction that
    matters.  Every value on the page is also in the embedded file, the
    marker comment and the XMP packet, so a wallet that re-rendered the page
    and left the machine-readable copies alone would still show up as "the
    text is there" — which is precisely the disagreement between rendering
    and payload the route exists to refuse.  The inspector would have
    reported the one thing it is here to notice as fine.

    So the haystack is the content streams, inflated if need be, identified
    by carrying a font operator.  A document whose page was rewritten with
    compression turned on is still searched; a document whose page was
    rewritten to say something else is not found.
    """
    haystacks = content_streams(data)

    def present(needle: bytes) -> bool:
        return any(needle in hay for hay in haystacks)

    out: dict = {"searched_streams": len(haystacks)}
    if not haystacks:
        out["note"] = "no content stream found: nothing to search"
        return out
    if payload is None:
        return out
    blinded = payload["blinded_key"].encode("ascii")
    out["election_id"] = present(payload["election_id"].encode("utf-8"))
    out["config_digest"] = present(payload["config_digest"].encode("ascii"))
    out["first_line_of_c"] = present(blinded[:64])
    out["last_line_of_c"] = present(blinded[-64:])
    out["every_line_of_c"] = all(
        present(blinded[i:i + 64]) for i in range(0, len(blinded), 64)
    )
    return out


# --------------------------------------------------------------------------
# Revisions
# --------------------------------------------------------------------------

def revisions(data: bytes) -> list[int]:
    """Where each revision ends, as a byte count from the start of the file.

    A signed PDF is the original followed by one or more incremental updates,
    and the first of these offsets is therefore the length of the document the
    citizen actually signed.  Knowing it without being handed the original is
    the office's position exactly.

    **The end-of-line after `%%EOF` belongs to the revision.**  Written out
    because getting it wrong is silent and convincing: cutting at the end of
    the `%%EOF` token alone produced a prefix one byte short of a real
    original, whose digest then disagreed with the citizen's own copy -- which
    reads precisely like a wallet that rewrote the file, and was nothing of
    the kind.  The terminator may be `\\r\\n`, `\\n`, `\\r`, or absent at the
    very end of the file, so all four are consumed.
    """
    out: list[int] = []
    for match in re.finditer(rb"%%EOF", data):
        end = match.end()
        if data[end:end + 2] == b"\r\n":
            end += 2
        elif data[end:end + 1] in (b"\n", b"\r"):
            end += 1
        out.append(end)
    return out


def looks_like_a_whole_pdf(data: bytes) -> bool:
    """Enough of a shape check to tell a revision boundary from a coincidence.

    `%%EOF` can occur inside a stream, so an offset is not by itself evidence
    that a revision ends there.  A revision has a cross-reference pointer and
    a header.
    """
    return (data.startswith(b"%PDF-")
            and b"startxref" in data
            and data.rstrip().endswith(b"%%EOF"))


# --------------------------------------------------------------------------
# The signature, structurally
# --------------------------------------------------------------------------

def byte_ranges(data: bytes) -> list[list[int]]:
    out = []
    for match in BYTERANGE_RE.finditer(data):
        try:
            out.append([int(n) for n in match.group(1).split()])
        except ValueError:
            continue
    return out


def signature_dictionaries(data: bytes) -> list[dict]:
    found = []
    for obj in objects(data):
        header = obj["header"]
        if b"/ByteRange" not in header:
            continue
        contents = re.search(rb"/Contents\s*<([0-9A-Fa-f\s]*)>", header)
        blob = None
        if contents:
            hexed = re.sub(rb"\s", b"", contents.group(1))
            # A PAdES /Contents is zero-padded to a fixed width; the trailing
            # zeros are padding and not part of the DER.
            try:
                blob = bytes.fromhex(hexed.decode("ascii")).rstrip(b"\x00")
            except ValueError:
                blob = None
        found.append({
            "object": obj["number"],
            "offset": obj["offset"],
            "filter": _name_after(header, b"/Filter"),
            "subfilter": _name_after(header, b"/SubFilter"),
            "has_M": b"/M" in header,
            "docmdp": b"/DocMDP" in header,
            "docmdp_level": _int_after(header, b"/P") if b"/DocMDP" in header else None,
            "contents_bytes": len(blob) if blob is not None else None,
            "blob": blob,
        })
    return found


def _name_after(header: bytes, key: bytes) -> str | None:
    match = re.search(re.escape(key) + rb"\s*/([A-Za-z0-9.#_-]+)", header)
    return match.group(1).decode("ascii") if match else None


def _int_after(header: bytes, key: bytes) -> int | None:
    match = re.search(re.escape(key) + rb"\s+(\d+)", header)
    return int(match.group(1)) if match else None


def cms_hints(blob: bytes | None) -> dict:
    if not blob:
        return {"scanned": False}
    out: dict = {"scanned": True, "bytes": len(blob), "seen": [], "not_seen": []}
    for label, dotted in OIDS.items():
        (out["seen"] if _oid_der(dotted) in blob else out["not_seen"]).append(label)
    return out


def appearance(data: bytes, original: bytes | None) -> dict:
    """Whether the wallet drew anything, and where it drew it.

    A visible signature that arrives as a widget annotation leaves the page's
    own content stream alone, and the office would disregard it in any case.
    One flattened into the page content would have broken the prefix already;
    this says so in the terms that explain why.
    """
    out: dict = {
        "annots_present": b"/Annots" in data,
        "widget_annotations": data.count(b"/Subtype /Widget") + data.count(b"/Subtype/Widget"),
        "appearance_streams": data.count(b"/AP"),
    }
    if original is None:
        return out
    before = _page_content(original)
    after = _page_content(data)
    out["page_content_unchanged"] = (before is not None and before == after)
    return out


def _page_content(data: bytes) -> bytes | None:
    """The first content stream in the file, which for the probe is the page."""
    found = content_streams(data)
    return found[0] if found else None


def signed_document_end(data: bytes) -> int | None:
    """Where the document the citizen signed ends, found by the signature.

    Not "the first revision": a linearised PDF carries a `%%EOF` a few
    hundred bytes in, after the cross-reference table for its first page, and
    that prefix satisfies every cheap shape check while being no revision at
    all.  The signed file examined here has one at byte 445 and its real
    original at 15907, so a tool that reported the first would report a
    four-hundred-byte document and be believed.

    The signature locates it instead.  The signature dictionary lives in the
    update that added it, so the document that was signed is whatever ended
    at the last revision boundary before that object -- which needs no
    guessing about linearisation and no original to compare against.
    """
    sigs = signature_dictionaries(data)
    if not sigs:
        return None
    first_signature_at = min(s["offset"] for s in sigs)
    candidates = [e for e in revisions(data)
                  if e <= first_signature_at and looks_like_a_whole_pdf(data[:e])]
    return max(candidates) if candidates else None


def incremental_updates(data: bytes) -> dict:
    ends = revisions(data)
    out = {
        "eof_markers": len(ends),
        "revision_ends": ends,
        "complete_revisions": [e for e in ends if looks_like_a_whole_pdf(data[:e])],
        "startxref_markers": data.count(b"startxref"),
        "xref_streams": data.count(b"/Type /XRef") + data.count(b"/Type/XRef"),
        "trailer_prev": data.count(b"/Prev"),
        "linearized": b"/Linearized" in data[:2048],
    }
    end = signed_document_end(data)
    if end is not None:
        # The document as the citizen handed it over, if the wallet appended
        # rather than re-saved. Offered as a length and a digest so that it
        # can be checked against their own copy without this tool being
        # trusted about anything else.
        out["signed_document_bytes"] = end
        out["signed_document_sha256"] = hashlib.sha256(data[:end]).hexdigest()
    return out


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------

def recovered_payload(data: bytes) -> tuple[dict | None, str]:
    """A candidate payload, and where it came from.

    The office's rule treats this as a hint: whatever comes out is fed back
    through the renderer, and it is the comparison that decides.  So the order
    here is cheapest first, and a failure to recover is not yet a refusal.
    """
    for name, raw in (
        ("embedded file", carrier_embedded(data)),
        ("marker comment", carrier_marker(data)),
        ("xmp", carrier_xmp(data)),
    ):
        if raw is None:
            continue
        try:
            candidate = json.loads(raw)
        except ValueError:
            continue
        if isinstance(candidate, dict) and "blinded_key" in candidate:
            return candidate, name
    return None, "nowhere"


def inspect(signed: bytes, original: bytes | None, payload: dict | None) -> dict:
    recovered, source = recovered_payload(signed)
    payload = payload or recovered

    rebuilt = None
    if payload is not None:
        try:
            rebuilt = probe_document(payload, unb64(payload["blinded_key"]))
        except Exception:  # noqa: BLE001 - a malformed payload is a finding
            rebuilt = None

    expected = original if original is not None else rebuilt
    prefix: dict = {"checked_against": "original" if original is not None else "rebuilt"}
    if expected is None:
        prefix["holds"] = None
        prefix["note"] = "no original and nothing rebuildable: cannot check"
    else:
        prefix["expected_bytes"] = len(expected)
        prefix["signed_bytes"] = len(signed)
        prefix["holds"] = signed[:len(expected)] == expected
        if not prefix["holds"]:
            limit = min(len(expected), len(signed))
            first = next((i for i in range(limit) if signed[i] != expected[i]), limit)
            prefix["first_difference_at"] = first
            prefix["expected_here"] = expected[first:first + 48].decode("latin-1")
            prefix["found_here"] = signed[first:first + 48].decode("latin-1")

    if original is not None and rebuilt is not None:
        prefix["rebuild_matches_original"] = (rebuilt == original)

    ranges = byte_ranges(signed)
    coverage: dict = {"byte_ranges": ranges}
    if ranges:
        # What the range says about itself needs no expected bytes; only the
        # question "does it cover the prefix" does, and it is kept separate
        # so that a file with no recoverable payload still reports its shape.
        first_range = ranges[0]
        coverage["starts_at_zero"] = first_range[0] == 0
        if expected is not None:
            coverage["covers_expected_prefix"] = (
                len(first_range) >= 2 and first_range[0] == 0
                and first_range[1] >= len(expected)
            )
        if len(first_range) == 4:
            start_a, len_a, start_b, len_b = first_range
            # The gap between the two covered runs is the /Contents hole --
            # the signature cannot cover itself -- and is expected. Anything
            # beyond the second run is appended and *unsigned*, which is the
            # number worth looking at: it is zero for an ordinary signed file.
            coverage["contents_hole_bytes"] = start_b - (start_a + len_a)
            coverage["unsigned_bytes_at_the_end"] = len(signed) - (start_b + len_b)

    carriers = {}
    for name, found in (
        ("embedded_file", carrier_embedded(signed)),
        ("marker_comment", carrier_marker(signed)),
        ("xmp", carrier_xmp(signed)),
    ):
        if found is None:
            carriers[name] = {"present": False}
            continue
        entry: dict = {"present": True, "bytes": len(found)}
        if payload is not None:
            entry["agrees_with_payload"] = (found == canonical_bytes(payload))
        carriers[name] = entry
    carriers["visible_text"] = carrier_visible(signed, payload)

    sigs = signature_dictionaries(signed)
    for sig in sigs:
        sig["cms"] = cms_hints(sig.pop("blob"))

    return {
        "signed_sha256": hashlib.sha256(signed).hexdigest(),
        "signed_bytes": len(signed),
        "payload": payload,
        "payload_recovered_from": source,
        "prefix": prefix,
        "coverage": coverage,
        "carriers": carriers,
        "signatures": sigs,
        "appearance": appearance(signed, original),
        "updates": incremental_updates(signed),
    }


def _yes(value) -> str:
    return {True: "yes", False: "NO", None: "unknown"}.get(value, str(value))


def render_report(report: dict) -> str:
    out: list[str] = []
    w = out.append

    w("PAdES probe — what the wallet did")
    w("=" * 60)
    w(f"signed file      {report['signed_bytes']} bytes, sha256 {report['signed_sha256'][:16]}…")
    w(f"payload found in {report['payload_recovered_from']}")
    w("")

    prefix = report["prefix"]
    w("THE QUESTION THAT DECIDES THE DESIGN")
    w(f"  original bytes survive as a prefix   {_yes(prefix.get('holds'))}"
      f"   (checked against the {prefix['checked_against']})")
    if prefix.get("holds") is False:
        w(f"  first difference at byte             {prefix.get('first_difference_at')}")
        w(f"    expected                           {prefix.get('expected_here')!r}")
        w(f"    found                              {prefix.get('found_here')!r}")
    if "rebuild_matches_original" in prefix:
        w(f"  rebuild reproduces the original      {_yes(prefix['rebuild_matches_original'])}")
    w("")

    cov = report["coverage"]
    w("WHAT THE SIGNATURE COVERS")
    for r in cov.get("byte_ranges", []) or [None]:
        w(f"  ByteRange                            {r}")
    w(f"  starts at byte 0                     {_yes(cov.get('starts_at_zero'))}")
    w(f"  covers the whole expected prefix     {_yes(cov.get('covers_expected_prefix'))}")
    if "contents_hole_bytes" in cov:
        w(f"  /Contents hole (expected)            {cov['contents_hole_bytes']}")
        w(f"  unsigned bytes at the end            {cov['unsigned_bytes_at_the_end']}"
          "   (should be 0)")
    w("")

    w("CARRIERS")
    for name in ("embedded_file", "marker_comment", "xmp"):
        entry = report["carriers"][name]
        if not entry["present"]:
            w(f"  {name:<20} gone")
        else:
            w(f"  {name:<20} present, {entry['bytes']} bytes, "
              f"agrees: {_yes(entry.get('agrees_with_payload'))}")
    vis = report["carriers"]["visible_text"]
    if "every_line_of_c" in vis:
        w(f"  {'visible_text':<20} election_id {_yes(vis['election_id'])}, "
          f"digest {_yes(vis['config_digest'])}, all 8 lines of c {_yes(vis['every_line_of_c'])}")
    w(f"  {'(content streams)':<20} {vis['searched_streams']} searched"
      + (f" — {vis['note']}" if "note" in vis else ""))
    w("")

    w("THE SIGNATURE")
    if not report["signatures"]:
        w("  none found — was the file actually signed?")
    for sig in report["signatures"]:
        w(f"  object {sig['object']} at {sig['offset']}")
        w(f"    Filter/SubFilter                   {sig['filter']} / {sig['subfilter']}")
        w(f"    /M signing time present            {_yes(sig['has_M'])}")
        w(f"    DocMDP                             {_yes(sig['docmdp'])}"
          + (f" (P={sig['docmdp_level']})" if sig["docmdp"] else ""))
        w(f"    CMS blob                           {sig['contents_bytes']} bytes")
        cms = sig["cms"]
        if cms.get("scanned"):
            w(f"    OIDs seen                          {', '.join(cms['seen']) or 'none'}")
            w(f"    not seen                           {', '.join(cms['not_seen'])}")
    w("")

    app = report["appearance"]
    w("APPEARANCE AND UPDATES")
    w(f"  annotations present                  {_yes(app['annots_present'])}")
    w(f"  widget annotations                   {app['widget_annotations']}")
    if "page_content_unchanged" in app:
        w(f"  page content stream unchanged        {_yes(app['page_content_unchanged'])}")
    u = report["updates"]
    w(f"  %%EOF markers                        {u['eof_markers']}"
      "   (more than one means an incremental update)")
    w(f"  revision boundaries                  {u['revision_ends']}")
    w(f"  linearised                           {_yes(u['linearized'])}"
      + ("   (its early %%EOF is not a revision)" if u["linearized"] else ""))
    if "signed_document_bytes" in u:
        w(f"  the document that was signed ends at {u['signed_document_bytes']}")
        w(f"    its sha256                         {u['signed_document_sha256']}")
        w("    compare that with the document you handed the wallet")
    w(f"  /Prev in a trailer                   {u['trailer_prev']}")
    w(f"  cross-reference streams              {u['xref_streams']}")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a signed PAdES probe.")
    parser.add_argument("signed", type=Path)
    parser.add_argument("--original", type=Path, default=None,
                        help="the unsigned probe, if it is still to hand")
    parser.add_argument("--sidecar", type=Path, default=None,
                        help="pades-probe.json, if the original is not")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    signed = args.signed.read_bytes()
    original = args.original.read_bytes() if args.original else None
    payload = None
    if args.sidecar:
        payload = json.loads(args.sidecar.read_text(encoding="utf-8"))["payload"]

    report = inspect(signed, original, payload)
    if args.json:
        report = json.loads(json.dumps(report, default=str))
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
