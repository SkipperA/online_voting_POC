"""The token request as a document the citizen's own wallet will sign.

The second route to a token request.  On the first, the voting application
hands the wallet a small JSON file and the wallet signs the bytes it is given.
That works because the wallet is ours.  A real wallet -- the European Digital
Identity Wallet, and in Hungary the DAP application -- signs PDFs and nothing
else, so the request has to *be* a document.  What that buys is a token
request which is a legally probative instrument, and a real wallet integrated
without any authority's cooperation.

It also takes something away, and the design here is mostly about putting it
back.  On the first route the wallet is the party that checks: `WalletFlow`
fetches the election configuration itself and refuses a request whose
`election_id` or `config_digest` disagrees, and `web/wallet/static/wallet.js`
does the same.  A real wallet does no such thing.  It renders the document,
asks for a password, and signs.  The two checks that make consent mean
something have nowhere left to live except the page the citizen reads.

So the honest rendering is not a convenience for the office.  It is the whole
of the voter's protection, and it replaces a check the code used to perform on
their behalf.  A document whose visible text and embedded payload could
disagree would turn the delegated-signing entry in `docs/threats.md` from a
*sale*, which needs the seller's cooperation, into a *theft*, which needs only
deception: a hostile voting application shows a plausible request, embeds
somebody else's `c`, and the citizen spends their entitlement on a ballot they
will never see.  The seller at least knows what they are doing.

THE RULE: RECOMPUTE, DO NOT PARSE
---------------------------------
The office does not read this document.  It rebuilds it.

    1. recover a candidate payload   (`extract`)
    2. expected = render(candidate)
    3. require the signed document to *begin* with `expected`, byte for byte
    4. require the signature to cover at least that prefix

Three things follow, and they are why the rule is shaped this way.

**There are not two copies to keep in step.**  There is one payload and one
function of it.  The visible text says what the embedded data says because the
same `render` call produced both, and the office has checked that the file it
holds is that call's output.  A document whose rendering and payload disagree
is not refused by a comparison -- it is unconstructable, and the prefix check
is what makes it so.

**Extraction is therefore allowed to be fragile.**  A wrong candidate rebuilds
to different bytes and the comparison fails.  The worst a broken extractor can
do is refuse a good document; it cannot accept a bad one.  That is what lets
the carriers below be hints rather than evidence.

**No PDF library is trusted for what the document says.**  The validator in
`driver/` answers four questions -- does a signature cover bytes 0 to n, does
it verify, does the certificate chain to a trust anchor, who signed -- and the
*meaning* comes from bytes this office recomputed with the function below.  A
parsing bug upstream can cause a wrong refusal and not a wrong acceptance.

WHAT THE REAL WALLET DOES, AND HOW THAT WAS ESTABLISHED
-------------------------------------------------------
Not inferred.  `tools/pades_probe.py` wrote a ladder of documents differing by
one feature each, they were signed on a phone by the DAP application, and
`tools/pades_inspect.py` read them back:

* **The signed file begins with the document it was given, unaltered.**  The
  signature arrives as an incremental update and the `ByteRange` starts at
  zero.  Step 3 above rests on this and it is measured, not assumed.
* **A document with no `/Info` dictionary is refused outright**, before any
  signature is attempted, as a file with "content problems".  That was the
  whole of the objection: the carriers were never the trouble.  So `/Info` is
  written here, which puts its dates inside the recomputation -- see
  `_INFO_DATE`.
* **There are unsigned bytes after the signature.**  The wallet appends a
  second incremental update, outside the first signature's coverage, carrying
  a `/DSS` with certificates and OCSP responses.  So "the signature covers the
  whole file" is false for every such document and an office requiring it
  would refuse all of them.  Step 4 asks for coverage of the prefix and
  disregards the rest, which is both correct and necessary.
* **XMP is not used as a carrier.**  The packet survives inside the signed
  prefix, but the wallet writes a newer `/Metadata` object in the unsigned
  tail, so the copy a reader resolves is one nobody signed.

DETERMINISM
-----------
`render` is a pure function.  The document contains nothing its recipient
could not recompute: no creation time read from a clock, no producer version,
no device identifier, and an `/ID` derived from the payload rather than drawn
at random.  Byte offsets are computed, line endings are `\\n` throughout, and
the three fonts are standard-14, so no font binary becomes a second artefact
to keep identical across implementations.

The cost is that the prose and the fields are ASCII.  That rules out rendering
a free-text election name: `o-double-acute` and `u-double-acute` are outside
WinAnsiEncoding, `election.store.json` ships non-ASCII names on purpose
(clause X4), and a document silently rendering *Elovalasztas* for the accented
form is exactly the dishonest rendering this module exists to prevent.  The
election is named by its identifier and the digest of its configuration, which
is what the citizen can check against their application in any case.  A
deployment-grade document embeds a font.

`tests/vectors/pdf-request.json` pins the bytes, because the Swift client must
produce the same ones and the office must rebuild them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable

from .messages import canonical_bytes, unb64

#: The three fields, and no fourth. The same set the first route's handover
#: file carries, so nothing new about serialisation has to be agreed.
FIELDS = ("blinded_key", "config_digest", "election_id")

#: The cheapest carrier: a PDF comment ahead of the first object, findable
#: with `grep` and needing no parser at all.
MARKER = b"%OVPOC-REQUEST "

#: The name the embedded copy is given inside the document.
EMBEDDED_NAME = "ovpoc-request.json"

#: A4, in points.
PAGE_W, PAGE_H = 595, 842
MARGIN = 56

#: Fixed, and the fixity is the point: a producer that reads a clock is not a
#: function of its payload, and the office could not rebuild the document.
#: It is not a claim about when anything happened.
#:
#: A deployment has a better answer than a constant and does not need a new
#: wire field for it: `election.json` already carries the poll's opening time
#: (Table 1, footnote a), which is per-election, published, and currently read
#: by nothing at all -- clause A4 exists to say so. Taking the date from there
#: would make it both honest and recomputable.
_INFO_DATE = "D:20260101000000Z"


# --------------------------------------------------------------------------
# What the office depends on, declared as the shape it needs
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidatedSignature:
    """What an electronic-signature validator reports about one document.

    Declared here and implemented in `driver/`, for the same reason
    `CertificateLookup` is: validating a qualified signature is EU
    infrastructure the design consults, not a component the design builds.
    On this route it *replaces* the population register -- the certificate
    arrives with the signature instead of being looked up -- so it is the
    same dependency in the same position.

    `revoked` and `expired` are reported rather than used to refuse, and
    that is load-bearing.  A revoked certificate still verifies
    mathematically, so by the time anyone can see revocation they already
    know who they are speaking to.  `vro.py` sets out at length why that
    puts revocation *below* the identity boundary; a validator that
    collapsed it into "no valid signature" would move the check back above
    the boundary and hand the office's endpoint to anyone who can spell an
    identifier.  `None` on either field means not determined, which is a
    third thing and not a quiet "no".
    """

    #: The signer's distinguished name, field by field, as the certificate
    #: gives it. Composing an identifier out of it is the identity
    #: infrastructure's business and happens in `driver/`.
    subject: Mapping[str, str]
    #: The subject composed into the identifier the office looks for on its
    #: electoral register. Composed in `driver/`, because how a scheme
    #: names its people is the identity infrastructure's business and not
    #: the protocol's. `None` when the certificate carries nothing that
    #: could serve, which the office treats as not having been identified.
    identifier: str | None = None
    #: How many bytes from the start of the file this signature covers.
    #: Zero when it does not begin at byte zero, which is the honest answer
    #: for the office's purposes: it covers none of the prefix.
    covered_prefix_length: int = 0
    signing_time: datetime | None = None
    revoked: bool | None = None
    expired: bool | None = None
    #: Whether a trust list said this is a qualified signature. `None` when
    #: no trust list was consulted -- the demonstration pins a dated
    #: snapshot, and an office running without one should not be able to
    #: claim the word.
    qualified: bool | None = None


@dataclass(frozen=True)
class SignatureRefused:
    """Why no signature was established. Recorded, never disclosed.

    §3.2 requires that the pre-identity failures be *answered* identically,
    not that they be indistinguishable to the office. The office records
    the true reason for every refusal and hands a requester the enum: that
    is the whole shape of the clause, and it is the arrangement everywhere
    else in `vro.py`.

    On this route it was not. The validator returned a bare `None` and the
    office wrote one sentence covering every way a signature can fail to
    establish anybody -- so the operator's own log was as blind as the
    answer given to the citizen, and an office refusing every genuine
    request looked exactly like an office meeting forged ones. That is a
    thing an operator must be able to tell apart, and nobody else.

    So the reason travels here, where only `_record` reads it. It must
    never reach a response; `test_two_routes.py` is what holds that.
    """

    #: Said to an operator reading the audit log, so it names the library's
    #: finding rather than paraphrasing it. Treated as sensitive: it can
    #: describe a certificate the office refused.
    reason: str


@runtime_checkable
class SignatureValidation(Protocol):
    """`document` in, one signature's findings or nothing out.

    Every pre-identity failure -- no signature, a signature that does not
    verify, a certificate that chains to nothing the office trusts -- is
    answered with one opaque refusal (§3.2), so none of them returns a
    `ValidatedSignature`. Reasons below the boundary travel in the fields
    of that type; reasons above it travel in `SignatureRefused`, which
    goes to the audit log and nowhere else.

    A bare `None` is still a refusal and still permitted, for a validator
    with nothing to add. It records as a refusal whose reason was not
    given, which is honest and is not something a deployment should ship.
    """

    def validate(
        self, document: bytes
    ) -> "ValidatedSignature | SignatureRefused | None": ...


class Refusal(Enum):
    """Why a document is not a token request, as the office would say it.

    Reported to a party who has already proved who they are with a qualified
    signature, so detail is permitted here in a way it is not before the
    identity boundary in `vro.py`.
    """

    #: Nothing that could be a payload came out of it.
    NOT_A_REQUEST_DOCUMENT = "not_a_request_document"
    #: Two carriers, two different answers. The office refuses rather than
    #: choosing: a document that cannot say one thing about itself is worse
    #: than one that says nothing.
    CARRIERS_DISAGREE = "carriers_disagree"
    #: A payload came out, and the document is not what that payload renders
    #: to. Either it was edited after rendering or it was never rendered by
    #: this function.
    NOT_AS_RENDERED = "not_as_rendered"
    #: The bytes are right and the signature does not cover all of them.
    SIGNATURE_DOES_NOT_COVER_IT = "signature_does_not_cover_it"


@dataclass(frozen=True)
class DocumentCheck:
    """What the office concluded about a document, before it looks at anybody.

    `payload` is set only when the document passed: a candidate that failed
    the rebuild is not a payload, it is a guess that turned out wrong, and
    handing it back would invite a caller to use it.
    """

    accepted: bool
    payload: dict[str, Any] | None = None
    recovered_from: str | None = None
    refusal: Refusal | None = None
    rendered_bytes: int | None = None


# --------------------------------------------------------------------------
# The payload
# --------------------------------------------------------------------------

def payload_of(election_id: str, config_digest: str, blinded_key: bytes) -> dict:
    from .messages import b64
    return {
        "blinded_key": b64(blinded_key),
        "config_digest": config_digest,
        "election_id": election_id,
    }


def fingerprint(blinded_key: bytes) -> str:
    """The sixty-four bits of `c` a person is asked to compare.

    The base64 of `c` is 512 characters and nobody checks that by eye.  What
    the citizen compares is this, shown identically on the page and in the
    application: four groups of four hex digits.  Sixty-four bits is ample,
    because the attack it must resist is a targeted second preimage -- an
    adversary producing a *different* `c` with this same fingerprint -- and
    not a birthday collision between two values of their own choosing.
    """
    short = hashlib.sha256(blinded_key).digest()[:8].hex()
    return "-".join(short[i:i + 4] for i in range(0, 16, 4))


def _well_formed(candidate: Any) -> bool:
    if not isinstance(candidate, dict) or set(candidate) != set(FIELDS):
        return False
    if not all(isinstance(candidate[f], str) for f in FIELDS):
        return False
    try:
        unb64(candidate["blinded_key"])
    except Exception:  # noqa: BLE001 - any decoding failure is the same answer
        return False
    return True


# --------------------------------------------------------------------------
# Writing the document
# --------------------------------------------------------------------------

def _pdf_text(text: str) -> bytes:
    """A PDF literal string.

    ASCII only, by the rule in the module docstring.  Three characters have
    to be escaped; a non-ASCII one is refused rather than transliterated,
    because transliterating it is the dishonest rendering.
    """
    if not text.isascii():
        raise ValueError(
            f"non-ASCII text cannot be rendered honestly in a standard-14 "
            f"font: {text!r}"
        )
    out = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return b"(" + out.encode("ascii") + b")"


def _lines(payload: dict) -> list[tuple[str, int, float, float, str]]:
    """What the document says, which is the only part of it a citizen can check."""
    blinded_text = payload["blinded_key"]
    x = float(MARGIN)
    out: list[tuple[str, int, float, float, str]] = []
    y = PAGE_H - 72.0

    out.append(("F3", 16, x, y, "TOKEN REQUEST"))
    y -= 20
    out.append(("F1", 9, x, y,
                "Anonymous Authenticated Ballot System. This is not a ballot."))

    y -= 30
    for label, value in (
        ("election", payload["election_id"]),
        ("configuration", payload["config_digest"]),
        ("fingerprint of c", fingerprint(unb64(blinded_text))),
    ):
        out.append(("F2", 9, x, y, f"{label:<20}{value}"))
        y -= 13

    y -= 16
    for sentence in (
        "By signing this document I request one ballot token for the election named",
        "above. The document does not record, and cannot record, how I will vote: the",
        "value below conceals the key that will carry my ballot, and the office that",
        "signs the token never sees that key. The fingerprint above is of that value,",
        "and should match the one shown by the application that produced this file.",
    ):
        out.append(("F1", 9, x, y, sentence))
        y -= 12

    y -= 16
    out.append(("F1", 9, x, y,
                "c - the blinded ad-hoc public key, base64url, 64 characters to the line:"))
    y -= 16
    for i in range(0, len(blinded_text), 64):
        out.append(("F2", 8, x, y, blinded_text[i:i + 64]))
        y -= 10

    y -= 18
    out.append(("F1", 8, x, y,
                "The same three values are carried in an embedded file and in a marker"))
    y -= 10
    out.append(("F1", 8, x, y,
                "comment. The office rebuilds this document from them and refuses the"))
    y -= 10
    out.append(("F1", 8, x, y,
                "file if what it rebuilds is not what it was given."))
    return out


def _content(payload: dict) -> bytes:
    """One `BT ... ET` block per line, each positioned absolutely.

    Positioned rather than led, because a renderer that must be reproduced in
    another language is easier to agree about when every line's position is
    written down than when it is accumulated.
    """
    out = bytearray()
    for font, size, x, y, text in _lines(payload):
        out += b"BT /" + font.encode("ascii") + f" {size} Tf ".encode("ascii")
        out += f"{x:g} {y:g} Td ".encode("ascii") + _pdf_text(text) + b" Tj ET\n"
    return bytes(out)


def render(payload: dict) -> bytes:
    """The document, as a pure function of the payload.

    Object order is fixed, offsets are computed, and there is no value in
    here a holder of the payload could not reproduce.  Everything the office
    concludes about a signed request rests on being able to run this and get
    the same bytes back.
    """
    if not _well_formed(payload):
        raise ValueError(f"not a token-request payload: {sorted(payload)}")
    body = canonical_bytes({f: payload[f] for f in FIELDS})
    content = _content(payload)

    # Derived. A random /ID is the commonest reason two runs of a PDF writer
    # disagree, and the trailer is inside the signed bytes.
    ident = hashlib.sha256(body).hexdigest()[:32].upper()

    def ref(n: int) -> bytes:
        return str(n).encode("ascii") + b" 0 R"

    objects: list[bytes] = [
        # 1 catalogue. /Names reaches the embedded copy; /AF marks it an
        # associated file of the document, which is what it is.
        b"<< /Type /Catalog /Pages " + ref(2) + b" /AF [ " + ref(8) + b" ]"
        b" /Names << /EmbeddedFiles << /Names [ ("
        + EMBEDDED_NAME.encode("ascii") + b") " + ref(8) + b" ] >> >> >>",
        # 2
        b"<< /Type /Pages /Kids [ " + ref(3) + b" ] /Count 1 >>",
        # 3
        b"<< /Type /Page /Parent " + ref(2) + b" /MediaBox [ 0 0 "
        + f"{PAGE_W} {PAGE_H}".encode("ascii")
        + b" ] /Resources << /Font << /F1 " + ref(4) + b" /F2 " + ref(5)
        + b" /F3 " + ref(6) + b" >> >> /Contents " + ref(7) + b" >>",
        # 4, 5, 6: three of the standard fourteen, so nothing is embedded.
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica"
        b" /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier"
        b" /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold"
        b" /Encoding /WinAnsiEncoding >>",
        # 7: the page, uncompressed. A reader should be able to open this
        # document in an editor and find every copy of the payload in it,
        # which is the same argument the X-clauses make about the surfaces.
        # Each stream is `stream\n DATA \nendstream` with /Length counting
        # DATA alone.
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n"
        + content + b"\nendstream",
        # 8: the file specification for the embedded copy.
        b"<< /Type /Filespec /F (" + EMBEDDED_NAME.encode("ascii") + b") /UF ("
        + EMBEDDED_NAME.encode("ascii") + b") /AFRelationship /Source"
        b" /Desc (The three values this document states, as canonical JSON.)"
        b" /EF << /F " + ref(9) + b" >> >>",
        # 9: the embedded copy itself.
        b"<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length "
        + str(len(body)).encode("ascii")
        + b" /Params << /Size " + str(len(body)).encode("ascii")
        + b" >> >>\nstream\n" + body + b"\nendstream",
        # 10: without this the wallet refuses the file outright, before any
        # signature is attempted. Established by experiment, not by reading.
        b"<< /Title (Token request)"
        b" /Subject (Anonymous Authenticated Ballot System)"
        b" /Producer (ovpoc) /Creator (ovpoc)"
        b" /CreationDate (" + _INFO_DATE.encode("ascii") + b")"
        b" /ModDate (" + _INFO_DATE.encode("ascii") + b") >>",
    ]

    out = bytearray()
    out += b"%PDF-1.7\n"
    # The conventional binary comment, so a transport guessing at text or
    # binary guesses right.
    out += b"%\xe2\xe3\xcf\xd3\n"
    out += MARKER + body + b"\n"

    offsets: list[int] = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += str(number).encode("ascii") + b" 0 obj\n" + obj + b"\nendobj\n"

    startxref = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n"
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        b"trailer\n<< /Size " + str(len(objects) + 1).encode("ascii")
        + b" /Root " + ref(1) + b" /Info " + ref(10)
        + b" /ID [ <" + ident.encode("ascii") + b"> <"
        + ident.encode("ascii") + b"> ] >>\n"
    )
    out += b"startxref\n" + str(startxref).encode("ascii") + b"\n%%EOF\n"
    return bytes(out)


# --------------------------------------------------------------------------
# Reading a candidate back out
# --------------------------------------------------------------------------

def _from_marker(document: bytes) -> bytes | None:
    start = document.find(MARKER)
    if start == -1:
        return None
    end = document.find(b"\n", start)
    return document[start + len(MARKER):end if end != -1 else len(document)]


def _from_embedded(document: bytes) -> bytes | None:
    """The embedded stream, found without a parser.

    Deliberately crude.  Under the rule above a wrong answer here costs a
    refusal and never an acceptance, so this does not need to be a PDF
    reader and should not grow into one.
    """
    at = document.find(b"/Type /EmbeddedFile")
    if at == -1:
        return None
    start = document.find(b"stream\n", at)
    stop = document.find(b"endstream", start)
    if start == -1 or stop == -1:
        return None
    return document[start + len(b"stream\n"):stop].strip()


def extract(document: bytes) -> tuple[dict | None, str | None, Refusal | None]:
    """A candidate payload, where it came from, and why not if not.

    Every carrier present must say the same thing.  Two carriers with two
    answers means the document was edited after it was rendered, and the
    office refuses rather than picking one -- preferring either would make
    the choice of carrier into a decision an attacker gets to influence.
    """
    found: dict[str, bytes] = {}
    for name, raw in (("embedded file", _from_embedded(document)),
                      ("marker comment", _from_marker(document))):
        if raw is not None:
            found[name] = raw

    if not found:
        return None, None, Refusal.NOT_A_REQUEST_DOCUMENT
    if len(set(found.values())) > 1:
        return None, None, Refusal.CARRIERS_DISAGREE

    where, raw = next(iter(found.items()))
    try:
        candidate = json.loads(raw)
    except ValueError:
        return None, None, Refusal.NOT_A_REQUEST_DOCUMENT
    if not _well_formed(candidate):
        return None, None, Refusal.NOT_A_REQUEST_DOCUMENT
    return candidate, where, None


# --------------------------------------------------------------------------
# The rule
# --------------------------------------------------------------------------

def check(document: bytes, *, covered_prefix_length: int) -> DocumentCheck:
    """Decide what, if anything, this document requests.

    `covered_prefix_length` is how many bytes from the start of the file the
    signature covers, as reported by the validator in `driver/`.  It is an
    argument rather than something read here, and that separation is the
    point: this module decides what the document *says*, the validator
    decides what was *signed*, and neither is trusted with the other's
    question.  A fake validator is therefore all the test suite needs.

    Nothing here looks at the signer.  Who they are, whether their
    certificate is valid and whether they may vote are the office's
    questions, in the order `vro.py` sets, and a document check that started
    answering them would move the identity boundary into a PDF reader.
    """
    candidate, where, refusal = extract(document)
    if candidate is None:
        return DocumentCheck(accepted=False, refusal=refusal)

    try:
        expected = render(candidate)
    except ValueError:
        # A payload that cannot be rendered cannot have produced this file.
        return DocumentCheck(accepted=False, refusal=Refusal.NOT_AS_RENDERED)

    # The whole rule, in one comparison. Not a field-by-field reading of the
    # document: the bytes either are what this payload renders to or they are
    # not, and anything after them is the wallet's business and not ours.
    if document[:len(expected)] != expected:
        return DocumentCheck(accepted=False, refusal=Refusal.NOT_AS_RENDERED,
                             rendered_bytes=len(expected))

    if covered_prefix_length < len(expected):
        return DocumentCheck(
            accepted=False, refusal=Refusal.SIGNATURE_DOES_NOT_COVER_IT,
            rendered_bytes=len(expected))

    return DocumentCheck(accepted=True, payload=candidate, recovered_from=where,
                         rendered_bytes=len(expected))
