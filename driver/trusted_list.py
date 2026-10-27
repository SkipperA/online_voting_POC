"""The European trusted list, pinned as a dated snapshot.

The third occupant of `driver/`, and like the other two it is
infrastructure the design consults rather than anything the design
builds. `qualified_signature.py` answers *did this person sign it*; this
answers *is the authority that vouched for them one the Union
recognises*, which is the question the word **qualified** names and the
one an office pinning a root certificate by hand cannot ask.

**What this replaces is trust on first use.** Pinning
`govca-ecc-root.cer` from the authority's own web server and believing
it is exactly that: the office then accepts whoever that authority
vouches for, on the strength of one download nobody corroborated. The
list-of-the-lists is signed, and pyHanko ships the signer certificates
that were current when it was released, so a snapshot taken through
`pin` is anchored to something that did not come down the same wire as
the data. That is clause S6 discharged rather than labelled.

**And it is still a snapshot.** The office reads it offline and never
reaches the Union's servers while a poll runs, for the reason
`allow_fetching` is off in the validator: an office that fetched would
tell a third party which certificates it was asked about, and the
electoral register is the last thing to leak a query log from. The cost
is that a service withdrawn from the list after the snapshot was taken
is still trusted here, which is a real limitation and belongs on the
page rather than in a comment. The manifest records the day, so how
stale it is, is a thing a reader can see rather than guess.

Two signatures are checked, and the second is why the first matters:

    LOTL  --signed by--> certificates pyHanko shipped
      |
      `--names--> HU's list and the certificates that sign it
                    |
                    `--signed by--> those certificates

So an attacker who can serve a member state's list cannot change whose
signatures this office believes without also forging the LOTL, and the
LOTL's signers are not theirs to choose.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

#: The file the manifest's `trusted_list` section lives beside. Shared with
#: `qualified_signature.py`, which owns the hand-pinned half of the same
#: directory; the two sections do not interact and either may be absent.
MANIFEST = "MANIFEST.json"

#: The Union's list of the member states' lists. Where the operator's
#: `pin` begins, recorded here so the manifest can say what was fetched
#: and `tools/fetch_trust_anchors.py` need not invent it.
LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"


class TrustedListRefused(Exception):
    """The pinned list is not the one the manifest records, or will not
    validate against the certificates pinned beside it.

    Raised at load, like `TrustAnchorsRefused`, and for the same reason:
    an office that started up having silently accepted a swapped trusted
    list would be an office trusting whoever swapped it, and nothing
    downstream would look wrong.
    """


@dataclass(frozen=True)
class PinnedTrustedList:
    """One member state's list, validated and ready to consult.

    `registry` is pyHanko's `TSPRegistry`: every qualified certification
    authority and timestamp authority the territory recognises, with the
    qualifications that say what each one's certificates are *for*. It
    serves two purposes at once in `QualifiedSignatureValidation` --
    which anchors to trust, and whether a signature under one of them is
    qualified -- and those are the same question asked twice, which is
    why one object answers both.
    """

    territory: str
    pinned_on: str
    location: str
    registry: object
    #: What was parsed and what was not. A member state's list routinely
    #: carries services this parser cannot interpret, and dropping them
    #: silently would leave an office quietly trusting less than the
    #: operator believes it does.
    skipped: tuple[str, ...] = ()

    @property
    def authorities(self) -> int:
        return len(list(self.registry.known_certificate_authorities))

    @property
    def timestamp_authorities(self) -> int:
        return len(list(self.registry.known_timestamp_authorities))

    def age_in_days(self, today: datetime.date | None = None) -> int:
        """How stale the snapshot is, for a page that must say so."""
        day = datetime.date.fromisoformat(self.pinned_on)
        return ((today or datetime.date.today()) - day).days


@dataclass
class _Snapshot:
    """The manifest's `trusted_list` section, as written and as read."""

    territory: str
    location: str
    lotl_file: str
    lotl_sha256: str
    list_file: str
    list_sha256: str
    #: DER, base64. The certificates the *LOTL* named as able to sign this
    #: member state's list -- carried in the manifest rather than re-read
    #: from the LOTL at load, so that the thing the office checks against
    #: is the thing the operator saw.
    tlso_certs: list[str] = field(default_factory=list)
    pinned_on: str = ""

    def as_json(self) -> dict:
        return {
            "territory": self.territory,
            "location": self.location,
            "lotl": {"file": self.lotl_file, "sha256": self.lotl_sha256,
                     "source": LOTL_URL},
            "list": {"file": self.list_file, "sha256": self.list_sha256},
            "tlso_certs": self.tlso_certs,
            "pinned": self.pinned_on,
        }

    @classmethod
    def from_json(cls, body: dict) -> "_Snapshot":
        try:
            return cls(
                territory=body["territory"],
                location=body["location"],
                lotl_file=body["lotl"]["file"],
                lotl_sha256=body["lotl"]["sha256"],
                list_file=body["list"]["file"],
                list_sha256=body["list"]["sha256"],
                tlso_certs=list(body.get("tlso_certs", [])),
                pinned_on=body.get("pinned", ""),
            )
        except (KeyError, TypeError) as exc:
            raise TrustedListRefused(
                f"the manifest's trusted_list section is malformed: {exc}"
            ) from exc


def _require_pades():
    """The same probe `qualified_signature.require_validator` makes.

    Imported here rather than at module scope so that `driver` stays
    importable without the `pades` extra, and probed rather than left to
    fail inside a parse, for the reason in that module: an office
    configured for something it cannot do should not start.
    """
    from .qualified_signature import require_validator

    require_validator()
    try:
        import xsdata  # noqa: F401
        from pyhanko.sign.validation.qualified import eutl_parse  # noqa: F401
    except ImportError as exc:  # pragma: no cover - the extra brings both
        from .qualified_signature import ValidatorUnavailable

        raise ValidatorUnavailable(
            "this office has a trusted list pinned and cannot read it: "
            f"{exc}. The `pades` extra provides the parser."
        ) from exc


# --------------------------------------------------------------------------
# The operator's act, which needs a network
# --------------------------------------------------------------------------

def pin(
    directory: Path,
    *,
    territory: str,
    lotl_xml: str,
    member_xml: str,
    moment: datetime.datetime | None = None,
    today: datetime.date | None = None,
) -> PinnedTrustedList:
    """Validate both signatures, then write the snapshot.

    The bytes arrive as arguments rather than being fetched here, so that
    `driver/` opens no sockets and a test can pin a list it built itself.
    `tools/fetch_trust_anchors.py` is what downloads them, which is also
    where an operator can see the URLs being used.

    Nothing is written until both signatures check out. A directory
    half-pinned is a directory an office would load.
    """
    _require_pades()
    from pyhanko.sign.validation.qualified.eutl_parse import (
        trust_list_to_registry, validate_and_parse_lotl)

    parsed = validate_and_parse_lotl(lotl_xml, validation_time=moment)
    wanted = territory.upper()
    for reference in parsed.references:
        if (reference.territory or "").upper() == wanted:
            break
    else:
        listed = sorted({r.territory for r in parsed.references if r.territory})
        raise TrustedListRefused(
            f"the list-of-the-lists names no trusted list for {wanted}. "
            f"It names: {', '.join(listed)}")

    registry, errors = trust_list_to_registry(member_xml, reference.tlso_certs)

    directory.mkdir(parents=True, exist_ok=True)
    lotl_file, list_file = "eu-lotl.xml", f"{wanted.lower()}-tl.xml"
    (directory / lotl_file).write_text(lotl_xml, encoding="utf-8")
    (directory / list_file).write_text(member_xml, encoding="utf-8")

    snapshot = _Snapshot(
        territory=wanted,
        location=reference.location_uri or "",
        lotl_file=lotl_file,
        lotl_sha256=_digest(directory / lotl_file),
        list_file=list_file,
        list_sha256=_digest(directory / list_file),
        tlso_certs=[base64.b64encode(c.dump()).decode("ascii")
                    for c in reference.tlso_certs],
        pinned_on=(today or datetime.date.today()).isoformat(),
    )
    _write_section(directory, snapshot)
    return PinnedTrustedList(
        territory=wanted, pinned_on=snapshot.pinned_on,
        location=snapshot.location, registry=registry,
        skipped=tuple(str(e) for e in errors))


# --------------------------------------------------------------------------
# The office's act, which needs none
# --------------------------------------------------------------------------

def load(directory: Path) -> PinnedTrustedList | None:
    """The pinned snapshot, re-validated offline. `None` if none is pinned.

    `None` rather than an exception for an absent section, because a
    directory holding only hand-pinned roots is a perfectly ordinary
    configuration and the office falls back to those. A section that is
    *present* and wrong raises: that is an operator's mistake, and an
    office that quietly ignored it would go on answering with anchors
    the operator thinks it has stopped using.

    The member list's signature is checked again here, against the
    certificates the manifest carries. It was checked at pin time too,
    and doing it twice is the point -- between the two moments the file
    sat in a directory on a server, which is the whole reason the
    hand-pinned roots have digests.
    """
    section = _read_section(directory)
    if section is None:
        return None

    _require_pades()
    from asn1crypto import x509 as asn1_x509
    from pyhanko.sign.validation.qualified.eutl_parse import trust_list_to_registry

    for name, expected in ((section.lotl_file, section.lotl_sha256),
                           (section.list_file, section.list_sha256)):
        path = directory / name
        if not path.exists():
            raise TrustedListRefused(
                f"{name} is in {MANIFEST} and not in {directory}")
        actual = _digest(path)
        if actual != expected:
            raise TrustedListRefused(
                f"{name} is not the file this office pinned: the manifest "
                f"says {expected[:16]}… and the file is {actual[:16]}…")

    if not section.tlso_certs:
        raise TrustedListRefused(
            f"{MANIFEST} pins a trusted list and names no certificate that "
            "may sign it, so nothing here could tell a swapped list from "
            "the pinned one")

    certs = [asn1_x509.Certificate.load(base64.b64decode(c))
             for c in section.tlso_certs]
    try:
        registry, errors = trust_list_to_registry(
            (directory / section.list_file).read_text(encoding="utf-8"), certs)
    except Exception as exc:  # noqa: BLE001 - every parse failure is one answer
        raise TrustedListRefused(
            f"the pinned trusted list for {section.territory} would not "
            f"validate: {type(exc).__name__}: {exc}") from exc

    return PinnedTrustedList(
        territory=section.territory, pinned_on=section.pinned_on,
        location=section.location, registry=registry,
        skipped=tuple(str(e) for e in errors))


def describe(directory: Path) -> dict | None:
    """What is pinned, without the `pades` extra and without parsing it.

    For `tools/fetch_trust_anchors.py --check`, which runs on an
    operator's machine and should not need a PDF library to say whether
    the files on disk are the files the manifest records.
    """
    section = _read_section(directory)
    if section is None:
        return None
    problems = []
    for name, expected in ((section.lotl_file, section.lotl_sha256),
                           (section.list_file, section.list_sha256)):
        path = directory / name
        if not path.exists():
            problems.append(f"{name}: named in the manifest, not on disk")
        elif _digest(path) != expected:
            problems.append(
                f"{name}: manifest says {expected[:16]}…, "
                f"file is {_digest(path)[:16]}…")
    return {
        "territory": section.territory,
        "pinned": section.pinned_on,
        "location": section.location,
        "signers": len(section.tlso_certs),
        "problems": problems,
    }


# --------------------------------------------------------------------------

def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_section(directory: Path) -> _Snapshot | None:
    path = directory / MANIFEST
    if not path.exists():
        return None
    body = json.loads(path.read_text(encoding="utf-8"))
    section = body.get("trusted_list")
    return None if section is None else _Snapshot.from_json(section)


def _write_section(directory: Path, snapshot: _Snapshot) -> None:
    path = directory / MANIFEST
    body = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    body.setdefault("anchors", [])
    body["trusted_list"] = snapshot.as_json()
    path.write_text(
        json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")
