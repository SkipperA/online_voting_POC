"""Pin the certificates this office is willing to believe.

The shortest and most consequential configuration in the project.  A token
request on the qualified-signature route is accepted because its signature
chains to one of these; add a certificate here and the office will accept
requests from whoever that authority vouches for, and nothing downstream will
look wrong, because a signature under a trusted anchor is exactly what a valid
request looks like.

WHY A TOOL AND NOT A FETCH AT VALIDATION TIME
----------------------------------------------
pyHanko splits obtaining the European trust list from parsing it, and the
split is the right shape for a deployment: pinning is an operator action that
produces a dated directory, and validation then runs offline against it.  Two
things follow that are worth having.  The office does not reach the
certification authority while deciding a citizen's request -- which would tell
that authority which certificates an election office is asking about, from a
machine that also holds the electoral register.  And a reader can see what was
pinned and when, which a live fetch would never show them.

It is affordable because of what the wallet turned out to do.  Every document
DAP signs carries a `/DSS` holding the certificates and OCSP responses behind
it -- in the first real example, the signer, the issuing authority, the
timestamp authority and its own issuer, four in all.  **None of them was
self-signed.**  Everything chains to `GovCA Fotanusitvanykiado`, and that root
is the one thing the document does not carry.  So the office pins exactly
that: one certificate, obtained out of band, and the rest rides in the file.

TRUST ON FIRST USE, AND SAYING SO
----------------------------------
Downloading a root certificate from the authority's own web server and
trusting it is trust on first use over a channel the certificate itself is
supposed to secure.  This tool does not pretend otherwise.  It prints the
fingerprint and the subject and **asks the operator to check them against a
source that did not come down the same wire** -- the authority's published
practice statement, the national trusted list, a colleague's copy.  The
manifest then records the digest, and `QualifiedSignatureValidation.from_pinned`
refuses to load an anchor whose bytes have changed since.

That is weaker than taking the anchors from a signed European trusted list,
which is what a deployment does and what pyHanko's `etsi` extra is for. The
difference is a scope clause and not a detail.

USAGE
-----
    python tools/fetch_trust_anchors.py --into election-data/trust-anchors \\
        http://qca.hiteles.gov.hu/ecc/cer/govca-ecc-root.cer

    python tools/fetch_trust_anchors.py --into DIR --add some-root.cer
    python tools/fetch_trust_anchors.py --into DIR --check
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "MANIFEST.json"
SUFFIXES = (".cer", ".crt", ".der")


def _as_der(data: bytes) -> bytes:
    """DER, whether the authority served DER or PEM.

    Both are published and the extension says nothing reliable about which.
    """
    if data.lstrip().startswith(b"-----BEGIN"):
        from base64 import b64decode
        body = b"".join(
            line for line in data.splitlines()
            if line and not line.startswith(b"-----")
        )
        return b64decode(body)
    return data


def _describe(der: bytes) -> dict:
    """Subject, issuer and validity, so the operator can see what they pinned.

    Parsed with `cryptography`, which the project already depends on, rather
    than with anything the `pades` extra brings: pinning an anchor should
    work on a machine that is not going to validate anything.
    """
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": hashlib.sha256(der).hexdigest(),
    }


def _load_manifest(directory: Path) -> dict:
    path = directory / MANIFEST
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"anchors": []}


def _write_manifest(directory: Path, manifest: dict) -> None:
    manifest["pinned"] = datetime.date.today().isoformat()
    (directory / MANIFEST).write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")


def add(directory: Path, der: bytes, name: str, source: str) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(der)

    described = _describe(der)
    manifest = _load_manifest(directory)
    manifest["anchors"] = [a for a in manifest["anchors"] if a["file"] != name]
    manifest["anchors"].append({
        "file": name,
        "source": source,
        "sha256": described["sha256"],
        "subject": described["subject"],
        "not_after": described["not_after"],
        "self_signed": described["self_signed"],
    })
    manifest["anchors"].sort(key=lambda a: a["file"])
    _write_manifest(directory, manifest)
    return described


def check(directory: Path) -> list[str]:
    """Every complaint `from_pinned` would make, without importing it.

    Duplicated on purpose: this runs on an operator's machine, which may
    not have the `pades` extra installed, and an operator checking their
    anchors should not have to install a PDF library to do it.
    """
    problems: list[str] = []
    if not (directory / MANIFEST).exists():
        return [f"no {MANIFEST} in {directory}"]
    manifest = _load_manifest(directory)
    recorded = set()
    for entry in manifest["anchors"]:
        recorded.add(entry["file"])
        path = directory / entry["file"]
        if not path.exists():
            problems.append(f"{entry['file']}: named in the manifest, not on disk")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            problems.append(
                f"{entry['file']}: manifest says {entry['sha256'][:16]}…, "
                f"file is {actual[:16]}…")
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() in SUFFIXES and path.name not in recorded:
            problems.append(f"{path.name}: on disk, in no manifest entry")
    return problems


def _describe_trusted_list(directory: Path):
    """What `driver.trusted_list.describe` says, if it can be imported.

    `--check` runs on an operator's machine, which need not have the
    `pades` extra; `describe` reads the manifest and hashes files and
    needs none of it, but importing the module at the top of this tool
    would still tie the two together. Kept local and forgiving.
    """
    try:
        sys.path.insert(0, str(ROOT))
        from driver.trusted_list import describe
    except ImportError:  # pragma: no cover - a checkout without `driver/`
        return None
    return describe(directory)


def _pin_trusted_list(directory: Path, territory: str) -> int:
    """Fetch the list-of-the-lists, then the member state's own list.

    Two downloads and two signature checks, and the second is why the
    first matters: the LOTL is signed by certificates pyHanko ships, and
    it names the certificates that may sign each member state's list. So
    nothing here is trusted because it arrived from a plausible address.
    That is the step `--add`ing a root by hand cannot do, and the whole
    of what clause S6 said a deployment does differently.

    This is the one command in this tool that must reach the internet,
    and it is an operator's act performed once, not something the office
    does while a poll runs.
    """
    sys.path.insert(0, str(ROOT))
    from driver.trusted_list import LOTL_URL, TrustedListRefused, pin
    from driver.trusted_list import load as load_trusted_list

    # Said rather than raised. This is the one subcommand here that needs
    # the `pades` extra, and the place an operator runs it is a server --
    # where the extra is inside the office's container and not on the host.
    # A traceback there reads as a broken tool rather than as a command
    # typed on the wrong machine.
    try:
        import pyhanko  # noqa: F401
    except ImportError:
        print("This needs the `pades` extra, which is not installed here.\n")
        print("On a server it is in the office's own container, which also")
        print("has the volume mounted, so run it there:\n")
        print("  docker compose -f deploy/compose.yaml exec ovpoc \\")
        print("      python tools/fetch_trust_anchors.py \\")
        print(f"          --into /data/trust-anchors --trusted-list {territory}\n")
        print('Elsewhere: pip install -e ".[pades]"')
        return 2

    print(f"fetching {LOTL_URL}")
    with urllib.request.urlopen(LOTL_URL, timeout=60) as response:
        lotl_xml = response.read().decode("utf-8")

    # The member state's own URL comes out of the signed LOTL rather than
    # being typed here: an address an operator pasted is an address an
    # operator can mistype, and this one decides whose signatures an
    # electoral office accepts.
    from pyhanko.sign.validation.qualified.eutl_parse import validate_and_parse_lotl

    parsed = validate_and_parse_lotl(lotl_xml)
    wanted = territory.upper()
    reference = next((r for r in parsed.references
                      if (r.territory or "").upper() == wanted), None)
    if reference is None:
        listed = sorted({r.territory for r in parsed.references if r.territory})
        print(f"the list-of-the-lists names no list for {wanted}.")
        print(f"It names: {', '.join(listed)}")
        return 1

    print(f"fetching {reference.location_uri}")
    with urllib.request.urlopen(reference.location_uri, timeout=60) as response:
        member_xml = response.read().decode("utf-8")

    try:
        pinned = pin(directory, territory=wanted,
                     lotl_xml=lotl_xml, member_xml=member_xml)
    except TrustedListRefused as refused:
        print(f"refused: {refused}")
        return 1

    # Read it back the way the office will, offline, before saying it is
    # pinned. A snapshot that writes and does not load is a deployment
    # that will not start, discovered now rather than at the next restart.
    reloaded = load_trusted_list(directory)

    print(f"\npinned into {directory}\n")
    print(f"  territory               {pinned.territory}")
    print(f"  list                    {pinned.location}")
    print(f"  certification authorities {reloaded.authorities}")
    print(f"  timestamp authorities   {reloaded.timestamp_authorities}")
    print(f"  services not understood {len(pinned.skipped)}")
    print(f"  pinned on               {pinned.pinned_on}")
    print()
    print("Both signatures checked: the list-of-the-lists against the signer")
    print("certificates pyHanko ships, and this list against the certificates")
    print("the list-of-the-lists names for it. No trust on first use here.")
    print()
    print("The office reads this snapshot offline and never reaches the")
    print("Union while a poll runs, so a service withdrawn after today is")
    print("still trusted by it. Re-pin before an election rather than after.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Pin trust anchors for the office.")
    parser.add_argument("url", nargs="?", help="a certificate to download and pin")
    parser.add_argument("--into", type=Path,
                        default=ROOT / "election-data" / "trust-anchors")
    parser.add_argument("--add", type=Path, default=None,
                        help="pin a certificate already on disk")
    parser.add_argument("--check", action="store_true",
                        help="verify the directory against its manifest")
    parser.add_argument("--trusted-list", metavar="CC", default=None,
                        help="pin a member state's EU trusted list, e.g. HU. "
                             "Replaces hand-pinned roots: the office then "
                             "takes its anchors from the list and can say "
                             "whether a signature is qualified")
    args = parser.parse_args()

    if args.check:
        problems = check(args.into)
        described = _describe_trusted_list(args.into)
        if described is not None:
            print(f"  trusted list  {described['territory']}, pinned "
                  f"{described['pinned']}, {described['signers']} signer(s)")
            problems.extend(described["problems"])
        for problem in problems:
            print(f"  {problem}")
        print("The pinned anchors are as recorded." if not problems
              else f"{len(problems)} problem(s).")
        return 1 if problems else 0

    if args.trusted_list:
        return _pin_trusted_list(args.into, args.trusted_list)

    if args.add is not None:
        der = _as_der(args.add.read_bytes())
        described = add(args.into, der, args.add.name, f"file:{args.add}")
    elif args.url:
        with urllib.request.urlopen(args.url, timeout=30) as response:
            der = _as_der(response.read())
        described = add(args.into, der, args.url.rsplit("/", 1)[-1], args.url)
    else:
        parser.error("give a URL, or --add a file, or --check")
        return 2

    print(f"pinned into {args.into}\n")
    print(f"  subject     {described['subject']}")
    print(f"  issuer      {described['issuer']}")
    print(f"  self-signed {described['self_signed']}")
    print(f"  expires     {described['not_after']}")
    print(f"  sha256      {described['sha256']}")
    print()
    print("Check that fingerprint against a source that did not come down")
    print("this wire -- the authority's published practice statement, the")
    print("national trusted list, somebody else's copy. Downloading a root")
    print("from the authority's own web server and trusting it is trust on")
    print("first use, and this office will believe whoever it vouches for.")
    if not described["self_signed"]:
        print()
        print("NOTE: this certificate is not self-signed, so it is not a root.")
        print("Pinning an intermediate works and narrows what you trust to")
        print("that one authority -- which may be what you want, and is not")
        print("what a trusted list would give you.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
