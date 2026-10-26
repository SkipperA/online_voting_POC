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


def main() -> int:
    parser = argparse.ArgumentParser(description="Pin trust anchors for the office.")
    parser.add_argument("url", nargs="?", help="a certificate to download and pin")
    parser.add_argument("--into", type=Path,
                        default=ROOT / "election-data" / "trust-anchors")
    parser.add_argument("--add", type=Path, default=None,
                        help="pin a certificate already on disk")
    parser.add_argument("--check", action="store_true",
                        help="verify the directory against its manifest")
    args = parser.parse_args()

    if args.check:
        problems = check(args.into)
        for problem in problems:
            print(f"  {problem}")
        print("The pinned anchors are as recorded." if not problems
              else f"{len(problems)} problem(s).")
        return 1 if problems else 0

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
