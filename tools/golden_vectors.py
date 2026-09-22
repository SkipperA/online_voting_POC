"""Generate the golden vectors that pin this implementation for the others.

Why this exists.  `voter.py` is the reference implementation of the voter's
side, and stage 1 adds a second implementation in TypeScript, stage 3 a third
in Swift.  Those two will never run this test suite.  What crosses to them is
this directory: fixed inputs, and the bytes this implementation produces from
them.  A second implementation that disagrees about any of it does not merely
format things differently -- its signatures fail to verify here, and ours fail
to verify there.

Two properties make the files worth committing.

**Regeneration is deterministic.**  Every value that cannot be derived -- key
material, the one-off blinded value and its inverse, the sample objects -- is
stored in the `input` of each vector and is *preserved* across runs.  Only
`expected` is recomputed.  So re-running this script on unchanged code produces
a byte-identical tree and an empty diff, and any diff at all is a real change
in behaviour.  `--check` exploits that: it regenerates into memory and fails if
the committed files disagree, which is what CI runs.

**Randomised operations are pinned through their outputs, not their inputs.**
`blind()` draws a fresh PSS salt and a fresh `r`, so it cannot be a fixed
vector and no seam is added to make it one -- a seam that lets a caller choose
`r` is a seam an attacker wants.  Instead the blinded value `c` and the inverse
`r_inv` from one historical run are committed as *inputs*, and everything
downstream of them (`blind_sign`, `finalize`, `verify`) is deterministic and
pinned.  `blind()` itself is covered by the round-trip property tests in
`tests/test_rsabssa.py` and by the cross-implementation run in CI.

Usage:
    python tools/golden_vectors.py --bootstrap   # once: mint key material
    python tools/golden_vectors.py               # rewrite expected values
    python tools/golden_vectors.py --check       # CI: fail on any drift
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from ovpoc import keys as ovkeys, ledger, rsabssa  # noqa: E402
from ovpoc.messages import AuthRequest, Ballot, b64, canonical_bytes, digest, unb64  # noqa: E402
from ovpoc.vro import denial_payload, release_query_payload  # noqa: E402

VECTOR_DIR = ROOT / "tests" / "vectors"
SCHEMA_VERSION = 1

# A test key, in a public repository, on purpose.  It signs nothing outside
# this suite and must never be used for an election; the file says so too.
KEY_BITS = 3072


# --------------------------------------------------------------------------
# File handling
# --------------------------------------------------------------------------

def read(suite: str) -> dict | None:
    path = VECTOR_DIR / f"{suite}.json"
    return json.loads(path.read_text()) if path.exists() else None


def render(suite: str, description: str, vectors: list[dict]) -> str:
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "suite": suite,
            "description": description,
            "vectors": vectors,
        },
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
    ) + "\n"


def inputs_of(suite: str, fallback: list[dict]) -> list[dict]:
    """Preserve committed inputs; use the fallback only when bootstrapping."""
    existing = read(suite)
    if existing is None:
        return fallback
    return [{"name": v["name"], "input": v["input"]} for v in existing["vectors"]]


# --------------------------------------------------------------------------
# Key material
# --------------------------------------------------------------------------

def bootstrap_keys() -> None:
    priv, pub = rsabssa.generate_vro_keypair(KEY_BITS)
    seed_wallet = hashlib.sha256(b"ovpoc-golden-wallet").digest()
    seed_adhoc = hashlib.sha256(b"ovpoc-golden-adhoc").digest()
    body = {
        "schema_version": SCHEMA_VERSION,
        "suite": "keys",
        "description": (
            "TEST KEY MATERIAL. Generated once for the conformance vectors. "
            "It is published deliberately and must never be used in an election."
        ),
        "warning": "TEST KEY -- NOT FOR ANY ELECTION",
        "vro_private_key_pkcs8_der": b64(
            priv.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
        "vro_public_key_spki_der": b64(
            pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ),
        "modulus_bits": KEY_BITS,
        "ed25519_wallet_seed": b64(seed_wallet),
        "ed25519_adhoc_seed": b64(seed_adhoc),
    }
    (VECTOR_DIR / "keys.json").write_text(
        json.dumps(body, indent=2, ensure_ascii=False) + "\n"
    )


def load_keys():
    body = read("keys")
    if body is None:
        raise SystemExit("no tests/vectors/keys.json -- run with --bootstrap first")
    priv = serialization.load_der_private_key(
        unb64(body["vro_private_key_pkcs8_der"]), password=None
    )
    wallet = ovkeys.SigningKeyPair(
        ed25519.Ed25519PrivateKey.from_private_bytes(unb64(body["ed25519_wallet_seed"]))
    )
    adhoc = ovkeys.SigningKeyPair(
        ed25519.Ed25519PrivateKey.from_private_bytes(unb64(body["ed25519_adhoc_seed"]))
    )
    return priv, priv.public_key(), wallet, adhoc


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------

def group_canonical_json() -> tuple[str, str, list[dict]]:
    fallback = [
        {"name": "ascii-identifier",
         "input": {"voter_id": "HU-1970-0442", "blinded_key": "AAA"}},
        {"name": "accented-latin",
         "input": {"voter_id": "Vágujhelyi Ferenc"}},
        {"name": "release-query-shape",
         "input": {"query": "token-release", "voter_id": "Kovács Ágnes"}},
        {"name": "ballot-shape",
         "input": {"selection": 3,
                   "adhoc_public_key": "zMc_Bk-LXguCvIxroKQRXwx5GBoLCYCIK31enkB_zO0"}},
        {"name": "cjk-and-astral",
         "input": {"voter_id": "日本語", "note": "emoji 🗳"}},
        {"name": "key-order-is-not-insertion-order",
         "input": {"z": 1, "a": 2, "M": 3, "_": 4}},
    ]
    out = []
    for v in inputs_of("canonical-json", fallback):
        raw = canonical_bytes(v["input"])
        out.append({
            "name": v["name"],
            "input": v["input"],
            "expected": {
                "canonical_utf8": raw.decode("utf-8"),
                "canonical_b64url": b64(raw),
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            },
        })
    return ("canonical-json",
            "Sorted keys, ',' and ':' with no whitespace, non-ASCII left as UTF-8, "
            "base64url without padding for binary. Everything signed in this "
            "protocol is signed over these bytes.",
            out)


def group_payloads(wallet, adhoc) -> tuple[str, str, list[dict]]:
    fallback = [
        {"name": "auth-request-ascii",
         "input": {"kind": "auth_request", "voter_id": "HU-1970-0442",
                   "blinded_key_b64url": b64(bytes(range(64)))}},
        {"name": "auth-request-accented",
         "input": {"kind": "auth_request", "voter_id": "Kovács Ágnes",
                   "blinded_key_b64url": b64(bytes(range(64)))}},
        {"name": "ballot-in-range",
         "input": {"kind": "ballot", "selection": 2,
                   "adhoc_public_key_b64url": b64(adhoc.public_bytes)}},
        {"name": "ballot-protest",
         "input": {"kind": "ballot", "selection": -1,
                   "adhoc_public_key_b64url": b64(adhoc.public_bytes)}},
        {"name": "release-query-accented",
         "input": {"kind": "release_query", "voter_id": "Kovács Ágnes"}},
        {"name": "denial-accented",
         "input": {"kind": "denial", "voter_id": "Kovács Ágnes"}},
    ]
    out = []
    for v in inputs_of("payloads", fallback):
        i = v["input"]
        if i["kind"] == "auth_request":
            payload = AuthRequest(
                voter_id=i["voter_id"],
                blinded_key=unb64(i["blinded_key_b64url"]),
                wallet_signature=b"",
            ).signed_payload()
        elif i["kind"] == "ballot":
            payload = Ballot(
                selection=i["selection"],
                adhoc_public_key=unb64(i["adhoc_public_key_b64url"]),
                token=b"",
                vote_signature=b"",
            ).signed_payload()
        elif i["kind"] == "release_query":
            payload = release_query_payload(i["voter_id"])
        elif i["kind"] == "denial":
            payload = denial_payload(i["voter_id"])
        else:
            raise SystemExit(f"unknown payload kind {i['kind']!r}")
        out.append({
            "name": v["name"],
            "input": i,
            "expected": {"signed_payload_sha256": payload.hex()},
        })
    return ("payloads",
            "The four objects whose bytes get signed. An implementation that "
            "builds any of them differently produces signatures the others "
            "reject -- the accented cases are where that actually happens.",
            out)


def group_ed25519(wallet, adhoc) -> tuple[str, str, list[dict]]:
    fallback = [
        {"name": "wallet-key-raw-encoding",
         "input": {"key": "wallet", "message_b64url": b64(b"")}},
        {"name": "adhoc-key-over-32-bytes",
         "input": {"key": "adhoc", "message_b64url": b64(bytes(range(32)))}},
        {"name": "adhoc-key-over-a-digest",
         "input": {"key": "adhoc",
                   "message_b64url": b64(hashlib.sha256(b"ovpoc").digest())}},
    ]
    pairs = {"wallet": wallet, "adhoc": adhoc}
    out = []
    for v in inputs_of("ed25519", fallback):
        pair = pairs[v["input"]["key"]]
        msg = unb64(v["input"]["message_b64url"])
        out.append({
            "name": v["name"],
            "input": v["input"],
            "expected": {
                "public_key_raw_b64url": b64(pair.public_bytes),
                "public_key_raw_length": len(pair.public_bytes),
                "signature_b64url": b64(pair.sign(msg)),
            },
        })
    return ("ed25519",
            "Raw 32-byte public keys and deterministic signatures. WebCrypto "
            "exports raw directly; where it does not, the trailing 32 bytes of "
            "the SPKI export are the same value.",
            out)


def group_fingerprint(pub) -> tuple[str, str, list[dict]]:
    spki = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return ("fingerprint",
            "SHA-256 over the DER SubjectPublicKeyInfo. This is the value the "
            "voter application pins and displays; a client computing it "
            "differently would accept a VRO key the design forbids.",
            [{
                "name": "vro-token-signing-key",
                "input": {"spki_der_b64url": b64(spki)},
                "expected": {"fingerprint_sha256": rsabssa.public_key_fingerprint(pub)},
            }])


def group_rsabssa(priv, pub, adhoc) -> tuple[str, str, list[dict]]:
    existing = read("rsabssa")
    if existing is None:
        msg = adhoc.public_bytes
        blinded, state = rsabssa.blind(pub, msg)
        fallback = [{
            "name": "adhoc-key-blind-signed",
            "input": {
                "message_b64url": b64(msg),
                "blinded_b64url": b64(blinded),
                "r_inv": str(state.r_inv),
            },
        }]
        raw_inputs = fallback
    else:
        raw_inputs = [{"name": v["name"], "input": v["input"]} for v in existing["vectors"]]

    n = pub.public_numbers().n
    k = (n.bit_length() + 7) // 8
    out = []
    for v in raw_inputs:
        i = v["input"]
        msg = unb64(i["message_b64url"])
        blinded = unb64(i["blinded_b64url"])
        s_c = rsabssa.blind_sign(priv, blinded)
        state = rsabssa.BlindState(r_inv=int(i["r_inv"]), encoded_msg=b"", modulus=n)
        token = rsabssa.finalize(pub, msg, s_c, state)
        tampered = bytearray(token)
        tampered[0] ^= 0xFF
        out.append({
            "name": v["name"],
            "input": i,
            "expected": {
                "blind_signature_b64url": b64(s_c),
                "fault_check_passes": rsabssa.check_blind_signature(pub, blinded, s_c),
                "token_b64url": b64(token),
                "token_length": len(token),
                "token_verifies": rsabssa.verify(pub, msg, token),
                "tampered_token_verifies": rsabssa.verify(pub, msg, bytes(tampered)),
                "modulus_bytes": k,
            },
        })
    return ("rsabssa",
            "RFC 9474 RSABSSA-SHA384-PSS-Deterministic. `blind` is randomised "
            "and cannot be pinned, so its output is committed as an input; "
            "everything downstream of it is deterministic. The token is an "
            "ordinary RSA-PSS signature and must verify under a stock library.",
            out)


def group_ledger() -> tuple[str, str, list[dict]]:
    fallback = [{
        "name": "three-entry-chain",
        "input": {
            "genesis_hex": ledger.GENESIS.hex(),
            "payloads": [
                {"selection": 1, "adhoc_public_key": "AAA"},
                {"selection": 2, "adhoc_public_key": "BBB", "voter_note": "Ágnes"},
                {"selection": -1, "adhoc_public_key": "CCC"},
            ],
        },
    }]
    out = []
    for v in inputs_of("ledger", fallback):
        log = ledger.Ledger()
        entries = []
        for payload in v["input"]["payloads"]:
            entry = log.append(payload)
            entries.append({
                "index": entry.index,
                "prev_hash_hex": entry.prev_hash.hex(),
                "entry_hash_hex": entry.entry_hash.hex(),
            })
        out.append({
            "name": v["name"],
            "input": v["input"],
            "expected": {
                "entries": entries,
                "head_hex": log.head().hex(),
                "chain_verifies": log.verify_chain(),
            },
        })
    return ("ledger",
            "entry_hash = SHA-256(index as 8 big-endian bytes || prev_hash || "
            "canonical_bytes(payload)). The independent checker recomputes this "
            "chain, so it is the one calculation two implementations must agree "
            "on for the inclusion check to mean anything.",
            out)


# --------------------------------------------------------------------------

def build() -> dict[str, str]:
    priv, pub, wallet, adhoc = load_keys()
    groups = [
        group_canonical_json(),
        group_payloads(wallet, adhoc),
        group_ed25519(wallet, adhoc),
        group_fingerprint(pub),
        group_rsabssa(priv, pub, adhoc),
        group_ledger(),
    ]
    return {suite: render(suite, desc, vecs) for suite, desc, vecs in groups}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", action="store_true",
                        help="mint key material; refuses to overwrite")
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed vectors differ from this code")
    args = parser.parse_args()

    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    if args.bootstrap:
        if (VECTOR_DIR / "keys.json").exists():
            print("keys.json already exists; refusing to mint new key material.")
            return 1
        bootstrap_keys()
        print("Wrote tests/vectors/keys.json")

    rendered = build()

    if args.check:
        drift = []
        for suite, text in rendered.items():
            path = VECTOR_DIR / f"{suite}.json"
            if not path.exists() or path.read_text() != text:
                drift.append(suite)
        if drift:
            print("Committed vectors do not match this code:")
            for suite in drift:
                print(f"  - {suite}")
            print("\nRun: python tools/golden_vectors.py")
            return 1
        print(f"All {len(rendered)} vector files match.")
        return 0

    for suite, text in rendered.items():
        (VECTOR_DIR / f"{suite}.json").write_text(text)
    print(f"Wrote {len(rendered)} vector files to tests/vectors/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
