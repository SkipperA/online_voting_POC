"""Consume the golden vectors the way a second implementation would.

These tests read `tests/vectors/*.json` and check this implementation against
them.  That is worth less than it looks on its own -- the files were generated
from this code, so Python here is pinned against its own future self, which is
regression evidence rather than interop evidence.  The interop half arrives
when the TypeScript client reads the same files in CI.  Both halves are needed:
without this one, drift in the Python is invisible until someone reruns the
generator; without the other, the vectors are a monologue.

**Unknown schema versions are refused, not skipped.**  A conformance suite that
quietly declines to run is the exact failure this directory exists to prevent,
and a version bump years from now must be loud on the day it happens.
"""

import hashlib
import json
import pathlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ovpoc import keys as ovkeys, ledger, rsabssa
from ovpoc.messages import AuthRequest, Ballot, b64, canonical_bytes, unb64
from ovpoc.vro import denial_payload, release_query_payload

VECTOR_DIR = pathlib.Path(__file__).resolve().parent / "vectors"
SUPPORTED_SCHEMA_VERSIONS = {1}


def load(
    suite: str,
    directory: pathlib.Path | None = None,
    expect_vectors: bool = True,
) -> dict:
    path = (directory or VECTOR_DIR) / f"{suite}.json"
    assert path.exists(), f"missing vector file {path}; run tools/golden_vectors.py"
    body = json.loads(path.read_text())
    version = body.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise AssertionError(
            f"{path.name} declares schema_version {version!r}, which this "
            f"consumer does not understand (supported: "
            f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}). Refusing rather than "
            f"skipping: a conformance suite that silently does nothing is worse "
            f"than one that fails."
        )
    assert body["suite"] == suite
    if expect_vectors:
        assert body["vectors"], f"{path.name} has no vectors"
    return body


@pytest.fixture(scope="module")
def key_material():
    body = load("keys", expect_vectors=False)
    priv = serialization.load_der_private_key(
        unb64(body["vro_private_key_pkcs8_der"]), password=None
    )
    return {
        "priv": priv,
        "pub": priv.public_key(),
        "wallet": ovkeys.SigningKeyPair(
            ed25519.Ed25519PrivateKey.from_private_bytes(
                unb64(body["ed25519_wallet_seed"])
            )
        ),
        "adhoc": ovkeys.SigningKeyPair(
            ed25519.Ed25519PrivateKey.from_private_bytes(
                unb64(body["ed25519_adhoc_seed"])
            )
        ),
    }


def test_every_vector_file_declares_a_schema_version_we_understand():
    found = sorted(p.stem for p in VECTOR_DIR.glob("*.json"))
    assert found, "no vector files at all"
    for suite in found:
        load(suite, expect_vectors=(suite != "keys"))  # raises on an unknown version


def test_an_unknown_schema_version_is_refused(tmp_path):
    """The refusal is itself a claim, so it gets a test.

    Skipping would leave a green suite that checks nothing -- the failure mode
    this whole directory exists to prevent.
    """
    (tmp_path / "future.json").write_text(
        json.dumps({"schema_version": 99, "suite": "future", "vectors": [{}]})
    )
    with pytest.raises(AssertionError, match="does not understand"):
        load("future", directory=tmp_path)


def test_canonical_json_vectors():
    for v in load("canonical-json")["vectors"]:
        produced = canonical_bytes(v["input"])
        expected = v["expected"]
        assert produced.decode("utf-8") == expected["canonical_utf8"], v["name"]
        assert b64(produced) == expected["canonical_b64url"], v["name"]
        assert len(produced) == expected["byte_length"], v["name"]
        assert hashlib.sha256(produced).hexdigest() == expected["sha256"], v["name"]


def test_signed_payload_vectors():
    for v in load("payloads")["vectors"]:
        i = v["input"]
        if i["kind"] == "auth_request":
            produced = AuthRequest(
                voter_id=i["voter_id"],
                blinded_key=unb64(i["blinded_key_b64url"]),
                wallet_signature=b"",
            ).signed_payload()
        elif i["kind"] == "ballot":
            produced = Ballot(
                selection=i["selection"],
                adhoc_public_key=unb64(i["adhoc_public_key_b64url"]),
                token=b"",
                vote_signature=b"",
            ).signed_payload()
        elif i["kind"] == "release_query":
            produced = release_query_payload(i["voter_id"])
        elif i["kind"] == "denial":
            produced = denial_payload(i["voter_id"])
        else:
            raise AssertionError(f"unknown payload kind {i['kind']!r}")
        assert produced.hex() == v["expected"]["signed_payload_sha256"], v["name"]


def test_ed25519_vectors(key_material):
    for v in load("ed25519")["vectors"]:
        pair = key_material[v["input"]["key"]]
        msg = unb64(v["input"]["message_b64url"])
        expected = v["expected"]

        assert b64(pair.public_bytes) == expected["public_key_raw_b64url"], v["name"]
        assert len(pair.public_bytes) == expected["public_key_raw_length"], v["name"]
        # Ed25519 is deterministic, so the signature itself is a fixed vector.
        assert b64(pair.sign(msg)) == expected["signature_b64url"], v["name"]
        assert ovkeys.verify_signature(
            pair.public_bytes, unb64(expected["signature_b64url"]), msg
        ), v["name"]


def test_fingerprint_vectors():
    for v in load("fingerprint")["vectors"]:
        pub = serialization.load_der_public_key(unb64(v["input"]["spki_der_b64url"]))
        assert (
            rsabssa.public_key_fingerprint(pub)
            == v["expected"]["fingerprint_sha256"]
        ), v["name"]


def test_rsabssa_vectors(key_material):
    priv, pub = key_material["priv"], key_material["pub"]
    n = pub.public_numbers().n
    for v in load("rsabssa")["vectors"]:
        i, expected = v["input"], v["expected"]
        msg = unb64(i["message_b64url"])
        blinded = unb64(i["blinded_b64url"])

        s_c = rsabssa.blind_sign(priv, blinded)
        assert b64(s_c) == expected["blind_signature_b64url"], v["name"]
        assert rsabssa.check_blind_signature(pub, blinded, s_c) is expected[
            "fault_check_passes"
        ], v["name"]

        state = rsabssa.BlindState(r_inv=int(i["r_inv"]), encoded_msg=b"", modulus=n)
        token = rsabssa.finalize(pub, msg, s_c, state)
        assert b64(token) == expected["token_b64url"], v["name"]
        assert len(token) == expected["token_length"], v["name"]

        # The point of RFC 9474: an ordinary PSS verify, no bespoke code.
        assert rsabssa.verify(pub, msg, token) is expected["token_verifies"], v["name"]
        tampered = bytearray(token)
        tampered[0] ^= 0xFF
        assert rsabssa.verify(pub, msg, bytes(tampered)) is expected[
            "tampered_token_verifies"
        ], v["name"]


def test_ledger_vectors():
    for v in load("ledger")["vectors"]:
        assert v["input"]["genesis_hex"] == ledger.GENESIS.hex(), v["name"]
        log = ledger.Ledger()
        for payload in v["input"]["payloads"]:
            log.append(payload)

        expected = v["expected"]
        for entry, want in zip(log.entries, expected["entries"]):
            assert entry.index == want["index"], v["name"]
            assert entry.prev_hash.hex() == want["prev_hash_hex"], v["name"]
            assert entry.entry_hash.hex() == want["entry_hash_hex"], v["name"]
        assert log.head().hex() == expected["head_hex"], v["name"]
        assert log.verify_chain() is expected["chain_verifies"], v["name"]
