"""Canonical serialisation, pinned against an independent implementation.

Everything signed in this protocol is signed over the bytes `canonical_bytes`
produces.  A second implementation that serialises the same object differently
does not merely disagree about formatting: its signatures fail to verify here,
and ours fail to verify there.

The expected values below were produced by `JSON.stringify` in Node over the
same objects with the keys sorted, not by this module.  That is the whole
point -- a test that asked Python what Python does would pass under any
convention at all, including one no other language shares.
"""

import hashlib

from ovpoc.messages import canonical_bytes, digest
from ovpoc.vro import denial_payload, release_query_payload

# (object, bytes JSON.stringify produced, sha256 of those bytes)
VECTORS = [
    (
        {"voter_id": "HU-1970-0442", "blinded_key": "AAA"},
        '{"blinded_key":"AAA","voter_id":"HU-1970-0442"}',
        "b315f36c296c56623227ac853036a01b5b656e4ce955a6aa44a3926b584253bf",
    ),
    (
        {"voter_id": "Vágujhelyi Ferenc"},
        '{"voter_id":"Vágujhelyi Ferenc"}',
        "0d33b79a8d642c680fa378695984ae873ad6537878e43b625ca60096973d15f6",
    ),
    (
        {"query": "token-release", "voter_id": "Kovács Ágnes"},
        '{"query":"token-release","voter_id":"Kovács Ágnes"}',
        "6f4e34bbb74f62d8c747f01859f710c3ff6ec2d05ce1e8c5f4155e9f9dcfee4a",
    ),
    (
        {"selection": 3, "adhoc_public_key": "zMc_Bk-LXguCvIxroKQRXwx5GBoLCYCIK31enkB_zO0"},
        '{"adhoc_public_key":"zMc_Bk-LXguCvIxroKQRXwx5GBoLCYCIK31enkB_zO0","selection":3}',
        "7f589d4b6ac2f8d539c65ee9c05310f6bcba8eb90fa9623c0553497feab378a9",
    ),
    (
        {"voter_id": "日本語", "note": "emoji 🗳"},
        '{"note":"emoji 🗳","voter_id":"日本語"}',
        "08ae0e5073e599bf1df9e8e12bcfbbf241c9d188c2f4522a43007096dcc83247",
    ),
]


def test_canonical_bytes_match_an_independent_implementation():
    for obj, expected_text, expected_sha in VECTORS:
        produced = canonical_bytes(obj)
        assert produced == expected_text.encode("utf-8"), obj
        assert hashlib.sha256(produced).hexdigest() == expected_sha, obj


def test_digest_matches_the_pinned_hashes():
    """`digest` is what actually gets signed; pin it, not only the bytes."""
    for obj, _, expected_sha in VECTORS:
        assert digest(obj).hex() == expected_sha, obj


def test_non_ascii_is_emitted_as_utf8_not_escaped():
    """The specific divergence this pins: Python's default would escape.

    A voter_id carrying an accent is the case that breaks across the wire and
    nowhere else, so it cannot be left to 'every identifier we happen to use is
    ASCII'.
    """
    produced = canonical_bytes({"voter_id": "Vágujhelyi"})
    assert b"\\u00e1" not in produced
    assert "á".encode("utf-8") in produced


def test_the_payloads_the_checker_verifies_are_affected():
    """Why this matters beyond formatting: two signed payloads carry voter_id.

    `release_query_payload` is signed in the wallet and verified by the office;
    `denial_payload` is signed by the office and verified by the independent
    checker, which in stage 1 is a different implementation.  Both go through
    `canonical_bytes`, so both diverge for a non-ASCII identifier.
    """
    voter_id = "Kovács Ágnes"
    assert release_query_payload(voter_id) == digest(
        {"query": "token-release", "voter_id": voter_id}
    )
    assert denial_payload(voter_id) == digest(
        {"statement": "no-token-released", "voter_id": voter_id}
    )
