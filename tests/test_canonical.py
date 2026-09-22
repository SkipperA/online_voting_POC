"""Canonical serialisation: the claims, as opposed to the table of values.

The fixed input/output pairs now live in `tests/vectors/canonical-json.json`
and are checked by `tests/test_vectors.py`, so they are not repeated here --
two copies of the same constants drift, and the copy nobody regenerates is the
one that lies.

What stays here is what the vectors cannot say on their own: *which* property
is being defended, and *where* in the protocol a divergence would surface.
"""

from ovpoc.messages import canonical_bytes, digest
from ovpoc.vro import denial_payload, release_query_payload


def test_non_ascii_is_emitted_as_utf8_not_escaped():
    """Python's default would escape; JavaScript, Swift and RFC 8785 do not.

    A voter_id carrying an accent is the case that breaks across the wire and
    nowhere else, so it cannot be left to 'every identifier we happen to use is
    ASCII'.
    """
    produced = canonical_bytes({"voter_id": "Vágujhelyi"})
    assert b"\\u00e1" not in produced
    assert "á".encode("utf-8") in produced


def test_keys_are_sorted_not_insertion_ordered():
    assert canonical_bytes({"z": 1, "a": 2}) == canonical_bytes({"a": 2, "z": 1})
    assert canonical_bytes({"z": 1, "a": 2}) == b'{"a":2,"z":1}'


def test_separators_carry_no_whitespace():
    assert b" " not in canonical_bytes({"a": 1, "b": 2})


def test_the_payloads_the_checker_verifies_are_affected():
    """Why this matters beyond formatting: two signed payloads carry voter_id.

    `release_query_payload` is signed in the wallet and verified by the office;
    `denial_payload` is signed by the office and verified by the independent
    checker, which in stage 1 is a different implementation.  Both go through
    `canonical_bytes`, so both diverge for a non-ASCII identifier -- and the
    denial is precisely the message a voter would need to rely on.
    """
    voter_id = "Kovács Ágnes"
    assert release_query_payload(voter_id) == digest(
        {"query": "token-release", "voter_id": voter_id}
    )
    assert denial_payload(voter_id) == digest(
        {"statement": "no-token-released", "voter_id": voter_id}
    )
