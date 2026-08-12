"""The full protocol, end to end, plus independent verification of the result."""

from conftest import register
from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot, unb64


def test_three_voters_cast_and_verify(election):
    vro, voters, box = election
    intended = {0: 1, 1: 3, 2: 1}

    for index, voter in enumerate(voters):
        register(vro, voter)                                  # steps 1-8
        result = box.submit(voter.cast(intended[index]))       # steps 9-11
        assert result.accepted
        voter.record_head(result.ledger_head)

    # Each voter checks their own recorded ballot, from an independent device.
    for index, voter in enumerate(voters):
        assert voter.verify_recorded_ballot(box, intended[index])

    tally = box.tally()
    assert tally == {
        "counts": {1: 2, 2: 0, 3: 1},
        "invalid": 0,
        "protest_codes": {},
        "voters": 3,
        "rejected": 0,
        "ledger_head": box.valid.head().hex(),
    }


def test_an_outsider_can_recompute_the_result_from_the_public_ledger(election):
    """The transparency claim, made executable.

    This function uses nothing but the published ledger and the VRO's public
    key -- no privileged access, no trust in the ballot box.  It is the shape
    the standalone `verifier` tool will take.
    """
    vro, voters, box = election
    for index, voter in enumerate(voters):
        register(vro, voter)
        box.submit(voter.cast(index + 1))

    published = [entry.payload for entry in box.valid.entries]
    vro_public_key = vro.public_key

    # 1. Every published ballot carries a genuine VRO token and a matching
    #    vote signature.
    latest = {}
    for payload in published:
        ballot = Ballot.from_dict(payload)
        assert rsabssa.verify(vro_public_key, ballot.adhoc_public_key, ballot.token)
        assert keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload()
        )
        latest[payload["adhoc_public_key"]] = ballot.selection

    # 2. The chain is intact, so nothing was removed or reordered.
    assert box.valid.verify_chain()

    # 3. No more ballots than tokens released.
    assert len(latest) <= vro.release_count()

    # 4. The independently computed result matches the announced one.
    independent = {i: sum(1 for s in latest.values() if s == i) for i in (1, 2, 3)}
    assert independent == box.tally()["counts"]


def test_the_vro_cannot_link_its_signature_to_a_published_ballot(election):
    """Anonymity, stated as a test.

    Everything the VRO saw was the blinded value; nothing it retained appears
    in the ballot box.  The only thing it knows is *that* each voter took a
    token, never which ballot became theirs.
    """
    vro, voters, box = election
    seen_by_vro = []
    for voter in voters:
        request = voter.build_auth_request()
        seen_by_vro.append(request.blinded_key)
        voter.accept_token(vro.issue_token(request))
        box.submit(voter.cast(1))

    published_keys = {unb64(e.payload["adhoc_public_key"]) for e in box.valid.entries}
    for blinded in seen_by_vro:
        assert not any(key in blinded for key in published_keys)

    # The release log publishes commitments only -- neither ids nor any
    # cryptographic material that could be matched against the ballot box.
    for entry in vro.release_log.entries:
        assert set(entry.payload) == {"commitment"}
