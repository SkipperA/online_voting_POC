"""Where this system sits on the verifiability/coercion trade-off.

These are not attacks. They record a *policy property* of the design, and one
negative result that constrains what future work can hope for.

The papers frame the placement of this balance as a legislative decision. The
tests below make the current placement explicit and executable, so that nobody
reading the code has to infer it from comments.
"""

import secrets

from conftest import register
from ovpoc import keys
from ovpoc.handles import AdHocKeyHandle
from ovpoc.messages import unb64


def third_party_is_convinced(published_ballot: dict, challenge: bytes, proof: bytes) -> bool:
    """What a vote buyer, or an adjudicator, can check for themselves.

    Both use exactly this procedure. That is the point.
    """
    return keys.verify_signature(
        unb64(published_ballot["adhoc_public_key"]), proof, challenge
    )


def test_the_handle_locates_the_voters_own_ballot(election):
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(2))

    assert isinstance(voter.handle, AdHocKeyHandle)
    assert voter.handle.locate(box)["selection"] == 2
    assert voter.handle.confirms(box, 2)
    assert not voter.handle.confirms(box, 3)


def test_variant_b_authorship_is_provable_to_a_third_party(election):
    """The defining property of variant B, stated as a test.

    This is deliberate, not a defect: it is what lets a voter substantiate a
    complaint under requirement 8. It is also what a vote buyer needs. The two
    are the same capability, which is why the papers treat the balance as a
    value judgment rather than an engineering problem.
    """
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(2))

    assert voter.handle.transferable

    challenge = b"prove-it:" + secrets.token_bytes(16)
    proof = voter.handle.prove_authorship(challenge)
    published = voter.handle.locate(box)

    assert third_party_is_convinced(published, challenge, proof)


def test_an_anonymous_lookup_index_does_not_remove_provability(election):
    """The negative result: variant A is not variant B with a different index.

    Suppose the voter never uses their ad-hoc key to find their ballot, and
    instead notes down a freely chosen random number as an anonymous tracker.
    They have told nobody about `k_p^a`.

    A coercer is unaffected. They do not ask "what is your tracker?" -- they say
    "sign this nonce", and check the result against the `k_p^a` published in the
    ballot. Provability is a property of the ballot's structure, not of the
    index the voter happens to use for lookup.

    Note also that the coercer chooses the demand. Letting each voter pick their
    own handle therefore protects no one, and would misleadingly present a
    choice as a safeguard.

    Consequence: shifting this system towards receipt-freeness requires that the
    ballot no longer be bound to a signing key the voter retains -- encrypted
    ballots and a trapdoor tracker, per `handles.py`. It cannot be retrofitted
    onto a publish-in-clear design.
    """
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(2))

    anonymous_tracker = secrets.token_bytes(16)   # never leaves the voter
    published = [entry.payload for entry in box.valid.entries][0]

    challenge = b"buyer-nonce:" + secrets.token_bytes(16)
    proof = voter.adhoc.sign(challenge)

    assert anonymous_tracker not in proof
    assert third_party_is_convinced(published, challenge, proof), (
        "the coercer is convinced regardless of how the voter locates the ballot"
    )


def test_a_bystander_cannot_forge_such_a_proof(election):
    """Provability is confined to the ballot's author.

    Without this, the previous test would be uninteresting: a proof anyone can
    produce convinces nobody, and would be useless to a complainant too.
    """
    vro, voters, box = election
    voter, bystander = voters[0], voters[1]
    register(vro, voter)
    box.submit(voter.cast(2))
    register(vro, bystander)

    published = voter.handle.locate(box)
    challenge = b"prove-it:" + secrets.token_bytes(16)

    forged = bystander.handle.prove_authorship(challenge)
    assert not third_party_is_convinced(published, challenge, forged)
