"""The adversarial suite: attacks that must be rejected.

This file is the argument.  A proof of concept that only walks the happy path
demonstrates very little; one that names each attack and shows it failing is
evidence.  Every test here corresponds to a threat named in the paper.

Attacks that are *not* covered, and are not covered by the design either, are
listed in docs/threats.md so their absence is deliberate rather than an
oversight.
"""

import secrets

import pytest

from conftest import register
from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot
from ovpoc.vro import RegistrationError


# --------------------------------------------------------------------------
# Eligibility
# --------------------------------------------------------------------------

def test_unregistered_voter_gets_no_token(election):
    """A citizen not on the register cannot obtain a token."""
    vro, voters, _ = election
    outsider = voters[0]
    outsider.voter_id = "HU-WALLET-999"

    with pytest.raises(RegistrationError, match="not valid or not eligible"):
        vro.issue_token(outsider.build_auth_request())


def test_impersonation_fails_without_the_wallet_key(election):
    """Knowing someone's id is not enough; the wallet signature must match."""
    vro, voters, _ = election
    attacker, victim = voters[0], voters[1]

    request = attacker.build_auth_request()
    request.voter_id = victim.voter_id  # claim the victim's identity
    # attacker re-signs with their own wallet -- the only key they have
    request.wallet_signature = attacker.wallet.sign(request.signed_payload())

    with pytest.raises(RegistrationError, match="not from the wallet"):
        vro.issue_token(request)


def test_forged_token_is_rejected_by_the_ballot_box(election):
    """A self-minted token cannot pass verification against the VRO key."""
    _, voters, box = election
    voter = voters[0]
    voter.adhoc = keys.generate_adhoc_keypair()
    voter.token = secrets.token_bytes(256)  # invented from nothing

    result = box.submit(voter.cast(1))
    assert not result.accepted
    assert result.reason == "token not signed by VRO"
    assert len(box.valid) == 0 and len(box.rejected) == 1


# --------------------------------------------------------------------------
# Equality -- one vote per voter
# --------------------------------------------------------------------------

def test_a_second_token_request_is_refused(election):
    """Step 7: the release is recorded, so the same id cannot draw twice."""
    vro, voters, _ = election
    voter = voters[0]
    register(vro, voter)

    with pytest.raises(RegistrationError, match="already been released"):
        vro.issue_token(voter.build_auth_request())


def test_revoting_yields_one_counted_ballot(election):
    """Many submissions, one effective vote -- the last one."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)

    for selection in (1, 3, 2):
        box.submit(voter.cast(selection))

    assert len(box.valid) == 3                      # full history retained
    assert box.tally()["voters"] == 1               # one voter
    assert box.tally()["counts"] == {1: 0, 2: 1, 3: 0}


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------

def test_tampering_with_the_selection_breaks_the_signature(election):
    """A network attacker or malicious relay cannot change a vote silently."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)

    ballot = voter.cast(1)
    ballot.selection = 2  # tamper in flight, leaving s_vote untouched

    result = box.submit(ballot)
    assert not result.accepted
    assert result.reason == "vote signature invalid"


def test_a_valid_token_cannot_be_reused_with_a_different_key(election):
    """Stealing a published token buys nothing without k_s^a.

    The token is a signature over k_p^a specifically, so it cannot be lifted
    from a public ballot and attached to a fresh key.
    """
    vro, voters, box = election
    honest, thief = voters[0], voters[1]
    register(vro, honest)
    box.submit(honest.cast(1))

    stolen_token = box.valid.entries[0].payload["token"]
    from ovpoc.messages import unb64

    thief.adhoc = keys.generate_adhoc_keypair()
    thief.token = unb64(stolen_token)

    result = box.submit(thief.cast(3))
    assert not result.accepted
    assert result.reason == "token not signed by VRO"


def test_multiplicative_forgery_is_defeated_by_pss_encoding(vro_keypair):
    """The classic attack on raw RSA blind signatures.

    Raw RSA is multiplicative: sig(m1) * sig(m2) == sig(m1 * m2).  A voter with
    two legitimate tokens could therefore forge a third.  PSS encoding destroys
    the structure, because m1 * m2 mod n is not a well-formed PSS encoding of
    anything.  This test is why the implementation does not sign k_p^a directly.
    """
    priv, pub = vro_keypair
    n = pub.public_numbers().n

    m1, m2 = secrets.token_bytes(32), secrets.token_bytes(32)
    b1, s1 = rsabssa.blind(pub, m1)
    b2, s2 = rsabssa.blind(pub, m2)
    sig1 = rsabssa.finalize(pub, m1, rsabssa.blind_sign(priv, b1), s1)
    sig2 = rsabssa.finalize(pub, m2, rsabssa.blind_sign(priv, b2), s2)

    product = (int.from_bytes(sig1, "big") * int.from_bytes(sig2, "big")) % n
    forged = product.to_bytes((n.bit_length() + 7) // 8, "big")

    # The forged signature is a valid *raw* RSA signature, but verifies against
    # no message we can construct.
    for candidate in (m1, m2, m1 + m2, bytes(a ^ b for a, b in zip(m1, m2))):
        assert not rsabssa.verify(pub, candidate, forged)


# --------------------------------------------------------------------------
# Invalid votes -- the distinction the paper insists on
# --------------------------------------------------------------------------

def test_a_protest_ballot_is_counted_as_invalid_not_rejected(election):
    """An out-of-range selection, properly signed, is a political statement."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)

    result = box.submit(voter.cast(99))
    assert result.accepted                       # cryptographically valid
    tally = box.tally()
    assert tally["invalid"] == 1
    assert tally["counts"] == {1: 0, 2: 0, 3: 0}


def test_a_rejected_ballot_does_not_supersede_a_genuine_one(election):
    """A coercer's malformed submission must not erase an earlier real vote."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(2))

    garbage = voter.cast(3)
    garbage.vote_signature = secrets.token_bytes(64)
    box.submit(garbage)

    assert box.tally()["counts"] == {1: 0, 2: 1, 3: 0}  # the genuine vote survives


# --------------------------------------------------------------------------
# Ledger integrity
# --------------------------------------------------------------------------

def test_deleting_a_ballot_breaks_the_hash_chain(election):
    """The ballot box cannot quietly drop a ballot it acknowledged."""
    vro, voters, box = election
    for voter in voters:
        register(vro, voter)
        box.submit(voter.cast(1))

    assert box.valid.verify_chain()
    del box.valid.entries[1]
    assert not box.valid.verify_chain()


def test_altering_a_recorded_ballot_breaks_the_hash_chain(election):
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(1))

    assert box.valid.verify_chain()
    box.valid.entries[0].payload["selection"] = 3
    assert not box.valid.verify_chain()


# --------------------------------------------------------------------------
# Step 12 -- the independent check
# --------------------------------------------------------------------------

def test_a_token_minted_without_the_voter_is_detectable(election):
    """The stolen-identity attack, and the check that catches it.

    A voter who never registered asks the public release log whether a token
    exists in their name.  A 'yes' is proof that something happened without
    them.  This works only because the log is public.
    """
    vro, voters, _ = election
    victim, other = voters[0], voters[1]

    assert not vro.token_released(victim.voter_id)
    register(vro, victim)                       # stands in for the attacker's request
    assert vro.token_released(victim.voter_id)
    assert not vro.token_released(other.voter_id)
