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

from conftest import query, register
from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot
from ovpoc.vro import RegistrationError, release_query_payload, verify_release_answer


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


def test_a_substituted_vro_key_is_refused_by_the_voter_app(election):
    """The voter app must enforce the pinned VRO fingerprint.

    This is the defence Section 3.2 of the paper rests on. A VRO free to use a
    different signing key per voter gains nothing from blinding: it can later
    determine which of its keys verifies a given ballot in the public box and
    re-link that ballot to the identified requester. Blinding hides the ad-hoc
    key from the signer; it does not constrain which key the signer uses. Only
    the client-side pinning check does that, so it must be exercised.
    """
    _, voters, _ = election
    voter = voters[0]

    # The VRO presents a second, unpublished key pair to this voter alone.
    _, singling_out_key = rsabssa.generate_vro_keypair(2048)
    voter.vro_public_key = singling_out_key

    with pytest.raises(ValueError, match="pinned fingerprint"):
        voter.build_auth_request()


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
# Step 12 -- the release log and the authenticated check
# --------------------------------------------------------------------------

def test_the_release_log_records_exactly_who_took_a_token(election):
    """The log is accurate and specific: one entry per token, no others.

    This is a building block for step 12, not a detection result. It shows the
    log says 'yes' for a voter who took a token and 'no' for one who did not.
    Whether a *dishonest VRO* can be caught minting tokens is a separate
    question, addressed only partially and only in aggregate -- see
    test_the_aggregate_audit_bounds_ballots_by_tokens and docs/threats.md.
    """
    vro, voters, _ = election
    took, abstained = voters[0], voters[1]

    assert vro.release_count() == 0
    register(vro, took)
    assert vro.release_count() == 1

    assert query(vro, took).released
    assert not query(vro, abstained).released


def test_the_release_log_publishes_no_voter_identities(election):
    """Published entries are commitments; the ids do not appear.

    A plaintext log would be a public register of who registered. Absence of an
    entry is proof of non-voting, which is what a coercer demanding turnout
    needs, so the log must not be enumerable by third parties.
    """
    vro, voters, _ = election
    for voter in voters:
        register(vro, voter)

    for entry in vro.release_log.entries:
        assert set(entry.payload) == {"commitment"}
        for voter in voters:
            assert voter.voter_id not in entry.payload["commitment"]


def test_an_unauthenticated_release_query_is_refused(election):
    """Step 12 requires sig(id). Without it the log becomes public."""
    vro, voters, _ = election
    victim, snoop = voters[0], voters[1]
    register(vro, victim)

    # The snoop knows the victim's id but holds only their own wallet key.
    forged = snoop.wallet.sign(release_query_payload(victim.voter_id))
    with pytest.raises(RegistrationError, match="not signed by the wallet"):
        vro.query_token_release(victim.voter_id, forged)


def test_a_voter_can_verify_the_answer_against_the_published_log(election):
    """The affirmative answer rests on the public log, not on the VRO's word."""
    vro, voters, _ = election
    voter = voters[0]
    register(vro, voter)

    answer = query(vro, voter)
    published = [e.payload for e in vro.release_log.entries]
    assert verify_release_answer(published, voter.voter_id, answer)

    # The same nonce does not open the commitment for a different id.
    assert not verify_release_answer(published, voters[1].voter_id, answer)


def test_the_aggregate_audit_bounds_ballots_by_tokens(election):
    """What a third party *can* check without learning who anyone is.

    Distinct ad-hoc keys in the ballot box must not exceed released tokens. A
    VRO minting tokens without logging them is caught here; one that logs a
    release for a citizen who never voted is not, since that is
    indistinguishable from a citizen who took a token and abstained.
    """
    vro, voters, box = election
    for voter in voters:
        register(vro, voter)
        box.submit(voter.cast(1))

    distinct_keys = len(box.effective_ballots())
    assert distinct_keys <= vro.release_count()
