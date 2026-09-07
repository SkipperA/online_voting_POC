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
from ovpoc.ballotbox import BOX_CLOSED
from ovpoc.messages import Ballot
from ovpoc.vro import (
    FaultDetected,
    Outcome,
    ReleaseOutcome,
    denial_payload,
    release_query_payload,
    verify_denial,
    verify_release_answer,
)


# --------------------------------------------------------------------------
# Eligibility
# --------------------------------------------------------------------------

def test_an_unknown_id_is_not_identified(election):
    """An id the population register has never heard of gets one opaque answer.

    Not "no such person" and not "not eligible": either would answer a
    question about a citizen the requester has not proved to be.
    """
    vro, voters, _ = election
    outsider = voters[0]
    outsider.voter_id = "HU-WALLET-999"

    response = vro.issue_token(outsider.build_auth_request())
    assert response.outcome is Outcome.NOT_IDENTIFIED
    assert response.blind_signature is None
    assert vro.audit_log[-1].reason == "no entry for this id in the population register"


def test_an_identified_person_not_on_the_electoral_register_is_told_so(election):
    """Past the identity boundary, the office may give the real reason.

    This citizen holds a valid certificate and signs correctly, so the office
    knows who it is talking to; refusing without explanation would be
    unhelpful rather than private.
    """
    vro, voters, _ = election
    population = vro.population_register
    wallet = keys.SigningKeyPair.generate()
    population.enrol("HU-WALLET-404", wallet.public_bytes)   # identity, yes
    # ... but no vro.enrol: not on the electoral register

    outsider = voters[0]
    outsider.voter_id = "HU-WALLET-404"
    outsider.wallet = wallet

    response = vro.issue_token(outsider.build_auth_request())
    assert response.outcome is Outcome.NOT_ELIGIBLE
    assert vro.audit_log[-1].reason == "not on the electoral register"


def test_eligibility_is_never_revealed_before_identity(election):
    """The token endpoint cannot be used to probe the electoral roll.

    An unsigned request naming an *enrolled and eligible* voter and one
    naming a person who is neither must be indistinguishable to the
    requester. This is the whole content of the identity boundary, and the
    mutation `eligibility_checked_before_identity` in tools/sabotage.py is
    what confirms the test constrains it.
    """
    vro, voters, _ = election
    population = vro.population_register
    stranger_wallet = keys.SigningKeyPair.generate()
    population.enrol("HU-WALLET-777", stranger_wallet.public_bytes)

    snoop = voters[0]
    probes = []
    for target in (voters[1].voter_id, "HU-WALLET-777", "HU-WALLET-000000"):
        request = snoop.build_auth_request()
        request.voter_id = target                    # claim it, cannot sign it
        probes.append(vro.issue_token(request).outcome)

    assert probes == [Outcome.NOT_IDENTIFIED] * 3


def test_a_revoked_certificate_is_reported_only_after_the_signature(election):
    """Revocation sits below the identity boundary, deliberately.

    A revoked certificate still verifies mathematically -- the key is
    unchanged -- so by the time the office can see revocation it has already
    established who it is speaking to and may as well say so. The article's
    §3.2 enumerates certificate validity first; that order is expository, and
    this one is the privacy-preserving one.
    """
    vro, voters, _ = election
    voter = voters[0]
    vro.population_register.revoke(voter.voter_id)

    response = vro.issue_token(voter.build_auth_request())
    assert response.outcome is Outcome.CERTIFICATE_REVOKED

    # A *bad* signature under the same revoked certificate is still opaque:
    # the office must not confirm revocation to someone it cannot identify.
    request = voters[1].build_auth_request()
    request.voter_id = voter.voter_id
    assert vro.issue_token(request).outcome is Outcome.NOT_IDENTIFIED


def test_an_expired_certificate_is_refused(election):
    vro, voters, _ = election
    voter = voters[0]
    vro.population_register.expire(voter.voter_id)

    response = vro.issue_token(voter.build_auth_request())
    assert response.outcome is Outcome.CERTIFICATE_EXPIRED


def test_the_audit_log_records_the_true_reason_in_every_case(election):
    """What the requester is not told, the office still writes down.

    The two pre-boundary situations are distinguishable in the log and
    indistinguishable on the wire.
    """
    vro, voters, _ = election
    voter = voters[0]

    missing = voters[1]
    missing.voter_id = "HU-WALLET-888"
    vro.issue_token(missing.build_auth_request())

    bad_signature = voters[2].build_auth_request()
    bad_signature.voter_id = voter.voter_id
    vro.issue_token(bad_signature)

    outcomes = [e.outcome for e in vro.audit_log]
    reasons = [e.reason for e in vro.audit_log]
    assert outcomes == [Outcome.NOT_IDENTIFIED, Outcome.NOT_IDENTIFIED]
    assert reasons == [
        "no entry for this id in the population register",
        "request signature does not verify under the certified key",
    ]


def test_impersonation_fails_without_the_wallet_key(election):
    """Knowing someone's id is not enough; the wallet signature must match."""
    vro, voters, _ = election
    attacker, victim = voters[0], voters[1]

    request = attacker.build_auth_request()
    request.voter_id = victim.voter_id  # claim the victim's identity
    # attacker re-signs with their own wallet -- the only key they have
    request.wallet_signature = attacker.wallet.sign(request.signed_payload())

    response = vro.issue_token(request)
    assert response.outcome is Outcome.NOT_IDENTIFIED
    assert response.blind_signature is None
    assert vro.audit_log[-1].reason == (
        "request signature does not verify under the certified key"
    )


def test_forged_token_is_rejected_by_the_ballot_box(election):
    """A self-minted token cannot pass verification against the VRO key."""
    _, voters, box = election
    voter = voters[0]
    voter.adhoc = keys.generate_adhoc_keypair()
    voter.token = secrets.token_bytes(256)  # invented from nothing

    result = box.submit(voter.cast(1))
    assert not result.accepted
    assert result.reason == "token not signed by VRO"
    assert len(box.accepted) == 0 and len(box.rejected) == 1


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

    response = vro.issue_token(voter.build_auth_request())
    assert response.outcome is Outcome.TOKEN_ALREADY_ISSUED
    assert response.blind_signature is None


def test_revoting_yields_one_counted_ballot(election):
    """Many submissions, one effective vote -- the last one."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)

    for selection in (1, 3, 2):
        box.submit(voter.cast(selection))

    box.close()
    assert len(box.accepted) == 3                      # full history retained
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

    stolen_token = box.accepted.entries[0].payload["token"]
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
    assert result.accepted                       # passed both crypto checks
    box.close()
    tally = box.tally()
    assert tally["valid"] == 0                   # accepted, but not a valid vote
    assert tally["invalid"] == 1
    assert tally["counts"] == {1: 0, 2: 0, 3: 0}


def test_distinct_protest_codes_are_not_merged(election):
    """Two out-of-range selections must stay distinguishable in the tally.

    A single scalar 'invalid' count would make an organised bloc voting
    under one ad-hoc code indistinguishable from an unrelated bloc using a
    different one -- exactly the distinction paper ballots cannot offer.
    """
    vro, voters, box = election
    left, right, other = voters[0], voters[1], voters[2]
    for voter in (left, right, other):
        register(vro, voter)

    box.submit(left.cast(-1))
    box.submit(right.cast(-2))
    box.submit(other.cast(-1))

    box.close()
    tally = box.tally()
    assert tally["invalid"] == 3
    assert tally["protest_codes"] == {-1: 2, -2: 1}


def test_a_rejected_ballot_does_not_supersede_a_genuine_one(election):
    """A coercer's malformed submission must not erase an earlier real vote."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(2))

    garbage = voter.cast(3)
    garbage.vote_signature = secrets.token_bytes(64)
    box.submit(garbage)

    box.close()
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

    assert box.accepted.verify_chain()
    del box.accepted.entries[1]
    assert not box.accepted.verify_chain()


def test_altering_a_recorded_ballot_breaks_the_hash_chain(election):
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(1))

    assert box.accepted.verify_chain()
    box.accepted.entries[0].payload["selection"] = 3
    assert not box.accepted.verify_chain()


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
    answer = vro.query_token_release(victim.voter_id, forged)
    assert answer.outcome is ReleaseOutcome.NOT_IDENTIFIED
    assert not answer.released
    assert answer.nonce is None

    # An id with no certificate at all is answered identically, so this
    # endpoint cannot be used to probe either register.
    unknown = vro.query_token_release(
        "HU-WALLET-555", snoop.wallet.sign(release_query_payload("HU-WALLET-555"))
    )
    assert unknown.outcome is ReleaseOutcome.NOT_IDENTIFIED


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


# --------------------------------------------------------------------------
# The token key is an oracle -- it must sign nothing else
# --------------------------------------------------------------------------

def test_any_voter_can_forge_an_office_statement_under_the_token_key(election):
    """Why office statements need a key of their own (§3.3).

    A blind signer applies its private key to values it cannot inspect, and
    no structural check can protect it: the blinded value is uniformly
    distributed and carries no recognisable structure. So an ordinary token
    request *is* a signing oracle. Any registered voter can drive it over a
    message of their choosing -- here, the office's own denial statement
    about a different citizen -- and obtain a signature that verifies under
    k_p^(R) with a standard library.

    This test forges the artefact. The next one shows the office does not
    rely on that key for its statements, which is what makes the forgery
    worthless.
    """
    vro, voters, _ = election
    attacker, victim = voters[0], voters[1]

    # The message the attacker wants signed, standing in for any statement
    # the office might otherwise make under its token key.
    target = denial_payload(victim.voter_id)

    blinded, state = rsabssa.blind(vro.public_key, target)
    request = attacker.build_auth_request()
    request.blinded_key = blinded                      # substitute the payload
    request.wallet_signature = attacker.wallet.sign(request.signed_payload())

    response = vro.issue_token(request)
    assert response.issued                             # an ordinary request

    forged = rsabssa.finalize(
        vro.public_key, target, response.blind_signature, state
    )
    assert rsabssa.verify(vro.public_key, target, forged)


def test_release_denials_are_signed_under_a_separate_office_key(election):
    """So the forgery above buys nothing.

    The denial verifies under the published office statement key and not
    under the token key, and the two keys are distinct.
    """
    vro, voters, _ = election
    abstainer = voters[0]

    answer = query(vro, abstainer)
    assert answer.outcome is ReleaseOutcome.NOT_RELEASED
    assert answer.signed_denial is not None

    assert verify_denial(
        vro.office_public_key, abstainer.voter_id, answer.signed_denial
    )
    # Not the token key, and not transferable to another citizen's statement.
    assert not rsabssa.verify(
        vro.public_key, denial_payload(abstainer.voter_id), answer.signed_denial
    )
    assert not verify_denial(
        vro.office_public_key, voters[1].voter_id, answer.signed_denial
    )


# --------------------------------------------------------------------------
# The office checks its own arithmetic
# --------------------------------------------------------------------------

def test_a_faulty_blind_signature_is_not_released(election, monkeypatch):
    """s_c^e == c, before s_c leaves the building.

    An error during a CRT exponentiation yields a value from which the
    modulus can be factored (Boneh-DeMillo-Lipton), so an unchecked
    signature is a liability to the office rather than to the voter. The
    fault is simulated by corrupting the returned value.
    """
    vro, voters, _ = election
    voter = voters[0]

    genuine = rsabssa.blind_sign

    def faulty(private_key, blinded_msg):
        good = bytearray(genuine(private_key, blinded_msg))
        good[-1] ^= 0x01
        return bytes(good)

    monkeypatch.setattr(rsabssa, "blind_sign", faulty)

    with pytest.raises(FaultDetected):
        vro.issue_token(voter.build_auth_request())


# --------------------------------------------------------------------------
# Publication schedule -- what is visible, and when
# --------------------------------------------------------------------------

def test_no_record_is_published_while_voting_is_open(election):
    """The commitments are published; the selections are not.

    Publishing selections as they arrive would broadcast a running result,
    and -- because a later ballot supersedes an earlier one -- would tell an
    observer that somebody reversed a choice, which in a small enough
    population approaches identification.
    """
    vro, voters, box = election
    for voter in voters:
        register(vro, voter)
        box.submit(voter.cast(2))

    view = box.published_view()
    assert view["phase"] == "open"
    assert "records" not in view
    assert view["counts"] == {"accepted": 3, "rejected": 0}
    assert len(view["commitments"]["accepted"]) == 3
    assert view["heads"]["accepted"] == box.accepted.head().hex()

    # Nothing in the open view discloses a selection or an ad-hoc key.
    assert "selection" not in repr(view)
    assert "adhoc_public_key" not in repr(view)

    box.close()
    closed = box.published_view()
    assert closed["phase"] == "closed"
    assert len(closed["records"]["accepted"]) == 3
    # No row moves backwards: what was published stays published.
    assert closed["commitments"] == view["commitments"]


def test_the_voter_can_still_find_their_own_ballot_while_the_box_is_shut_to_others(
    election,
):
    """k_p^a is a lookup secret as well as a locating handle.

    Before the close it is known to the voter's application and to the box
    and to nobody else, so presenting it is sufficient authentication for
    retrieval -- which is what keeps the voter's own checks available
    throughout the poll while the contents stay closed.
    """
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(3))

    assert box.published_view().get("records") is None
    assert voter.verify_recorded_ballot(box, 3)          # still available
    assert box.find_ballot(keys.generate_adhoc_keypair().public_bytes) is None


def test_a_running_tally_is_published_only_when_configured(election, vro_keypair):
    """The publication interval is the legislator's dial (§3.5).

    Left unset, no tally exists for anybody -- the operator gets no
    privileged early sight of the result. Set to a count, snapshots appear as
    the poll runs, which is the alternative setting the article describes.
    """
    from ovpoc.ballotbox import BallotBox, BoxStillOpen

    vro, voters, box = election
    assert box.tally_interval is None
    register(vro, voters[0])
    box.submit(voters[0].cast(1))

    with pytest.raises(BoxStillOpen):
        box.tally()
    assert box.published_view()["running_tally"] == []

    _, pub = vro_keypair
    running = BallotBox(vro_public_key=pub, num_choices=3, tally_interval=2)
    for voter in voters:
        if voter.token is None:
            register(vro, voter)
        running.submit(voter.cast(1))

    snapshots = running.published_view()["running_tally"]
    assert [s["after_accepted"] for s in snapshots] == [2]
    assert snapshots[0]["counts"] == {1: 2, 2: 0, 3: 0}
    assert running.tally()["voters"] == 3        # callable while open, as configured


def test_a_ballot_arriving_after_the_close_is_not_recorded(election):
    """A submission after the close is not a rejected ballot; it is not a ballot."""
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    box.submit(voter.cast(1))
    box.close()

    before = (len(box.accepted), len(box.rejected))
    result = box.submit(voter.cast(3))

    assert not result.accepted
    assert result.reason == BOX_CLOSED
    assert (len(box.accepted), len(box.rejected)) == before
    assert box.tally()["counts"] == {1: 1, 2: 0, 3: 0}

def test_the_inclusion_check_works_from_the_receipt_alone(election):
    vro, voters, box = election
    voter = voters[0]
    register(vro, voter)
    ballot = voter.cast(2)
    receipt = box.submit(ballot)

    # Everything below uses the receipt, the record the voter holds, and the
    # published view -- no method on the box, and no query it could answer
    # falsely, since it is the component under audit.
    announced = box.published_view()["commitments"]["accepted"][receipt.index]
    assert announced["index"] == receipt.index
    assert announced["commitment"] == receipt.ledger_head.hex()
    