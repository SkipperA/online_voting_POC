import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

import pytest

from driver import PopulationRegister
from ovpoc import keys, rsabssa
from ovpoc.ballotbox import BallotBox
from ovpoc.voter import Voter
from ovpoc.vro import VRO, release_query_payload

TEST_BITS = 2048  # smaller than the 3072-bit default, to keep the suite fast


@pytest.fixture(scope="session")
def vro_keypair():
    return rsabssa.generate_vro_keypair(TEST_BITS)


@pytest.fixture
def election(vro_keypair):
    """A fresh election: three voters, three options.

    Note the two registers, and which party holds each.  The population
    register is external -- it enrols a certificate naming the person and the
    key they sign under.  The electoral register is the VRO's own, and it
    holds ids alone.
    """
    priv, pub = vro_keypair
    population = PopulationRegister()
    vro = VRO(
        private_key=priv,
        public_key=pub,
        population_register=population,
        office_key=keys.SigningKeyPair.generate(),
    )
    fingerprint = rsabssa.public_key_fingerprint(pub)

    voters = []
    for i in range(3):
        wallet = keys.SigningKeyPair.generate()
        voter_id = f"HU-WALLET-{i:03d}"
        population.enrol(voter_id, wallet.public_bytes)   # identity, externally
        vro.enrol(voter_id)                               # eligibility, by the VRO
        voters.append(Voter(voter_id, wallet, pub, fingerprint))

    box = BallotBox(vro_public_key=pub, num_choices=3)
    return vro, voters, box


@pytest.fixture
def population(election):
    """The external population register behind the `election` fixture."""
    vro, _, _ = election
    return vro.population_register


def register(vro, voter):
    """Run steps 1-8 for one voter."""
    response = vro.issue_token(voter.build_auth_request())
    assert response.issued, response.outcome
    voter.accept_token(response.blind_signature)


def query(vro, voter):
    """Run an authenticated step-12 release query on the voter's behalf."""
    return vro.query_token_release(
        voter.voter_id, voter.wallet.sign(release_query_payload(voter.voter_id))
    )

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
    