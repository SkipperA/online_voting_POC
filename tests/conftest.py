import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import pytest

from ovpoc import keys, rsabssa
from ovpoc.ballotbox import BallotBox
from ovpoc.voter import Voter
from ovpoc.vro import VRO

TEST_BITS = 2048  # smaller than the 3072-bit default, to keep the suite fast


@pytest.fixture(scope="session")
def vro_keypair():
    return rsabssa.generate_vro_keypair(TEST_BITS)


@pytest.fixture
def election(vro_keypair):
    """A fresh election: three registered voters, three options."""
    priv, pub = vro_keypair
    vro = VRO(private_key=priv, public_key=pub)
    fingerprint = rsabssa.public_key_fingerprint(pub)

    voters = []
    for i in range(3):
        wallet = keys.SigningKeyPair.generate()
        voter_id = f"HU-WALLET-{i:03d}"
        vro.register_voter(voter_id, wallet.public_bytes)
        voters.append(Voter(voter_id, wallet, pub, fingerprint))

    box = BallotBox(vro_public_key=pub, num_choices=3)
    return vro, voters, box


def register(vro, voter):
    """Run steps 1-8 for one voter."""
    voter.accept_token(vro.issue_token(voter.build_auth_request()))


def query(vro, voter):
    """Run an authenticated step-12 release query on the voter's behalf."""
    from ovpoc.vro import release_query_payload

    return vro.query_token_release(
        voter.voter_id, voter.wallet.sign(release_query_payload(voter.voter_id))
    )
