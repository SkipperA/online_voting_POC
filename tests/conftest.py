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

#: Variables that change what a `Deployment` *does* rather than where it
#: listens. The suite must mean the same thing on every machine, and an
#: operator's shell is a machine.
POLICY_ENVIRONMENT = ("OVPOC_OPEN_ENROLMENT",)


@pytest.fixture(autouse=True)
def _no_policy_from_the_environment(monkeypatch):
    """Clause S7 is a deployment's choice and never the suite's.

    `Deployment.create` reads `OVPOC_OPEN_ENROLMENT`, so an operator who
    exported it in order to run their own server, and then ran the tests
    in the same shell, got an office that enrolled its own citizens --
    and `test_a_real_signature_reaches_the_office_through_the_endpoint`
    sailed past the eligibility check it exists to stop at.

    Twice now, the same fault by two doors: the first was
    `election-data/trust-anchors`, read from a module-level path, which
    made the suite behave differently in a clone that happened to carry
    pinned anchors. The lesson each time is the one in CLAUDE.md -- the
    suite depends on what `pyproject.toml` declares and on nothing else
    -- so this is cleared at the root rather than passed at thirty call
    sites, and it covers the next variable as well as this one.

    A test that wants a policy sets it: explicitly on the call, which is
    what `open_enrolment=` is for, or with its own `monkeypatch.setenv`,
    which runs after this.
    """
    for name in POLICY_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


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
    box.open()          # an election is a poll that is running
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

