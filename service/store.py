"""What survives a restart, and what does not.

The split is not arbitrary.  The durable half is everything the setup console
authors *before* the poll opens -- Phase A of the action table: the two key
pairs, the electoral register, the wallet personas, and the configuration
derived from them.  The volatile half is everything the poll itself produces:
the ballot box, the hash chain, the released-token register.

So restarting mid-demonstration loses the votes and keeps the election, which
is the right way round.  The alternative -- minting a fresh key at every
startup, as this service did until now -- silently voids every open page,
every saved token request and every token already issued, and makes the
pinning story on the voter's page aspirational rather than true: a
fingerprint that changes whenever the process restarts is not something
anybody could have pinned.

**The volatile half is a scope limit, not a design claim.** A real ballot box
does not lose its contents when its process stops. Clause: the demo's box and
release register are in memory.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ovpoc import keys, rsabssa
from ovpoc.messages import b64, unb64

STORE_VERSION = 1


class NoElection(RuntimeError):
    """Raised when the runtime is asked to serve an election nobody created.

    Deliberately fatal rather than falling back to minting one. An election
    that appears because a process started is not an election.
    """


def seed_of(pair: keys.SigningKeyPair) -> bytes:
    return pair.private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def pair_from(seed: bytes) -> keys.SigningKeyPair:
    return keys.SigningKeyPair(ed25519.Ed25519PrivateKey.from_private_bytes(seed))


def write(path: Path, *, token_private, statement_key, register, personas,
          election_id: str, num_choices: int) -> None:
    """Write the durable half. Called by the setup console, never at runtime."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "vro_token_key.pem").write_bytes(
        token_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (path / "election.store.json").write_text(
        json.dumps(
            {
                "store_version": STORE_VERSION,
                "election_id": election_id,
                "num_choices": num_choices,
                "vro_statement_seed": b64(seed_of(statement_key)),
                "electoral_register": sorted(register),
                # Wallet personas. A real wallet's key is in hardware and is
                # never written anywhere, least of all beside the election.
                # This file is the substitution, and it is why the store must
                # never be mistaken for a deployment artefact.
                "wallet_seeds": {v: b64(seed_of(p)) for v, p in sorted(personas.items())},
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def read(path: Path) -> dict:
    store = path / "election.store.json"
    pem = path / "vro_token_key.pem"
    if not store.exists() or not pem.exists():
        raise NoElection(
            f"no election at {path}. Create one with `python -m service --init`, "
            f"or point --data at an existing one. The runtime does not mint "
            f"keys: an election that appears because a process started is not "
            f"an election."
        )
    body = json.loads(store.read_text(encoding="utf-8"))
    if body.get("store_version") != STORE_VERSION:
        raise NoElection(
            f"{store.name} declares store_version {body.get('store_version')!r}, "
            f"which this service does not understand (expected {STORE_VERSION})."
        )
    private = serialization.load_pem_private_key(pem.read_bytes(), password=None)
    return {
        "election_id": body["election_id"],
        "num_choices": body["num_choices"],
        "token_private": private,
        "token_public": private.public_key(),
        "statement_key": pair_from(unb64(body["vro_statement_seed"])),
        "electoral_register": set(body["electoral_register"]),
        "wallet_personas": {
            v: pair_from(unb64(s)) for v, s in body["wallet_seeds"].items()
        },
    }
