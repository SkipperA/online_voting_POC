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

**The store is committed, key material and all.** Every wallet seed in it is
in the clear, because one machine has to play a whole electorate and the
substitution should be visible rather than hinted at. A reader can open the
file and see exactly what the demo holds on each voter's behalf, which is
worth more here than the habit of hiding keys -- the voters are fictional,
the election is a demonstration, and `tests/vectors/keys.json` already
publishes a private key on the same reasoning. What must not happen is anyone
mistaking this for a deployment artefact, so the file says so about itself.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ovpoc import keys, rsabssa
from ovpoc.messages import b64, unb64

STORE_VERSION = 2

# Version 1 is still readable, and deliberately so. The only difference is
# one optional key, `tally_interval_seconds`, whose absence means exactly
# what the version-1 behaviour was: no publication interval, so the close is
# the only publication point. Refusing an election because its file predates
# a field that defaults to the old behaviour would lose the token key, the
# register and every persona for nothing. The next save writes version 2.
READABLE_STORE_VERSIONS = {1, 2}


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


def write(path: Path, *, token_private, statement_key, box_statement_key,
          register, personas,
          election_id: str, num_choices: int,
          tally_interval_seconds: int | None = None,
          supervisors: tuple[str, ...] = ()) -> None:
    """Write the durable half. Called by the setup console, never at runtime."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "README.md").write_text(
        "# election-data\n\n"
        "The durable half of a demonstration election, written by the setup\n"
        "console (`python -m service --init`) and reloaded at every start.\n\n"
        "**Committed on purpose, key material included.** `election.store.json`\n"
        "carries every wallet seed in the clear and `vro_token_key.pem` is the\n"
        "office's token signing key. Publishing them is the point: the demo\n"
        "substitutes a file for an eIDAS wallet and a directory for an HSM, and\n"
        "a reader should be able to see exactly what that substitution costs\n"
        "rather than take it on trust. The voters are fictional and this\n"
        "election is not one.\n\n"
        "What is **not** here is everything the poll produced: the ballot box,\n"
        "the hash chain and the released-token register are in memory and are\n"
        "lost when the process stops. A real ballot box does not forget its\n"
        "contents; this one does.\n",
        encoding="utf-8",
    )
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
                "warning": (
                    "DEMONSTRATION KEY MATERIAL, PUBLISHED DELIBERATELY. Every "
                    "wallet seed below is in the clear so that a reader can see "
                    "what this demo holds on each voter's behalf. The voters are "
                    "fictional and this election is not one. A deployment keeps "
                    "k_s^(v) in hardware it never leaves, and keeps k_s^(R) "
                    "nowhere a file can reach."
                ),
                "election_id": election_id,
                "num_choices": num_choices,
                "tally_interval_seconds": tally_interval_seconds,
                "supervisors": list(supervisors),
                "vro_statement_seed": b64(seed_of(statement_key)),
                "ebb_statement_seed": b64(seed_of(box_statement_key)),
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
    body.pop("warning", None)   # prose for the reader, not a field
    if body.get("store_version") not in READABLE_STORE_VERSIONS:
        raise NoElection(
            f"{store.name} declares store_version {body.get('store_version')!r}, "
            f"which this service does not understand (expected one of "
            f"{sorted(READABLE_STORE_VERSIONS)})."
        )
    private = serialization.load_pem_private_key(pem.read_bytes(), password=None)
    return {
        "election_id": body["election_id"],
        "num_choices": body["num_choices"],
        "tally_interval_seconds": body.get("tally_interval_seconds"),
        "supervisors": tuple(body.get("supervisors", ())),
        "token_private": private,
        "token_public": private.public_key(),
        "statement_key": pair_from(unb64(body["vro_statement_seed"])),
        "box_statement_key": pair_from(unb64(body["ebb_statement_seed"]))
        if "ebb_statement_seed" in body else None,
        "electoral_register": set(body["electoral_register"]),
        "wallet_personas": {
            v: pair_from(unb64(s)) for v, s in body["wallet_seeds"].items()
        },
    }
