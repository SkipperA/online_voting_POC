"""The election configuration: Table 1 footnote (a), as a file.

Authored by the setup console (A5, Voting Administrator), served as a static
file by the config origin, and consumed by all four runtime trust domains.
Everything downstream rests on it -- pinning, token verification, range
checking, and now the verification of the office's signed statements.

Two properties are deliberate and easy to lose.

**It is inert.** The config origin computes nothing at request time. What it
serves is bytes written before the poll opened, which is why the digest beside
it means anything.

**It is not signed.** Clause S4: the demo publishes a digest and no signature,
so tampering is demonstrable but not attributable. That is a scope limit, not
a design claim -- see `docs/Demo_Scope_Limits.md`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ovpoc import ledger, rsabssa
from ovpoc.messages import b64

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ElectionConfig:
    election_id: str
    vro_token_key_spki: bytes          # k_p^(R), DER SubjectPublicKeyInfo
    vro_statement_key: bytes           # k_p^(O), raw Ed25519
    num_choices: int
    genesis_hash: bytes
    tally_interval: int | None
    opens: str
    closes: str

    @classmethod
    def build(
        cls,
        election_id: str,
        token_key: rsa.RSAPublicKey,
        statement_key: bytes,
        num_choices: int,
        opens: str,
        closes: str,
        tally_interval: int | None = None,
    ) -> "ElectionConfig":
        return cls(
            election_id=election_id,
            vro_token_key_spki=token_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            vro_statement_key=statement_key,
            num_choices=num_choices,
            genesis_hash=ledger.GENESIS,
            tally_interval=tally_interval,
            opens=opens,
            closes=closes,
        )

    def token_key(self) -> rsa.RSAPublicKey:
        return serialization.load_der_public_key(self.vro_token_key_spki)

    @property
    def token_key_fingerprint(self) -> str:
        """What the voter application pins, and what a human compares.

        Pinned at build time, never fetched from the VRO at startup: an office
        that supplied the key its own signature is checked against would make
        §3.3's defence against per-voter signing keys vacuous.
        """
        return rsabssa.public_key_fingerprint(self.token_key())

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "election_id": self.election_id,
            "vro_token_key_spki": b64(self.vro_token_key_spki),
            "vro_token_key_fingerprint": self.token_key_fingerprint,
            "vro_statement_key": b64(self.vro_statement_key),
            "num_choices": self.num_choices,
            "genesis_hash": self.genesis_hash.hex(),
            "tally_interval": self.tally_interval,
            "opens": self.opens,
            "closes": self.closes,
            "scope_limits": {
                "signature": (
                    "Clause S4: this configuration is published with a digest "
                    "and no signature. Tampering is demonstrable, not "
                    "attributable."
                ),
                "schedule": (
                    "Opening and closing times are recorded, not enforced. The "
                    "close is an act of the EBB (E1), performed by an operator."
                ),
            },
        }

    def to_bytes(self) -> bytes:
        """Stable bytes, because the published digest is over exactly these."""
        return (
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False, sort_keys=False)
            + "\n"
        ).encode("utf-8")

    def digest_hex(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def write(self, document_root: Path) -> Path:
        """Write the artefact and its digest into the config origin's root.

        The setup console does this once, before the poll opens, and then has
        no further role.
        """
        document_root.mkdir(parents=True, exist_ok=True)
        path = document_root / "election.json"
        path.write_bytes(self.to_bytes())
        (document_root / "election.json.sha256").write_text(
            f"{self.digest_hex()}  election.json\n"
        )
        return path
