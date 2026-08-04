"""An append-only, hash-chained log.

Used for both public registries in the design: the ballot box and the VRO's
token-release log (step 12).

Why a hash chain and not just a list.  Publishing ballots is not by itself
enough to make the ballot box trustworthy.  A dishonest box could show ledger
A to one verifier and ledger B to another -- *equivocate* -- or quietly drop a
ballot it had already acknowledged.  Chaining each entry to the hash of the
previous one, and publishing the head periodically, makes both detectable: any
removal or reordering changes every subsequent hash, so a voter who recorded
the head at the moment they voted can prove later that the published ledger no
longer contains their entry.

This does not by itself stop equivocation across *separate* verifiers, which
needs the head to be published somewhere the box does not control (a gossip
protocol, a newspaper, several mutually distrusting mirrors).  The chain is the
mechanism that makes such publication meaningful.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .messages import canonical_bytes

GENESIS = b"\x00" * 32


@dataclass
class Entry:
    index: int
    payload: dict[str, Any]
    prev_hash: bytes
    entry_hash: bytes


def compute_entry_hash(index: int, payload: dict[str, Any], prev_hash: bytes) -> bytes:
    return hashlib.sha256(
        index.to_bytes(8, "big") + prev_hash + canonical_bytes(payload)
    ).digest()


@dataclass
class Ledger:
    entries: list[Entry] = field(default_factory=list)

    def append(self, payload: dict[str, Any]) -> Entry:
        index = len(self.entries)
        prev_hash = self.entries[-1].entry_hash if self.entries else GENESIS
        entry = Entry(
            index=index,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=compute_entry_hash(index, payload, prev_hash),
        )
        self.entries.append(entry)
        return entry

    def head(self) -> bytes:
        """The current chain head -- the value to publish and for voters to record."""
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def verify_chain(self) -> bool:
        """Recompute the whole chain.  Any tampering shows up here."""
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            if entry.index != i or entry.prev_hash != prev:
                return False
            if entry.entry_hash != compute_entry_hash(i, entry.payload, prev):
                return False
            prev = entry.entry_hash
        return True

    def __len__(self) -> int:
        return len(self.entries)
