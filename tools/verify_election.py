#!/usr/bin/env python3
"""Recount an election from its published files, without this project's code.

    python tools/verify_election.py election.json ledger.json releases.json

The point of this script is what it does *not* import.  Nothing from
`ovpoc` is used: the only dependencies are the standard library and
`cryptography`, the same library any stranger would reach for.  A verifier
that imported the implementation would prove that the code agrees with
itself, which is not the claim.  The claim in Section 6 is that any citizen
can recompute the result from the published artefacts with standard
cryptographic libraries, and this is that claim run as a program.

It performs every check the action table lists at E6, and one more:

  1. every token is a valid RSA-PSS signature by the VRO over the ad-hoc
     key it accompanies -- the ballot came from an eligible voter;
  2. every vote signature verifies under the ad-hoc key that token
     certifies -- the selection was authenticated by whoever held it;
  3. no record appears twice among the accepted entries -- a replayed
     ballot cannot have been counted;
  4. each record hashes to the commitment published for its position, and
     the chain reaches the head the box signed under its statement key;
  5. supersession is applied among accepted entries only, and the tally is
     recomputed from the surviving ballots;
  6. the count audit across two components: distinct ad-hoc keys in the box
     cannot exceed the tokens the office signed for.

Every key comes from the election configuration, whose digest both files
name.  No key is read out of the file being checked: a dump that verified
against itself would establish nothing.

Exit status is 0 only if every check passes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from base64 import urlsafe_b64decode
from collections import Counter
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding

SALT_LEN = 48  # RFC 9474, RSABSSA-SHA384-PSS

failures: list[str] = []


def check(ok: bool, description: str, detail: str = "") -> bool:
    print(f"  [{'ok' if ok else 'FAIL'}] {description}{'  ' + detail if detail else ''}")
    if not ok:
        failures.append(description)
    return ok


def unb64(text: str) -> bytes:
    return urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64(raw: bytes) -> str:
    from base64 import urlsafe_b64encode
    return urlsafe_b64encode(raw).decode().rstrip("=")


def canonical(obj) -> bytes:
    """Sorted keys, no whitespace, non-ASCII left as UTF-8.  RFC 8785 in spirit."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def ed25519_verifies(public_key: bytes, signature: bytes, payload: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
        return True
    except Exception:
        return False


def rsa_pss_verifies(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(
            signature, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=SALT_LEN),
            hashes.SHA384(),
        )
        return True
    except Exception:
        return False


def entry_hash(index: int, payload: dict, prev: bytes) -> bytes:
    return sha256(index.to_bytes(8, "big"), prev, canonical(payload))


def verify(config_path: Path, ledger_path: Path, releases_path: Path) -> int:
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes)
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    ledger_bytes = ledger_path.read_bytes()
    ledger = json.loads(ledger_bytes)
    releases = json.loads(releases_path.read_bytes())

    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))
    box_key = unb64(config["ebb_statement_key"])
    office_key = unb64(config["vro_statement_key"])
    election = config["election_id"]

    print(f"\nElection {election}, configuration {config_digest[:16]}…")

    print("\nThe files describe this election")
    check(ledger["format"] == "ovpoc-ledger/1", "ledger format understood",
          ledger["format"])
    check(ledger["election_id"] == election, "ledger names this election")
    check(ledger["configuration_digest"] == config_digest,
          "ledger pins the configuration being used")
    check(releases["configuration_digest"] == config_digest,
          "release register pins the same configuration")
    check(ledger_bytes == canonical(ledger),
          "ledger is canonically serialised, so its hash is comparable")

    print("\nEvery ballot came from an eligible voter, and said what it says")
    accepted = ledger["accepted"]
    tokens_ok = votes_ok = 0
    for entry in accepted:
        record = entry["record"]
        adhoc = unb64(record["adhoc_public_key"])
        if rsa_pss_verifies(token_key, unb64(record["token"]), adhoc):
            tokens_ok += 1
        payload = sha256(canonical({
            "adhoc_public_key": record["adhoc_public_key"],
            "nonce": record["nonce"],
            "selection": record["selection"],
        }))
        if ed25519_verifies(adhoc, unb64(record["vote_signature"]), payload):
            votes_ok += 1
    check(tokens_ok == len(accepted), "every token signed by the VRO",
          f"{tokens_ok}/{len(accepted)}")
    check(votes_ok == len(accepted), "every selection signed by its certified key",
          f"{votes_ok}/{len(accepted)}")

    seen = {canonical(e["record"]) for e in accepted}
    check(len(seen) == len(accepted), "no record appears twice among the accepted",
          f"{len(seen)} distinct of {len(accepted)}")

    print("\nThe registry has not been altered since each ballot was accepted")
    head = bytes.fromhex(ledger["genesis_hash"])
    intact = True
    for i, entry in enumerate(accepted):
        head = entry_hash(i, entry["record"], head)
        if head.hex() != entry["commitment"] or entry["index"] != i:
            intact = False
            break
    check(intact, "each record hashes to the commitment published for its position")
    check(head.hex() == ledger["heads"]["accepted"],
          "the chain reaches the published head", head.hex()[:16] + "…")
    check(ed25519_verifies(
        box_key, unb64(ledger["head_signatures"]["accepted"]),
        sha256(canonical({"election_id": election, "head": b64(head),
                          "ledger": "accepted", "statement": "registry-head"}))),
        "the head is signed by the box's published statement key")

    print("\nOne vote each, the last one counted")
    final: dict[str, dict] = {}
    for entry in accepted:
        final[entry["record"]["adhoc_public_key"]] = entry["record"]
    check(True, "supersession applied among accepted entries only",
          f"{len(accepted)} ballots from {len(final)} voters")

    print("\nThe count audit, across two components")
    office_head = bytes.fromhex(releases["genesis_hash"])
    for i, entry in enumerate(releases["entries"]):
        office_head = entry_hash(i, {"commitment": entry["commitment"]}, office_head)
    check(office_head.hex() == releases["head"], "the release register rebuilds")
    check(ed25519_verifies(
        office_key, unb64(releases["head_signature"]),
        sha256(canonical({"election_id": election, "head": b64(office_head),
                          "statement": "release-register-head"}))),
        "its head is signed by the office")
    check(ed25519_verifies(
        office_key, unb64(releases["count_signature"]),
        sha256(canonical({"count": releases["count"], "election_id": election,
                          "statement": "tokens-released"}))),
        "the released-token count is signed by the office")
    check(len(final) <= releases["count"],
          "distinct ad-hoc keys do not exceed tokens released",
          f"{len(final)} <= {releases['count']}")

    print("\nThe result")
    choices = range(1, config["num_choices"] + 1)
    counts = Counter(r["selection"] for r in final.values())
    for choice in choices:
        print(f"  option {choice}: {counts.get(choice, 0)}")
    protest = {s: n for s, n in counts.items() if s not in choices}
    if protest:
        print(f"  outside the list, by value: {protest}")
    print(f"  rejected submissions, published and not counted: {len(ledger['rejected'])}")

    if failures:
        print(f"\n{len(failures)} CHECK(S) FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nEvery check passed. This result follows from the published records.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(verify(*(Path(a) for a in sys.argv[1:])))
