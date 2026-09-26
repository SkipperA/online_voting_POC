#!/usr/bin/env python3
"""demo.py, over the wire.

Same story as `demo.py`, with one difference that is the whole point: nothing
here calls `ovpoc` across a trust boundary.  Every step is an HTTP request to
a separately-addressed origin, so the boundaries the article draws are
boundaries the demo cannot cheat across.

Two things become visible that the in-process demo could only assert.

**The voter application never holds `id`.**  `demo.py` uses `ovpoc.voter.Voter`,
which carries `voter_id` because one object plays both the application and the
wallet.  Here the application side is `VoterApp` below, and it has no field
for an identifier and no way to obtain one: it hands `c` to the wallet origin
and later collects `s_c` from the office by presenting `c`.  Read its
attributes -- there is nowhere for an identity to hide.

**The office answers two different parties.**  The wallet transmits the
request (B7); the application collects the reply (B16).  Those are different
origins making different calls, which is what §5.3 argues for and what a
single in-process object cannot demonstrate.

Run `python -m service` in one terminal, then this script in another.
"""

from __future__ import annotations

import sys
import time

import httpx
from cryptography.hazmat.primitives import serialization

from ovpoc import keys, rsabssa
from ovpoc.messages import Ballot, b64, unb64
from ovpoc.vro import verify_release_answer

CONFIG = "http://127.0.0.1:8000"
WALLET = "http://127.0.0.1:8002"
VRO = "http://127.0.0.1:8003"
EBB = "http://127.0.0.1:8004"
SETUP = "http://127.0.0.1:8009"

# Labels are a matter for the ballot paper; the *number* of choices is a
# configuration field (Table 1 footnote a) and is read from 8000 rather than
# assumed here. Assuming it is how an outsider's count and the box's count
# come to disagree about an option nobody used.
LABELS = ["Reform", "Continuity", "Renewal", "Concord"]


def options_from(num_choices: int) -> dict[int, str]:
    return {
        i: LABELS[i - 1] if i <= len(LABELS) else f"Option {i}"
        for i in range(1, num_choices + 1)
    }


def rule(title: str) -> None:
    print(f"\n{'─' * 72}\n{title}\n{'─' * 72}")


def short(data, n: int = 16) -> str:
    raw = data if isinstance(data, str) else b64(data)
    return raw[:n] + "…"


class VoterApp:
    """The voting application, and only it.

    Holds the ad-hoc key pair, the blinding state, and the pinned fingerprint.
    It does not hold, receive, or have any means of learning `id`.
    """

    def __init__(self, http: httpx.Client, token_key, pinned_fingerprint: str):
        self.http = http
        self.token_key = token_key
        self.pinned = pinned_fingerprint
        self.adhoc = keys.SigningKeyPair.generate()
        self.blinded: bytes | None = None
        self.state = None
        self.token: bytes | None = None

    def blind(self) -> bytes:
        """B2–B3, client-side. In the browser this is blindrsa-ts."""
        self.blinded, self.state = rsabssa.blind(self.token_key, self.adhoc.public_bytes)
        return self.blinded

    def collect(self, attempts: int = 20) -> str:
        """B16. Poll until the office has a reply for this `c`.

        A plain GET that 404s until the value exists. The application holds no
        credential other than `c`, which it generated and which is
        unguessable, so none is invented for the purpose.
        """
        url = f"{VRO}/token-replies/{b64(self.blinded)}"
        for _ in range(attempts):
            response = self.http.get(url)
            if response.status_code == 200:
                return response.json()["blind_signature"]
            time.sleep(0.05)
        raise SystemExit("the office never produced a reply")

    def accept(self, blind_signature: str) -> None:
        """B17–B18. Unblind, then verify before `r` is discarded.

        The verification is the only moment at which the voter learns whether
        the office followed the protocol, and the entitlement is already spent
        if it did not (§5.5).
        """
        self.token = rsabssa.finalize(
            self.token_key, self.adhoc.public_bytes, unb64(blind_signature), self.state
        )
        if not rsabssa.verify(self.token_key, self.adhoc.public_bytes, self.token):
            raise SystemExit("the office returned a signature that does not verify")
        self.state = None

    def cast(self, selection: int) -> dict:
        """C2–C3. Sign the selection, submit over the anonymising channel.

        There is no anonymising channel on localhost. Clause A2.
        """
        ballot = Ballot(
            selection=selection,
            adhoc_public_key=self.adhoc.public_bytes,
            token=self.token,
            vote_signature=b"",
        )
        ballot = Ballot(
            selection=selection,
            adhoc_public_key=self.adhoc.public_bytes,
            token=self.token,
            vote_signature=self.adhoc.sign(ballot.signed_payload()),
        )
        response = self.http.post(
            f"{EBB}/ballots",
            json={
                "selection": ballot.selection,
                "adhoc_public_key": b64(ballot.adhoc_public_key),
                "token": b64(ballot.token),
                "vote_signature": b64(ballot.vote_signature),
            },
        )
        response.raise_for_status()
        return response.json()


def require_service(http: httpx.Client) -> None:
    try:
        http.get(f"{CONFIG}/health", timeout=2.0)
    except httpx.ConnectError:
        raise SystemExit(
            "no service on 127.0.0.1:8000 — run `python -m service` in another "
            "terminal first."
        )


def main() -> int:
    http = httpx.Client(timeout=30.0)
    require_service(http)

    rule("SETUP  ·  the configuration is fetched and pinned, not asked for")
    config = http.get(f"{CONFIG}/election.json").json()
    digest_line = http.get(f"{CONFIG}/election.json.sha256").text
    token_key = serialization.load_der_public_key(unb64(config["vro_token_key_spki"]))
    fingerprint = rsabssa.public_key_fingerprint(token_key)

    print(f"  election         {config['election_id']}")
    print(f"  k_p^(R) pinned   {fingerprint[:32]}…")
    print(f"  matches config   {fingerprint == config['vro_token_key_fingerprint']}")
    print(f"  digest published {digest_line.split()[0][:32]}…")
    options = options_from(config["num_choices"])
    print(f"  choices 1..{config['num_choices']}      {', '.join(options.values())}")
    print("  The key comes from the config origin, never from the VRO. An office")
    print("  that supplied the key its own signatures are checked against would")
    print("  make the single-key discipline of §3.3 vacuous.")
    print(f"  Not signed: {config['scope_limits']['signature']}")

    rule("SETUP  ·  two registers, held by different parties")
    names = ["Anna", "Béla", "Csilla"]
    ids = {}
    for i, name in enumerate(names):
        voter_id = f"HU-WALLET-{i:03d}"
        http.post(f"{SETUP}/voters", json={"voter_id": voter_id}).raise_for_status()
        ids[name] = voter_id
    print(f"  population register (external): {len(names)} certificates binding a")
    print("    signing key to a named person — infrastructure this design consults")
    print(f"  electoral register (the VRO's):  {len(names)} ids, and nothing else")
    print("  Both were written through 8009, which takes no further part.")

    choices = {"Anna": 1, "Béla": 3, "Csilla": 1}
    apps: dict[str, VoterApp] = {}

    for name in names:
        rule(f"{name}  ·  registration and voting, across four origins")
        app = VoterApp(http, token_key, fingerprint)
        apps[name] = app

        blinded = app.blind()
        print("  8001  generates an ad-hoc key pair and blinds its public key")
        print(f"        c = {short(blinded)}")
        print(f"        fields this object holds: {sorted(vars(app))}")
        print("        — no identifier among them, and no endpoint returns one")

        http.post(f"{WALLET}/session", json={"voter_id": ids[name]}).raise_for_status()
        reply = http.post(f"{WALLET}/requests", json={"blinded_key": b64(blinded)})
        outcome = reply.json()["outcome"]
        print(f"  8002  wallet signs [id, c] and transmits to the office itself")
        print(f"        the application is told only: {outcome}")

        blind_signature = app.collect()
        print(f"  8003  application collects by presenting c → {short(blind_signature)}")
        print("        404 until the reply exists; c is the only credential used")

        app.accept(blind_signature)
        print(f"  8001  unblinds and verifies → token {short(app.token)}")
        print("        an ordinary RSA-PSS signature now; any library can check it")

        receipt = app.cast(choices[name])
        print(f"  8004  casts {options[choices[name]]!r} → accepted={receipt['accepted']}, "
              f"index {receipt['index']}")
        print(f"        head now {short(receipt['ledger_head'], 12)}")

    rule("Béla changes his mind  ·  re-voting")
    receipt = apps["Béla"].cast(2)
    choices["Béla"] = 2
    print(f"  A second ballot under the same ad-hoc key, index {receipt['index']}.")
    print("  It supersedes the first. Both stay published; supersession is applied")
    print("  when counting, so the full history remains auditable.")

    rule("Csilla verifies  ·  from origins the voting application does not control")
    credentials = http.post(f"{WALLET}/release-query-credentials").json()
    answer = http.post(f"{VRO}/release-queries", json=credentials).json()
    log = http.get(f"{VRO}/release-log").json()
    print("  Token-request check (D1) — the query carries sig(id), so only she can ask.")
    print(f"    → released: {answer['released']}")
    verified = verify_release_answer(
        log["entries"],
        credentials["voter_id"],
        type("A", (), {
            "released": answer["released"],
            "nonce": unb64(answer["nonce"]) if "nonce" in answer else None,
            "index": answer.get("index"),
        })(),
    )
    print(f"    → verified against the published log: {verified}")
    print(f"    the log names nobody: {log['entries'][answer['index']]}")
    print("    Note the credentials came from 8002 and the answer from 8003.")
    print("    Neither passed through 8001, which is what the check requires.")

    record = http.get(
        f"{EBB}/ballots/{b64(apps['Csilla'].adhoc.public_bytes)}"
    ).json()
    print("  Selection check (D3) — retrieve by k_p^a and compare.")
    print(f"    → recorded {record['selection']}, intended {choices['Csilla']}, "
          f"match {record['selection'] == choices['Csilla']}")

    rule("ANYONE  ·  independent verification from the published view alone")
    view = http.get(f"{EBB}/published").json()
    print(f"    while open:  {len(view['commitments']['accepted'])} commitments, "
          f"records withheld ({'records' in view})")

    http.post(f"{EBB}/close").raise_for_status()
    view = http.get(f"{EBB}/published").json()
    published = view["records"]["accepted"]
    print(f"    at close:    {len(published)} records in clear")
    print(f"    {len(published)} published ballots, {log['count']} tokens released")

    latest = {}
    for payload in published:
        ballot = Ballot.from_dict(payload)
        assert rsabssa.verify(token_key, ballot.adhoc_public_key, ballot.token)
        assert keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload()
        )
        latest[payload["adhoc_public_key"]] = ballot.selection

    print("  every ballot carries a genuine VRO token           ✓")
    print("  every selection is signed by the certified key      ✓")
    print(f"  ballots ≤ tokens released ({len(latest)} ≤ {log['count']})              ✓")

    counts = {i: sum(1 for s in latest.values() if s == i) for i in options}
    announced = {int(k): v for k, v in http.get(f"{EBB}/tally").json()["counts"].items()}
    print("\n  Independently computed result:")
    for i, label in options.items():
        print(f"    {label:<12} {counts[i]}")
    print(f"\n  Announced by the ballot box: {announced}")
    print(f"  Computed by an outsider:     {counts}")
    print(f"  Match: {counts == announced}")
    print("\n  Nothing above used privileged access — only the published view and")
    print("  the key pinned from the config origin.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
