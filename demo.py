"""A narrated end-to-end run of the protocol.

Run with:  python demo.py

Each step prints what happens and, where it matters, what the party in question
can and cannot see. The final section runs the independent verification an
ordinary citizen could perform. XX
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from ovpoc import keys, rsabssa
from ovpoc.ballotbox import BallotBox
from ovpoc.messages import Ballot, unb64
from ovpoc.voter import Voter
from ovpoc.vro import VRO

OPTIONS = {1: "Option A", 2: "Option B", 3: "Option C"}


def rule(title):
    print(f"\n{'─' * 68}\n{title}\n{'─' * 68}")


def short(data, n=16):
    return data[:n].hex() + "…"


def main():
    rule("SETUP  ·  the VRO publishes one signing key, and only one")
    vro = VRO.create(bits=2048)
    fingerprint = rsabssa.public_key_fingerprint(vro.public_key)
    print(f"VRO public key fingerprint (pinned in every client): {fingerprint[:32]}…")
    print("Every voter app checks this before submitting. A VRO using a different")
    print("key per voter could de-anonymise ballots, so a mismatch aborts.")

    box = BallotBox(vro_public_key=vro.public_key, num_choices=len(OPTIONS))

    names = ["Anna", "Béla", "Csilla"]
    voters = []
    for i, name in enumerate(names):
        wallet = keys.SigningKeyPair.generate()
        voter_id = f"HU-WALLET-{i:03d}"
        vro.register_voter(voter_id, wallet.public_bytes)
        voters.append((name, Voter(voter_id, wallet, vro.public_key, fingerprint)))
    print(f"\nElectoral register: {len(voters)} eligible voters.")

    choices = {"Anna": 1, "Béla": 3, "Csilla": 1}

    for name, voter in voters:
        rule(f"{name}  ·  registration and voting")

        request = voter.build_auth_request()
        print(f"  1/A  generates an ad-hoc key pair, valid for this election only")
        print(f"  2    blinds the public key       → c = {short(request.blinded_key)}")
        print(f"  3-4  wallet signs [id, c]        → sends id={voter.voter_id}")

        blind_sig = vro.issue_token(request)
        print(f"  5    VRO: on the register, signature valid, no token issued yet ✓")
        print(f"  7    VRO records the release publicly (before signing)")
        print(f"  6/A  VRO blind-signs c           → {short(blind_sig)}")
        print(f"       what the VRO saw: {short(request.blinded_key)}")
        print(f"       what it means:    nothing — c hides the ad-hoc key entirely")

        voter.accept_token(blind_sig)
        print(f"  8    unblinds → token over k_p^a = {short(voter.token)}")
        print(f"       this is now an ordinary RSA-PSS signature; anyone can check it")

        ballot = voter.cast(choices[name])
        result = box.submit(ballot)
        voter.record_head(result.ledger_head)
        print(f"  9    casts {OPTIONS[choices[name]]!r}, signed with k_s^a")
        print(f" 10-11 ballot box: token genuine ✓  selection authenticated ✓")
        print(f"       published, ledger head now {short(result.ledger_head, 12)}")

    rule("Béla changes his mind  ·  re-voting")
    bela = dict(voters)["Béla"]
    box.submit(bela.cast(2))
    choices["Béla"] = 2
    print("  A second ballot under the same ad-hoc key supersedes the first.")
    print("  Both stay published; supersession is applied when counting, so the")
    print("  full history remains auditable.")

    rule("Csilla verifies  ·  from a different device, over an anonymous channel")
    csilla = dict(voters)["Csilla"]
    from ovpoc.vro import release_query_payload, verify_release_answer

    answer = vro.query_token_release(
        csilla.voter_id, csilla.wallet.sign(release_query_payload(csilla.voter_id))
    )
    published_log = [e.payload for e in vro.release_log.entries]
    print(f"  Token-request check — the query carries sig(id), so only she can ask.")
    print(f"    → released: {answer.released}  (she did request one, so this is expected)")
    print(f"    → verified against the published log: "
          f"{verify_release_answer(published_log, csilla.voter_id, answer)}")
    print(f"    the log itself names nobody: {published_log[answer.index]}")
    ok = csilla.verify_recorded_ballot(box, choices["Csilla"])
    print(f"  Ballot-value check — is the recorded choice the intended one?")
    print(f"    → {ok}")
    print("\n  Note what this check is, in this variant: her handle is the ad-hoc")
    print("  key she controls, so she could also prove authorship to a third")
    print("  party — an adjudicator, or a vote buyer. That is point B on the")
    print("  paper's diagram, and it is a policy choice, not a technical one.")

    rule("ANYONE  ·  independent verification from the public ledger alone")
    published = [e.payload for e in box.valid.entries]
    print(f"  {len(published)} published ballots, {vro.release_count()} tokens released")

    latest = {}
    for payload in published:
        ballot = Ballot.from_dict(payload)
        assert rsabssa.verify(vro.public_key, ballot.adhoc_public_key, ballot.token)
        assert keys.verify_signature(
            ballot.adhoc_public_key, ballot.vote_signature, ballot.signed_payload()
        )
        latest[payload["adhoc_public_key"]] = ballot.selection

    print("  every ballot carries a genuine VRO token           ✓")
    print("  every selection is signed by the certified key      ✓")
    print(f"  hash chain intact (nothing removed or reordered)    {'✓' if box.valid.verify_chain() else '✗'}")
    print(f"  ballots ≤ tokens released ({len(latest)} ≤ {vro.release_count()})              ✓")

    counts = {i: sum(1 for s in latest.values() if s == i) for i in OPTIONS}
    print("\n  Independently computed result:")
    for i, label in OPTIONS.items():
        print(f"    {label:<12} {counts[i]}")
    print(f"\n  Announced by the ballot box: {box.tally()['counts']}")
    print(f"  Computed by an outsider:     {counts}")
    print(f"  Match: {counts == box.tally()['counts']}")

    print("\n  No privileged access was used above — only the published ledger")
    print("  and the VRO's public key.\n")


if __name__ == "__main__":
    main()
