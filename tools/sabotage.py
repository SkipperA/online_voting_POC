"""Sabotage runner: disable each defense in turn, record which tests notice.

Why this exists. A test that asserts an attack *fails* can pass for the wrong
reason -- because the attack failed, or because the check it targets was never
reached, or because the assertion is too weak to distinguish. Twenty-eight
passing tests are therefore weaker evidence than they look.

This script breaks one defense at a time and records which tests fail as a
result. A defense with no failing tests is not defended by the suite, whatever
the code comments claim.

Run with:  python tools/sabotage.py
It rewrites docs/sabotage.md from the actual results and always restores the
source files, including on error or interrupt.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Mutation:
    name: str
    what: str          # the defense being removed, in plain words
    path: str
    find: str
    replace: str


MUTATIONS = [
    Mutation(
        name="token_verification_disabled",
        what="The ballot box no longer checks that the token is a genuine VRO signature.",
        path="src/ovpoc/rsabssa.py",
        find="    try:\n        public_key.verify(",
        replace="    return True  # SABOTAGE\n    try:\n        public_key.verify(",
    ),
    Mutation(
        name="ed25519_verification_disabled",
        what="All Ed25519 signature checks pass unconditionally -- wallet signatures and vote signatures alike.",
        path="src/ovpoc/keys.py",
        find="    try:\n        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)",
        replace="    return True  # SABOTAGE\n    try:\n        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)",
    ),
    Mutation(
        name="eligibility_check_removed",
        what="The VRO stops requiring that the id appear on the electoral register.",
        path="src/ovpoc/vro.py",
        find='        if request.voter_id not in self.register:\n            return self._record(\n                request.voter_id, Outcome.NOT_ELIGIBLE, "not on the electoral register"\n            )',
        replace="        pass  # SABOTAGE: no electoral register check",
    ),
    Mutation(
        name="one_token_per_voter_removed",
        what="The VRO no longer refuses a second token request from the same id.",
        path="src/ovpoc/vro.py",
        find='        if request.voter_id in self._released:\n            return self._record(\n                request.voter_id,\n                Outcome.TOKEN_ALREADY_ISSUED,\n                "a token has already been released for this id",\n            )',
        replace="        pass  # SABOTAGE: no one-token-per-voter rule",
    ),
    Mutation(
        name="wallet_signature_check_removed",
        what="The VRO issues tokens without checking that the request was signed by the wallet owning that id.",
        path="src/ovpoc/vro.py",
        find="        if not keys.verify_signature(\n            cert.public_key, request.wallet_signature, request.signed_payload()\n        ):\n            return self._record(\n                request.voter_id,\n                Outcome.NOT_IDENTIFIED,\n                \"request signature does not verify under the certified key\",\n            )",
        replace="        pass  # SABOTAGE: no wallet signature check",
    ),
    Mutation(
        name="finalize_selfcheck_removed",
        what="The voter's device stops verifying the VRO's blind signature before accepting it.",
        path="src/ovpoc/rsabssa.py",
        find='    if not verify(public_key, msg, sig):\n        raise BlindSignatureError("VRO returned a signature that does not verify")\n    return sig',
        replace="    return sig  # SABOTAGE: trust the VRO's response",
    ),
    Mutation(
        name="chain_verification_disabled",
        what="Ledger chain verification always reports the chain as intact.",
        path="src/ovpoc/ledger.py",
        find="        prev = GENESIS\n        for i, entry in enumerate(self.entries):",
        replace="        return True  # SABOTAGE\n        prev = GENESIS\n        for i, entry in enumerate(self.entries):",
    ),
    Mutation(
        name="ledger_chaining_removed",
        what="Ledger entries no longer reference the previous entry, so order and deletions are unconstrained.",
        path="src/ovpoc/ledger.py",
        find="        prev_hash = self.entries[-1].entry_hash if self.entries else GENESIS",
        replace="        prev_hash = GENESIS  # SABOTAGE: no chaining",
    ),
    Mutation(
        name="rejected_ballots_supersede",
        what="A ballot that fails its signature check is recorded as valid as well, so it annuls the voter's earlier ballot.",
        path="src/ovpoc/ballotbox.py",
        find='            entry = self.rejected.append(\n                {**ballot.to_dict(), "reason": "vote signature invalid"}\n            )',
        replace='            self.accepted.append(ballot.to_dict())  # SABOTAGE\n            entry = self.rejected.append(\n                {**ballot.to_dict(), "reason": "vote signature invalid"}\n            )',
    ),
    Mutation(
        name="selection_range_check_removed",
        what="The tally counts any selection, so protest ballots are folded into the options.",
        path="src/ovpoc/ballotbox.py",
        find="            if 1 <= selection <= self.num_choices:",
        replace="            if True:  # SABOTAGE: no range check",
    ),
    Mutation(
        name="vro_key_pinning_removed",
        what="The voter app stops checking the VRO public key against the pinned fingerprint, so a per-voter VRO key would go unnoticed.",
        path="src/ovpoc/voter.py",
        find='        if rsabssa.public_key_fingerprint(self.vro_public_key) != self.pinned_vro_fingerprint:\n            raise ValueError(\n                "VRO public key does not match the pinned fingerprint -- refusing to "\n                "proceed (a per-voter VRO key would destroy anonymity)"\n            )',
        replace="        pass  # SABOTAGE: no key pinning",
    ),
    Mutation(
        name="release_log_publishes_ids",
        what="The release log publishes plaintext voter ids instead of commitments.",
        path="src/ovpoc/vro.py",
        find='        self.release_log.append({"commitment": b64(commit(request.voter_id, nonce))})',
        replace='        self.release_log.append({"voter_id": request.voter_id})  # SABOTAGE',
    ),
    Mutation(
        name="release_query_auth_removed",
        what="Step-12 release queries no longer require sig(id), turning the log into a public participation register.",
        path="src/ovpoc/vro.py",
        find='        if not keys.verify_signature(\n            cert.public_key, signature, release_query_payload(voter_id)\n        ):\n            return ReleaseAnswer(ReleaseOutcome.NOT_IDENTIFIED)',
        replace="        pass  # SABOTAGE: unauthenticated queries allowed",
    ),
    Mutation(
        name="eligibility_checked_before_identity",
        what=(
            "The VRO decides eligibility before verifying the request signature, so "
            "anyone who can spell an id learns whether that citizen is on the roll."
        ),
        path="src/ovpoc/vro.py",
        find="        cert = self.population_register.lookup(request.voter_id)\n        if cert is None:",
        replace=(
            "        cert = self.population_register.lookup(request.voter_id)\n"
            "        if request.voter_id not in self.register:  # SABOTAGE: before identity\n"
            "            return self._record(\n"
            "                request.voter_id, Outcome.NOT_ELIGIBLE, \"not on the electoral register\"\n"
            "            )\n"
            "        if cert is None:"
        ),
    ),
    Mutation(
        name="revocation_reported_before_identity",
        what=(
            "Certificate revocation is reported before the signature is checked, so the "
            "endpoint answers a question about a citizen the requester has not proved to be."
        ),
        path="src/ovpoc/vro.py",
        find="        if not keys.verify_signature(\n            cert.public_key, request.wallet_signature, request.signed_payload()\n        ):",
        replace=(
            "        if cert.revoked:  # SABOTAGE: reported before identity\n"
            "            return self._record(\n"
            "                request.voter_id, Outcome.CERTIFICATE_REVOKED, \"certificate revoked\"\n"
            "            )\n"
            "        if not keys.verify_signature(\n"
            "            cert.public_key, request.wallet_signature, request.signed_payload()\n"
            "        ):"
        ),
    ),
    Mutation(
        name="denials_signed_with_the_token_key",
        what=(
            "Release denials are signed with the blind-signing key, which any registered "
            "voter can drive as an oracle through an ordinary token request."
        ),
        path="src/ovpoc/vro.py",
        find="                signed_denial=self.office_key.sign(denial_payload(voter_id)),",
        replace=(
            "                signed_denial=rsabssa.finalize(  # SABOTAGE: token key reused\n"
            "                    self.public_key,\n"
            "                    denial_payload(voter_id),\n"
            "                    rsabssa.blind_sign(\n"
            "                        self.private_key,\n"
            "                        rsabssa.blind(self.public_key, denial_payload(voter_id))[0],\n"
            "                    ),\n"
            "                    rsabssa.blind(self.public_key, denial_payload(voter_id))[1],\n"
            "                ),"
        ),
    ),
    Mutation(
        name="blind_signature_fault_check_removed",
        what=(
            "The office releases s_c without checking s_c^e == c, so a faulty CRT "
            "exponentiation would be handed out -- and a single faulty signature leaks p."
        ),
        path="src/ovpoc/vro.py",
        find="        if not rsabssa.check_blind_signature(\n            self.public_key, request.blinded_key, blind_sig\n        ):",
        replace="        if False:  # SABOTAGE: no fault check before release",
    ),
    Mutation(
        name="records_published_while_voting_is_open",
        what=(
            "The ballot box publishes every record in clear before the close, broadcasting "
            "a running result and, with re-voting, that somebody reversed a choice."
        ),
        path="src/ovpoc/ballotbox.py",
        find="        if self._closed:\n            view[\"records\"] = {",
        replace="        if True:  # SABOTAGE: records published while open\n            view[\"records\"] = {",
    ),
    Mutation(
        name="tally_available_before_the_close",
        what=(
            "The full count can be read while voting is open even when no running tally "
            "is published, giving the operator privileged early sight of the result."
        ),
        path="src/ovpoc/ballotbox.py",
        find="        if not self._closed and self.tally_interval is None:",
        replace="        if False:  # SABOTAGE: tally always available",
    ),
    Mutation(
        name="submissions_accepted_after_the_close",
        what="The ballot box keeps accepting ballots after the poll has closed.",
        path="src/ovpoc/ballotbox.py",
        find="        if self._closed:\n            # Not recorded at all",
        replace="        if False:  # SABOTAGE: closing does not stop submissions\n            # Not recorded at all",
    ),
]


class SuiteDidNotRun(RuntimeError):
    """pytest failed to execute, as opposed to executing and reporting failures.

    This distinction is the whole point of the tool. If a broken environment
    produced an empty failure list, every mutation would look undetected and the
    report would be confidently wrong.
    """


def failing_tests() -> list[str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "-rf"],
        cwd=ROOT, capture_output=True, text=True,
    )
    # pytest: 0 = all passed, 1 = tests failed. Anything else means it did not
    # get as far as running the suite (2 interrupted, 3 internal error,
    # 4 usage error, 5 no tests collected), as does a missing pytest.
    if result.returncode not in (0, 1):
        raise SuiteDidNotRun(
            f"pytest exited {result.returncode}\n"
            f"--- stdout ---\n{result.stdout[-2000:]}\n"
            f"--- stderr ---\n{result.stderr[-2000:]}"
        )

    names = []
    for line in result.stdout.splitlines():
        if line.startswith("FAILED "):
            names.append(line.split()[1].split("::")[-1])
        elif line.startswith("ERROR "):
            names.append("ERROR " + line.split()[1])

    # A non-zero exit with nothing parsed means the output format changed and we
    # would silently under-report. Refuse rather than guess.
    if result.returncode == 1 and not names:
        raise SuiteDidNotRun(
            "pytest reported failures but none could be parsed; "
            f"output format may have changed:\n{result.stdout[-2000:]}"
        )
    return sorted(set(names))


def main() -> int:
    try:
        baseline = failing_tests()
    except SuiteDidNotRun as exc:
        print("Cannot run the sabotage suite: the test suite itself did not run.")
        print("Install the dev extras first:  pip install -e \".[dev]\"\n")
        print(exc)
        return 2
    if baseline:
        print("Baseline suite is not green; fix that first:", baseline)
        return 1
    print("Baseline green.\n")

    results: list[tuple[Mutation, list[str]]] = []
    for mutation in MUTATIONS:
        target = ROOT / mutation.path
        original = target.read_text()
        if mutation.find not in original:
            print(f"  !! {mutation.name}: pattern not found -- source has drifted")
            results.append((mutation, ["PATTERN NOT FOUND"]))
            continue
        try:
            target.write_text(original.replace(mutation.find, mutation.replace, 1))
            caught = failing_tests()
        finally:
            target.write_text(original)
        status = f"{len(caught)} test(s)" if caught else "NOT CAUGHT"
        print(f"  {mutation.name:<34} {status}")
        results.append((mutation, caught))

    write_report(results)
    uncaught = [m.name for m, c in results if not c]
    print(f"\nWrote docs/sabotage.md. Undetected mutations: {len(uncaught)}")
    for name in uncaught:
        print(f"  - {name}")
    return 0


def write_report(results: list[tuple[Mutation, list[str]]]) -> None:
    lines = [
        "# Sabotage log",
        "",
        "Generated by `python tools/sabotage.py`. Do not edit by hand.",
        "",
        "Each defense below was disabled in turn and the full suite re-run. The",
        "listed tests are those that failed as a result -- that is, the tests which",
        "actually constrain that defense rather than merely coexisting with it.",
        "",
        "A mutation with no failing tests is **not covered by the suite**, however",
        "confident the surrounding comments sound.",
        "",
    ]
    caught = [(m, c) for m, c in results if c and "PATTERN NOT FOUND" not in c]
    missed = [(m, c) for m, c in results if not c]

    lines += [f"| Defense removed | Tests that caught it |", "|---|---|"]
    for m, c in results:
        cell = "**none**" if not c else "<br>".join(f"`{n}`" for n in c)
        lines.append(f"| {m.name} | {cell} |")
    lines += ["", "## Detail", ""]
    for m, c in results:
        lines += [f"### `{m.name}`", "", m.what, "", f"Patched in `{m.path}`.", ""]
        if c:
            lines.append("Caught by:")
            lines += [f"- `{n}`" for n in c]
        else:
            lines.append("**Not caught by any test.** This is a coverage gap.")
        lines.append("")
    lines += [
        "## Summary",
        "",
        f"- {len(caught)} of {len(results)} mutations were detected.",
        f"- {len(missed)} were not.",
        "",
    ]
    (ROOT / "docs" / "sabotage.md").write_text("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
