"""Sabotage runner: disable each defense in turn, record which tests notice.

Why this exists. A test that asserts an attack *fails* can pass for the wrong
reason -- because the attack failed, or because the check it targets was never
reached, or because the assertion is too weak to distinguish. Twenty-eight
passing tests are therefore weaker evidence than they look.

This script breaks one defense at a time and records which tests fail as a
result. A defense with no failing tests is not defended by the suite, whatever
the code comments claim.

Run with:  python tools/sabotage.py          (one suite per core)
           python tools/sabotage.py -j 1     (one at a time)

It rewrites docs/sabotage.md from the actual results. Each worker sabotages
its own copy of the working tree rather than the checkout, so an interrupted
run cannot leave your sources mutated -- and the report is the same whatever
`--jobs` is, because the rows are written in list order rather than in the
order workers finished.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
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
        find='        self.release_log.append({"commitment": b64(commit(request.voter_id, opening))})',
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
        name="receipt_signed_with_a_throwaway_key",
        what=(
            "Receipts are signed under a key nobody published, so a voter's evidence "
            "verifies against nothing and the box can disown anything it issued."
        ),
        path="src/ovpoc/ballotbox.py",
        find="            signature=self.statement_key.sign(receipt_payload(",
        replace="            signature=keys.SigningKeyPair.generate().sign(receipt_payload(",
    ),
    Mutation(
        name="replayed_ballot_accepted_again",
        what=(
            "A ballot identical to one already accepted is accepted a second time, so "
            "an operator can re-enter a ballot the voter had superseded and make it count."
        ),
        path="src/ovpoc/ballotbox.py",
        find="        record = digest(ballot.to_dict())\n        if record in self._accepted_records:",
        replace="        record = digest(ballot.to_dict())\n        if False:  # SABOTAGE: a replay is accepted again",
    ),
    Mutation(
        name="tally_available_before_the_close",
        what=(
            "The full count can be read while voting is open even when no running tally "
            "is published, giving the operator privileged early sight of the result."
        ),
        path="src/ovpoc/ballotbox.py",
        find="        if self._closed:\n            return self._count()\n        self._catch_up()\n        if not self._snapshots:",
        replace="        if True:  # SABOTAGE: tally always available\n            return self._count()\n        if False:",
    ),
    Mutation(
        name="restored_records_not_re-derived",
        what=(
            "A finished poll is loaded from storage without recomputing its chain "
            "against the heads the box signed, so an altered ledger is served through "
            "the published surfaces as though the box stood behind it."
        ),
        path="src/ovpoc/ballotbox.py",
        find=('        if reached != expected_heads:\n'
              '            raise ValueError('),
        replace=("        if False:  # SABOTAGE: load whatever is on disk\n"
                 "            raise ValueError("),
    ),
    Mutation(
        name="cadence_changeable_while_open",
        what=(
            "The publication cadence can be re-timed after the poll has opened, letting "
            "the operator choose mid-poll how much of the result the public is shown and "
            "when -- and re-anchoring the series away from the opening act, so the "
            "boundaries no longer line up with the time the box says it opened."
        ),
        path="src/ovpoc/ballotbox.py",
        find=('        if self.opened:\n'
              '            raise RuntimeError(\n'
              '                "the publication interval is fixed once the ballot box is open"\n'
              '            )'),
        replace="        pass  # SABOTAGE: the cadence is a running-poll setting",
    ),
    Mutation(
        name="reservation_publishes_the_commitment",
        what="The office writes the release commitment when it reserves rather than when it releases, so the published count overstates the tokens that exist and a pause becomes visible to third parties.",
        path="src/ovpoc/vro.py",
        find="        self._reserved[request.voter_id] = request.blinded_key",
        replace="        self._reserved[request.voter_id] = request.blinded_key\n        self.release_log.append({\"commitment\": b64(commit(request.voter_id, secrets.token_bytes(32)))})  # SABOTAGE",
    ),
    Mutation(
        name="protest_distribution_collapsed",
        what="The tally merges every out-of-range selection into one figure, losing the distinction between distinct protest codes.",
        path="src/ovpoc/ballotbox.py",
        find="                protest_codes[selection] += 1",
        replace="                protest_codes[0] += 1  # SABOTAGE",
    ),
    Mutation(
        name="submissions_accepted_after_the_close",
        what="The ballot box keeps accepting ballots after the poll has closed.",
        path="src/ovpoc/ballotbox.py",
        find="        if self._closed:\n            # Not recorded at all",
        replace="        if False:  # SABOTAGE: closing does not stop submissions\n            # Not recorded at all",
    ),
    Mutation(
        name="receipt_omits_the_entry_position",
        what=(
            "The receipt carries the chain head but not the entry position, so the "
            "voter must ask the ballot box where to look -- a query answered by the "
            "component under audit."
        ),
        path="src/ovpoc/ballotbox.py",
        find=(
            "            index=entry.index,\n"
            "            signature=self.statement_key.sign(receipt_payload(\n"
            "                self.election_id, accepted, reason, entry.index, entry.entry_hash)),"
        ),
        replace=(
            "            index=None,  # SABOTAGE: the receipt omits the position\n"
            "            signature=self.statement_key.sign(receipt_payload(\n"
            "                self.election_id, accepted, reason, None, entry.entry_hash)),"
        ),
    ),
    Mutation(
        name="reloaded_register_keeps_the_stored_order",
        what=(
            "A reloaded poll serves the office's openings in whatever order "
            "storage returned them rather than the order the release chain was "
            "built in. The register a supervisor reads then cannot be chained to "
            "the head printed beside it, with every commitment recomputing "
            "perfectly -- which is the signature of an entry inserted, dropped "
            "or reordered, and is instead a serialisation artefact."
        ),
        path="src/ovpoc/vro.py",
        find="        self._openings = _in_chain_order(self.release_log, openings)",
        replace="        self._openings = dict(openings)  # SABOTAGE: storage order",
    ),
    Mutation(
        name="document_prefix_check_removed",
        what=(
            "The office accepts the payload it extracted from a token-request "
            "document without rebuilding the document and comparing."
        ),
        path="src/ovpoc/pdfrequest.py",
        find=(
            "    if document[:len(expected)] != expected:\n"
            "        return DocumentCheck(accepted=False, refusal=Refusal.NOT_AS_RENDERED,\n"
            "                             rendered_bytes=len(expected))"
        ),
        replace="    pass  # SABOTAGE: trust what was extracted, do not rebuild",
    ),
    Mutation(
        name="carrier_disagreement_resolved_by_preference",
        what=(
            "A document whose embedded copy and marker comment disagree is "
            "resolved in favour of whichever was found first, rather than refused."
        ),
        path="src/ovpoc/pdfrequest.py",
        find=(
            "    if len(set(found.values())) > 1:\n"
            "        return None, None, Refusal.CARRIERS_DISAGREE"
        ),
        replace="    pass  # SABOTAGE: prefer the first carrier",
    ),
    Mutation(
        name="document_coverage_check_removed",
        what=(
            "The office stops requiring the signature to cover the whole of "
            "the document it rebuilt."
        ),
        path="src/ovpoc/pdfrequest.py",
        find=(
            "    if covered_prefix_length < len(expected):\n"
            "        return DocumentCheck(\n"
            "            accepted=False, refusal=Refusal.SIGNATURE_DOES_NOT_COVER_IT,\n"
            "            rendered_bytes=len(expected))"
        ),
        replace="    pass  # SABOTAGE: ignore what the signature covered",
    ),
    Mutation(
        name="self_enrolment_not_marked_in_the_register",
        what=(
            "The release register does not say which identifiers the office "
            "added itself, so a supervisor comparing it against the citizen "
            "registry's roll reads the office's own additions as a fault in "
            "the roll."
        ),
        path="src/ovpoc/vro.py",
        find='                 "self_enrolled": voter_id in self_enrolled,\n'
             '                 **_request_for_supervision',
        replace='                 "self_enrolled": False,  # SABOTAGE\n'
                '                 **_request_for_supervision',
    ),
    Mutation(
        name="unvouched_time_published_as_vouched",
        what=(
            "The office reports the moment it judged the certificate "
            "against as authenticated whenever a timestamp is present, "
            "whether or not that timestamp validated -- so an expiry "
            "finding made against a time nobody vouched for is published "
            "as one made against a time somebody did."
        ),
        path="driver/qualified_signature.py",
        find="    return bool(timestamp.trusted)",
        replace="    return True  # SABOTAGE",
    ),
    Mutation(
        name="unjudged_signatures_published_as_unqualified",
        what=(
            "The release register writes `None` -- this office had no "
            "trusted list to judge against -- as a finding that the "
            "signature was not qualified."
        ),
        path="src/ovpoc/vro.py",
        find="            qualified=found.qualified,",
        replace="            qualified=bool(found.qualified),  # SABOTAGE",
    ),
    Mutation(
        name="qualified_claimed_without_a_trust_list",
        what=(
            "The office calls a signature qualified on its own authority, "
            "with no trusted list to establish it -- turning 'this office "
            "has no standing to judge' into a finding under Article 3(12)."
        ),
        path="driver/qualified_signature.py",
        find="        if self.trusted_list is None:\n            return None",
        replace="        if self.trusted_list is None:\n            return True  # SABOTAGE",
    ),
    Mutation(
        name="validator_called_on_the_event_loop",
        what=(
            "The signature validator is called directly from the office's "
            "async upload handler, where pyHanko's own `asyncio.run` cannot "
            "start a loop -- so every genuinely signed request is answered "
            "NOT_IDENTIFIED and only on a server."
        ),
        path="driver/qualified_signature.py",
        find=(
            "            status = _off_the_event_loop(\n"
            "                validate_pdf_signature, embedded,\n"
            "                signer_validation_context=context)"
        ),
        replace=(
            "            status = validate_pdf_signature(  # SABOTAGE\n"
            "                embedded, signer_validation_context=context)"
        ),
    ),
    Mutation(
        name="refusal_reason_collapsed_in_the_audit_log",
        what=(
            "The office records one sentence for every way a signature can "
            "fail to identify anybody, so its own log cannot tell a wrongly "
            "pinned trust anchor from a signature it was right to refuse."
        ),
        path="src/ovpoc/vro.py",
        find=(
            "                found.reason if found is not None else\n"
            "                \"no valid signature over this document, or none that chains \"\n"
            "                \"to a trusted anchor \u2014 the validator gave no further detail\","
        ),
        replace=(
            "                \"no valid signature over this document, or none \"  # SABOTAGE\n"
            "                \"that chains to a trusted anchor\","
        ),
    ),
    Mutation(
        name="revocation_collapsed_into_not_identified",
        what=(
            "The signature validator inherits the library's verdict whole, so "
            "a revoked or expired certificate is reported as no valid "
            "signature rather than as an identified signer with a problem."
        ),
        path="driver/qualified_signature.py",
        find="        if not status.trusted and not (revoked or expired):",
        replace="        if not status.trusted:  # SABOTAGE",
    ),
    Mutation(
        name="identity_taken_from_the_common_name",
        what=(
            "The office identifies a citizen by the name on their certificate "
            "rather than by the serial number the authority allocated."
        ),
        path="driver/qualified_signature.py",
        find='    serial = subject.get("serial_number")',
        replace='    serial = subject.get("common_name")  # SABOTAGE',
    ),
    Mutation(
        name="coverage_counted_from_a_range_not_starting_at_zero",
        what=(
            "A signature whose ByteRange does not begin at byte zero is "
            "credited with covering the document's prefix anyway."
        ),
        path="driver/qualified_signature.py",
        find=(
            "    if len(byte_range) < 2 or byte_range[0] != 0:\n"
            "        return 0"
        ),
        replace="    pass  # SABOTAGE: do not check where the range starts",
    ),
    Mutation(
        name="document_route_keeps_its_own_released_set",
        what=(
            "The qualified-signature route claims identifiers in a set of "
            "its own, so one citizen can take a token by each route."
        ),
        path="src/ovpoc/vro.py",
        find=(
            "        return self._claim(request, revoked=request.revoked,\n"
            "                           expired=request.expired), request"
        ),
        replace=(
            "        if request.voter_id in getattr(self, '_doc_released', set()):\n"
            "            return self._record(request.voter_id,\n"
            "                                Outcome.TOKEN_ALREADY_ISSUED,\n"
            "                                'already issued on this route'), None\n"
            "        self._doc_released = getattr(self, '_doc_released', set())\n"
            "        self._doc_released.add(request.voter_id)  # SABOTAGE\n"
            "        return TokenResponse(outcome=Outcome.RESERVED), request"
        ),
    ),
    Mutation(
        name="request_payload_accepts_extra_fields",
        what=(
            "A token-request payload may carry fields beyond the three, so a "
            "document can assert things the renderer never showed anybody -- "
            "an identifier among them."
        ),
        path="src/ovpoc/pdfrequest.py",
        find="    if not isinstance(candidate, dict) or set(candidate) != set(FIELDS):",
        replace=(
            "    if not isinstance(candidate, dict) or not set(FIELDS) <= set(candidate):"
            "  # SABOTAGE"
        ),
    ),
    Mutation(
        name="document_check_skipped",
        what=(
            "The office issues against a signed document without checking "
            "that the document is what its payload renders to."
        ),
        path="src/ovpoc/vro.py",
        find=(
            "        if not checked.accepted:\n"
            "            return None, self._record(\n"
            "                found.identifier, Outcome.DOCUMENT_REFUSED,\n"
            '                f"the signed document was refused: {checked.refusal.value}",\n'
            "            )"
        ),
        replace="        pass  # SABOTAGE: take the document on trust",
    ),
    Mutation(
        name="validator_inherits_the_modification_verdict",
        what=(
            "The office refuses a signed document because of what a later, "
            "unsigned revision did to it -- which is every document the "
            "real wallet produces."
        ),
        path="driver/qualified_signature.py",
        find="        if not status.trusted and not (revoked or expired):",
        replace="        if not status.bottom_line and not (revoked or expired):",
    ),
    Mutation(
        name="pdf_reader_put_back_in_strict_mode",
        what=(
            "The office reads an uploaded document with a strict parser, "
            "which refuses the structure the real wallet writes before any "
            "signature is checked."
        ),
        path="driver/qualified_signature.py",
        find="            reader = PdfFileReader(io.BytesIO(document), strict=False)",
        replace="            reader = PdfFileReader(io.BytesIO(document))",
    ),
    Mutation(
        name="pinned_anchor_digests_not_checked",
        what=(
            "The office loads its trust anchors without checking them "
            "against the manifest, so a certificate swapped on disk is "
            "trusted silently."
        ),
        path="driver/qualified_signature.py",
        find=(
            "            if actual != entry[\"sha256\"]:\n"
            "                raise TrustAnchorsRefused("
        ),
        replace=(
            "            if False:  # SABOTAGE\n"
            "                raise TrustAnchorsRefused("
        ),
    ),
    Mutation(
        name="unrecorded_anchors_are_trusted",
        what=(
            "A certificate dropped into the anchor directory that no "
            "manifest entry accounts for is loaded anyway."
        ),
        path="driver/qualified_signature.py",
        find=(
            "        if stray:\n"
            "            raise TrustAnchorsRefused("
        ),
        replace=(
            "        if False:  # SABOTAGE\n"
            "            raise TrustAnchorsRefused("
        ),
    ),
    Mutation(
        name="unconfigured_office_blames_the_citizen",
        what=(
            "An office that was never given trust anchors answers an "
            "uploaded document NOT_IDENTIFIED instead of saying it offers "
            "no such route."
        ),
        path="service/api.py",
        find='            return {"outcome": "ROUTE_NOT_OFFERED"}',
        replace='            return {"outcome": "NOT_IDENTIFIED"}  # SABOTAGE',
    ),
    Mutation(
        name="upload_size_cap_removed",
        what=(
            "The office reads an uploaded document of any size into memory "
            "before looking at it."
        ),
        path="service/api.py",
        find=(
            "            if len(body) > LARGEST_UPLOAD:\n"
            '                return {"outcome": "TOO_LARGE"}'
        ),
        replace="            pass  # SABOTAGE: read whatever arrives",
    ),
    # The hand-off between the two phone applications. These two mutate
    # Swift, which no test here compiles -- so what they establish is
    # narrower than usual and worth stating: that the Python tripwires over
    # `ios/` constrain the thing they name. `Info.plist` is generated by
    # Xcode and not in this repository, so for the scheme names a tripwire
    # is the only check there can be.
    Mutation(
        name="hand_off_scheme_renamed_in_code_alone",
        what=(
            "The wallet's URL scheme is renamed in the package and nowhere "
            "else, so the registration an operator was told to make in "
            "Xcode no longer matches and the hand-off silently does "
            "nothing."
        ),
        path="ios/OVPOCKit/Sources/OVPOCKit/HandOff.swift",
        find='    public static let walletScheme = "ovpoc-wallet"',
        replace='    public static let walletScheme = "ovpoc-wallet-v2"  // SABOTAGE',
    ),
    Mutation(
        name="half_a_token_request_period_is_published",
        what=(
            "The console accepts a token-request period with one end "
            "missing, so the configuration carries a declaration no "
            "reader can act on -- a window that might have opened with "
            "the poll, with the configuration, or never."
        ),
        path="service/api.py",
        find="    if bool(opens) != bool(closes):",
        replace="    if False:  # SABOTAGE",
    ),
    Mutation(
        name="a_real_polls_participation_register_is_published",
        what=(
            "The close archives the office's register into the public "
            "record for every election, not only a generated one -- so a "
            "real poll's list of who was issued a token goes into the "
            "directory somebody zips and sends on."
        ),
        path="service/api.py",
        find="    if deployment.config.generated:\n        try:\n            (folder / \"supervision.json\").write_bytes(",
        replace="    if True:  # SABOTAGE\n        try:\n            (folder / \"supervision.json\").write_bytes(",
    ),
    Mutation(
        name="the_challenge_bundle_carries_the_answer",
        what=(
            "The challenge bundle copies the answer key in beside the "
            "dataset, so the question it asks is one anybody can look up."
        ),
        path="tools/publish_challenge.py",
        find="    answer_digest = digest(answer_key)",
        replace=(
            "    answer_digest = digest(answer_key)\n"
            "    shutil.copyfile(answer_key, out / answer_key.name)  # SABOTAGE"
        ),
    ),
    Mutation(
        name="guessing_is_scored_as_a_win",
        what=(
            "The scorer calls any claim with a hit a win, so the challenge "
            "is settled by the first person who submits ten guesses."
        ),
        path="tools/score_challenge.py",
        find='        "leaked": p < ALPHA,',
        replace='        "leaked": len(hits) > 0,  # SABOTAGE',
    ),
    Mutation(
        name="a_generated_election_verifies_without_saying_so",
        what=(
            "The independent verifier stops reporting a synthetic "
            "electorate, so a page of green ticks is all a reader gets."
        ),
        path="tools/verify_election.py",
        find='    report.generated = bool(config.get("generated"))',
        replace="    report.generated = False  # SABOTAGE",
    ),
    Mutation(
        name="wallet_url_scheme_unregistered",
        what=(
            "The wallet claims a different URL scheme from the one the "
            "voting application opens, so the hand-off finds nobody and "
            "does nothing at all."
        ),
        path="ios/WalletApp/Info.plist",
        find="\t\t\t\t<string>ovpoc-wallet</string>",
        replace="\t\t\t\t<string>ovpoc-wallet-old</string>",
    ),
    Mutation(
        name="voting_application_offers_itself_for_documents",
        what=(
            "The voting application declares a document type, which puts "
            "it in the share sheet for the signed token request -- the "
            "one file it must never receive. No code required."
        ),
        path="ios/VoterApp/Info.plist",
        find="\t<key>UIFileSharingEnabled</key>",
        replace=(
            "\t<key>CFBundleDocumentTypes</key>\n"
            "\t<array>\n"
            "\t\t<dict>\n"
            "\t\t\t<key>CFBundleTypeRole</key>\n"
            "\t\t\t<string>Viewer</string>\n"
            "\t\t\t<key>LSItemContentTypes</key>\n"
            "\t\t\t<array>\n"
            "\t\t\t\t<string>com.adobe.pdf</string>\n"
            "\t\t\t</array>\n"
            "\t\t</dict>\n"
            "\t</array>\n"
            "\t<key>UIFileSharingEnabled</key>"
        ),
    ),
    Mutation(
        name="a_build_that_registers_nothing_looks_like_one_that_worked",
        what=(
            "The wallet stops reading its own CFBundleURLTypes, so a "
            "build whose Info.plist setting was never applied shows the "
            "same screen as one that works."
        ),
        path="ios/WalletApp/WalletApp/ContentView.swift",
        find="        let registered = HandOff.schemesRegistered()",
        replace="        let registered = [HandOff.walletScheme]  // SABOTAGE",
    ),
    Mutation(
        name="hand_off_carries_the_voter_id",
        what=(
            "The hand-off to the wallet grows a field naming the voter, "
            "which any application on the device could then read."
        ),
        path="ios/OVPOCKit/Sources/OVPOCKit/HandOff.swift",
        find='    static let payloadQuery = "r"',
        replace=(
            '    static let payloadQuery = "r"\n'
            '    static let voterID = "voter_id"  // SABOTAGE'
        ),
    ),
]


class SuiteDidNotRun(RuntimeError):
    """pytest failed to execute, as opposed to executing and reporting failures.

    This distinction is the whole point of the tool. If a broken environment
    produced an empty failure list, every mutation would look undetected and the
    report would be confidently wrong.
    """


#: How the suite is run, named so that the test which checks the output can
#: run it the same way.
#:
#: `-rfs` and not `-rf -rs`. A second `-r` *replaces* the first rather than
#: adding to it, so `-rf -rs` summarises skips and silently stops reporting
#: failures -- which is the half of this tool that matters, since a mutation
#: is caught by tests that fail. It was written that way for one patch, and
#: every mutation run after the first died in `SuiteDidNotRun` because eight
#: tests had failed and none could be parsed. The guard held; the flags did
#: not.
PYTEST_ARGS = ("-q", "--no-header", "-rfs")


def parse_report(stdout: str) -> tuple[list[str], list[str]]:
    """Failing test names and skip reasons, out of pytest's short summary.

    Separated from the subprocess so that it can be tested, which matters
    more than it looks: everything this tool reports is read through here,
    and a parser that silently stopped recognising a line would under-report
    in the direction that looks like success.
    """
    failures: list[str] = []
    skips: list[str] = []
    for line in stdout.splitlines():
        if line.startswith("FAILED "):
            failures.append(line.split()[1].split("::")[-1])
        elif line.startswith("ERROR "):
            failures.append("ERROR " + line.split()[1])
        elif line.startswith("SKIPPED "):
            # `SKIPPED [1] tests/x.py:36: the pades extra is not installed`
            skips.append(line.partition("] ")[2] or line)
    return sorted(set(failures)), skips


#: What no worker tree needs, whatever machine it is cut on, and what
#: copying it would cost. `.git` is the big one; the caches would be
#: rebuilt anyway and `node_modules` is the voter app's build input, not
#: the suite's.
#:
#: A floor rather than the whole answer: the files that actually make a
#: checkout heavy arrive later, under names this list could not have been
#: written knowing. See `ignored_by_git`.
NOT_COPIED = shutil.ignore_patterns(
    ".git", "__pycache__", ".pytest_cache", ".venv", "node_modules",
    ".build", "*.egg-info", ".DS_Store",
)


def ignored_by_git() -> set[str] | None:
    """What `.gitignore` calls this machine's, as paths relative to `ROOT`.

    The list above names artefacts. The expensive ones are named by
    whoever ran what last: `python -m service` mints an election into
    `election-data/` -- twelve megabytes of this machine's, which is what
    that entry in `.gitignore` exists to say -- and a patch delivered
    into `Claude outputs/` is twenty-eight more. Multiplied by the core
    count that is half a gigabyte of copying, to run a suite that reads
    none of it. Pattern-matching them one at a time would be a list that
    is correct until the next local run.

    So ask the repository rather than guess. `--others --ignored` lists
    only *untracked* ignored paths, and that distinction is what makes
    this safe to do: a tracked file is the repository's and is copied
    however it is named, while uncommitted work is untracked but not
    ignored, so it still reaches the worker -- which is the whole reason
    this copies the working tree instead of `HEAD`.

    `None` where there is no repository to ask. Not a corner case: a
    worker tree has no `.git`, and the suite it runs copies itself again.
    `NOT_COPIED` carries that second copy, and everything this would have
    dropped is already missing from it.
    """
    try:
        top = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True).stdout.strip()
        # `-C` searches upwards. Without this, a tree that merely sits
        # inside somebody else's checkout is told what that one ignores.
        if not top or Path(top).resolve() != Path(ROOT).resolve():
            return None
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--others", "--ignored",
             "--exclude-standard", "--directory", "-z"],
            capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return {entry.rstrip("/") for entry in listed.split("\0") if entry}


def worker_tree(into: pathlib.Path) -> pathlib.Path:
    """A copy of the working tree for one worker to sabotage.

    The **working** tree and not `git worktree add`, deliberately: this
    tool sabotages what is on disk, including changes not yet committed,
    and a worktree would silently test `HEAD` instead -- which is the
    worst kind of difference, since the report would look normal.

    What stays behind is `NOT_COPIED` plus whatever the repository
    ignores. Two lists because they answer two questions: the first is
    what no checkout needs, the second is what this one happens to have
    lying in it.

    One per worker rather than one per mutation. A copy is about a second
    and five megabytes; fifty-seven of them would be neither.
    """
    root = Path(ROOT).resolve()
    ignored = ignored_by_git()

    def not_copied(directory: str, names: list[str]) -> set[str]:
        skip = set(NOT_COPIED(directory, names))
        if ignored is not None:
            here = Path(directory).resolve().relative_to(root)
            skip.update(name for name in names if str(here / name) in ignored)
        return skip

    shutil.copytree(ROOT, into, ignore=not_copied, symlinks=True)
    return into


def failing_tests(tree: pathlib.Path,
                  skipped: list[str] | None = None) -> list[str]:
    """Which tests fail in this tree, and -- if asked -- which did not run.

    `skipped` is filled in rather than returned, because every caller but
    the baseline wants the failures and nothing else. See `main` for why
    anybody wants the skips.

    `PYTHONPATH` is what makes the copy count. The editable install is a
    `.pth` file, so it appends the *original* `src` to `sys.path`; without
    this the worker would mutate its own tree and import somebody else's
    `ovpoc`, and every mutation in `src/ovpoc/` would pass silently.
    `tests/service_process.py` already pins `PYTHONPATH` for the service
    subprocess and says why in its own comment -- this is the same hazard
    one level up.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *PYTEST_ARGS],
        cwd=tree,
        env=dict(os.environ,
                 PYTHONPATH=os.pathsep.join([str(tree / "src"), str(tree)])),
        capture_output=True, text=True,
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

    names, skips = parse_report(result.stdout)
    if skipped is not None:
        skipped.extend(skips)

    # A non-zero exit with nothing parsed means the output format changed and we
    # would silently under-report. Refuse rather than guess.
    if result.returncode == 1 and not names:
        raise SuiteDidNotRun(
            "pytest reported failures but none could be parsed; "
            f"output format may have changed:\n{result.stdout[-2000:]}"
        )
    return names


def run_one(mutation: Mutation, trees: "queue.Queue[pathlib.Path]") -> list[str]:
    """Apply one mutation in a borrowed tree, run the suite, give it back.

    The tree is restored rather than discarded, so a worker pays for its
    copy once. Restoring in `finally` matters less than it used to --
    nothing here touches the real checkout, so an interrupted run can no
    longer leave somebody's working tree sabotaged, which is a property
    the serial version only had as long as its cleanup actually ran.
    """
    tree = trees.get()
    try:
        target = tree / mutation.path
        original = target.read_text()
        try:
            target.write_text(original.replace(mutation.find, mutation.replace, 1))
            return failing_tests(tree)
        finally:
            target.write_text(original)
    finally:
        trees.put(tree)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--jobs", "-j", type=int, default=os.cpu_count() or 1,
        help="how many suites to run at once (default: the core count). "
             "Each gets its own copy of the working tree; the report is the "
             "same whatever this is set to.")
    args = parser.parse_args(argv)
    jobs = max(1, args.jobs)

    not_run: list[str] = []
    workspace = tempfile.TemporaryDirectory(prefix="ovpoc-sabotage-")
    root = pathlib.Path(workspace.name)
    print(f"Copying the working tree {jobs}× into {root}…")
    trees: "queue.Queue[pathlib.Path]" = queue.Queue()
    for n in range(jobs):
        trees.put(worker_tree(root / f"w{n}"))
    first = trees.queue[0]

    try:
        try:
            baseline = failing_tests(first, skipped=not_run)
        except SuiteDidNotRun as exc:
            print("Cannot run the sabotage suite: the test suite itself did not run.")
            print("Install the dev extras first:  pip install -e \".[dev]\"\n")
            print(exc)
            return 2
        if baseline:
            print("Baseline suite is not green; fix that first:", baseline)
            return 1

        # A skipped test cannot catch anything, so a mutation whose only
        # defenders are skipped is reported NOT CAUGHT -- truthfully, and about
        # the environment rather than about the code. That is the worst kind of
        # true: `docs/sabotage.md` is committed and CI diffs it, so a report
        # written here with the `pades` extra missing says a defence is
        # undefended when CI, which installs it, will say the opposite. The
        # report would describe a suite nobody else runs.
        #
        # It happened the first time an optional extra appeared. Three
        # mutations in `driver/qualified_signature.py` came back NOT CAUGHT on
        # a machine whose virtual environment predated the extra, and the only
        # thing distinguishing that from a real coverage gap was knowing which
        # patch had just landed.
        if not_run:
            print("Baseline green, but some tests did not run:\n")
            for reason in sorted(set(not_run)):
                print(f"  - {reason}")
            print("\nRefusing to write a report that describes a different suite")
            print("from the one CI runs. Each reason above says what is missing;")
            print("supply it and run again. A missing optional extra is")
            print('  pip install -e ".[dev]"')
            print("-- but a skip for anything else is a test that should not have")
            print("been written to skip, and the fix belongs in the test.")
            return 1

        print("Baseline green.\n")

        drifted: list[str] = []
        runnable: list[Mutation] = []
        for mutation in MUTATIONS:
            # Checked against the real checkout, once, before anything is
            # dispatched -- so drift is reported in the order it is listed
            # rather than whenever a worker happened to reach it.
            #
            # Not an aside. A mutation that cannot be applied tests nothing,
            # and recording it as caught -- which this did, by appending a
            # non-empty list -- reports a hole in the suite as a success. The
            # source moving out from under a mutation is exactly when the
            # mutation stops being worth anything.
            if mutation.find not in (ROOT / mutation.path).read_text():
                print(f"  !! {mutation.name}: pattern not found -- source has drifted")
                drifted.append(mutation.name)
            else:
                runnable.append(mutation)

        # Threads rather than processes: every one of them spends its life in
        # `subprocess.run`, which holds no lock worth contending for.
        #
        # `Executor.map` yields results in the order it was handed the inputs,
        # whatever order the workers finished in, so the pairing below is
        # positional. It was a dict keyed by the mutation until the first real
        # parallel run, which printed `Baseline green.` and then died on
        # `unhashable type: 'Mutation'`: a plain `@dataclass` defines `__eq__`
        # and therefore sets `__hash__` to None. Position is the better answer
        # anyway -- list order is the property being preserved, and a mapping
        # is a detour through a key to arrive back at it.
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            caught_by = list(pool.map(lambda m: run_one(m, trees), runnable))

        # Reported in list order, not completion order. The file this writes is
        # committed and CI diffs it, so a report whose rows moved with the
        # scheduler would show a diff on every run and mean nothing.
        results: list[tuple[Mutation, list[str]]] = []
        for mutation, caught in zip(runnable, caught_by):
            status = f"{len(caught)} test(s)" if caught else "NOT CAUGHT"
            print(f"  {mutation.name:<34} {status}")
            results.append((mutation, caught))

        write_report(results)
        uncaught = [m.name for m, c in results if not c]
        print(f"\nWrote docs/sabotage.md. Undetected mutations: {len(uncaught)}")
        for name in uncaught:
            print(f"  - {name}")
        if drifted:
            print(f"Mutations that could not be applied: {len(drifted)}")
            for name in drifted:
                print(f"  - {name}")

        # Exit status follows, so that a suite which has stopped defending
        # something says so to whatever runs it rather than only to whoever
        # reads the output. A mutation nobody caught and a mutation nobody
        # applied are different failures and both are failures.
        return 1 if (uncaught or drifted) else 0
    finally:
        # The trees are large enough to notice and useless the moment
        # the run ends, whichever way it ended.
        workspace.cleanup()


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
