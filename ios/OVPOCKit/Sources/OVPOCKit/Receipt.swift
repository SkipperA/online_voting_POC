/// The box's receipt, and the check that makes it evidence.
///
/// A receipt is only worth keeping if it is verified where it is received.
/// The signature is over `receipt_payload` -- the election, the verdict,
/// the reason, the position and the entry hash -- under `k_p^(B)` as
/// published in the configuration, not under any key that arrived with the
/// receipt itself. A signature checked against a key its signer supplied
/// verifies whatever the signer likes.
///
/// What the entry hash is for: it covers this record, its position, and
/// everything before it (§3.5). A voter who keeps it can show later that
/// the published ledger no longer contains their entry -- which is a
/// stronger thing to hold than a chain head, and is why `record_receipt`
/// in the Python keeps the entry hash rather than the head.
import Foundation

public struct Receipt: Sendable, Equatable {
    public let accepted: Bool
    public let reason: String
    /// `nil` when the box declined to say where it put the entry, which
    /// the `receipt_omits_the_entry_position` mutation exists to catch:
    /// a voter who must ask the box where to look is asking the component
    /// under audit.
    public let index: Int?
    public let entryHash: Data
    public let signature: Data

    /// Public because a receipt arrives as a file as often as from a
    /// response: the voter keeps one, and the checker page already accepts
    /// an uploaded receipt and verifies it. A client that can parse one it
    /// was handed can check it, which is the point of the receipt.
    public init(wire: [String: Any]) throws {
        guard let accepted = wire["accepted"] as? Bool else {
            throw TransportError.missingField("accepted")
        }
        guard let reason = wire["reason"] as? String else {
            throw TransportError.missingField("reason")
        }
        guard let entryText = wire["entry_hash"] as? String,
              let entry = Base64URL.decode(entryText) else {
            throw TransportError.malformedField("entry_hash")
        }
        guard let signatureText = wire["signature"] as? String,
              let signature = Base64URL.decode(signatureText) else {
            throw TransportError.malformedField("signature")
        }
        self.accepted = accepted
        self.reason = reason
        self.index = wire["index"] as? Int
        self.entryHash = entry
        self.signature = signature
    }

    /// Does this receipt verify under the box's published statement key?
    ///
    /// Rebuilt from the fields rather than taken on trust, so a receipt
    /// whose verdict or position was altered in transit fails here.
    public func verifies(under election: Election) -> Bool {
        let payload = Statements.ballotReceipt(
            electionID: election.electionID,
            accepted: accepted,
            reason: reason,
            index: index,
            entryHash: entryHash)
        return Ed25519.verify(
            publicKey: election.ebbStatementKey,
            signature: signature,
            over: payload)
    }

    /// What the voter keeps. Small enough to photograph, which on a phone
    /// is what people will actually do with it.
    public var exportable: [String: Any] {
        [
            "accepted": accepted,
            "reason": reason,
            "index": index as Any,
            "entry_hash": entryHash.b64url,
            "signature": signature.b64url,
        ]
    }
}
