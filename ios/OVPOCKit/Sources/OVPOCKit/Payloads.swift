/// The objects whose bytes get signed, and nothing else.
///
/// One file, because the whole of the interop risk lives here: an
/// implementation that builds any of these differently produces
/// signatures the others reject. Each is checked against
/// `tests/vectors/payloads.json`, which is generated from
/// `src/ovpoc/messages.py` and consumed by both sides.
///
/// Note what the ballot does *not* carry: nothing identifying the voter.
/// The link to eligibility runs only through `token`, the office's blind
/// signature over `adhocPublicKey`.
import Crypto
import Foundation

/// Steps 3–4: the authentication request `[id, c, s]`.
///
/// Built by the voter application as far as `c`, and completed by the
/// wallet, which is the only component that knows `voterID`. The
/// application never holds a populated one of these: it holds `c`.
public struct AuthRequest: Sendable, Equatable {
    public let voterID: String
    public let blindedKey: Data
    public var walletSignature: Data

    public init(voterID: String, blindedKey: Data, walletSignature: Data = Data()) {
        self.voterID = voterID
        self.blindedKey = blindedKey
        self.walletSignature = walletSignature
    }

    /// `hash([id, c])` -- exactly the bytes the wallet signs.
    public var signedPayload: Data {
        CanonicalJSON.digest([
            "voter_id": .string(voterID),
            "blinded_key": .string(blindedKey.b64url),
        ])
    }

    public var wireBody: [String: Any] {
        [
            "voter_id": voterID,
            "blinded_key": blindedKey.b64url,
            "wallet_signature": walletSignature.b64url,
        ]
    }
}

/// Step 9: the ballot `[i, k_p^a, s_{k_p^a}, n, s_vote]`.
public struct Ballot: Sendable, Equatable {
    public let selection: Int
    public let adhocPublicKey: Data
    public let token: Data
    public let nonce: Data
    public var voteSignature: Data

    /// The nonce defaults to fresh bytes for the reason `messages.py`
    /// gives at length: Ed25519 is deterministic and the signed payload
    /// names only the selection and the key, so without it a voter's two
    /// submissions of the same selection are byte-identical, and an
    /// operator could re-enter a ballot the voter had already superseded.
    /// Freshness is a property of constructing a ballot, not a discipline
    /// the caller has to remember -- which is why this is a default and
    /// not a parameter the UI passes.
    public init(
        selection: Int,
        adhocPublicKey: Data,
        token: Data,
        nonce: Data = Data((0 ..< 16).map { _ in UInt8.random(in: .min ... .max) }),
        voteSignature: Data = Data()
    ) {
        self.selection = selection
        self.adhocPublicKey = adhocPublicKey
        self.token = token
        self.nonce = nonce
        self.voteSignature = voteSignature
    }

    /// `hash([i, k_p^a, n])` -- the bytes the ad-hoc key signs.
    public var signedPayload: Data {
        CanonicalJSON.digest([
            "selection": .int(selection),
            "adhoc_public_key": .string(adhocPublicKey.b64url),
            "nonce": .string(nonce.b64url),
        ])
    }

    public var wireBody: [String: Any] {
        [
            "selection": selection,
            "adhoc_public_key": adhocPublicKey.b64url,
            "token": token.b64url,
            "nonce": nonce.b64url,
            "vote_signature": voteSignature.b64url,
        ]
    }
}

/// The statements the two authorities sign, as the clients must rebuild
/// them to verify. Domain-separated by a `statement` or `query` field, so
/// a signature captured in one role cannot be replayed in another.
public enum Statements {
    /// What the box signs when it issues a receipt (`receipt_payload`).
    public static func ballotReceipt(
        electionID: String, accepted: Bool, reason: String,
        index: Int?, entryHash: Data
    ) -> Data {
        CanonicalJSON.digest([
            "statement": .string("ballot-receipt"),
            "election_id": .string(electionID),
            "accepted": .bool(accepted),
            "reason": .string(reason),
            "index": index.map { CanonicalValue.int($0) } ?? .null,
            "entry_hash": .string(entryHash.b64url),
        ])
    }

    /// What the voter signs to authenticate a step-12 release query.
    public static func releaseQuery(voterID: String) -> Data {
        CanonicalJSON.digest([
            "query": .string("token-release"),
            "voter_id": .string(voterID),
        ])
    }

    /// What the office signs when it denies a release.
    ///
    /// Here so the Swift side covers every payload kind the vectors name,
    /// rather than four of five. Neither app performs a step-12 query --
    /// §3.7 requires that check to be independent of the voting
    /// application, which is why it lives on the checker -- but a signed
    /// denial is the one object in that exchange a voter might be handed
    /// by someone else and want to check, and a client that can rebuild
    /// the payload can check it.
    ///
    /// Worth repeating what it is worth: signing a denial does not stop a
    /// dishonest office denying a token it minted. It makes the denial
    /// attributable if later contradicted. It is not prevention and must
    /// not be described as any.
    public static func denial(voterID: String) -> Data {
        CanonicalJSON.digest([
            "statement": .string("no-token-released"),
            "voter_id": .string(voterID),
        ])
    }

    /// The three domain separators, named so a reader can see that they
    /// are three and not one. A signature captured in one role must not
    /// replay in another, and the only thing stopping that is that these
    /// strings differ.
    public static let domains = [
        "ballot-receipt", "token-release", "no-token-released",
    ]
}
