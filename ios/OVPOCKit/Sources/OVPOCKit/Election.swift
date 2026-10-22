/// The published election configuration, and the check that pins it.
///
/// Mirrors `service/election.py`. The field names are the wire's, not
/// Swift's, so the mapping between the two is visible rather than inferred
/// from a `CodingKeys` block nobody reads.
import Crypto
import Foundation
import _CryptoExtras

public struct Election: Sendable, Equatable {
    public let schemaVersion: Int
    public let electionID: String
    /// `k_p^(R)`, SPKI DER, base64url. The key every token verifies under.
    public let vroTokenKeySPKI: Data
    /// The office's own published fingerprint of the above.
    public let vroTokenKeyFingerprint: String
    /// `k_p^(O)` -- office statements. Not the token key; see `CLAUDE.md`.
    public let vroStatementKey: Data
    /// `k_p^(B)` -- the box's receipts and phase acts.
    public let ebbStatementKey: Data
    public let numChoices: Int
    public let genesisHash: Data
    public let tallyIntervalSeconds: Int?
    public let opens: String
    public let closes: String

    /// The digest the config origin publishes beside the file, as read.
    /// Not recomputed from the parsed object: the hash covers the bytes
    /// that were served, and a re-serialisation of the parsed form is a
    /// different artefact that happens to mean the same thing.
    public let publishedDigest: String

    /// Recomputed here from the bytes, so `publishedDigest` is checked
    /// rather than believed.
    public let computedDigest: String

    public var digestAgrees: Bool { publishedDigest == computedDigest }

    public enum Failure: Error, Equatable {
        case notJSON
        case missing(String)
        case malformed(String)
        /// The one refusal that cannot be downgraded to a warning.
        case fingerprintMismatch(pinned: String, recomputed: String)
    }

    /// Parse the served bytes and the served digest line.
    ///
    /// `digestLine` is the whole of `election.json.sha256`, which carries
    /// the hash and the filename the way `shasum` writes it.
    public init(bytes: Data, digestLine: String) throws {
        guard let root = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
            throw Failure.notJSON
        }
        func string(_ key: String) throws -> String {
            guard let v = root[key] as? String else { throw Failure.missing(key) }
            return v
        }
        func binary(_ key: String) throws -> Data {
            guard let d = Base64URL.decode(try string(key)) else {
                throw Failure.malformed(key)
            }
            return d
        }
        func int(_ key: String) throws -> Int {
            guard let v = root[key] as? Int else { throw Failure.missing(key) }
            return v
        }

        self.schemaVersion = (root["schema_version"] as? Int) ?? 0
        self.electionID = try string("election_id")
        self.vroTokenKeySPKI = try binary("vro_token_key_spki")
        self.vroTokenKeyFingerprint = try string("vro_token_key_fingerprint")
        self.vroStatementKey = try binary("vro_statement_key")
        self.ebbStatementKey = try binary("ebb_statement_key")
        self.numChoices = try int("num_choices")
        guard let genesis = Data(hexString: try string("genesis_hash")) else {
            throw Failure.malformed("genesis_hash")
        }
        self.genesisHash = genesis
        // Absent and null both mean "no running tally", which is the
        // article's default and not a missing field.
        self.tallyIntervalSeconds = root["tally_interval_seconds"] as? Int
        self.opens = try string("opens")
        self.closes = try string("closes")

        self.publishedDigest = digestLine
            .split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        self.computedDigest = Data(SHA256.hash(data: bytes)).hex
    }

    /// The fingerprint of the key as served, recomputed from the SPKI.
    public var recomputedFingerprint: String {
        Data(SHA256.hash(data: vroTokenKeySPKI)).hex
    }

    /// Refuse to proceed under a key that is not the pinned one.
    ///
    /// A VRO free to use a different signing key per voter would defeat
    /// blinding outright -- it could later tell which of its keys verifies
    /// a given ballot, and so which voter cast it. The defence is that
    /// there is one published key and every client checks it before
    /// submitting anything. This throws; it does not warn, and it is not
    /// optional. `Voter.build_auth_request` is the same refusal in Python.
    public func pinnedTokenKey() throws -> _RSA.BlindSigning.PublicKey<SHA384> {
        let recomputed = recomputedFingerprint
        guard recomputed == vroTokenKeyFingerprint else {
            throw Failure.fingerprintMismatch(
                pinned: vroTokenKeyFingerprint, recomputed: recomputed)
        }
        return try _RSA.BlindSigning.PublicKey<SHA384>(
            derRepresentation: vroTokenKeySPKI,
            parameters: .RSABSSA_SHA384_PSS_Deterministic)
    }
}

extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i ... i + 1]), radix: 16) else { return nil }
            out.append(byte)
        }
        self = out
    }
}
