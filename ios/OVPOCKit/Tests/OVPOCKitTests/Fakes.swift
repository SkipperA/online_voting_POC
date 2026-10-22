/// Stand-ins for the three conversations, so the flows can be driven
/// without a service.
///
/// They answer; they do not model. The office here does not check
/// eligibility, because that is `vro.py`'s job and reimplementing it in a
/// test fake would be testing the fake. What these exist to control is
/// *timing and content of replies* -- the office has not released yet,
/// the configuration moved, the box refused -- which is what the flows
/// have to be right about.
import Crypto
import Foundation
import OVPOCKit
import XCTest
import _CryptoExtras

/// A whole election, generated once per test, with the office's private
/// key to hand so a token can actually be issued.
struct Fixture {
    let election: Election
    let officePrivate: _RSA.BlindSigning.PrivateKey<SHA384>
    let boxStatementKey: Curve25519.Signing.PrivateKey
    let bytes: Data
    let digest: String

    /// 2048 rather than 3072. These tests exercise plumbing, not
    /// cryptography -- the golden vectors already pin a full-size key --
    /// and key generation is most of their runtime.
    init(electionID: String = "flow-test", numChoices: Int = 4) throws {
        let office = try _RSA.BlindSigning.PrivateKey<SHA384>(
            keySize: .bits2048, parameters: .RSABSSA_SHA384_PSS_Deterministic)
        let spki = office.publicKey.derRepresentation
        let boxKey = Curve25519.Signing.PrivateKey()

        let body: [String: Any] = [
            "schema_version": 2,
            "election_id": electionID,
            "vro_token_key_spki": spki.b64url,
            "vro_token_key_fingerprint": Data(SHA256.hash(data: spki)).hex,
            "vro_statement_key": Data(repeating: 1, count: 32).b64url,
            "ebb_statement_key": boxKey.publicKey.rawRepresentation.b64url,
            "num_choices": numChoices,
            "genesis_hash": String(repeating: "0", count: 64),
            "tally_interval_seconds": 10,
            "opens": "2026-09-25T08:00:00Z",
            "closes": "2026-09-25T20:00:00Z",
        ]
        let bytes = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let digest = Data(SHA256.hash(data: bytes)).hex

        self.bytes = bytes
        self.digest = digest
        self.officePrivate = office
        self.boxStatementKey = boxKey
        self.election = try Election(bytes: bytes, digestLine: "\(digest)  election.json")
    }
}

final class FakeElections: ElectionReading, @unchecked Sendable {
    private let fixture: Fixture
    /// Set to simulate a mint under an open flow.
    var digestNow: String?

    init(_ fixture: Fixture) {
        self.fixture = fixture
        self.digestNow = fixture.digest
    }

    func election() async throws -> Election { fixture.election }
    func publishedDigest() async throws -> String { digestNow ?? fixture.digest }
}

final class FakeOffice: ElectionReading, TokenReplyCollecting, RequestTransmitting,
                        @unchecked Sendable {
    private let fixture: Fixture

    /// What the voter is waiting for: the office has not released until
    /// the wallet has transmitted. `nil` until then, which is `404` on
    /// the wire and `notYet` in the flow.
    private var released: [Data: Data] = [:]
    private(set) var transmitted: [AuthRequest] = []
    var outcome = "ISSUED"

    init(_ fixture: Fixture) { self.fixture = fixture }

    func election() async throws -> Election { fixture.election }
    func publishedDigest() async throws -> String { fixture.digest }

    func transmit(_ request: AuthRequest) async throws -> String {
        transmitted.append(request)
        if outcome == "ISSUED" {
            // The raw private-key operation over a value the office
            // cannot inspect -- not a signature over `c`.
            let blind = try fixture.officePrivate.blindSignature(for: request.blindedKey)
            released[request.blindedKey] = blind.rawRepresentation
        }
        return outcome
    }

    func collect(blindedKey: Data) async throws -> Data? { released[blindedKey] }
}

final class FakeBox: BallotSubmitting, @unchecked Sendable {
    private let fixture: Fixture
    private var filed: [Data: Ballot] = [:]
    var accepts = true
    var reason = "accepted"

    init(_ fixture: Fixture) { self.fixture = fixture }

    func submit(_ ballot: Ballot) async throws -> Receipt {
        if accepts { filed[ballot.adhocPublicKey] = ballot }
        let index = accepts ? filed.count - 1 : nil
        let entryHash = Data(SHA256.hash(data: ballot.signedPayload))
        let payload = Statements.ballotReceipt(
            electionID: fixture.election.electionID,
            accepted: accepts, reason: reason, index: index, entryHash: entryHash)
        let signature = try fixture.boxStatementKey.signature(for: payload)
        return try Receipt(wire: [
            "accepted": accepts,
            "reason": reason,
            "index": index as Any,
            "entry_hash": entryHash.b64url,
            "signature": Data(signature).b64url,
        ])
    }

    func find(adhocPublicKey: Data) async throws -> [String: Any]? {
        guard let ballot = filed[adhocPublicKey] else { return nil }
        return ["selection": ballot.selection,
                "adhoc_public_key": ballot.adhocPublicKey.b64url]
    }
}

/// The demonstration's citizens, without the demonstration.
///
/// Holds the keys it hands out so a test can check that what the wallet
/// signs verifies under the key the register would have for that name --
/// which is the whole of what adoption is for.
final class FakePersonas: PersonaSource, @unchecked Sendable {
    private var keys: [String: WalletKey] = [:]
    let enrolled: [String]

    init(_ enrolled: [String]) {
        self.enrolled = enrolled
        for name in enrolled { keys[name] = WalletKey(voterID: name) }
    }

    func personas() async throws -> [String] { enrolled }

    func adopt(_ voterID: String) async throws -> WalletKey {
        guard let key = keys[voterID] else {
            throw TransportError.status(404, body: "no such persona")
        }
        return key
    }

    /// What the population register would hold for that citizen.
    func certifiedKey(for voterID: String) -> Data? {
        keys[voterID]?.publicBytes
    }
}
