/// Parsing the published configuration, and the digest check over it.
import Crypto
import Foundation
import OVPOCKit
import XCTest

final class ElectionTests: XCTestCase {
    /// The configuration served by the live deployment, byte for byte.
    ///
    /// Not a fixture written here: an election minted by the setup
    /// console, copied out of `election-data/`, so that the field set this
    /// parses is the field set the service writes. A fixture of our own
    /// would agree with whatever this file assumed.
    private func committedElection() throws -> (bytes: Data, digest: String) {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let path = root.appendingPathComponent("election.json")
        let bytes = try Data(contentsOf: path)
        return (bytes, Data(SHA256.hash(data: bytes)).hex)
    }

    func testTheCommittedConfigurationParses() throws {
        let served = try committedElection()
        let election = try Election(
            bytes: served.bytes,
            digestLine: "\(served.digest)  election.json")

        XCTAssertFalse(election.electionID.isEmpty)
        XCTAssertGreaterThan(election.numChoices, 0)
        XCTAssertEqual(election.genesisHash.count, 32)
        XCTAssertEqual(election.vroStatementKey.count, 32)
        XCTAssertEqual(election.ebbStatementKey.count, 32)
        XCTAssertTrue(election.digestAgrees)

        // The office publishes a fingerprint of its own key; this
        // recomputes it from the key as served. They must agree, and the
        // whole of the pinning discipline is that a client checks rather
        // than reads.
        XCTAssertEqual(election.recomputedFingerprint, election.vroTokenKeyFingerprint)
        XCTAssertNoThrow(try election.pinnedTokenKey())
    }

    func testADigestThatDoesNotCoverTheBytesIsVisible() throws {
        let served = try committedElection()
        let election = try Election(
            bytes: served.bytes,
            digestLine: String(repeating: "f", count: 64) + "  election.json")

        // Reported, not thrown. A configuration whose digest does not
        // cover it is a tampering claim the *page* must make, and clause
        // S4 is explicit that this is demonstrable rather than
        // attributable -- there is no signature to appeal to. An
        // application that refused outright would be asserting more than
        // the artefact supports.
        XCTAssertFalse(election.digestAgrees)
        XCTAssertEqual(election.computedDigest, served.digest)
    }

    /// Absent and null both mean "no running tally".
    ///
    /// Left unset, `tally()` refuses until the close -- for the operator
    /// too. That is the article's default and not a missing field, so a
    /// parser that treated it as an error would reject the configuration
    /// the article describes.
    func testNoCadenceIsAValueAndNotAnOmission() throws {
        var json: [String: Any] = [
            "schema_version": 2,
            "election_id": "no-cadence",
            "vro_token_key_spki": Data(repeating: 9, count: 32).b64url,
            "vro_token_key_fingerprint": String(repeating: "0", count: 64),
            "vro_statement_key": Data(repeating: 1, count: 32).b64url,
            "ebb_statement_key": Data(repeating: 2, count: 32).b64url,
            "num_choices": 3,
            "genesis_hash": String(repeating: "0", count: 64),
            "opens": "2026-09-25T08:00:00Z",
            "closes": "2026-09-25T20:00:00Z",
        ]
        let absent = try Election(
            bytes: try JSONSerialization.data(withJSONObject: json), digestLine: "x f")
        XCTAssertNil(absent.tallyIntervalSeconds)

        json["tally_interval_seconds"] = NSNull()
        let explicitNull = try Election(
            bytes: try JSONSerialization.data(withJSONObject: json), digestLine: "x f")
        XCTAssertNil(explicitNull.tallyIntervalSeconds)
    }

    func testBase64URLRoundTripsAndDropsPadding() {
        for length in 0 ... 40 {
            let data = Data((0 ..< length).map { UInt8($0 & 0xFF) })
            let text = data.b64url
            XCTAssertFalse(text.contains("="), "padding must be stripped")
            XCTAssertFalse(text.contains("+") || text.contains("/"),
                           "base64url uses - and _")
            XCTAssertEqual(Base64URL.decode(text), data)
        }
    }
}
