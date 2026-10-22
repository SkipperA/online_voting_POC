/// Every payload kind the vectors name, rebuilt here.
///
/// `payloads.json` covers the objects whose bytes get signed. The accented
/// cases are the ones that actually catch a divergence, and they are the
/// reason this file exists rather than a round-trip test against itself.
import Foundation
import OVPOCKit
import XCTest

final class PayloadTests: XCTestCase {
    func testEveryPayloadKindMatchesTheVector() throws {
        let cases = try Vectors.cases("payloads")
        XCTAssertGreaterThan(cases.count, 4, "the vector file did not parse")

        var kindsSeen: Set<String> = []

        for c in cases {
            guard let kind = c.input["kind"] as? String else {
                throw Vectors.Problem.notAnObject("\(c.name).input.kind")
            }
            kindsSeen.insert(kind)

            let payload: Data
            switch kind {
            case "auth_request":
                guard let voterID = c.input["voter_id"] as? String,
                      let blindedText = c.input["blinded_key_b64url"] as? String,
                      let blinded = Base64URL.decode(blindedText) else {
                    throw Vectors.Problem.notAnObject("\(c.name).input")
                }
                payload = AuthRequest(voterID: voterID, blindedKey: blinded).signedPayload

            case "ballot":
                guard let selection = c.input["selection"] as? Int,
                      let keyText = c.input["adhoc_public_key_b64url"] as? String,
                      let key = Base64URL.decode(keyText),
                      let nonceText = c.input["nonce_b64url"] as? String,
                      let nonce = Base64URL.decode(nonceText) else {
                    throw Vectors.Problem.notAnObject("\(c.name).input")
                }
                // The nonce comes from the vector, not from the default.
                // A ballot built with a fresh nonce could not be pinned,
                // which is exactly why the committed input carries one.
                payload = Ballot(
                    selection: selection, adhocPublicKey: key,
                    token: Data(), nonce: nonce).signedPayload

            case "release_query":
                guard let voterID = c.input["voter_id"] as? String else {
                    throw Vectors.Problem.notAnObject("\(c.name).input")
                }
                payload = Statements.releaseQuery(voterID: voterID)

            case "denial":
                guard let voterID = c.input["voter_id"] as? String else {
                    throw Vectors.Problem.notAnObject("\(c.name).input")
                }
                payload = Statements.denial(voterID: voterID)

            default:
                // Not skipped. A vector kind this consumer does not know
                // is a protocol object it cannot build, which is a gap in
                // the client rather than a detail of the test.
                XCTFail("\(c.name): unknown payload kind \(kind)")
                continue
            }

            XCTAssertEqual(
                payload.hex, c.expected["signed_payload_sha256"] as? String,
                "\(c.name): signed payload differs from the vector")
        }

        XCTAssertEqual(
            kindsSeen, ["auth_request", "ballot", "release_query", "denial"],
            "a payload kind has appeared or vanished since this was written")
    }

    /// A negative selection is a protest ballot, not an error.
    ///
    /// Three words, not two: a selection outside the range makes the vote
    /// *invalid* while the ballot stays *accepted* and still supersedes.
    /// Nothing in this package may reject one, and the type system is
    /// where that is easiest to get wrong -- an unsigned selection would
    /// make a protest ballot unrepresentable.
    func testAProtestSelectionIsRepresentable() {
        let ballot = Ballot(
            selection: -1, adhocPublicKey: Data(repeating: 1, count: 32),
            token: Data(), nonce: Data(repeating: 2, count: 16))
        XCTAssertEqual(ballot.selection, -1)
        XCTAssertFalse(ballot.signedPayload.isEmpty)
    }

    /// Two ballots for the same selection must not be byte-identical.
    func testTheDefaultNonceIsFreshPerBallot() {
        let key = Data(repeating: 3, count: 32)
        let first = Ballot(selection: 1, adhocPublicKey: key, token: Data())
        let second = Ballot(selection: 1, adhocPublicKey: key, token: Data())
        XCTAssertNotEqual(
            first.nonce, second.nonce,
            "without a fresh nonce an operator could re-enter a superseded ballot")
        XCTAssertNotEqual(first.signedPayload, second.signedPayload)
    }
}
