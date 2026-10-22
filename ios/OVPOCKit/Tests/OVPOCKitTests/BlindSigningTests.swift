/// The voter's half of RFC 9474, against the published test key.
///
/// `rsabssa.json` cannot be consumed directly and the vector file says
/// why: `blind` is randomised, so its output is committed as an *input*
/// and everything downstream of it is deterministic. The Python consumer
/// can inject the pinned `r_inv`; this one cannot, because
/// `_CryptoExtras.BlindingInverse` has no initialiser and no accessor --
/// "users cannot create values of this type manually", by design.
///
/// So the round trip is performed instead, using the private key from
/// `keys.json`: blind here, sign with the office's key, unblind here,
/// verify. That is weaker than reproducing a pinned signature and it is
/// not weak: it establishes that this client's `c` is signable by the
/// office's actual key and that what comes back unblinds to an ordinary
/// RSASSA-PSS signature over `k_p^a`. Interoperability of the *parameters*
/// -- SHA-384, PSS, 48-byte salt, identity preparation -- is what would
/// break if the two implementations drifted, and it is what this catches.
import Crypto
import Foundation
import OVPOCKit
import XCTest
import _CryptoExtras

final class BlindSigningTests: XCTestCase {
    private func testKeys() throws -> (private: Data, public: Data, bits: Int) {
        let body = try Vectors.load("keys")
        guard let privateText = body["vro_private_key_pkcs8_der"] as? String,
              let publicText = body["vro_public_key_spki_der"] as? String,
              let priv = Base64URL.decode(privateText),
              let pub = Base64URL.decode(publicText),
              let bits = body["modulus_bits"] as? Int else {
            throw Vectors.Problem.notAnObject("keys")
        }
        return (priv, pub, bits)
    }

    /// The whole of what the voter's device does, end to end.
    func testTheRoundTripProducesAnOrdinaryPSSSignature() throws {
        let material = try testKeys()
        XCTAssertEqual(material.bits, 3072, "the published test key has changed size")

        let office = try _RSA.BlindSigning.PrivateKey<SHA384>(
            derRepresentation: material.private,
            parameters: .RSABSSA_SHA384_PSS_Deterministic)
        let published = try _RSA.BlindSigning.PublicKey<SHA384>(
            derRepresentation: material.public,
            parameters: .RSABSSA_SHA384_PSS_Deterministic)

        // The message is the ad-hoc public key, as it is in the protocol.
        let adhoc = AdHocKey()
        let prepared = published.prepare(adhoc.publicBytes)
        let blinding = try published.blind(prepared)

        // What the office does: the raw private-key operation, over a
        // value it cannot inspect. Not a signature over `c`.
        let blindSignature = try office.blindSignature(for: blinding.blindedMessage)

        let token = try published.finalize(
            blindSignature, for: prepared, blindingInverse: blinding.inverse)

        XCTAssertTrue(published.isValidSignature(token, for: prepared))
        XCTAssertEqual(
            token.rawRepresentation.count, material.bits / 8,
            "a token is one modulus wide; \(material.bits / 8) bytes here")

        // The property the whole project leans on: what comes out is an
        // ordinary RSASSA-PSS signature over `k_p^a`, so an independent
        // verifier needs no bespoke cryptography. Checked through the
        // plain signing key rather than the blind-signing one, which is
        // the point -- a stock verifier would have only this.
        //
        // The digest is passed explicitly, and that is not fussiness.
        // `isValidSignature(_:for:padding:)` taking `DataProtocol` hashes
        // with SHA-256 -- its own documentation says so -- so handing it
        // `k_p^a` directly would check a SHA-384 token against a SHA-256
        // encoding and report, quietly, that the signature is invalid.
        // The failure would look like a blinding bug and be a one-word
        // mistake at the call site.
        let stock = try _RSA.Signing.PublicKey(derRepresentation: material.public)
        XCTAssertTrue(stock.isValidSignature(
            _RSA.Signing.RSASignature(rawRepresentation: token.rawRepresentation),
            for: SHA384.hash(data: adhoc.publicBytes),
            padding: .PSS))
    }

    /// A reply that is not a signature over this `c` must be refused here,
    /// not carried to the ballot box.
    ///
    /// `rsabssa.finalize` performs the same check and
    /// `test_attacks.py::test_finalize_rejects_a_dishonest_vro_response`
    /// shows it failing. A voter who accepts a bad reply finds out at the
    /// box, by which time the entitlement is spent.
    func testADishonestReplyIsRefusedAtUnblinding() throws {
        let material = try testKeys()
        let election = try fixtureElection(publicKey: material.public)
        let adhoc = AdHocKey()
        let blinding = try Blinding(adhocPublicKey: adhoc.publicBytes, under: election)

        let rubbish = Data(repeating: 0xAB, count: material.bits / 8)
        XCTAssertThrowsError(try blinding.finalize(blindSignature: rubbish)) { error in
            XCTAssertEqual(error as? Blinding.Failure, .replyDoesNotVerify)
        }
    }

    /// Nothing is blinded under a key that has not been pinned.
    ///
    /// A VRO free to use a different key per voter defeats blinding
    /// outright: it could later tell which of its keys verifies a given
    /// ballot. `Voter.build_auth_request` refuses on a fingerprint
    /// mismatch and so does this, and both refusals are load-bearing
    /// rather than advisory.
    func testASubstitutedKeyIsRefusedBeforeAnythingIsBlinded() throws {
        let material = try testKeys()
        var json = fixtureJSON(publicKey: material.public)
        json["vro_token_key_fingerprint"] = String(repeating: "0", count: 64)
        let bytes = try JSONSerialization.data(withJSONObject: json)
        let election = try Election(bytes: bytes, digestLine: "unused election.json")

        XCTAssertThrowsError(
            try Blinding(adhocPublicKey: Data(repeating: 7, count: 32), under: election)
        ) { error in
            guard case .fingerprintMismatch = error as? Election.Failure else {
                return XCTFail("expected a fingerprint mismatch, got \(error)")
            }
        }
    }

    // -- fixtures ---------------------------------------------------------

    private func fixtureJSON(publicKey: Data) -> [String: Any] {
        [
            "schema_version": 2,
            "election_id": "swift-test",
            "vro_token_key_spki": publicKey.b64url,
            "vro_token_key_fingerprint": Data(SHA256.hash(data: publicKey)).hex,
            "vro_statement_key": Data(repeating: 1, count: 32).b64url,
            "ebb_statement_key": Data(repeating: 2, count: 32).b64url,
            "num_choices": 4,
            "genesis_hash": String(repeating: "0", count: 64),
            "tally_interval_seconds": 10,
            "opens": "2026-09-25T08:00:00Z",
            "closes": "2026-09-25T20:00:00Z",
        ]
    }

    private func fixtureElection(publicKey: Data) throws -> Election {
        let bytes = try JSONSerialization.data(withJSONObject: fixtureJSON(publicKey: publicKey))
        return try Election(bytes: bytes, digestLine: "unused election.json")
    }
}
