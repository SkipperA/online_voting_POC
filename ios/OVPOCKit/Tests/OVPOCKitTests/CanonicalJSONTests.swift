/// The encoder, against the bytes Python produced.
///
/// This is the test that matters most in the package. Everything else
/// verifies a signature; this decides what the signature is over, and a
/// divergence here is invisible from either side on its own.
import CoreFoundation
import Crypto
import Foundation
import OVPOCKit
import XCTest

final class CanonicalJSONTests: XCTestCase {
    /// Rebuild each vector's input as a `CanonicalValue` tree.
    ///
    /// The vectors store inputs as ordinary JSON, so this is where the
    /// type is recovered. Only the shapes the protocol signs appear --
    /// strings, integers and nested objects -- which is the same
    /// restriction `CanonicalValue` declares.
    /// `NSNumber` is where this went wrong once, and the vector caught it.
    ///
    /// `JSONSerialization` returns every JSON number *and* every JSON
    /// boolean as `NSNumber`, and the bridge `n as? Bool` succeeds for
    /// exactly 0 and 1. So a `case let b as Bool` placed before the
    /// integer case turns the number 1 into `true` — and only the number
    /// 1, which is why `{"z":1,"a":2,"M":3,"_":4}` came out as
    /// `{"M":3,"_":4,"a":2,"z":true}` while every other numeric vector
    /// passed. A bug visible in one input out of thirteen is the kind a
    /// conformance file exists to find.
    ///
    /// The type is therefore asked rather than pattern-matched:
    /// `CFBooleanGetTypeID` is what distinguishes a JSON boolean from a
    /// JSON number once Foundation has bridged both to the same class.
    private func value(from any: Any) throws -> CanonicalValue {
        switch any {
        case let s as String:
            return .string(s)
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
            return .int(n.intValue)
        case let d as [String: Any]:
            var members: [String: CanonicalValue] = [:]
            for (k, v) in d { members[k] = try value(from: v) }
            return .object(members)
        case is NSNull:
            return .null
        default:
            throw Vectors.Problem.notAnObject("value of type \(type(of: any))")
        }
    }

    private func object(from input: [String: Any]) throws -> [String: CanonicalValue] {
        var out: [String: CanonicalValue] = [:]
        for (k, v) in input { out[k] = try value(from: v) }
        return out
    }

    func testEveryCanonicalVectorReproducesExactly() throws {
        let cases = try Vectors.cases("canonical-json")
        XCTAssertGreaterThan(cases.count, 5, "the vector file did not parse")

        for c in cases {
            let encoded = CanonicalJSON.bytes(try object(from: c.input))

            // Three expectations per case, and all three are checked: the
            // bytes, their length, and their hash. The length is not
            // redundant -- a UTF-8 encoding bug that produced the right
            // characters through the wrong bytes shows up here first and
            // most legibly.
            if let utf8 = c.expected["canonical_utf8"] as? String {
                XCTAssertEqual(
                    String(data: encoded, encoding: .utf8), utf8,
                    "\(c.name): canonical form differs")
            }
            if let length = c.expected["byte_length"] as? Int {
                XCTAssertEqual(encoded.count, length, "\(c.name): byte length differs")
            }
            if let sha = c.expected["sha256"] as? String {
                XCTAssertEqual(
                    Data(SHA256.hash(data: encoded)).hex, sha,
                    "\(c.name): digest differs")
            }
            if let b64 = c.expected["canonical_b64url"] as? String {
                XCTAssertEqual(encoded.b64url, b64, "\(c.name): base64url differs")
            }
        }
    }

    /// The three divergences a platform JSON writer would introduce.
    ///
    /// Named individually because `canonical-json` passing as a whole does
    /// not say *which* trap was avoided, and these are the three that a
    /// later refactor towards `JSONEncoder` would reintroduce one at a
    /// time. Each asserts the Python behaviour, not the Swift default.
    func testTheThreeDivergencesFromAPlatformEncoder() {
        XCTAssertEqual(
            String(data: CanonicalJSON.bytes(["path": .string("a/b")]), encoding: .utf8),
            #"{"path":"a/b"}"#,
            "the solidus must not be escaped; JSONEncoder escapes it by default")

        XCTAssertEqual(
            String(data: CanonicalJSON.bytes(["z": 1, "a": 2, "M": 3, "_": 4]),
                   encoding: .utf8),
            #"{"M":3,"_":4,"a":2,"z":1}"#,
            "keys sort by code point, not by Unicode collation")

        XCTAssertEqual(
            String(data: CanonicalJSON.bytes(["c": .string("\u{1F}")]), encoding: .utf8),
            #"{"c":"\u001f"}"#,
            "control characters take lower-case hex, as Python writes them")
    }

    func testAccentedIdentifiersSurviveAsUTF8() {
        // The failure this exists to prevent is not a crash. It is a
        // signature that verifies for every test voter and fails for
        // Kovács Ágnes, in production, once.
        let bytes = CanonicalJSON.bytes(["voter_id": .string("Kovács Ágnes")])
        XCTAssertEqual(String(data: bytes, encoding: .utf8), #"{"voter_id":"Kovács Ágnes"}"#)
        XCTAssertFalse(
            String(data: bytes, encoding: .utf8)!.contains("\\u"),
            "non-ASCII must stay as UTF-8, never as \\uXXXX")
    }
}
