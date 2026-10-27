/// The document this client writes, against the bytes the office rebuilds.
///
/// Byte equality and not a looser comparison, because the office's rule is
/// byte equality: it recomputes the document from the payload it recovered
/// and compares, so a renderer one space out produces requests refused as
/// "not as rendered". There is no tolerance to be generous with.
///
/// The vector carries the whole document rather than a digest, and these
/// tests use that: on a mismatch they report the first differing offset and
/// what is on either side of it, because a digest would only say "no".
import Foundation
import XCTest

@testable import OVPOCKit

final class PDFRequestTests: XCTestCase {

    func testEveryVectorRendersExactly() throws {
        let cases = try Vectors.cases("pdf-request")
        XCTAssertGreaterThan(cases.count, 1, "the vector file did not parse")

        for c in cases {
            let blinded = try XCTUnwrap(
                Base64URL.decode(try Self.string(c.input, "blinded_key_b64url")),
                c.name)
            let payload = PDFRequest.payload(
                electionID: try Self.string(c.input, "election_id"),
                configDigest: try Self.string(c.input, "config_digest"),
                blindedKey: blinded)

            let produced = try PDFRequest.render(payload)
            let want = try XCTUnwrap(
                Base64URL.decode(try Self.string(c.expected, "document_b64")),
                c.name)

            XCTAssertEqual(produced.count, want.count, "\(c.name): wrong length")
            if produced != want {
                XCTFail("\(c.name): \(Self.firstDifference(produced, want))")
            }
        }
    }

    func testTheFingerprintMatchesTheVector() throws {
        for c in try Vectors.cases("pdf-request") {
            let blinded = try XCTUnwrap(
                Base64URL.decode(try Self.string(c.input, "blinded_key_b64url")),
                c.name)
            XCTAssertEqual(PDFRequest.fingerprint(blinded),
                           try Self.string(c.expected, "fingerprint"), c.name)
        }
    }

    static func string(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String else {
            throw Vectors.Problem.notAnObject("pdf-request.\(key)")
        }
        return value
    }

    /// The case that catches an implementation escaping in the wrong place.
    ///
    /// `(`, `)` and `\` must be escaped in a PDF literal string and must
    /// *not* be escaped in the canonical JSON the same value goes into. An
    /// implementation that does both, or neither, agrees with this one on
    /// every input except this kind.
    func testDelimitersAreEscapedOnThePageAndNotInThePayload() throws {
        let blinded = Data(repeating: 7, count: 256)
        let payload = PDFRequest.payload(
            electionID: #"demo (2026) \ beta"#,
            configDigest: String(repeating: "b", count: 64),
            blindedKey: blinded)
        let document = try PDFRequest.render(payload)
        let text = String(decoding: document, as: UTF8.self)

        // The whole line, label and all: the value is rendered *after* the
        // padded label inside one literal, so a substring beginning `(demo`
        // never occurs and an assertion looking for one fails while the
        // renderer is perfectly correct. It did.
        XCTAssertTrue(
            text.contains(#"(election            demo \(2026\) \\ beta) Tj"#),
            "the page should carry the escaped form after the padded label")
        XCTAssertTrue(text.contains(#""election_id":"demo (2026) \\ beta""#),
                      "the payload should carry the JSON form, escaped as JSON")
    }

    func testTwoRendersOfOnePayloadAreIdentical() throws {
        let payload = PDFRequest.payload(
            electionID: "demo-2026",
            configDigest: String(repeating: "a", count: 64),
            blindedKey: Data(repeating: 3, count: 256))
        XCTAssertEqual(try PDFRequest.render(payload),
                       try PDFRequest.render(payload))
    }

    /// `ő` is outside WinAnsiEncoding and rendering it as `ö` is a lie.
    ///
    /// The document is the only thing the citizen can check, so a renderer
    /// that quietly changes what it says is the one failure this design
    /// cannot tolerate. Refusing is the honest answer until a font is
    /// embedded.
    func testNonAsciiIsRefusedRatherThanTransliterated() {
        let payload = PDFRequest.payload(
            electionID: "előválasztás",
            configDigest: String(repeating: "a", count: 64),
            blindedKey: Data(repeating: 1, count: 256))
        XCTAssertThrowsError(try PDFRequest.render(payload)) { error in
            guard case PDFRequest.Failure.notRenderableAsAscii = error else {
                return XCTFail("expected a refusal about ASCII, got \(error)")
            }
        }
    }

    func testAPayloadWithTheWrongFieldsIsRefused() {
        var payload = PDFRequest.payload(
            electionID: "demo-2026",
            configDigest: String(repeating: "a", count: 64),
            blindedKey: Data(repeating: 1, count: 256))
        payload["voter_id"] = "HU-1970-0442"
        XCTAssertThrowsError(try PDFRequest.render(payload))

        payload.removeValue(forKey: "voter_id")
        payload.removeValue(forKey: "election_id")
        XCTAssertThrowsError(try PDFRequest.render(payload))
    }

    /// Padding that truncates is the obvious way to write this and wrong.
    ///
    /// `String.padding(toLength:)` shortens a string longer than the width,
    /// silently, and the three labels here are all shorter -- so the bug
    /// would not show until a label grew.
    func testPaddingNeverTruncates() {
        XCTAssertEqual(PDFRequest.padded("election", 20),
                       "election            ")
        XCTAssertEqual(PDFRequest.padded("a label longer than twenty", 20),
                       "a label longer than twenty")
    }

    // -- saying where, not just that --------------------------------------

    static func firstDifference(_ produced: Data, _ want: Data) -> String {
        let limit = min(produced.count, want.count)
        var at = limit
        for i in 0..<limit where produced[i] != want[i] { at = i; break }
        let from = max(0, at - 30)
        func window(_ d: Data) -> String {
            String(decoding: d[from..<min(d.count, at + 40)], as: UTF8.self)
                .replacingOccurrences(of: "\n", with: "\\n")
        }
        return "first difference at byte \(at)\n"
            + "  expected …\(window(want))…\n"
            + "  produced …\(window(produced))…"
    }
}
