/// The token request as a document the citizen's own wallet will sign.
///
/// What `src/ovpoc/pdfrequest.py` is to the office, this is to the voting
/// application, and the two must agree **byte for byte**. That is a stronger
/// requirement than the rest of the wire contract and worth saying why: the
/// office does not read an uploaded document, it *rebuilds* it from the
/// payload it recovered and compares. So a renderer here that puts one space
/// in a different place does not produce a document that is formatted oddly.
/// It produces a document the office refuses as "not as rendered" -- a
/// message about the request which is really a message about this file.
///
/// `tests/vectors/pdf-request.json` carries the whole document, not just its
/// digest, for exactly that reason: a digest tells this implementation it is
/// wrong, the bytes tell it where. `PDFRequestTests` reads them.
///
/// WHY THERE IS A PDF WRITER IN HERE AT ALL
/// -----------------------------------------
/// PDFKit and `UIGraphicsPDFRenderer` both produce a PDF, and neither
/// produces *these* bytes: they stamp creation dates and random `/ID`s, and
/// offer no way to attach an embedded file stream. Determinism rules the
/// platform APIs out, and it is not negotiable -- the office cannot rebuild
/// a document whose renderer read a clock. What iOS does give for free is
/// *displaying* the document to the voter before they carry it to the
/// wallet, which is worth having and is not the same job.
///
/// WHAT THE WALLET REQUIRES, ESTABLISHED BY EXPERIMENT
/// ---------------------------------------------------
/// The `/Info` dictionary is not decoration. A document without one is
/// refused by the DAP application outright, before any signature is
/// attempted, as a file with "content problems" -- found by signing a ladder
/// of documents on a phone, not by reading anything. Its dates are constants
/// for the determinism reason above; see `_INFO_DATE` in the Python.
///
/// ASCII, AND WHY A REFUSAL IS THE HONEST ANSWER
/// ----------------------------------------------
/// Three of the standard fourteen fonts, so no font binary becomes a second
/// artefact to keep identical across two languages -- and therefore
/// WinAnsiEncoding, which has no `ő` and no `ű`. A renderer that quietly
/// transliterated them would be changing what the document says, and the
/// document is the only thing the citizen can check. So non-ASCII throws.
import Crypto
import Foundation

public enum PDFRequest {
    /// The three fields, and no fourth. A fourth would be a field the office
    /// might one day read, and the first thing anybody would put in it is
    /// whose request this is -- a document that names its own author.
    public static let fields = ["blinded_key", "config_digest", "election_id"]

    public static let marker = "%OVPOC-REQUEST "
    public static let embeddedName = "ovpoc-request.json"
    public static let infoDate = "D:20260101000000Z"

    static let pageWidth = 595
    static let pageHeight = 842
    static let margin = 56.0

    public enum Failure: Error, Equatable {
        /// A field this renderer cannot put on a page without changing it.
        case notRenderableAsAscii(String)
        case notATokenRequestPayload([String])
    }

    // -- the payload --------------------------------------------------

    public static func payload(
        electionID: String, configDigest: String, blindedKey: Data
    ) -> [String: String] {
        [
            "blinded_key": blindedKey.b64url,
            "config_digest": configDigest,
            "election_id": electionID,
        ]
    }

    /// The sixty-four bits of `c` a person is asked to compare.
    ///
    /// The base64 of `c` is 512 characters and nobody checks that by eye.
    /// What the citizen compares is this, shown identically on the page and
    /// by the application: four groups of four hex digits. Sixty-four bits
    /// is ample, because the attack it must resist is a targeted second
    /// preimage -- a *different* `c` with this same fingerprint -- and not a
    /// birthday collision between two values of an adversary's choosing.
    public static func fingerprint(_ blindedKey: Data) -> String {
        let digest = SHA256.hash(data: blindedKey)
        let hex = digest.prefix(8).map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: 16, by: 4)
            .map { String(Array(hex)[$0..<($0 + 4)]) }
            .joined(separator: "-")
    }

    // -- writing --------------------------------------------------------

    /// A PDF literal string. Three characters escape, in this order.
    static func text(_ s: String) throws -> Data {
        guard s.allSatisfy({ $0.isASCII }) else {
            throw Failure.notRenderableAsAscii(s)
        }
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "(", with: "\\(")
            .replacingOccurrences(of: ")", with: "\\)")
        return Data(("(" + escaped + ")").utf8)
    }

    /// `f"{label:<20}"`. Pads and never truncates, unlike
    /// `String.padding(toLength:)`, which silently would.
    static func padded(_ label: String, _ width: Int) -> String {
        label.count >= width ? label
            : label + String(repeating: " ", count: width - label.count)
    }

    /// `f"{value:g}"`, which for every coordinate here is a whole number.
    static func g(_ value: Double) -> String { String(format: "%g", value) }

    struct Line { let font: String; let size: Int; let x: Double
                  let y: Double; let body: String }

    /// What the document says, which is the only part of it a citizen can
    /// check. Mirrors `pdfrequest._lines`; the prose is compared against
    /// that function by `tests/test_native_sources.py`, so an edit to one
    /// and not the other is caught without a Mac.
    static func lines(_ payload: [String: String]) -> [Line] {
        let blindedText = payload["blinded_key"] ?? ""
        let x = margin
        var out: [Line] = []
        var y = Double(pageHeight) - 72.0

        out.append(Line(font: "F3", size: 16, x: x, y: y, body: "TOKEN REQUEST"))
        y -= 20
        out.append(Line(font: "F1", size: 9, x: x, y: y,
                        body: "Anonymous Authenticated Ballot System. This is not a ballot."))

        y -= 30
        let blinded = Base64URL.decode(blindedText) ?? Data()
        for (label, value) in [
            ("election", payload["election_id"] ?? ""),
            ("configuration", payload["config_digest"] ?? ""),
            ("fingerprint of c", fingerprint(blinded)),
        ] {
            out.append(Line(font: "F2", size: 9, x: x, y: y,
                            body: padded(label, 20) + value))
            y -= 13
        }

        y -= 16
        for sentence in [
            "By signing this document I request one ballot token for the election named",
            "above. The document does not record, and cannot record, how I will vote: the",
            "value below conceals the key that will carry my ballot, and the office that",
            "signs the token never sees that key. The fingerprint above is of that value,",
            "and should match the one shown by the application that produced this file.",
        ] {
            out.append(Line(font: "F1", size: 9, x: x, y: y, body: sentence))
            y -= 12
        }

        y -= 16
        out.append(Line(font: "F1", size: 9, x: x, y: y,
                        body: "c - the blinded ad-hoc public key, base64url, 64 characters to the line:"))
        y -= 16
        let characters = Array(blindedText)
        var i = 0
        while i < characters.count {
            let end = min(i + 64, characters.count)
            out.append(Line(font: "F2", size: 8, x: x, y: y,
                            body: String(characters[i..<end])))
            y -= 10
            i += 64
        }

        y -= 18
        for sentence in [
            "The same three values are carried in an embedded file and in a marker",
            "comment. The office rebuilds this document from them and refuses the",
            "file if what it rebuilds is not what it was given.",
        ] {
            out.append(Line(font: "F1", size: 8, x: x, y: y, body: sentence))
            y -= 10
        }
        return out
    }

    static func content(_ payload: [String: String]) throws -> Data {
        var out = Data()
        for line in lines(payload) {
            out.append(Data("BT /\(line.font) \(line.size) Tf ".utf8))
            out.append(Data("\(g(line.x)) \(g(line.y)) Td ".utf8))
            out.append(try text(line.body))
            out.append(Data(" Tj ET\n".utf8))
        }
        return out
    }

    /// The document, as a pure function of the payload.
    ///
    /// Object order is fixed, offsets are computed, and there is no value in
    /// here a holder of the payload could not reproduce.
    public static func render(_ payload: [String: String]) throws -> Data {
        guard Set(payload.keys) == Set(fields),
              let blindedText = payload["blinded_key"],
              Base64URL.decode(blindedText) != nil else {
            throw Failure.notATokenRequestPayload(payload.keys.sorted())
        }
        let body = CanonicalJSON.bytes(
            Dictionary(uniqueKeysWithValues:
                fields.map { ($0, CanonicalValue.string(payload[$0]!)) }))
        let page = try content(payload)

        // Derived. A random `/ID` is the commonest reason two runs of a PDF
        // writer disagree, and the trailer is inside the signed bytes.
        let ident = SHA256.hash(data: body)
            .map { String(format: "%02x", $0) }.joined()
            .prefix(32).uppercased()

        func ref(_ n: Int) -> String { "\(n) 0 R" }

        var objects: [Data] = []
        objects.append(Data((
            "<< /Type /Catalog /Pages \(ref(2)) /AF [ \(ref(8)) ]"
            + " /Names << /EmbeddedFiles << /Names [ (\(embeddedName)) \(ref(8))"
            + " ] >> >> >>").utf8))
        objects.append(Data("<< /Type /Pages /Kids [ \(ref(3)) ] /Count 1 >>".utf8))
        objects.append(Data((
            "<< /Type /Page /Parent \(ref(2)) /MediaBox [ 0 0 "
            + "\(pageWidth) \(pageHeight) ] /Resources << /Font << /F1 \(ref(4))"
            + " /F2 \(ref(5)) /F3 \(ref(6)) >> >> /Contents \(ref(7)) >>").utf8))
        for face in ["Helvetica", "Courier", "Helvetica-Bold"] {
            objects.append(Data((
                "<< /Type /Font /Subtype /Type1 /BaseFont /\(face)"
                + " /Encoding /WinAnsiEncoding >>").utf8))
        }
        var contentObject = Data("<< /Length \(page.count) >>\nstream\n".utf8)
        contentObject.append(page)
        contentObject.append(Data("\nendstream".utf8))
        objects.append(contentObject)
        objects.append(Data((
            "<< /Type /Filespec /F (\(embeddedName)) /UF (\(embeddedName))"
            + " /AFRelationship /Source"
            + " /Desc (The three values this document states, as canonical JSON.)"
            + " /EF << /F \(ref(9)) >> >>").utf8))
        var embedded = Data((
            "<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length "
            + "\(body.count) /Params << /Size \(body.count) >> >>\nstream\n").utf8)
        embedded.append(body)
        embedded.append(Data("\nendstream".utf8))
        objects.append(embedded)
        objects.append(Data((
            "<< /Title (Token request)"
            + " /Subject (Anonymous Authenticated Ballot System)"
            + " /Producer (ovpoc) /Creator (ovpoc)"
            + " /CreationDate (\(infoDate)) /ModDate (\(infoDate)) >>").utf8))

        var out = Data("%PDF-1.7\n".utf8)
        out.append(Data([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]))
        out.append(Data(marker.utf8))
        out.append(body)
        out.append(Data("\n".utf8))

        var offsets: [Int] = []
        for (index, object) in objects.enumerated() {
            offsets.append(out.count)
            out.append(Data("\(index + 1) 0 obj\n".utf8))
            out.append(object)
            out.append(Data("\nendobj\n".utf8))
        }

        let startxref = out.count
        out.append(Data("xref\n0 \(objects.count + 1)\n".utf8))
        out.append(Data("0000000000 65535 f \n".utf8))
        for offset in offsets {
            out.append(Data((String(format: "%010d", offset) + " 00000 n \n").utf8))
        }
        out.append(Data((
            "trailer\n<< /Size \(objects.count + 1) /Root \(ref(1))"
            + " /Info \(ref(10)) /ID [ <\(ident)> <\(ident)> ] >>\n").utf8))
        out.append(Data("startxref\n\(startxref)\n%%EOF\n".utf8))
        return out
    }
}
