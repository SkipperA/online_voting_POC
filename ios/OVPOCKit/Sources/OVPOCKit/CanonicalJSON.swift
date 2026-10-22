/// Canonical serialisation, written out rather than delegated.
///
/// A signature is over *bytes*. If this file and `src/ovpoc/messages.py`
/// disagree about how a ballot serialises, signatures made here fail to
/// verify there, and they fail only for the inputs where the two differ --
/// which, in practice, means only for voters whose identifier carries an
/// accent. No test written against one implementation can show that.
///
/// `JSONEncoder` is not used, and this is the reason. With
/// `.sortedKeys` it is close enough to be tempting and wrong in three
/// separate ways:
///
///   * it escapes the solidus as `\/` unless `.withoutEscapingSlashes` is
///     set, and Python never escapes it;
///   * `.sortedKeys` orders by `String`'s own comparison, which is
///     Unicode-aware; Python's `sort_keys` orders by code point. The
///     `key-order-is-not-insertion-order` vector pins the latter;
///   * it offers no control over which control characters take their
///     short form, and Python's choice is specific: `\b \f \n \r \t` short,
///     every other C0 character as `\u00xx` in *lower-case* hex.
///
/// Each of those is a silent divergence rather than an error, so the whole
/// encoding is spelled out here and checked against
/// `tests/vectors/canonical-json.json`, which is the same file the Python
/// implementation is checked against. Six lines of platform convenience
/// are not worth a signature that fails for Kovács Ágnes and nobody else.
import Crypto
import Foundation

/// A value that can appear in something this protocol signs.
///
/// Deliberately narrow: the payloads are small, fixed objects named in
/// `docs/wire-contract.md`, and every binary field reaches them already
/// base64url-encoded as a string. Floating point is absent because nothing
/// signed here contains any, and admitting it would mean deciding how to
/// render it -- a decision with no right answer and several plausible
/// wrong ones.
public enum CanonicalValue: Equatable, Sendable {
    case string(String)
    case int(Int)
    case bool(Bool)
    case null
    case object([String: CanonicalValue])
}

extension CanonicalValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}

extension CanonicalValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) { self = .int(value) }
}

extension CanonicalValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}

public enum CanonicalJSON {
    /// The bytes. Sorted keys, no whitespace, UTF-8, minimal escaping.
    public static func bytes(_ object: [String: CanonicalValue]) -> Data {
        var out = Data()
        write(.object(object), into: &out)
        return out
    }

    /// `SHA-256` over those bytes -- what every signature in this protocol
    /// is actually computed over. `messages.digest` in the Python.
    public static func digest(_ object: [String: CanonicalValue]) -> Data {
        Data(SHA256.hash(data: bytes(object)))
    }

    private static func write(_ value: CanonicalValue, into out: inout Data) {
        switch value {
        case .string(let s):
            writeString(s, into: &out)
        case .int(let n):
            out.append(contentsOf: Array(String(n).utf8))
        case .bool(let b):
            out.append(contentsOf: Array((b ? "true" : "false").utf8))
        case .null:
            out.append(contentsOf: Array("null".utf8))
        case .object(let members):
            // Code point order, which for Swift means ordering by unicode
            // scalars rather than by `<` on String. `"M" < "_" < "a" < "z"`
            // happens to agree either way; a key outside ASCII would not,
            // and relying on agreement that holds only for the keys we
            // happen to use now is how this breaks later.
            let keys = members.keys.sorted { lexicographicallyPrecedes($0, $1) }
            out.append(UInt8(ascii: "{"))
            for (i, key) in keys.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                writeString(key, into: &out)
                out.append(UInt8(ascii: ":"))
                write(members[key]!, into: &out)
            }
            out.append(UInt8(ascii: "}"))
        }
    }

    private static func lexicographicallyPrecedes(_ a: String, _ b: String) -> Bool {
        var left = a.unicodeScalars.makeIterator()
        var right = b.unicodeScalars.makeIterator()
        while true {
            switch (left.next(), right.next()) {
            case (nil, nil): return false
            case (nil, _): return true
            case (_, nil): return false
            case (let x?, let y?):
                if x.value != y.value { return x.value < y.value }
            }
        }
    }

    /// Python's `json.dumps(..., ensure_ascii=False)`, exactly.
    ///
    /// Non-ASCII passes through as UTF-8. Quote and backslash are escaped.
    /// Five control characters take their short form and the rest take
    /// `\u00xx` with lower-case hex digits -- the case matters, because it
    /// is in the bytes being hashed. The solidus is left alone.
    private static func writeString(_ s: String, into out: inout Data) {
        out.append(UInt8(ascii: "\""))
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"":
                out.append(contentsOf: Array("\\\"".utf8))
            case "\\":
                out.append(contentsOf: Array("\\\\".utf8))
            case "\u{08}":
                out.append(contentsOf: Array("\\b".utf8))
            case "\u{0C}":
                out.append(contentsOf: Array("\\f".utf8))
            case "\n":
                out.append(contentsOf: Array("\\n".utf8))
            case "\r":
                out.append(contentsOf: Array("\\r".utf8))
            case "\t":
                out.append(contentsOf: Array("\\t".utf8))
            default:
                if scalar.value < 0x20 {
                    out.append(contentsOf: Array(String(format: "\\u%04x", scalar.value).utf8))
                } else {
                    out.append(contentsOf: Array(String(scalar).utf8))
                }
            }
        }
        out.append(UInt8(ascii: "\""))
    }
}
