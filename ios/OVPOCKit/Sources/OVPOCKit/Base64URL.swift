/// base64url without padding, matching `messages.b64` and `messages.unb64`.
///
/// Every binary field on the wire uses this: the blinded value, the token,
/// the ad-hoc public key, every signature, every commitment. Foundation
/// speaks standard base64 only, so the translation is here rather than
/// scattered over the call sites -- and the padding is stripped rather
/// than kept, because the Python strips it and a `=` at the end of a token
/// would be a different string in a URL path (`GET /token-replies/{c}`)
/// as well as different bytes in anything hashed.
import Foundation

public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// `nil` rather than a throw: a malformed value from the network is an
    /// ordinary outcome here, and every caller has something to say about
    /// which field it was.
    public static func decode(_ text: String) -> Data? {
        var s = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return Data(base64Encoded: s)
    }
}

extension Data {
    public var b64url: String { Base64URL.encode(self) }

    /// Lower-case hex, as `public_key_fingerprint` and the ledger heads use.
    public var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
