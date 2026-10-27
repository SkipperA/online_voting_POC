/// Where the origins are, and which of them each app may speak to.
///
/// `service/origins.py` is the table this mirrors. Hosted, the eight
/// origins are separated by hostname: set `OVPOC_DOMAIN=diw.hu` there and
/// `config.diw.hu`, `vro.diw.hu`, `ebb.diw.hu` are what the pages address.
/// A native app has no same-origin policy to lean on, so the separation
/// here is which client type exists at all -- the wallet app is linked
/// against `OfficeClient` and the voter app is not linked against the
/// endpoint that carries an identifier.
///
/// `docs/Stage1_Surface_and_Boundary_Map.md` lists three cross-origin
/// allowances. Two of them are what these clients use: anyone may read the
/// configuration, and the voting application may collect its own reply
/// from `GET /token-replies/…`. The third is the box. Nothing here reaches
/// `POST /release-queries`, and that absence is §3.7: the token-request
/// check must be independent of the voting application.
import Foundation

public struct Origins: Sendable, Equatable {
    public let domain: String

    /// The hosted demonstration. A laptop deployment separates the origins
    /// by port instead, which a phone on a different machine cannot reach,
    /// so the default is the one that works from a device.
    public static let hosted = Origins(domain: "diw.hu")

    public init(domain: String) {
        self.domain = domain
    }

    private func origin(_ name: String) -> URL {
        URL(string: "https://\(name).\(domain)")!
    }

    /// 8000 — inert. The configuration and its digest, as static bytes.
    public var config: URL { origin("config") }
    /// 8002 — the browser demonstration's wallet.
    ///
    /// Reached by the *native wallet* and by nothing else here, and only
    /// to borrow a persona: see `DemoPersonaClient`. The voting
    /// application must never address this origin, which is why it does
    /// not appear in any voter-side type.
    public var wallet: URL { origin("wallet") }

    /// 8003 — the office. Token requests, and the reply collection.
    public var vro: URL { origin("vro") }
    /// Where a voter hands in a signed document, on the office's own
    /// origin.
    ///
    /// An address to *show* a person, never one anything here fetches.
    /// On the qualified-signature route the signed document carries the
    /// citizen's identifier, so it must not pass through the voting
    /// application — the page is served by the office and opened by the
    /// voter, in their browser. Clause A8.
    public var handIn: URL { vro.appendingPathComponent("upload") }
    /// 8004 — the ballot box. Submission, receipts, the published view.
    public var ebb: URL { origin("ebb") }
    /// 8005 — the checker. Not called by these apps; here because an
    /// audience asks where the independent checks live, and the answer is
    /// a URL they can open themselves.
    public var checker: URL { origin("checker") }
}

public enum TransportError: Error, Equatable {
    case status(Int, body: String)
    case notJSON
    case missingField(String)
    case malformedField(String)
}

enum HTTP {
    static func getJSON(_ url: URL) async throws -> [String: Any] {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        return try await send(request)
    }

    static func postJSON(_ url: URL, body: [String: Any]) async throws -> [String: Any] {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await send(request)
    }

    static func getBytes(_ url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(from: url)
        try check(response, data)
        return data
    }

    private static func send(_ request: URLRequest) async throws -> [String: Any] {
        let (data, response) = try await URLSession.shared.data(for: request)
        try check(response, data)
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw TransportError.notJSON
        }
        return object
    }

    private static func check(_ response: URLResponse, _ data: Data) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200 ..< 300).contains(http.statusCode) else {
            // The body is kept rather than discarded: the office's
            // refusals carry the one word the voter is entitled to -- and
            // only that word, since §3.2 collapses the two
            // pre-identification failures into one answer.
            throw TransportError.status(
                http.statusCode,
                body: String(data: data, encoding: .utf8) ?? "")
        }
    }
}
