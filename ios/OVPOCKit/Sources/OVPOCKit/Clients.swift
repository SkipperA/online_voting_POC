/// The three conversations, kept in separate types on purpose.
///
/// `ConfigClient` is read by both apps. `OfficeRequestClient` exists only
/// in the wallet, and `OfficeReplyClient` only in the voting application:
/// the boundary §3.6 draws is between those two, and here it is a boundary
/// between two types in two binaries rather than between two browser
/// origins. The voting application cannot post `[id, c, s]` because it is
/// not linked against anything that can.
///
/// That is weaker than the browser's separation, which a reviewer should
/// know: nothing stops a future edit adding the import. What it is not is
/// decorative -- the type that would carry an identifier does not exist in
/// the voter target, so adding it is a visible act in a diff rather than a
/// forgotten `fetch`.
import Foundation

public struct ConfigClient: Sendable {
    let origins: Origins

    public init(origins: Origins) { self.origins = origins }

    /// The configuration and its published digest, fetched together.
    ///
    /// Both, always. The digest is what makes the configuration an
    /// artefact rather than whatever the origin served this second, and an
    /// app that read the object and skipped the hash would have pinned
    /// nothing.
    public func election() async throws -> Election {
        async let bytes = HTTP.getBytes(origins.config.appendingPathComponent("election.json"))
        async let line = HTTP.getBytes(
            origins.config.appendingPathComponent("election.json.sha256"))
        return try Election(
            bytes: try await bytes,
            digestLine: String(data: try await line, encoding: .utf8) ?? "")
    }

    /// Just the digest, for the staleness check.
    ///
    /// The browser surfaces poll this every five seconds and say "reload"
    /// when it moves, because a mint replaces all three key pairs and a
    /// page that pinned the old ones then reports, accurately, that
    /// nothing verifies. An app has the same problem and a worse version
    /// of it -- it may have a half-finished ballot in memory -- so the
    /// voter application checks this before each step that depends on the
    /// configuration, rather than on a timer.
    public func publishedDigest() async throws -> String {
        let data = try await HTTP.getBytes(
            origins.config.appendingPathComponent("election.json.sha256"))
        let line = String(data: data, encoding: .utf8) ?? ""
        return line.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
    }
}

/// The wallet's end of B7. Present in the wallet app and nowhere else.
public struct OfficeRequestClient: Sendable {
    let origins: Origins

    public init(origins: Origins) { self.origins = origins }

    /// Transmit `[id, c, s]` to the office, from the wallet itself.
    ///
    /// Not returned to the voting application for forwarding. §5.3 is the
    /// whole reason: were the application to carry this, one component on
    /// the voter's own device would hold both `id` and `k_p^a` together
    /// with the office's signature over their association -- the blinding
    /// would still stop the office linking voter to ballot, but the
    /// linkage would survive where it could be recorded, exported, or
    /// produced under compulsion.
    ///
    /// The outcome is all that comes back, and all the wallet reports.
    /// The identifier does not travel onward in either direction.
    @discardableResult
    public func transmit(_ request: AuthRequest) async throws -> String {
        let body = try await HTTP.postJSON(
            origins.vro.appendingPathComponent("token-requests"),
            body: request.wireBody)
        guard let outcome = body["outcome"] as? String else {
            throw TransportError.missingField("outcome")
        }
        return outcome
    }
}

/// The voting application's end of B16. It presents `c` and nothing else.
public struct OfficeReplyClient: Sendable {
    let origins: Origins

    public init(origins: Origins) { self.origins = origins }

    /// Collect `s_c`, keyed by the blinded value.
    ///
    /// `c` is the credential and no other is invented: the application
    /// generated it, it is unguessable, and §5.3 notes that an intercepted
    /// `c` yields an intercepted `s_c` and no advantage, because unblinding
    /// needs the `r` that never leaves this device.
    ///
    /// `nil` means not yet -- the voter has not consented in the wallet,
    /// or the office has the request and has not released. Not an error:
    /// waiting is the normal state of this call, and the only one the
    /// voter can do anything about.
    public func collect(blindedKey: Data) async throws -> Data? {
        let url = origins.vro
            .appendingPathComponent("token-replies")
            .appendingPathComponent(blindedKey.b64url)
        do {
            let body = try await HTTP.getJSON(url)
            guard let text = body["blind_signature"] as? String else {
                throw TransportError.missingField("blind_signature")
            }
            guard let data = Base64URL.decode(text) else {
                throw TransportError.malformedField("blind_signature")
            }
            return data
        } catch TransportError.status(404, _) {
            return nil
        }
    }
}

public struct BoxClient: Sendable {
    let origins: Origins

    public init(origins: Origins) { self.origins = origins }

    /// Submit, and take the receipt.
    public func submit(_ ballot: Ballot) async throws -> Receipt {
        let body = try await HTTP.postJSON(
            origins.ebb.appendingPathComponent("ballots"),
            body: ballot.wireBody)
        return try Receipt(wire: body)
    }

    /// What a citizen sees. The whole of it.
    ///
    /// While the box is open this carries commitments, positions, head and
    /// counts; the records are released at the close. Returned as the raw
    /// object rather than a model, because the shape changes at the close
    /// and a type that smoothed over that difference would be hiding the
    /// one thing the view exists to show.
    public func published() async throws -> [String: Any] {
        try await HTTP.getJSON(origins.ebb.appendingPathComponent("published"))
    }

    /// D3 -- find this ballot by its ad-hoc public key.
    ///
    /// The lookup handle is a secret this device generated, and the box
    /// holds nothing else about the voter. This is the cast-as-intended
    /// check of §3.7, and the article's argument is that it should be run
    /// from a *different* device -- which an app on this one cannot be.
    /// Clause O2.
    public func find(adhocPublicKey: Data) async throws -> [String: Any]? {
        let url = origins.ebb
            .appendingPathComponent("ballots")
            .appendingPathComponent(adhocPublicKey.b64url)
        do {
            return try await HTTP.getJSON(url)
        } catch TransportError.status(404, _) {
            return nil
        }
    }
}
