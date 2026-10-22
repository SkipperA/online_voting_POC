/// Borrowing one of the demonstration's citizens.
///
/// **No deployment has any of this.** A wallet's signing key is generated
/// in the wallet, is hardware-bound under eIDAS, and cannot be read by
/// the application holding it, let alone fetched over a network. What
/// follows downloads a private key. It is here because of a specific and
/// temporary mismatch, and it should be deleted the moment that mismatch
/// goes away.
///
/// The mismatch: the office checks a token request against the key held
/// for that identifier in the population register, and the demonstration
/// enrols its citizens by generating their keys *server-side* — the
/// browser wallet never holds a key, it asks origin 8002 to sign. A
/// native wallet generates its own key, which nothing has ever enrolled,
/// so the office answers `NOT_IDENTIFIED`: not because the name is
/// unknown but because the key is, and the key is the credential. Typing
/// a name that is on the register does not help and should not.
///
/// Two ways to close it. The wallet enrols its own public key, which is
/// what §3.2 describes and needs `POST /voters` to accept one — and
/// founders here because the setup console sits behind an address
/// allowance and a password that a phone has no way through. Or the
/// wallet adopts a citizen the demonstration already created, which is
/// this file.
///
/// The endpoint it uses says the same thing about itself: "A real wallet
/// exposes no such endpoint. Under eIDAS the signature key is hardware-
/// bound by regulation: it cannot be read by the wallet application
/// itself, let alone returned over HTTP." Clause S1.
import Foundation

public protocol PersonaSource: Sendable {
    /// Who this demonstration has enrolled.
    func personas() async throws -> [String]
    /// That citizen's key, so this wallet can sign as them.
    func adopt(_ voterID: String) async throws -> WalletKey
}

public struct DemoPersonaClient: Sendable, PersonaSource {
    let origins: Origins

    public init(origins: Origins) { self.origins = origins }

    public func personas() async throws -> [String] {
        let body = try await HTTP.getJSON(
            origins.wallet.appendingPathComponent("personas"))
        guard let names = body["personas"] as? [String] else {
            throw TransportError.missingField("personas")
        }
        return names
    }

    /// A POST for what is plainly a read, because the identifier travels
    /// in the body as it does everywhere on that origin: `fetch` forbids
    /// a body on GET, and the alternative puts an identifier in a URL
    /// that a browser keeps in history and a server writes to a log.
    /// The native client has no such constraint and matches the browser
    /// anyway, because the endpoint is the browser's.
    public func adopt(_ voterID: String) async throws -> WalletKey {
        let body = try await HTTP.postJSON(
            origins.wallet.appendingPathComponent("keys"),
            body: ["voter_id": voterID])
        guard let seedText = body["k_s^(v)"] as? String else {
            throw TransportError.missingField("k_s^(v)")
        }
        guard let seed = Base64URL.decode(seedText) else {
            throw TransportError.malformedField("k_s^(v)")
        }
        return try WalletKey(voterID: voterID, seed: seed)
    }
}
