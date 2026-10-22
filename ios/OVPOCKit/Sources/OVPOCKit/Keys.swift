/// The two Ed25519 key pairs, and what each is allowed to do.
///
/// `keys.py` keeps its interface narrow so a real wallet key -- ECDSA
/// P-256 in a secure element, under eIDAS -- can be swapped in. The same
/// discipline here: these wrap `Curve25519.Signing` and expose signing and
/// the public bytes, and the ad-hoc one additionally exposes its seed,
/// because that is the one thing the voter application must be able to
/// keep across a restart.
///
/// The wallet key does not expose its seed. On a device it would live in
/// the Secure Enclave and be unreadable by the application holding it; the
/// demonstration cannot reproduce that, but it can decline to build the
/// accessor that would make the difference invisible.
import Crypto
import Foundation

/// `k_s^a, k_p^a` -- one key pair, for one election, generated on the
/// device and discarded when the election ends. Its public half is what
/// the office blind-signs; its private half signs the ballot and nothing
/// else, and is the voter's handle on their own ballot (variant B, see
/// `handles.py`).
public struct AdHocKey: Sendable {
    private let key: Curve25519.Signing.PrivateKey

    public init() {
        self.key = Curve25519.Signing.PrivateKey()
    }

    /// Restore from a seed kept across a restart.
    ///
    /// Worth being exact about what this does and does not rescue. The
    /// ad-hoc key is recoverable because its bytes are. The *blinding
    /// inverse* is not: `_CryptoExtras` gives it no accessor and no
    /// initialiser, by design, so a voter application that is terminated
    /// between blinding and unblinding cannot resume -- the token exists,
    /// `s_c` can still be collected, and nothing can unblind it. See
    /// clause A9 in `docs/Demo_Scope_Limits.md`.
    public init(seed: Data) throws {
        self.key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public var publicBytes: Data { key.publicKey.rawRepresentation }

    /// Kept only so the key survives the app being suspended mid-flow.
    public var seed: Data { key.rawRepresentation }

    public func sign(_ data: Data) throws -> Data {
        try key.signature(for: data)
    }
}

/// `k_s^(v), k_p^(v)` -- the identified wallet key. One citizen, one key.
///
/// In the browser demonstration one origin holds several of these so that
/// a single machine can play a whole electorate (clause A3). A wallet
/// *application* has exactly one owner, so there is no persona parameter
/// here: the identifier it signs for is a property of the installation.
public struct WalletKey: Sendable {
    private let key: Curve25519.Signing.PrivateKey
    public let voterID: String

    public init(voterID: String) {
        self.voterID = voterID
        self.key = Curve25519.Signing.PrivateKey()
    }

    public init(voterID: String, seed: Data) throws {
        self.voterID = voterID
        self.key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public var publicBytes: Data { key.publicKey.rawRepresentation }

    /// Only so the demonstration's persona survives a reinstall. A
    /// deployment has no such method, and `docs/Demo_Scope_Limits.md`
    /// clause A3 is where that difference is recorded.
    public var demoSeed: Data { key.rawRepresentation }

    public func sign(_ data: Data) throws -> Data {
        try key.signature(for: data)
    }
}

public enum Ed25519 {
    /// Verify a statement from one of the authorities. `false` rather than
    /// a throw: a signature that does not verify is an answer, and every
    /// caller here has something specific to say about which one failed.
    public static func verify(
        publicKey: Data, signature: Data, over data: Data
    ) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return key.isValidSignature(signature, for: data)
    }
}
