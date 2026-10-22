/// RFC 9474 RSABSSA-SHA384-PSS-Deterministic, the voter's half.
///
/// The office's half -- the raw private-key operation -- is in
/// `src/ovpoc/rsabssa.py` and stays there. This file does the two things
/// the voter's device must do itself and must never delegate: blind the
/// ad-hoc public key before anyone sees it, and unblind the office's
/// answer afterwards. The blinding factor `r` never leaves the device, and
/// §5.3 turns on that: an intercepted `c` yields an intercepted `s_c` and
/// no advantage whatever.
///
/// Why the deterministic variant. `rsabssa.py` implements
/// RSABSSA-SHA384-PSS-Deterministic and the parameter set here is its
/// exact counterpart -- SHA-384, PSS, 48-byte salt, identity preparation.
/// `_CryptoExtras` warns that the randomized variants protect a client
/// from a malicious signer and that the deterministic ones are safe where
/// the input message is high-entropy. The message here is a freshly
/// generated Ed25519 public key, so the condition is met by construction;
/// it would not be met if this ever signed something a party could steer.
///
/// Why the salt is the client's. RFC 9474 puts `EMSA-PSS-ENCODE` inside
/// `Blind()`, so the office never sees an unencoded message and cannot
/// choose the salt. `docs/blind-signature.md` §2.3 records that the
/// article said otherwise until August 2026.
import Crypto
import Foundation
import _CryptoExtras

/// A blinding in progress: what goes to the wallet, and what is needed to
/// unblind the reply.
///
/// `inverse` is deliberately not `Codable` and cannot be made so --
/// `_CryptoExtras.BlindingInverse` has no accessor and no initialiser, so
/// there is no representation to persist. That is a property of the
/// library and a constraint on the application: see `AdHocKey.init(seed:)`
/// and clause A9.
public struct Blinding {
    /// `c` -- the only thing the wallet is given.
    public let blindedKey: Data
    /// `k_p^a`, prepared. Needed again at `finalize`.
    let prepared: _RSA.BlindSigning.PreparedMessage
    let inverse: _RSA.BlindSigning.BlindingInverse
    let publicKey: _RSA.BlindSigning.PublicKey<SHA384>

    public enum Failure: Error, Equatable {
        /// The office returned something that is not a signature over `c`.
        case replyDoesNotVerify
    }

    /// Steps 1/A–2: blind the ad-hoc public key under the pinned office key.
    ///
    /// `election.pinnedTokenKey()` is what supplies the key, and it throws
    /// unless the published fingerprint matches the key as served. The
    /// order is not an accident: nothing is blinded under a key that has
    /// not been pinned, because a per-voter key would make the blinding
    /// pointless.
    public init(adhocPublicKey: Data, under election: Election) throws {
        let key = try election.pinnedTokenKey()
        let prepared = key.prepare(adhocPublicKey)
        let result = try key.blind(prepared)
        self.publicKey = key
        self.prepared = prepared
        self.inverse = result.inverse
        self.blindedKey = result.blindedMessage
    }

    /// Step 8: unblind `s_c` into `s_{k_p^a}`.
    ///
    /// A reply that is not a signature over this `c` must be refused here
    /// and never carried to the ballot box: the voter who accepts one
    /// finds out at submission, by which time the entitlement is spent.
    /// `rsabssa.finalize` performs the same refusal and
    /// `test_attacks.py::test_finalize_rejects_a_dishonest_vro_response`
    /// shows it failing.
    ///
    /// The `guard` below is a second line and not the first. RFC 9474
    /// puts the verification inside `Finalize` as step 5, and
    /// `_CryptoExtras` implements it: `publicKey.finalize` throws
    /// `ProtocolError.invalidSignature` before control reaches here, so
    /// in practice `Failure.replyDoesNotVerify` does not fire. It is kept
    /// because the dependency is pinned to an underscored, explicitly
    /// unstable API, and an upstream change that moved that check would
    /// otherwise remove it silently. It is not kept under the pretence of
    /// being the check that does the work.
    ///
    /// What comes back is an ordinary RSASSA-PSS signature over `k_p^a`,
    /// which is load-bearing for the whole project: the independent
    /// verifier needs no bespoke cryptography, only a stock RSA-PSS
    /// verify.
    public func finalize(blindSignature: Data) throws -> Data {
        let signature = try publicKey.finalize(
            _RSA.BlindSigning.BlindSignature(rawRepresentation: blindSignature),
            for: prepared,
            blindingInverse: inverse)
        guard publicKey.isValidSignature(signature, for: prepared) else {
            throw Failure.replyDoesNotVerify
        }
        return signature.rawRepresentation
    }
}
