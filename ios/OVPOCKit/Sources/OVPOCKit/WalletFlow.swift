/// The wallet's sequence: read a request, show it, sign it, transmit it.
///
/// Four steps and one refusal, and the refusal is the reason the screen
/// exists. A wallet that signed whatever it was handed would be a signing
/// oracle with a confirmation dialog in front of it; what makes consent
/// mean anything is that the wallet checks the request against a
/// configuration it fetched *itself*, and declines when they disagree.
/// `web/wallet/static/wallet.js` says the same in its opening comment and
/// performs the same two checks.
///
/// This type holds `id`. The voting application has no type that does,
/// and the two are in different binaries: that is the §3.6 boundary as a
/// native application can express it. Clause A8 records what enforces it
/// and what does not.
import Foundation

public final class WalletFlow {
    public enum Step: String, CaseIterable, Sendable {
        case load       // the file the voter carried
        case check      // against a configuration this wallet fetched
        case consent    // the voter authorises, knowing what
        case transmit   // B7 -- to the office, from here
    }

    public typealias Progress = VoterFlow.Progress
    public typealias Field = VoterFlow.Field

    public enum Failure: Error, Equatable {
        case notATokenRequest
        /// The two checks that make the consent screen worth having.
        case differentElection(inRequest: String, here: String)
        case differentConfiguration(inRequest: String, here: String)
        case nothingLoaded
    }

    /// What was read out of the file. `c` and the election it is for --
    /// and nothing that identifies anybody, because the voting
    /// application that wrote it does not know who the voter is.
    public struct Request: Sendable, Equatable {
        public let electionID: String
        public let configDigest: String
        public let blindedKey: Data
    }

    private let elections: any ElectionReading
    private let office: any RequestTransmitting
    private let wallet: WalletKey

    // No step list here, unlike the voting application. That screen is
    // eight steps the reader follows; this one is a single question --
    // is this the request you meant to authorise -- and a list of
    // progress rows around one question would be furniture.
    public private(set) var request: Request?
    public private(set) var election: Election?

    public init(
        wallet: WalletKey,
        elections: any ElectionReading,
        office: any RequestTransmitting
    ) {
        self.wallet = wallet
        self.elections = elections
        self.office = office
    }

    /// Whose wallet this is. One citizen, one key, no parameter --
    /// unlike the browser stand-in, which holds a whole electorate so one
    /// machine can play it (clause A3).
    public var voterID: String { wallet.voterID }

    // -- load and check ----------------------------------------------

    /// Read the file, then check it against a configuration fetched here.
    ///
    /// Fetched here, and that is the whole point: a forged voting
    /// application could otherwise hand the voter a request for a
    /// different election and the wallet would sign it blind. The digest
    /// check is what catches a request saved before a mint, which is the
    /// common case rather than the adversarial one.
    @discardableResult
    public func load(_ fileContents: Data) async throws -> Request {
        guard let body = try? JSONSerialization.jsonObject(with: fileContents)
                as? [String: Any],
              let electionID = body["election_id"] as? String,
              let digest = body["config_digest"] as? String,
              let blindedText = body["blinded_key"] as? String,
              let blinded = Base64URL.decode(blindedText) else {
            throw Failure.notATokenRequest
        }
        let request = Request(
            electionID: electionID, configDigest: digest, blindedKey: blinded)

        let election = try await elections.election()
        self.election = election

        guard request.electionID == election.electionID else {
            throw Failure.differentElection(
                inRequest: request.electionID, here: election.electionID)
        }
        guard request.configDigest == election.publishedDigest else {
            throw Failure.differentConfiguration(
                inRequest: request.configDigest, here: election.publishedDigest)
        }

        self.request = request
        return request
    }

    /// What the voter is being asked to authorise, in the terms they can
    /// check: which election, and that the thing being signed carries no
    /// selection and no identifier of its own.
    public var consentSummary: [Field] {
        guard let request else { return [] }
        return [
            Field("you are", wallet.voterID),
            Field("election", request.electionID),
            Field("configuration digest", request.configDigest),
            Field("c", request.blindedKey.b64url),
            Field("what you are signing", "hash([id, c]) — that this citizen asked for a token"),
            Field("what it does not say", "how you will vote; c hides the key it covers"),
        ]
    }

    // -- sign and transmit ---------------------------------------------

    /// B5–B7. Sign `hash([id, c])` and send `[id, c, s]` to the office.
    ///
    /// Sent from here, not returned to the voting application for
    /// forwarding. §5.3: were the application to carry this, one component
    /// on the voter's own device would hold both `id` and `k_p^a`
    /// together with the office's signature over their association. The
    /// blinding would still stop the office linking voter to ballot, and
    /// the linkage would survive where it could be recorded, exported, or
    /// produced under compulsion.
    ///
    /// Only the outcome comes back, and only the outcome is reported. The
    /// identifier travels no further in either direction.
    public func consentAndTransmit() async throws -> String {
        guard let request else { throw Failure.nothingLoaded }

        var auth = AuthRequest(
            voterID: wallet.voterID, blindedKey: request.blindedKey)
        auth.walletSignature = try wallet.sign(auth.signedPayload)

        return try await office.transmit(auth)
    }

    /// What was built and sent, for the disclosure row.
    ///
    /// The wallet's own screen may show this: it is the wallet's data, on
    /// the wallet's surface, and a demonstration in which the one
    /// identified message is invisible teaches nothing about where the
    /// identifier goes. The voting application is shown none of it.
    public func transmitted() throws -> [Field] {
        guard let request else { throw Failure.nothingLoaded }
        var auth = AuthRequest(
            voterID: wallet.voterID, blindedKey: request.blindedKey)
        auth.walletSignature = try wallet.sign(auth.signedPayload)
        return [
            Field("id", auth.voterID),
            Field("c", auth.blindedKey.b64url),
            Field("s", auth.walletSignature.b64url),
            Field("signed over", "hash([id, c])"),
            Field("sent to", "the office, by this wallet, over its own connection"),
            Field("not sent to", "the voting application, which never learns id"),
        ]
    }
}
