/// The voter's whole sequence, in one file and with no interface in it.
///
/// `voter.py` carries the same note: read this first if you want to
/// understand the scheme, because it is the only place the whole order
/// appears at once. The views over it draw a list and three buttons.
///
/// It lives in the package rather than in the app target so that the
/// parts that can be wrong in interesting ways -- the step order, what is
/// held and what is discarded, what happens when the published
/// configuration moves mid-flow, what `Collect` does when pressed too
/// early -- are reachable by `swift test` with no simulator and no
/// network.
import Crypto
import Foundation

public final class VoterFlow {
    /// The eight steps, in the order they happen. The same list the
    /// browser application renders, and the figure numbers are the
    /// article's.
    public enum Step: String, CaseIterable, Sendable {
        case config      // pin the published configuration
        case keygen      // 1/A -- the ad-hoc key pair
        case blind       // 2 -- c = enc(k_p^a) * r^e
        case handover    // B4 -- the file the voter carries to the wallet
        case collect     // 8 -- s_c, then unblind to s_{k_p^a}
        case cast        // 9 -- sign the ballot with k_s^a
        case submit      // 10 -- to the box, and take the receipt
        case verify      // 13 -- find it again under k_p^a
    }

    /// Which way this voter asks for their token.
    ///
    /// Two routes, and the voter chooses: the first is not replaced. They
    /// differ in one step -- what the handover file *is* -- and in nothing
    /// else. Blinding is unchanged, the token is the same ordinary RSA-PSS
    /// signature over `k_p^a`, the ballot is untouched, and `collect`
    /// presents the same `c` to the same endpoint.
    ///
    /// On `.wallet` the file is a small JSON object which the stand-in
    /// wallet signs as bytes. On `.qualifiedSignature` it is a PDF the
    /// citizen signs in their own wallet -- the European Digital Identity
    /// Wallet, and in Hungary the DÁP application -- which makes the
    /// request a legally probative document and needs no cooperation from
    /// any authority to arrange.
    ///
    /// **This application never handles the signed document.** It is the
    /// component holding `k_p^a` and `r`, so it is the component that must
    /// not learn `id`; the voter carries the file to the wallet and hands
    /// the signed one to the office themselves, on a page the office
    /// serves. Nothing comes back here. See clause A8.
    public enum Route: String, Sendable, CaseIterable {
        case wallet
        case qualifiedSignature
    }

    /// Said in words rather than in colour alone, as the browser client
    /// does, and for the reason `CLAUDE.md` records: a page that marks
    /// completed work and leaves the live step plain outlines everything
    /// except the one box the reader must look at.
    public enum Progress: String, Sendable {
        case notYet = "NOT YET"
        case awaitingYou = "AWAITING YOU"
        case done = "DONE"
    }

    /// What a step did, kept for the disclosure rows. Ordered pairs
    /// rather than a dictionary: these are read top to bottom by someone
    /// checking them, and a dictionary would reorder them per run.
    /// One line of a disclosure row. A named pair rather than a tuple,
    /// so the views can key on `name` and so the call sites below read as
    /// what they are.
    public struct Field: Sendable, Equatable {
        public let name: String
        public let value: String

        public init(_ name: String, _ value: String) {
            self.name = name
            self.value = value
        }
    }

    public struct Record: Sendable {
        public let step: Step
        public internal(set) var progress: Progress
        public internal(set) var payload: [Field]

        public init(step: Step, progress: Progress, payload: [Field] = []) {
            self.step = step
            self.progress = progress
            self.payload = payload
        }
    }

    public enum Failure: Error, Equatable {
        /// The configuration moved under an open flow. Everything
        /// computed so far belongs to the previous election.
        case electionSuperseded(pinned: String, now: String)
        /// A step was asked for out of order. Named rather than
        /// crashed: the apps have buttons, and a button pressed twice is
        /// an ordinary thing.
        case notReady(Step)
        /// Restored from a snapshot taken after blinding. The blinding
        /// inverse has no representation to keep, so the entitlement is
        /// spent -- clause A9.
        case blindingSecretLost
    }

    public enum Collected: Sendable, Equatable {
        /// The office has not released, which while the voter is in the
        /// wallet is the normal answer and not an error.
        case notYet
        case token
    }

    // -- what it is built from ---------------------------------------

    private let elections: any ElectionReading
    private let replies: any TokenReplyCollecting
    private let box: any BallotSubmitting

    // -- what it holds ------------------------------------------------

    public private(set) var records: [Record] =
        Step.allCases.map { Record(step: $0, progress: .notYet) }
    public private(set) var election: Election?
    private var adhoc: AdHocKey?
    private var blinding: Blinding?
    private var token: Data?
    private var ballot: Ballot?
    public private(set) var receipt: Receipt?

    /// The file the voter carries to the wallet. `nil` until blinding.
    public private(set) var requestFile: Data?

    /// Which route this flow took, and what the file it produced is called.
    public private(set) var route: Route = .wallet
    public var requestFileName: String {
        route == .wallet ? Self.walletRequestFileName : Self.documentRequestFileName
    }

    public init(
        elections: any ElectionReading,
        replies: any TokenReplyCollecting,
        box: any BallotSubmitting
    ) {
        self.elections = elections
        self.replies = replies
        self.box = box
    }

    public func record(_ step: Step) -> Record {
        records[Step.allCases.firstIndex(of: step)!]
    }

    private func set(_ step: Step, _ progress: Progress,
                     _ payload: [Field] = []) {
        let i = Step.allCases.firstIndex(of: step)!
        records[i].progress = progress
        if !payload.isEmpty { records[i].payload = payload }
    }

    // -- the one tap --------------------------------------------------

    /// Pin, generate, blind, and produce the file. Four steps, no
    /// decisions, nothing the voter has to understand.
    ///
    /// They run together because none of them asks the voter anything.
    /// The browser client makes each one a button because there the
    /// demonstration *is* the sequence; here the demonstration is that a
    /// citizen can vote without following it, and the sequence is one tap
    /// away for the people who came to check it.
    public func enrol(via route: Route = .wallet) async throws {
        self.route = route
        set(.config, .awaitingYou)
        let election = try await elections.election()
        self.election = election

        // Recomputed here and compared with what the office published.
        // `pinnedTokenKey()` inside `Blinding` throws on a mismatch; this
        // is the same comparison made visible, because a reader is
        // entitled to see it rather than be told it happened.
        set(.config, .done, [
            Field("election_id", election.electionID),
            Field("choices", "1..\(election.numChoices)"),
            Field("config_digest", election.publishedDigest),
            Field("digest recomputed here", election.computedDigest),
            Field("digest agrees", String(election.digestAgrees)),
            Field("k_p^(R) fingerprint", election.recomputedFingerprint),
            Field("agrees with published by VRO", String(election.recomputedFingerprint == election.vroTokenKeyFingerprint)),
        ])

        set(.keygen, .awaitingYou)
        let adhoc = AdHocKey()
        self.adhoc = adhoc
        set(.keygen, .done, [
            Field("k_p^a", adhoc.publicBytes.b64url),
            Field("k_s^a", "on this device, and never sent"),
        ])

        set(.blind, .awaitingYou)
        let blinding = try Blinding(adhocPublicKey: adhoc.publicBytes, under: election)
        self.blinding = blinding
        set(.blind, .done, [
            Field("c", blinding.blindedKey.b64url),
            Field("r", "on this device, and never sent"),
            Field("what the office will see", "c alone, and the identifier the wallet adds"),
        ])

        set(.handover, .awaitingYou)
        switch route {
        case .wallet:
            requestFile = try Self.requestFileBytes(
                electionID: election.electionID,
                configDigest: election.publishedDigest,
                blindedKey: blinding.blindedKey)
            set(.handover, .done, [
                Field("file", requestFileName),
                Field("carries", "c, the election it is for, and that election's digest"),
                Field("does not carry", "any identifier; the wallet adds that"),
                Field("then", "open the wallet and authorise it"),
            ])
        case .qualifiedSignature:
            requestFile = try PDFRequest.render(PDFRequest.payload(
                electionID: election.electionID,
                configDigest: election.publishedDigest,
                blindedKey: blinding.blindedKey))
            set(.handover, .done, [
                Field("file", requestFileName),
                Field("carries", "c, the election it is for, and that election's digest"),
                Field("does not carry", "any identifier; your certificate carries that"),
                Field("fingerprint of c",
                      PDFRequest.fingerprint(blinding.blindedKey)),
                Field("check on the page", "that fingerprint, before you sign"),
                // Said here because the application cannot do it, and a
                // voter who is not told will look for a button. It is the
                // same reason the upload page is served by the office: the
                // signed document must not pass through this application.
                Field("then", "sign it in your wallet, then hand the signed "
                      + "document to the office yourself"),
                Field("not done here", "this application never sees the signed "
                      + "document, and cannot hand it in for you"),
            ])
        }
        set(.collect, .awaitingYou)
    }

    // -- the file ------------------------------------------------------

    public static let walletRequestFileName = "blinded-key.json"

    /// A PDF, because a real wallet signs documents and not byte strings.
    public static let documentRequestFileName = "token-request.pdf"

    /// Byte-compatible with what `web/voter-app` writes and what
    /// `web/wallet` reads, deliberately: a request saved in the browser
    /// must open in the native wallet and the reverse. The field names
    /// are `wallet.js`'s, and `testTheRequestFileMatchesTheBrowsersFields`
    /// is what keeps them so.
    static func requestFileBytes(
        electionID: String, configDigest: String, blindedKey: Data
    ) throws -> Data {
        let body: [String: Any] = [
            "_transport": "carried by the voter between two applications, "
                + "as it is carried between two browser origins. The voting "
                + "application cannot invoke the wallet, and that is the point "
                + "rather than a limitation of the medium.",
            "election_id": electionID,
            "config_digest": configDigest,
            "blinded_key": blindedKey.b64url,
        ]
        return try JSONSerialization.data(
            withJSONObject: body, options: [.prettyPrinted, .sortedKeys])
    }

    // -- the office's reply ---------------------------------------------

    /// Ask the office whether it has released, and unblind if it has.
    ///
    /// A button rather than a timer: with the handover a file, nothing
    /// tells this application that the wallet has consented, and polling
    /// would be asking an office that has no reason to have changed its
    /// answer. The app checks once more when it returns to the
    /// foreground, because that is when it may have.
    public func collect() async throws -> Collected {
        guard let blinding, let election else { throw Failure.notReady(.collect) }
        try await refuseIfSuperseded(election)

        guard let reply = try await replies.collect(blindedKey: blinding.blindedKey) else {
            return .notYet
        }
        let token = try blinding.finalize(blindSignature: reply)
        self.token = token

        // The blinding secret has served its purpose; `voter.py` drops it
        // here too. It cannot be persisted in any case (A9), but holding
        // it after it is useless would be holding it for no reason.
        self.blinding = nil

        set(.collect, .done, [
            Field("s_c", reply.b64url),
            Field("s_{k_p^a}", token.b64url),
            Field("checked here", "the token verifies under the pinned k_p^(R)"),
            Field("ordinary RSA-PSS", "any stock verifier can check it"),
        ])
        set(.cast, .awaitingYou)
        return .token
    }

    // -- the ballot -------------------------------------------------------

    /// Sign the selection with `k_s^a`.
    ///
    /// A selection outside `1...num_choices` is *not* refused: it is a
    /// protest ballot, accepted and superseding, counted as invalid.
    /// Three words, not two. What is refused is a selection this client
    /// cannot represent at all, which is a different thing and is why the
    /// error names a range rather than a rule.
    public func cast(selection: Int) throws {
        guard let adhoc, let token else { throw Failure.notReady(.cast) }

        var ballot = Ballot(
            selection: selection, adhocPublicKey: adhoc.publicBytes, token: token)
        ballot.voteSignature = try adhoc.sign(ballot.signedPayload)
        self.ballot = ballot

        let inRange = election.map { (1 ... $0.numChoices).contains(selection) } ?? false
        set(.cast, .done, [
            Field("selection", String(selection)),
            Field("in the option list", String(inRange)),
            Field("n", ballot.nonce.b64url),
            Field("s_vote", ballot.voteSignature.b64url),
            Field("signed over", "hash([i, k_p^a, n])"),
        ])
        set(.submit, .awaitingYou)
    }

    public func submit() async throws -> Receipt {
        guard let ballot, let election else { throw Failure.notReady(.submit) }
        try await refuseIfSuperseded(election)

        let receipt = try await box.submit(ballot)
        self.receipt = receipt

        // Verified here rather than filed. A receipt nobody checks is a
        // string; the signature is over the verdict, the position and the
        // entry hash, under the key the configuration published -- not
        // under anything that arrived with the receipt.
        let authentic = receipt.verifies(under: election)
        set(.submit, .done, [
            Field("accepted", String(receipt.accepted)),
            Field("reason", receipt.reason),
            Field("position", receipt.index.map(String.init) ?? "not stated"),
            Field("entry hash", receipt.entryHash.b64url),
            Field("signature verifies under k_p^(B)", String(authentic)),
        ])
        set(.verify, .awaitingYou)
        return receipt
    }

    /// D3 -- find the ballot again under `k_p^a`, and compare.
    ///
    /// The article has this run from a *different* device, and an app on
    /// this one cannot be that (clause O2). What it still establishes is
    /// that the box holds what was sent; what it cannot establish is that
    /// the box would say the same to somebody else.
    public func verify(expecting selection: Int) async throws -> Bool {
        guard let adhoc else { throw Failure.notReady(.verify) }
        let found = try await box.find(adhocPublicKey: adhoc.publicBytes)
        let recorded = found?["selection"] as? Int
        let agrees = recorded == selection

        set(.verify, .done, [
            Field("found under k_p^a", String(found != nil)),
            Field("recorded selection", recorded.map(String.init) ?? "none"),
            Field("as intended", String(agrees)),
            Field("from another device", "no — clause O2"),
        ])
        return agrees
    }

    // -- the configuration moving underneath ------------------------------

    /// Refuse to continue under an election that has been replaced.
    ///
    /// The browser surfaces raise a bar saying "reload"; an application
    /// has the harder version of the same problem, because it may hold a
    /// half-finished ballot. Checked before each step that depends on the
    /// pinned configuration rather than on a timer, so the answer is
    /// fresh at the moment it matters.
    private func refuseIfSuperseded(_ election: Election) async throws {
        let now = try await elections.publishedDigest()
        guard now == election.publishedDigest else {
            throw Failure.electionSuperseded(
                pinned: election.publishedDigest, now: now)
        }
    }

    // -- what survives being killed ----------------------------------------

    /// Everything that *can* be kept, which is not everything.
    ///
    /// The ad-hoc key survives because its seed is bytes. The blinding
    /// inverse does not: `_CryptoExtras` gives it no accessor, so there is
    /// nothing to write down. A flow restored after blinding and before
    /// collecting therefore cannot proceed, and says so rather than
    /// failing later and obscurely. Clause A9.
    public struct Snapshot: Codable, Sendable {
        public var electionID: String
        public var configDigest: String
        public var adhocSeed: Data
        public var blindedKey: Data?
        public var token: Data?
        public var hadUncollectedBlinding: Bool
    }

    public var snapshot: Snapshot? {
        guard let election, let adhoc else { return nil }
        return Snapshot(
            electionID: election.electionID,
            configDigest: election.publishedDigest,
            adhocSeed: adhoc.seed,
            blindedKey: blinding?.blindedKey,
            token: token,
            hadUncollectedBlinding: blinding != nil && token == nil)
    }

    /// Put back what can be put back, and say what cannot.
    ///
    /// Throws `blindingSecretLost` when the snapshot was taken between
    /// blinding and collecting: the office may well have released a token
    /// for that `c`, and nothing on this device can unblind it. The
    /// honest report is that the entitlement is spent, which is a thing
    /// the voter needs told plainly rather than discovered at the box.
    public func restore(from snapshot: Snapshot) throws {
        adhoc = try AdHocKey(seed: snapshot.adhocSeed)
        token = snapshot.token
        if snapshot.token == nil && snapshot.hadUncollectedBlinding {
            throw Failure.blindingSecretLost
        }
    }
}
