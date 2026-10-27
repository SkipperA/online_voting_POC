/// What the screen observes. The protocol is in `OVPOCKit`; this holds a
/// `VoterFlow` and turns its outcomes into things a view can draw.
///
/// Deliberately thin. Every decision about order, refusal and disclosure
/// is in the flow, where `swift test` reaches it; what is here is the
/// handling of buttons, the temporary file the share sheet needs, and the
/// one place the application speaks to the operating system about its own
/// lifecycle.
import Foundation
import Observation
import OVPOCKit

@MainActor
@Observable
final class VoterModel {
    enum Phase: Equatable {
        case fresh
        case working(String)
        case awaitingWallet
        case holdingToken
        case submitted(accepted: Bool)
        /// Terminal, and explained rather than merely shown. The two
        /// cases here are a mint under an open flow and a blinding
        /// secret lost to a termination — both leave nothing to resume.
        case stopped(String)
    }

    private(set) var flow: VoterFlow
    private(set) var phase: Phase = .fresh
    private(set) var problem: String?
    private(set) var requestFileURL: URL?
    private(set) var transcriptURL: URL?
    private(set) var lastVerification: Bool?

    var selection: Int = 1

    init(origins: Origins = .hosted) {
        let config = ConfigClient(origins: origins)
        self.flow = VoterFlow(
            elections: config,
            replies: OfficeReplyClient(origins: origins),
            box: BoxClient(origins: origins))
    }

    var election: Election? { flow.election }
    var records: [VoterFlow.Record] { flow.records }

    /// Which way this voter is asking. Chosen before the one tap, and
    /// fixed once it has happened: the two routes diverge at the handover
    /// and the file is written there.
    var route: VoterFlow.Route = .wallet

    /// The one tap. Four steps that ask the voter nothing.
    func enrol() async {
        phase = .working("Pinning the configuration, generating a key, blinding…")
        problem = nil
        do {
            try await flow.enrol(via: route)
            requestFileURL = try writeRequestFile()
            phase = .awaitingWallet
            refreshTranscript()
        } catch {
            report(error)
        }
    }

    /// Ask the office whether it has released. Pressed by the voter, and
    /// once automatically on return to the foreground — see
    /// `cameBackToTheForeground`.
    func collect() async {
        guard phase == .awaitingWallet else { return }
        problem = nil
        do {
            switch try await flow.collect() {
            case .notYet:
                problem = "The office has not released a token for this request "
                        + "yet. Consent in the wallet first, then try again."
            case .token:
                phase = .holdingToken
            refreshTranscript()
            }
        } catch {
            report(error)
        }
    }

    /// Returning from the wallet is the one moment `s_c` is likely to
    /// have appeared, so the application looks once. Not a timer: with
    /// the handover a file, nothing else tells it anything has changed,
    /// and polling would be asking an office with no reason to have
    /// changed its answer.
    func cameBackToTheForeground() async {
        guard phase == .awaitingWallet, flow.requestFile != nil else { return }
        await collect()
        // A silent miss here is correct. The voter may be switching back
        // for any reason, and "not yet" is not news worth a banner.
        if case .awaitingWallet = phase { problem = nil }
    }

    func castAndSubmit() async {
        guard phase == .holdingToken else { return }
        phase = .working("Signing the ballot and submitting it…")
        problem = nil
        do {
            try flow.cast(selection: selection)
            let receipt = try await flow.submit()
            phase = .submitted(accepted: receipt.accepted)
            refreshTranscript()
        } catch {
            report(error)
        }
    }

    func verify() async {
        problem = nil
        do {
            lastVerification = try await flow.verify(expecting: selection)
            refreshTranscript()
        } catch {
            report(error)
        }
    }

    // -- the file the voter carries ----------------------------------

    /// Written to a real file because the share sheet moves files, and
    /// because a cryptographer in the room should be able to take it
    /// away and read it. It is not a secret: it carries `c`, the election
    /// it is for, and nothing that identifies anybody.
    private func writeRequestFile() throws -> URL? {
        guard let bytes = flow.requestFile else { return nil }
        // The flow's name, not a constant of this type's: the two routes
        // write different files and only the flow knows which it took.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(flow.requestFileName)
        try bytes.write(to: url, options: .atomic)
        return url
    }

    /// The whole run, for the people who came to check it.
    ///
    /// Rewritten after every act rather than built while the view draws:
    /// a `body` that writes a file to disk does it again on every
    /// redraw, and the file is what the share sheet hands over, so it
    /// has to exist before the button does.
    func refreshTranscript() {
        transcriptURL = try? transcript()
    }

    private func transcript() throws -> URL {
        var lines: [String] = ["# Voter application transcript", ""]
        if let election {
            lines += ["election: \(election.electionID)",
                      "configuration digest: \(election.publishedDigest)", ""]
        }
        for record in records {
            lines.append("## \(record.step.rawValue) — \(record.progress.rawValue)")
            for field in record.payload {
                lines.append("  \(field.name): \(field.value)")
            }
            lines.append("")
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("voter-transcript.txt")
        try Data(lines.joined(separator: "\n").utf8).write(to: url, options: .atomic)
        return url
    }

    // -- failures, said in words --------------------------------------

    private func report(_ error: Error) {
        switch error {
        case VoterFlow.Failure.electionSuperseded(let pinned, let now):
            phase = .stopped(
                "The election was replaced while this was open. Everything "
                + "computed here belongs to the previous one: the token would "
                + "not verify and the ballot would not be accepted.\n\n"
                + "pinned: \(pinned.prefix(16))…\nnow:    \(now.prefix(16))…")
        case VoterFlow.Failure.blindingSecretLost:
            phase = .stopped(
                "This application was closed between asking for a token and "
                + "receiving it, and the blinding factor cannot be stored. A "
                + "token may exist for that request and nothing here can use "
                + "it. Clause A9.")
        case Election.Failure.fingerprintMismatch(let pinned, let recomputed):
            phase = .stopped(
                "The office is serving a key that is not the published one. "
                + "Nothing has been blinded under it.\n\n"
                + "published: \(pinned.prefix(16))…\nserved:    \(recomputed.prefix(16))…")
        default:
            problem = String(describing: error)
        }
    }
}
