/// The wallet's state. It holds the identifier; the voting application
/// has no type that does.
///
/// The persona is a demonstration substitution and is marked as one.
/// A real wallet belongs to one citizen, its key is hardware-bound under
/// eIDAS and cannot be read by the application holding it, and there is
/// no screen on which you choose who you are. Here the identifier is
/// typed in once, because a demonstration needs to be able to play
/// several citizens from one device. Clause A3.
import Foundation
import Observation
import OVPOCKit

@MainActor
@Observable
final class WalletModel {
    enum Phase: Equatable {
        case noPersona
        case idle
        case loaded
        case working
        case transmitted(String)
        /// A refusal, with the reason. This is the screen's whole purpose
        /// and must never be a silent failure.
        case refused(String)
    }

    private(set) var phase: Phase = .noPersona
    private(set) var flow: WalletFlow?
    private(set) var summary: [VoterFlow.Field] = []
    private(set) var sent: [VoterFlow.Field] = []

    var voterID: String = ""

    private let origins: Origins

    init(origins: Origins = .hosted) {
        self.origins = origins
    }

    /// One citizen, from here on. Changing it starts a new wallet rather
    /// than re-signing as somebody else, because a wallet whose owner is
    /// a text field is already a thing no deployment has.
    func adopt() {
        let trimmed = voterID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        flow = WalletFlow(
            wallet: WalletKey(voterID: trimmed),
            elections: ConfigClient(origins: origins),
            office: OfficeRequestClient(origins: origins))
        summary = []
        sent = []
        phase = .idle
    }

    /// Read the file the voter carried, and check it against a
    /// configuration this wallet fetches itself.
    ///
    /// Fetched here, and that is the point. A forged voting application
    /// could otherwise hand over a request for a different election and
    /// this wallet would sign it blind — which is precisely what a
    /// consent screen exists to prevent, and what makes it more than a
    /// confirmation dialog.
    func load(_ url: URL) async {
        guard let flow else { return }
        phase = .working

        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        do {
            let bytes = try Data(contentsOf: url)
            _ = try await flow.load(bytes)
            summary = flow.consentSummary
            phase = .loaded
        } catch let failure as WalletFlow.Failure {
            summary = []
            phase = .refused(Self.explain(failure))
        } catch {
            summary = []
            phase = .refused("That file could not be read: \(error)")
        }
    }

    /// The voter authorises; the wallet signs and transmits.
    func consent() async {
        guard let flow else { return }
        phase = .working
        do {
            sent = try flow.transmitted()
            let outcome = try await flow.consentAndTransmit()
            phase = .transmitted(outcome)
        } catch {
            phase = .refused("The office did not accept the request: \(error)")
        }
    }

    private static func explain(_ failure: WalletFlow.Failure) -> String {
        switch failure {
        case .notATokenRequest:
            return "That file is not a token request."
        case .differentElection(let inRequest, let here):
            return "That request is for a different election.\n\n"
                 + "in the request: \(inRequest)\nthis wallet sees: \(here)\n\n"
                 + "Nothing has been signed."
        case .differentConfiguration(let inRequest, let here):
            return "That request was made under a different configuration of "
                 + "this election — most likely it was saved before the "
                 + "election was minted again.\n\n"
                 + "in the request: \(inRequest.prefix(16))…\n"
                 + "this wallet sees: \(here.prefix(16))…\n\n"
                 + "Nothing has been signed. Make a new request in the voting "
                 + "application."
        case .nothingLoaded:
            return "There is no request loaded."
        }
    }
}
