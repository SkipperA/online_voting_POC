/// The wallet's state. It holds the identifier; the voting application
/// has no type that does.
///
/// The persona is a demonstration substitution and is marked as one.
/// A real wallet belongs to one citizen, its key is hardware-bound under
/// eIDAS and cannot be read by the application holding it, and there is
/// no screen on which you choose who you are. Here the identifier is
/// typed in once, because a demonstration needs to be able to play
/// several citizens from one device. Clause S1.
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

    /// Who this demonstration has enrolled, for the picker.
    private(set) var available: [String] = []
    private(set) var adopted: String?

    private let origins: Origins
    private let personas: any PersonaSource

    init(origins: Origins = .hosted) {
        self.origins = origins
        self.personas = DemoPersonaClient(origins: origins)
    }

    /// Who the office will accept a request from.
    ///
    /// Asked rather than typed, and that is the correction. A free text
    /// field invited the assumption that the *name* is the credential;
    /// it is not, the key is. A wallet that generated its own key signed
    /// as nobody the register knows, and the office answered
    /// `NOT_IDENTIFIED` — correctly, and indistinguishably from an
    /// unknown identifier, which is §3.2 working rather than a fault.
    func loadPersonas() async {
        do {
            available = try await personas.personas()
        } catch {
            phase = .refused("Could not reach the demonstration's wallet "
                             + "origin to list its citizens: \(error)")
        }
    }

    /// Become one of the demonstration's citizens.
    ///
    /// This downloads that citizen's private key, which no wallet does
    /// and no deployment permits. The alternative — this wallet
    /// generating its own key and enrolling the public half — is what
    /// §3.2 describes, and it needs an enrolment endpoint that accepts a
    /// supplied key and a setup console a phone can reach. Neither
    /// exists yet. See `Personas.swift` and clause S1.
    func adopt(_ voterID: String) async {
        phase = .working
        do {
            let key = try await personas.adopt(voterID)
            flow = WalletFlow(
                wallet: key,
                elections: ConfigClient(origins: origins),
                office: OfficeRequestClient(origins: origins))
            adopted = voterID
            summary = []
            sent = []
            phase = .idle
        } catch {
            phase = .refused("Could not take that identity: \(error)")
        }
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
