/// The Digital Identity Wallet: one question, asked properly.
///
/// Load a request, see what it is, authorise it or don't. The screen
/// exists so that the voter knows what they are signing, which is the
/// part of a wallet that cannot be delegated — the signing itself could
/// be, and the key would be in hardware doing it.
import OVPOCKit
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var model = WalletModel()
    @State private var choosingFile = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationStack {
            Form {
                persona

                switch model.phase {
                case .noPersona:
                    if model.awaitingPersona {
                        Section {
                            Text("A token request is waiting.")
                        } footer: {
                            Text("The voting application handed one over, but "
                                 + "a request is signed by somebody. Choose "
                                 + "whose wallet this is and it will be "
                                 + "checked and shown to you.")
                        }
                    }

                case .idle:
                    Section {
                        Button("Open a token request") { choosingFile = true }
                    } footer: {
                        Text("On this phone the voting application hands the "
                             + "request straight over and this wallet opens "
                             + "on its own; in the browser it saves a file "
                             + "you carry here, and that button is the same "
                             + "route by hand. What never changes is this "
                             + "screen: an application can put the question "
                             + "in front of you, and cannot answer it. "
                             + "Clause A8.\n\n"
                             + "If the voting application just opened this "
                             + "wallet and you are reading this, the request "
                             + "did not arrive — share it over as a file and "
                             + "use the button.")
                    }
                    
                case .working:
                    Section { HStack { ProgressView(); Text("Checking…") } }
                    
                case .loaded:
                    if model.cameFromTheVotingApplication {
                        Section {
                            Text("The voting application sent this request "
                                 + "over and opened this wallet.")
                        } footer: {
                            Text("It did not come with a name attached. This "
                                 + "wallet fetched the election's own "
                                 + "configuration and checked the request "
                                 + "against it, which is why the next screen "
                                 + "is worth reading.")
                        }
                    }
                    Section("You are being asked to authorise") {
                        ForEach(model.summary, id: \.name) { field in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(field.name)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(field.value)
                                    .font(.system(.footnote, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    Section {
                        Button("Consent and send to the office") {
                            Task { await model.consent() }
                        }
                    } footer: {
                        Text("This wallet sends [id, c, s] to the office over "
                             + "its own connection. It does not go back through "
                             + "the voting application, which never learns your "
                             + "identifier.")
                    }
                    
                case .transmitted(let outcome):
                    Section("Sent") {
                        LabeledContent("the office answered", value: outcome)
                    }
                    if !model.sent.isEmpty {
                        Section("What was sent") {
                            ForEach(model.sent, id: \.name) { field in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(field.name)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(field.value)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                }
                            }
                        }
                    }
                    Section {
                        Button("Open another request") { choosingFile = true }
                    } footer: {
                        Text(model.cameFromTheVotingApplication
                             ? "Taking you back to the voting application, "
                               + "where the token is waiting to be collected."
                             : "Go back to the voting application and collect "
                               + "the token.")
                    }
                    
                case .refused(let why):
                    Section {
                        Text(why)
                            .font(.callout)
                            .foregroundStyle(.red)
                    } header: {
                        Text("Refused")
                    }
                    Section {
                        Button("Open a different request") { choosingFile = true }
                    }
                }

                buildRegistration
            }
            .navigationTitle("Identity Wallet")
            .fileImporter(isPresented: $choosingFile,
                          allowedContentTypes: [.json]) { result in
                switch result {
                case .success(let url):
                    Task { await model.load(url) }
                case .failure:
                    break   // the picker was dismissed; not an event
                }
            }
        }
        // Outside the navigation stack, deliberately. A URL that launches
        // the application arrives before anything inside a container view
        // is reliably in the hierarchy, and a missed launch URL is the
        // silent failure this whole screen exists to avoid.
        //
        // The voting application opening this one. `HandOff.request`
        // answers `nil` for anything that is not a request, because a URL
        // scheme can be opened by anything on the device and a malformed
        // one is an ordinary event rather than an alarm.
        .onOpenURL { url in Task { await model.receive(url) } }
        // Whose wallet this is, remembered from last time. A real wallet
        // does not ask on every launch, and asking is clause S1's
        // substitution rather than a step the design has.
        .task { await model.restoreRememberedPersona() }
        // And back to the voting application, once the office has
        // answered — but only for a request that arrived that way.
        // `returnTo` is nil for a file the voter carried in, so this
        // wallet does not decide where somebody who walked in goes next.
        .onChange(of: model.returnTo) { _, destination in
            if let destination { openURL(destination) }
        }
    }
    
    /// What this binary answers to, read out of its own bundle.
    ///
    /// This is the one that matters: the voting application cannot see
    /// whether this wallet registered its scheme, and an unregistered
    /// one is indistinguishable from a wallet that is not installed.
    /// Whoever is holding the phone can see it here, which is the
    /// cheapest instrument there is for a fault that otherwise shows up
    /// as nothing happening on two screens at once.
    ///
    /// Read from the running bundle, not from the file in the
    /// repository. A test can check what the committed `Info.plist`
    /// says; nothing can check whether the build was told to read it.
    @ViewBuilder
    private var buildRegistration: some View {
        let registered = HandOff.schemesRegistered()
        if registered.contains(HandOff.walletScheme) {
            Section("This build") {
                LabeledContent("answers to", value: registered.joined(separator: " · "))
                    .font(.footnote)
            }
        } else {
            Section {
                Text("This build registers no URL scheme of its own.")
                    .font(.callout)
                    .foregroundStyle(.red)
            } header: {
                Text("This build")
            } footer: {
                Text("It should answer to \(HandOff.walletScheme). Until it "
                     + "does, the voting application cannot open this "
                     + "wallet: it will report that nothing on the device "
                     + "did, and you carry the request over as a file "
                     + "instead — which works, and is the browser's "
                     + "arrangement rather than the integrated one.\n\n"
                     + "One build setting: Packaging → Info.plist File, "
                     + "which must be Info.plist. Step 4 of "
                     + "ios/README.md.")
            }
        }
    }

    @ViewBuilder
    private var persona: some View {
        Section {
            if model.available.isEmpty {
                Button("Find out who is enrolled") {
                    Task { await model.loadPersonas() }
                }
            } else {
                ForEach(model.available, id: \.self) { name in
                    Button {
                        Task { await model.adopt(name) }
                    } label: {
                        HStack {
                            Text(name)
                            Spacer()
                            if model.adopted == name {
                                Image(systemName: "checkmark")
                            }
                        }
                    }
                    .foregroundStyle(.primary)
                }
            }
        } header: {
            Text("Whose wallet this is")
        } footer: {
            Text("Chosen from the citizens this demonstration enrolled, "
                 + "because taking one of their identities means taking "
                 + "their key — and the key, not the name, is what the "
                 + "office checks. A real wallet has one owner, generates "
                 + "its own key in hardware it cannot read, and offers no "
                 + "such list. Clause S1.")
        }
    }
}
#Preview {
    ContentView()
}
