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

    var body: some View {
        NavigationStack {
            Form {
                persona

                switch model.phase {
                case .noPersona:
                    EmptyView()

                case .idle:
                    Section {
                        Button("Open a token request") { choosingFile = true }
                    } footer: {
                        Text("The voting application saves a file and you "
                             + "carry it here. It cannot open this wallet "
                             + "itself, and that is deliberate: a wallet an "
                             + "application can invoke is an interface with a "
                             + "consent screen painted on it.")
                    }

                case .working:
                    Section { HStack { ProgressView(); Text("Checking…") } }

                case .loaded:
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
                        Text("Go back to the voting application and collect "
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
    }

    @ViewBuilder
    private var persona: some View {
        Section {
            TextField("Your identifier", text: $model.voterID)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Use this identity") { model.adopt() }
                .disabled(model.voterID.trimmingCharacters(
                    in: .whitespacesAndNewlines).isEmpty)
        } header: {
            Text("Whose wallet this is")
        } footer: {
            Text("A real wallet has one owner and no such screen: the key is "
                 + "bound to hardware under eIDAS and the application holding "
                 + "it cannot read it. This exists so one device can play "
                 + "several citizens in a demonstration — clause A3.")
        }
    }
}

#Preview {
    ContentView()
}
