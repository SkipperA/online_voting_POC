/// The voting application: eight rows and three deliberate acts.
///
/// *Enrol in election* runs the four steps that ask nothing. Then the
/// voter carries a file to the wallet, comes back and presses *Collect*,
/// chooses, and submits. Everything else on this screen is disclosure.
import OVPOCKit
import SwiftUI

struct ContentView: View {
    @State private var model = VoterModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            Form {
                if case .stopped(let why) = model.phase {
                    Section {
                        Text(why)
                            .font(.callout)
                            .foregroundStyle(.red)
                    } header: {
                        Text("This cannot continue")
                    }
                }

                if let problem = model.problem {
                    Section { Text(problem).font(.callout) }
                }

                Section {
                    ForEach(model.records, id: \.step) { StepRow(record: $0) }
                } header: {
                    Text("What this device did")
                } footer: {
                    Text("Open any step to see exactly what it produced. "
                         + "Nothing here is summarised: these are the bytes.")
                }

                actions

                if let election = model.election {
                    Section("This election") {
                        LabeledContent("identifier", value: election.electionID)
                        LabeledContent("choices", value: "1…\(election.numChoices)")
                        LabeledContent("digest",
                                       value: String(election.publishedDigest.prefix(16)) + "…")
                    }
                    .font(.callout)
                }

                if let transcript = model.transcriptURL {
                    Section {
                        ShareLink("Save the whole transcript", item: transcript)
                    } footer: {
                        Text("A demonstration whose workings cannot be taken "
                             + "away and checked is a demonstration you have "
                             + "to take on trust.")
                    }
                }
            }
            .navigationTitle("Voter application")
        }
        .onChange(of: scenePhase) { _, phase in
            // Coming back from the wallet is when the office may have
            // released. One look, not a timer.
            if phase == .active {
                Task { await model.cameBackToTheForeground() }
            }
        }
    }

    @ViewBuilder
    private var actions: some View {
        switch model.phase {
        case .fresh:
            Section {
                Button("Enrol in election") { Task { await model.enrol() } }
            } footer: {
                Text("Pins the published configuration, checks the office's key "
                     + "against the fingerprint it published, generates a key "
                     + "pair for this election only, and blinds it.")
            }

        case .working(let what):
            Section { HStack { ProgressView(); Text(what).font(.callout) } }

        case .awaitingWallet:
            Section {
                if let url = model.requestFileURL {
                    ShareLink("Send the request to the wallet", item: url)
                }
                Button("Collect the token") { Task { await model.collect() } }
            } header: {
                Text("Over to the wallet")
            } footer: {
                Text("The file carries the blinded key and the election it is "
                     + "for. It does not say who you are — the wallet adds "
                     + "that, and sends it to the office itself. This "
                     + "application never learns your identifier, and cannot "
                     + "make the wallet sign anything.")
            }

        case .holdingToken:
            Section {
                Stepper("Selection: \(model.selection)",
                        value: $model.selection, in: -9 ... 9)
                Button("Cast and submit") { Task { await model.castAndSubmit() } }
            } header: {
                Text("Your ballot")
            } footer: {
                Text("A selection outside the option list is a protest ballot. "
                     + "It is accepted and it supersedes your earlier one; it "
                     + "is counted as invalid rather than refused, and the "
                     + "published figures report how many of each were cast.")
            }

        case .submitted(let accepted):
            Section {
                LabeledContent("accepted", value: accepted ? "yes" : "no")
                Button("Check it is there, as cast") { Task { await model.verify() } }
                if let ok = model.lastVerification {
                    LabeledContent("as intended", value: ok ? "yes" : "NO")
                }
            } header: {
                Text("The receipt")
            } footer: {
                Text("The receipt was verified here under the key the "
                     + "configuration published, not under anything that "
                     + "arrived with it. The article has this last check run "
                     + "from a different device; an application on this one "
                     + "cannot be that.")
            }

        case .stopped:
            EmptyView()
        }
    }
}

#Preview {
    ContentView()
}
