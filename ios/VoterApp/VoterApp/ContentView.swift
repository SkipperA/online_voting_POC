/// The voting application: eight rows and four deliberate acts.
///
/// First the route, because the two diverge at the handover and the file
/// is written there. Then *Enrol in election* runs the four steps that
/// ask nothing. Then the voter carries a file out — to the demonstration's
/// wallet, or to their own and on to the office — comes back and presses
/// *Collect*, chooses, and submits.
///
/// Everything else on this screen is disclosure, and one thing on it is
/// an absence the voter is told about: on the qualified-signature route
/// there is no way to hand the signed document in from here, and the
/// footer says so rather than leaving them hunting for it. Clause A8.
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

    /// What the choice above actually changes, said before it is made.
    ///
    /// One step differs and the footer says which. Everything a reader
    /// might worry the choice affects — the blinding, the token, the
    /// ballot — is the same on both, and saying so here is cheaper than
    /// leaving them to wonder.
    private var routeExplanation: String {
        switch model.route {
        case .wallet:
            return "This demonstration's stand-in wallet signs a small JSON "
                 + "file as bytes, and transmits it to the office itself. "
                 + "Nothing on this device is a real identity."
        case .qualifiedSignature:
            return "The request is written as a PDF you sign in your own "
                 + "wallet — in Hungary the DÁP application. Your certificate "
                 + "says who you are, so the office reads your identifier out "
                 + "of your signature and never from anything this application "
                 + "sends. You hand the signed document in yourself.\n\n"
                 + "Only the handover changes. The blinded key, the token and "
                 + "the ballot are the same either way."
        }
    }

    @ViewBuilder
    private var actions: some View {
        switch model.phase {
        case .fresh:
            Section {
                Picker("Route", selection: $model.route) {
                    Text("The demonstration's wallet")
                        .tag(VoterFlow.Route.wallet)
                    Text("Your own wallet, as a signed PDF")
                        .tag(VoterFlow.Route.qualifiedSignature)
                }
                .pickerStyle(.inline)
                .labelsHidden()
            } header: {
                Text("How you will prove you may vote")
            } footer: {
                Text(routeExplanation)
            }

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
            switch model.route {
            case .wallet:
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

            case .qualifiedSignature:
                Section {
                    if let url = model.requestFileURL {
                        ShareLink("Export the request as a PDF", item: url)
                    }
                    if let fingerprint = model.fingerprintOfC {
                        LabeledContent("fingerprint of c") {
                            Text(fingerprint).monospaced()
                        }
                    }
                } header: {
                    Text("Over to your wallet")
                } footer: {
                    Text("Export the document and sign it in your wallet. The "
                         + "document prints that fingerprint on its own page: "
                         + "check the two agree before you sign, because it is "
                         + "the only thing tying what you are signing to the key "
                         + "this application generated.")
                }

                Section {
                    Link("Open the office's hand-in page",
                         destination: model.handInPage)
                    Button("Collect the token") { Task { await model.collect() } }
                } footer: {
                    Text("Then hand the signed document in yourself, in your "
                         + "browser, and come back and press Collect.\n\n"
                         + "There is no Upload button here and there will not "
                         + "be one. Your signature carries who you are, and "
                         + "this application holds the blinding factor — so it "
                         + "is the one component that must never see the signed "
                         + "document. Clause A8.")
                }
            }

        case .holdingToken:
            Section {
                Stepper("Selection: \(model.selection)",
                        value: $model.selection, in: -9 ... 9)
                Button(model.flow.attempt == 0 ? "Cast and submit"
                       : "Cast and submit — attempt \(model.flow.attempt + 1)") {
                    Task { await model.castAndSubmit() }
                }
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

            if accepted {
                Section {
                    Button("Cast a different ballot") { model.voteAgain() }
                } header: {
                    Text("Changed your mind — or were made to")
                } footer: {
                    Text("Your ballot is not final, and this is the design's "
                         + "answer to coercion rather than a convenience. A "
                         + "later ballot under the same key on this device "
                         + "supersedes the one above among the accepted, so "
                         + "somebody who stood over you while you voted, or "
                         + "who paid you to, cannot know whether what they "
                         + "watched is what counts.\n\n"
                         + "Nothing is spent by submitting — the token was "
                         + "spent when the office issued it — so no second "
                         + "token is needed, none is available, and the "
                         + "office is not asked for anything. Every attempt "
                         + "stays in the transcript; only the last is "
                         + "counted.")
                }
            }

        case .stopped:
            EmptyView()
        }
    }
}

#Preview {
    ContentView()
}
