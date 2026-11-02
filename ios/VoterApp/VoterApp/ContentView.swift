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
    /// How this application opens the wallet. The environment's, not
    /// `UIApplication`'s: the model decides *that* a hand-off exists and
    /// the view performs it, which keeps the one type `swift test` reaches
    /// free of the operating system.
    @Environment(\.openURL) private var openURL

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
                        if let question = election.question {
                            LabeledContent("question", value: question)
                        }
                        if let options = election.options {
                            LabeledContent("options",
                                           value: options.joined(separator: " · "))
                        }
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

                buildRegistration
            }
            .navigationTitle("Voter application")
            .task { await model.readTheElectionForTheLabel() }
        }
        // Blinding is done and the wallet route has somewhere to go, so it
        // goes -- no tap, which is the whole of what this demonstrates.
        // The voter still has to sign over there; what has gone is the
        // carrying, not the consent.
        .onChange(of: model.handOff) { _, url in
            guard let url else { return }
            // The completion is the whole point of using it. `openURL`
            // reports whether *anything* on the device claimed the
            // scheme, and reports it to nobody by default -- so a wallet
            // that is not installed, or one whose URL type was never
            // registered in Xcode, is a handover that silently did not
            // happen. Told, this application can offer the file instead.
            openURL(url) { accepted in
                Task { @MainActor in model.handOffWasAccepted(accepted) }
            }
        }
        // The wallet puts the voter back here when it has transmitted.
        .onOpenURL { url in
            Task { await model.returnedFromWallet(outcome: HandOff.outcome(from: url)) }
        }
        .onChange(of: scenePhase) { _, phase in
            // Coming back from the wallet is when the office may have
            // released. One look, not a timer.
            if phase == .active {
                Task { await model.cameBackToTheForeground() }
            }
        }
    }

    /// What this binary answers to, read out of its own bundle.
    ///
    /// Quiet when it is right and loud when it is not. The scheme this
    /// application registers is how the wallet puts the voter back here;
    /// it is also the only visible evidence that the target's
    /// `INFOPLIST_FILE` was set at all, because the two targets are
    /// configured the same way and in the same sitting. An application
    /// that does not answer to its own scheme is one whose sibling
    /// almost certainly does not either -- and the wallet's silence is
    /// indistinguishable from a wallet that is not installed.
    ///
    /// No test can see a build setting. This is the instrument that can.
    @ViewBuilder
    private var buildRegistration: some View {
        let registered = HandOff.schemesRegistered()
        if registered.contains(HandOff.voterScheme) {
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
                Text("It should answer to \(HandOff.voterScheme), which is "
                     + "how the wallet brings you back here once the office "
                     + "has answered.\n\n"
                     + "The cause is almost always one build setting: "
                     + "Packaging → Info.plist File, which must be "
                     + "Info.plist for both targets — step 4 of "
                     + "ios/README.md. If it is unset here it is unset on "
                     + "the wallet too, and the hand-off will do nothing "
                     + "with no error on either side.")
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
                // Which election, before enrolling in it rather than
                // after. Read for the label only -- the configuration
                // this run is bound to is the one `enrol` pins.
                if let name = model.electionName {
                    LabeledContent("election", value: name)
                }
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
                // The hand-off went nowhere. Said plainly and with the
                // way out beside it, rather than leaving a voter looking
                // at a screen that says the wallet should have opened.
                if model.handOffAccepted == false {
                    Section {
                        if let url = model.requestFileURL {
                            ShareLink("Send the request to the wallet", item: url)
                        }
                    } header: {
                        Text("Nothing on this device opened the wallet")
                    } footer: {
                        Text("Either the wallet application is not installed, "
                             + "or it is installed and did not register the "
                             + "URL type the hand-off uses — step 5 of "
                             + "ios/README.md, which Xcode writes into a file "
                             + "this repository does not carry.\n\n"
                             + "Nothing is lost. The request is unchanged and "
                             + "the button above carries it over by hand, "
                             + "which is exactly what the browser "
                             + "demonstration does and what the wallet's own "
                             + "Open button is for. Then come back and press "
                             + "Collect.")
                    }
                }

                Section {
                    if let outcome = model.walletOutcome {
                        LabeledContent("the office answered", value: outcome)
                    }
                    Button("Collect the token") { Task { await model.collect() } }
                } header: {
                    Text("Over to the wallet")
                } footer: {
                    Text(model.handOffAccepted == false
                         ? "What crossed is the blinded key, the election and "
                           + "its digest — and by the button above, it crosses "
                           + "as a file, which is the browser's arrangement. "
                           + "It does not say who you are: the wallet adds "
                           + "that and transmits to the office itself. Clause "
                           + "A8."
                         : "The blinded key went straight to the wallet, which "
                           + "should have opened. Sign there and you come back "
                           + "here holding the token.\n\n"
                           + "What crossed is the blinded key, the election "
                           + "and its digest — the same three things the "
                           + "browser demonstration writes into a file the "
                           + "voter carries. It does not say who you are: the "
                           + "wallet adds that and transmits to the office "
                           + "itself, so this application never learns your "
                           + "identifier and never sees your signature.\n\n"
                           + "What it can now do, and could not before, is "
                           + "put the signing question in front of you. It "
                           + "cannot answer it. Clause A8.\n\n"
                           + "Collect is here for when the switch back does "
                           + "not happen on its own.")
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
                // What the ballot asks, above what it offers. From the
                // pinned configuration and from nothing else, so the
                // question a voter answers is the question the digest
                // covers.
                if let question = model.election?.question {
                    Text(question).font(.headline)
                }
                Stepper("Selection: \(model.selection)",
                        value: $model.selection, in: -9 ... 9)
                Text(model.selectionLabel)
                    .font(.callout)
                    .foregroundStyle(.secondary)
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
