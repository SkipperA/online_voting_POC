/// The sequence, driven end to end with no service running.
///
/// What these are for is the order and the refusals -- the things a view
/// cannot be relied upon to get right and a simulator is a slow way to
/// find out about. The cryptography is covered by the vectors; this is
/// covered by what the protocol says must happen in what order.
import Crypto
import Foundation
import OVPOCKit
import XCTest

final class VoterFlowTests: XCTestCase {
    private func makeFlow(_ fixture: Fixture, office: FakeOffice, box: FakeBox) -> VoterFlow {
        VoterFlow(elections: FakeElections(fixture), replies: office, box: box)
    }

    /// One tap takes the voter to the handover and stops there.
    func testEnrolCompletesFourStepsAndWaitsForTheWallet() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let flow = makeFlow(fixture, office: office, box: FakeBox(fixture))

        try await flow.enrol()

        XCTAssertEqual(flow.record(.config).progress, .done)
        XCTAssertEqual(flow.record(.keygen).progress, .done)
        XCTAssertEqual(flow.record(.blind).progress, .done)
        XCTAssertEqual(flow.record(.handover).progress, .done)
        // And stops: the next thing that happens is a person carrying a
        // file to another application.
        XCTAssertEqual(flow.record(.collect).progress, .awaitingYou)
        XCTAssertEqual(flow.record(.cast).progress, .notYet)
        XCTAssertNotNil(flow.requestFile)
    }

    /// Pressed before the wallet has transmitted, `Collect` says "not
    /// yet". It is the normal state of that button, not a failure.
    func testCollectBeforeTheWalletHasTransmittedIsNotAnError() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let flow = makeFlow(fixture, office: office, box: FakeBox(fixture))
        try await flow.enrol()

        let first = try await flow.collect()
        XCTAssertEqual(first, .notYet)
        XCTAssertEqual(flow.record(.collect).progress, .awaitingYou,
                       "asking too early must not advance the sequence")
    }

    /// The whole run, with the wallet in the middle.
    func testTheWholeSequence() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let box = FakeBox(fixture)
        let flow = makeFlow(fixture, office: office, box: box)

        try await flow.enrol()

        // The voter carries the file to the wallet, which is a separate
        // flow holding a separate key and the identifier.
        let wallet = WalletFlow(
            wallet: WalletKey(voterID: "Kovács Ágnes"),
            elections: office, office: office)
        try await wallet.load(try XCTUnwrap(flow.requestFile))
        let outcome = try await wallet.consentAndTransmit()
        XCTAssertEqual(outcome, "ISSUED")

        // Back in the voting application.
        let collected = try await flow.collect()
        XCTAssertEqual(collected, .token)
        XCTAssertEqual(flow.record(.collect).progress, .done)

        try flow.cast(selection: 3)
        let receipt = try await flow.submit()
        XCTAssertTrue(receipt.accepted)
        let authentic = receipt.verifies(under: try XCTUnwrap(flow.election))
        XCTAssertTrue(authentic, "a receipt nobody checks is a string")

        let asIntended = try await flow.verify(expecting: 3)
        XCTAssertTrue(asIntended)
        let wrongExpectation = try await flow.verify(expecting: 2)
        XCTAssertFalse(wrongExpectation, "the check must be able to say no")
    }

    /// A protest selection is accepted and superseding, not refused.
    ///
    /// Three words, not two. A client that rejected one would take from
    /// the voter a thing the design gives them, and `tally()` reports the
    /// distribution of these rather than one scalar count.
    func testAProtestSelectionIsCastLikeAnyOther() async throws {
        let fixture = try Fixture(numChoices: 4)
        let office = FakeOffice(fixture)
        let box = FakeBox(fixture)
        let flow = makeFlow(fixture, office: office, box: box)
        try await flow.enrol()
        let wallet = WalletFlow(wallet: WalletKey(voterID: "HU-PROTEST-008"),
                                elections: office, office: office)
        try await wallet.load(try XCTUnwrap(flow.requestFile))
        _ = try await wallet.consentAndTransmit()
        _ = try await flow.collect()

        try flow.cast(selection: -7)

        let shown = flow.record(.cast).payload
        XCTAssertEqual(shown.first { $0.name == "selection" }?.value, "-7")
        XCTAssertEqual(shown.first { $0.name == "in the option list" }?.value, "false",
                       "it must say so, and still cast it")
        let protestReceipt = try await flow.submit()
        XCTAssertTrue(protestReceipt.accepted)
    }

    /// A mint under an open flow halts it, and names what happened.
    func testAMintUnderAnOpenFlowStopsIt() async throws {
        let fixture = try Fixture()
        let elections = FakeElections(fixture)
        let office = FakeOffice(fixture)
        let flow = VoterFlow(elections: elections, replies: office, box: FakeBox(fixture))
        try await flow.enrol()

        // The setup console mints. All three key pairs are replaced and
        // the digest moves; everything this flow holds belongs to the
        // previous election.
        elections.digestNow = String(repeating: "a", count: 64)

        do {
            _ = try await flow.collect()
            XCTFail("the flow continued under a superseded election")
        } catch let error as VoterFlow.Failure {
            guard case .electionSuperseded(let pinned, let now) = error else {
                return XCTFail("wrong failure: \(error)")
            }
            XCTAssertEqual(pinned, fixture.digest)
            XCTAssertEqual(now, String(repeating: "a", count: 64))
        }
    }

    /// Clause A9, as a test rather than as a paragraph.
    func testARestoreAfterBlindingReportsTheEntitlementSpent() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let flow = makeFlow(fixture, office: office, box: FakeBox(fixture))
        try await flow.enrol()

        let snapshot = try XCTUnwrap(flow.snapshot)
        XCTAssertTrue(snapshot.hadUncollectedBlinding)
        XCTAssertNotNil(snapshot.blindedKey)
        XCTAssertNil(snapshot.token)

        // What a relaunched application can rebuild. The ad-hoc key comes
        // back, because its seed is bytes; the blinding inverse has no
        // representation to keep, so the token that may already have been
        // issued for this `c` can never be unblinded.
        let revived = makeFlow(fixture, office: office, box: FakeBox(fixture))
        XCTAssertThrowsError(try revived.restore(from: snapshot)) { error in
            XCTAssertEqual(error as? VoterFlow.Failure, .blindingSecretLost)
        }
    }

    /// Steps out of order are named, not crashed. The apps have buttons.
    func testStepsOutOfOrderAreRefusedByName() async throws {
        let fixture = try Fixture()
        let flow = makeFlow(fixture, office: FakeOffice(fixture), box: FakeBox(fixture))

        XCTAssertThrowsError(try flow.cast(selection: 1)) { error in
            XCTAssertEqual(error as? VoterFlow.Failure, .notReady(.cast))
        }
        do {
            _ = try await flow.collect()
            XCTFail("collected before enrolling")
        } catch {
            XCTAssertEqual(error as? VoterFlow.Failure, .notReady(.collect))
        }
    }

    /// The handover file is the browser's file.
    ///
    /// A request saved in `web/voter-app` must open in the native wallet
    /// and the reverse, so the field names are `wallet.js`'s and are
    /// pinned here rather than left to drift.
    func testTheRequestFileMatchesTheBrowsersFields() async throws {
        let fixture = try Fixture()
        let flow = makeFlow(fixture, office: FakeOffice(fixture), box: FakeBox(fixture))
        try await flow.enrol()

        let body = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(flow.requestFile))
                as? [String: Any])

        XCTAssertEqual(Set(body.keys),
                       ["_transport", "election_id", "config_digest", "blinded_key"])
        XCTAssertEqual(body["election_id"] as? String, fixture.election.electionID)
        XCTAssertEqual(body["config_digest"] as? String, fixture.digest)

        // And nothing that identifies anybody: the application that wrote
        // it does not know who the voter is, and this is the assertion
        // that keeps it that way.
        let text = String(data: try XCTUnwrap(flow.requestFile), encoding: .utf8) ?? ""
        for forbidden in ["voter_id", "wallet_signature", "id\":"] {
            XCTAssertFalse(text.contains(forbidden), "the file carries \(forbidden)")
        }
    }

    // -- the second route ------------------------------------------------

    func testTheQualifiedSignatureRouteWritesTheDocumentInstead() async throws {
        let fixture = try Fixture()
        let flow = makeFlow(fixture, office: FakeOffice(fixture), box: FakeBox(fixture))
        try await flow.enrol(via: .qualifiedSignature)

        XCTAssertEqual(flow.route, .qualifiedSignature)
        XCTAssertEqual(flow.requestFileName, "token-request.pdf")
        let document = try XCTUnwrap(flow.requestFile)
        XCTAssertTrue(document.starts(with: Data("%PDF-1.7\n".utf8)))

        // The same document the office will rebuild, not merely a PDF
        // carrying the same values. If these two ever disagree, every
        // request this application writes is refused as "not as rendered".
        let expected = try PDFRequest.render(PDFRequest.payload(
            electionID: fixture.election.electionID,
            configDigest: fixture.digest,
            blindedKey: try XCTUnwrap(Self.blindedKey(of: document))))
        XCTAssertEqual(document, expected)
    }

    /// The one value a voter checks by eye, in the three places it appears.
    ///
    /// The screen shows it from the key this application generated, the
    /// document prints it on the page about to be signed, and the office's
    /// page recomputes it from the file handed in. A voter comparing the
    /// first two is checking that the document in their wallet is the
    /// request this device made — so these two readings disagreeing would
    /// make that check meaningless while still looking like a check.
    func testTheFingerprintOnTheScreenIsTheOnePrintedOnTheDocument() async throws {
        let fixture = try Fixture()
        let flow = makeFlow(fixture, office: FakeOffice(fixture), box: FakeBox(fixture))
        XCTAssertNil(flow.blindedKeyFingerprint, "nothing is blinded yet")

        try await flow.enrol(via: .qualifiedSignature)
        let shown = try XCTUnwrap(flow.blindedKeyFingerprint)
        XCTAssertEqual(shown.count, 19, "four groups of four, three dashes")

        let document = String(decoding: try XCTUnwrap(flow.requestFile),
                              as: UTF8.self)
        XCTAssertTrue(document.contains(shown),
                      "the document does not print the fingerprint the screen shows")

        // And the disclosure row, which is what ends up in the transcript
        // the audience takes away.
        let handover = try XCTUnwrap(flow.records.first { $0.step == .handover })
        let row = handover.payload.first { $0.name == "fingerprint of c" }
        XCTAssertEqual(row?.value, shown)
    }

    func testNeitherRouteLetsTheApplicationLearnWhoTheVoterIs() async throws {
        for route in VoterFlow.Route.allCases {
            let fixture = try Fixture()
            let flow = makeFlow(fixture, office: FakeOffice(fixture),
                                box: FakeBox(fixture))
            try await flow.enrol(via: route)
            let text = String(decoding: try XCTUnwrap(flow.requestFile),
                              as: UTF8.self)
            for forbidden in ["voter_id", "wallet_signature"] {
                XCTAssertFalse(text.contains(forbidden),
                               "\(route): the file carries \(forbidden)")
            }
        }
    }

    /// The step order, the blinding and the ballot are the same on both.
    ///
    /// Three things were settled as untouchable when this route was
    /// designed: `c` is still `c`, the token is still an ordinary RSA-PSS
    /// signature over `k_p^a`, and the ballot is unchanged. The first is
    /// what this asserts; the other two never see the route at all.
    func testTheRouteChangesTheHandoverAndNothingElse() async throws {
        var files: [VoterFlow.Route: Data] = [:]
        var steps: [VoterFlow.Route: [VoterFlow.Step]] = [:]
        for route in VoterFlow.Route.allCases {
            let fixture = try Fixture()
            let flow = makeFlow(fixture, office: FakeOffice(fixture),
                                box: FakeBox(fixture))
            try await flow.enrol(via: route)
            files[route] = flow.requestFile
            steps[route] = flow.records.filter { $0.progress == .done }
                .map(\.step)
        }
        XCTAssertEqual(steps[.wallet], steps[.qualifiedSignature],
                       "the two routes completed different steps")
        XCTAssertNotEqual(files[.wallet], files[.qualifiedSignature])
    }

    /// `c` out of the document's marker comment, which is how the office
    /// recovers it too.
    static func blindedKey(of document: Data) -> Data? {
        let text = String(decoding: document, as: UTF8.self)
        guard let at = text.range(of: PDFRequest.marker),
              let end = text[at.upperBound...].firstIndex(of: "\n"),
              let body = try? JSONSerialization.jsonObject(
                with: Data(text[at.upperBound..<end].utf8)) as? [String: Any],
              let encoded = body["blinded_key"] as? String else { return nil }
        return Base64URL.decode(encoded)
    }
}

final class WalletFlowTests: XCTestCase {
    private func request(for fixture: Fixture, office: FakeOffice) async throws -> Data {
        let flow = VoterFlow(
            elections: FakeElections(fixture), replies: office, box: FakeBox(fixture))
        try await flow.enrol()
        return try XCTUnwrap(flow.requestFile)
    }

    func testARequestForAnotherElectionIsRefused() async throws {
        let here = try Fixture(electionID: "here")
        let elsewhere = try Fixture(electionID: "elsewhere")
        let office = FakeOffice(here)

        let foreign = try await request(for: elsewhere, office: FakeOffice(elsewhere))
        let wallet = WalletFlow(wallet: WalletKey(voterID: "Nagy Béla"),
                                elections: office, office: office)

        do {
            try await wallet.load(foreign)
            XCTFail("the wallet signed a request for another election")
        } catch let error as WalletFlow.Failure {
            guard case .differentElection(let inRequest, let hereID) = error else {
                return XCTFail("wrong failure: \(error)")
            }
            XCTAssertEqual(inRequest, "elsewhere")
            XCTAssertEqual(hereID, "here")
        }
        XCTAssertTrue(office.transmitted.isEmpty, "nothing may have been sent")
    }

    /// The case that actually happens: a request saved before a mint.
    func testARequestFromBeforeAMintIsRefused() async throws {
        let fixture = try Fixture(electionID: "same-name")
        let office = FakeOffice(fixture)
        // Awaited before the assertion rather than inside it. `XCTUnwrap`
        // takes an autoclosure, which is not async, so an `await` in its
        // argument is a compile error -- one the Python suite cannot see
        // and `tests/test_native_sources.py` now looks for.
        let saved = try await request(for: fixture, office: office)
        var body = try XCTUnwrap(
            JSONSerialization.jsonObject(with: saved) as? [String: Any])
        body["config_digest"] = String(repeating: "b", count: 64)

        let wallet = WalletFlow(wallet: WalletKey(voterID: "Nagy Béla"),
                                elections: office, office: office)
        do {
            try await wallet.load(try JSONSerialization.data(withJSONObject: body))
            XCTFail("the wallet accepted a stale request")
        } catch let error as WalletFlow.Failure {
            guard case .differentConfiguration = error else {
                return XCTFail("wrong failure: \(error)")
            }
        }
        XCTAssertTrue(office.transmitted.isEmpty)
    }

    func testSomethingThatIsNotARequestIsRefused() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let wallet = WalletFlow(wallet: WalletKey(voterID: "Nagy Béla"),
                                elections: office, office: office)
        do {
            try await wallet.load(Data("not json".utf8))
            XCTFail("loaded")
        } catch {
            XCTAssertEqual(error as? WalletFlow.Failure, .notATokenRequest)
        }
    }

    /// What the wallet sends, and what it signs over.
    func testTheWalletSignsHashOfIdAndCAndTransmitsItself() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let file = try await request(for: fixture, office: office)

        let key = WalletKey(voterID: "Kovács Ágnes")
        let wallet = WalletFlow(wallet: key, elections: office, office: office)
        let loaded = try await wallet.load(file)
        _ = try await wallet.consentAndTransmit()

        let sent = try XCTUnwrap(office.transmitted.first)
        XCTAssertEqual(sent.voterID, "Kovács Ágnes")
        XCTAssertEqual(sent.blindedKey, loaded.blindedKey)

        // The signature is over `hash([id, c])` and verifies under the
        // wallet's own key -- the one object in the exchange the office
        // could not have manufactured.
        XCTAssertTrue(Ed25519.verify(
            publicKey: key.publicBytes,
            signature: sent.walletSignature,
            over: sent.signedPayload))
    }
}

final class PersonaTests: XCTestCase {
    /// An adopted citizen signs as that citizen.
    ///
    /// The failure this prevents is the one that reached the simulator: a
    /// wallet generating its own key signs as nobody the register knows,
    /// and the office answers `NOT_IDENTIFIED` — correctly, and
    /// indistinguishably from an unknown identifier, which is §3.2 rather
    /// than a fault. The name is not the credential; the key is.
    func testAnAdoptedPersonaSignsUnderTheCertifiedKey() async throws {
        let fixture = try Fixture()
        let office = FakeOffice(fixture)
        let registry = FakePersonas(["Kovács Ágnes", "Nagy Béla"])

        let voter = VoterFlow(elections: FakeElections(fixture),
                              replies: office, box: FakeBox(fixture))
        try await voter.enrol()

        let adopted = try await registry.adopt("Kovács Ágnes")
        let wallet = WalletFlow(wallet: adopted, elections: office, office: office)
        try await wallet.load(try XCTUnwrap(voter.requestFile))
        _ = try await wallet.consentAndTransmit()

        let sent = try XCTUnwrap(office.transmitted.first)
        XCTAssertEqual(sent.voterID, "Kovács Ágnes")

        // Verified under the key the register holds for that name, which
        // is the check the office performs and the one a freshly
        // generated key fails.
        let certified = try XCTUnwrap(registry.certifiedKey(for: "Kovács Ágnes"))
        XCTAssertTrue(Ed25519.verify(publicKey: certified,
                                     signature: sent.walletSignature,
                                     over: sent.signedPayload))

        // And a key nobody enrolled does not verify under it.
        let stranger = WalletKey(voterID: "Kovács Ágnes")
        var forged = AuthRequest(voterID: "Kovács Ágnes", blindedKey: sent.blindedKey)
        forged.walletSignature = try stranger.sign(forged.signedPayload)
        XCTAssertFalse(Ed25519.verify(publicKey: certified,
                                      signature: forged.walletSignature,
                                      over: forged.signedPayload),
                       "the name must not be what the office accepts")
    }

    func testAdoptingSomebodyWhoIsNotEnrolledFails() async throws {
        let registry = FakePersonas(["Nagy Béla"])
        do {
            _ = try await registry.adopt("Nobody")
            XCTFail("adopted a citizen who is not on the register")
        } catch {
            // The demonstration's own origin answers 404; the office's
            // refusal is the opaque one and belongs to §3.2.
        }
    }
}
