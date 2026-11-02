/// The hand-off between the two applications, and what it is allowed to
/// carry.
///
/// These exist because the hand-off is the one place where this
/// demonstration gives the voting application something it did not have
/// before -- the ability to make the wallet put a question in front of
/// the voter. Clause A8 says that is the trade; these say what was *not*
/// traded: the wallet still reads the same bytes through the same reader,
/// still checks them against a configuration it fetched itself, and still
/// refuses the same requests it refused when somebody carried them in.
import Foundation
import OVPOCKit
import XCTest

final class HandOffTests: XCTestCase {
    private func enrolled(_ fixture: Fixture,
                          via route: VoterFlow.Route = .wallet) async throws -> VoterFlow {
        let flow = VoterFlow(elections: FakeElections(fixture),
                             replies: FakeOffice(fixture),
                             box: FakeBox(fixture))
        try await flow.enrol(via: route)
        return flow
    }

    /// Whole, not rebuilt. A hand-off that reassembled the three fields
    /// would be a second renderer of the request, and the wallet's checks
    /// would be reading one copy while the file the browser writes is the
    /// other.
    func testTheHandOffCarriesTheRequestFileByteForByte() async throws {
        let flow = try await enrolled(try Fixture())
        let url = try XCTUnwrap(flow.walletHandOff)
        XCTAssertEqual(HandOff.request(from: url), flow.requestFile)
    }

    /// The same three fields as the file, and no fourth one.
    ///
    /// Nothing here could put an identifier in -- this application does
    /// not hold one -- which is exactly why it is worth asserting: the
    /// test fails the day somebody adds a field to make the wallet's
    /// screen friendlier.
    func testTheHandOffNamesTheElectionAndNobodyElse() async throws {
        let flow = try await enrolled(try Fixture())
        let url = try XCTUnwrap(flow.walletHandOff)
        let bytes = try XCTUnwrap(HandOff.request(from: url))
        let body = try XCTUnwrap(
            JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(Set(body.keys),
                       ["blinded_key", "config_digest", "election_id"])
    }

    /// No inbound direction on the other route, so nothing to open.
    ///
    /// The signed document carries `id`, and an application that could
    /// ask a wallet to produce one and hand it back would be holding the
    /// association §5.3 exists to keep apart.
    func testTheQualifiedSignatureRouteHandsOffToNobody() async throws {
        let flow = try await enrolled(try Fixture(), via: .qualifiedSignature)
        XCTAssertNotNil(flow.requestFile)
        XCTAssertNil(flow.walletHandOff,
                     "the document route must not open the stand-in wallet")
    }

    /// Nothing until there is something to carry.
    func testThereIsNoHandOffBeforeBlinding() throws {
        let fixture = try Fixture()
        let flow = VoterFlow(elections: FakeElections(fixture),
                             replies: FakeOffice(fixture),
                             box: FakeBox(fixture))
        XCTAssertNil(flow.walletHandOff)
    }

    /// Anything on the device can open a URL scheme, so a malformed one
    /// is an ordinary event: `nil`, not a throw and not an alarm.
    func testOnlyTheWalletSchemeAndHostAreRead() async throws {
        let flow = try await enrolled(try Fixture())
        let payload = try XCTUnwrap(flow.requestFile).b64url

        let bad = [
            "https://example.invalid/request?r=\(payload)",   // another scheme
            "ovpoc-wallet://collected?r=\(payload)",          // another host
            "ovpoc-wallet://request",                         // nothing carried
            "ovpoc-wallet://request?s=\(payload)",            // another name
            "ovpoc-wallet://request?r=not%20base64url",       // not decodable
        ]
        for text in bad {
            let url = try XCTUnwrap(URL(string: text))
            XCTAssertNil(HandOff.request(from: url), "accepted \(text)")
        }
    }

    /// A wallet opened by the application checks what it was handed
    /// exactly as it checks what it was carried, and refuses the same
    /// things. This is the whole of what makes the consent screen worth
    /// having on this path.
    func testAHandedRequestGoesThroughTheSameTwoChecks() async throws {
        let here = try Fixture(electionID: "here")
        let elsewhere = try Fixture(electionID: "elsewhere")
        let office = FakeOffice(here)

        let honest = try await enrolled(here)
        let foreign = try await enrolled(elsewhere)

        let wallet = WalletFlow(wallet: WalletKey(voterID: "Nagy Béla"),
                                elections: office, office: office)

        // The one this office is serving: read, and summarised for the
        // voter to look at.
        let good = try XCTUnwrap(HandOff.request(from: try XCTUnwrap(honest.walletHandOff)))
        _ = try await wallet.load(good)
        XCTAssertFalse(wallet.consentSummary.isEmpty)

        // One for another election, arriving the new way: refused the old
        // way, and nothing transmitted.
        let wrong = try XCTUnwrap(HandOff.request(from: try XCTUnwrap(foreign.walletHandOff)))
        do {
            try await wallet.load(wrong)
            XCTFail("a handed-over request escaped the election check")
        } catch let failure as WalletFlow.Failure {
            guard case .differentElection = failure else {
                return XCTFail("wrong failure: \(failure)")
            }
        }
        XCTAssertTrue(office.transmitted.isEmpty, "nothing may have been sent")
    }

    /// And back. The outcome and nothing else: the office's answer is
    /// already the voting application's to learn, since it collects `s_c`
    /// by presenting `c`.
    func testTheWayBackCarriesTheOutcomeAlone() throws {
        let url = try XCTUnwrap(HandOff.backToVoter(outcome: "RELEASED"))
        XCTAssertEqual(url.scheme, HandOff.voterScheme)
        XCTAssertEqual(HandOff.outcome(from: url), "RELEASED")

        let components = try XCTUnwrap(
            URLComponents(url: url, resolvingAgainstBaseURL: false))
        XCTAssertEqual(components.queryItems?.count, 1)
    }

    func testTheWayBackIsReadOnlyOnItsOwnScheme() throws {
        for text in ["ovpoc-wallet://collected?outcome=RELEASED",
                     "ovpoc-voter://request?outcome=RELEASED",
                     "ovpoc-voter://collected"] {
            let url = try XCTUnwrap(URL(string: text))
            XCTAssertNil(HandOff.outcome(from: url), "accepted \(text)")
        }
    }

    /// What a build says it answers to, out of the shapes a plist can
    /// take. The bundle itself is not constructible in a test; the part
    /// that goes wrong is this reading, so this is the part separated
    /// out and checked.
    func testTheRegisteredSchemesAreReadOutOfTheUrlTypes() {
        // The shape a correct build has.
        let good: Any = [["CFBundleURLName": "hu.diw.ovpoc.wallet",
                          "CFBundleURLSchemes": ["ovpoc-wallet"]]]
        XCTAssertEqual(HandOff.schemes(in: good), ["ovpoc-wallet"])

        // Several entries, several schemes: flattened in order.
        let many: Any = [["CFBundleURLSchemes": ["a", "b"]],
                         ["CFBundleURLSchemes": ["c"]]]
        XCTAssertEqual(HandOff.schemes(in: many), ["a", "b", "c"])

        // And every way a build can have registered nothing. Each of
        // these must read as *nothing*, never as a crash and never as a
        // plausible wrong answer: the screen that shows this is the one
        // instrument for a fault that otherwise looks like silence.
        for empty: Any? in [nil,
                            [],
                            ["not a dictionary"],
                            [["CFBundleURLName": "named, claims nothing"]],
                            [["CFBundleURLSchemes": "not an array"]]] {
            XCTAssertEqual(HandOff.schemes(in: empty), [],
                           "read a scheme out of \(String(describing: empty))")
        }
    }

    /// The two schemes are different strings, which is not a tautology:
    /// one application registering the other's would have the wallet
    /// opening itself, and the voter would never see the office answer.
    func testTheTwoSchemesAreNotTheSame() {
        XCTAssertNotEqual(HandOff.walletScheme, HandOff.voterScheme)
    }
}
