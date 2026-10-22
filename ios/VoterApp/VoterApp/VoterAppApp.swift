/// The voting client. It never learns who you are.
///
/// That is a property of what is linked into this target, not a promise
/// in a comment: `OVPOCKit` keeps `RequestTransmitting` — the protocol
/// that carries `[id, c, s]` — for the wallet, and nothing here conforms
/// to it or depends on it. A voting application that wanted to transmit a
/// token request would have to grow a dependency visible in a diff.
///
/// The addresses come from `Origins.hosted`, so a device works over the
/// internet with nothing configured. A laptop deployment separates the
/// origins by port, which a phone on another machine cannot reach.
import SwiftUI

@main
struct VoterAppApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
