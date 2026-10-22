/// The wallet. It holds the identifier and talks to the office itself.
///
/// §5.3 is the whole reason this is a separate application rather than a
/// screen in the other one: were the voting application to carry
/// `[id, c, s]`, one component on the voter's own device would hold both
/// `id` and `k_p^a` together with the office's signature over their
/// association. The blinding would still stop the office linking voter to
/// ballot — and the linkage would survive where it could be recorded,
/// exported, or produced under compulsion.
///
/// What separates the two here is the app sandbox, and clause A8 is
/// honest about the difference: a browser origin is enforced by the
/// browser, which a page cannot talk its way around, while a sandbox is
/// enforced by the same system that offers `openURL`. Nothing in this
/// repository makes the shortcut impossible. The file handover is the
/// discipline that declines to take it.
import SwiftUI

@main
struct WalletAppApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
