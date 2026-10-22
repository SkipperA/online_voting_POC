// swift-tools-version:5.9
//
// The protocol logic the two apps share, as a package rather than as files
// in an Xcode target.
//
// Two reasons. It can be tested with `swift test` on a Mac with no
// simulator, no device and no signing identity, which is how the vector
// conformance below is meant to be run. And it keeps the protocol separate
// from the interface, the way `src/ovpoc` is separate from `service` and
// `web`: a rule about what makes a ballot valid belongs here, and a rule
// about what a screen shows does not belong here at all.
//
// The dependency is pinned to an exact version. `_CryptoExtras` is
// underscored, which is Apple saying the API is not yet stable, and
// `_RSA.BlindSigning` is the part of it this project cannot do without.
// `.exact` rather than `.upToNextMinor` so that a change to that API
// arrives as a deliberate bump with a test run behind it, rather than as a
// resolution on someone else's machine.
//
// 3.12.3 rather than the newest. From 4.0 the package declares
// `swift-tools-version:6.1` and from 5.0 it declares 6.2, which would make
// a current Xcode a requirement of reading this repository. 3.12.3
// declares 5.9 and carries the identical blind-signing API --
// `RSABSSA_SHA384_PSS_Deterministic`, `prepare`, `blind`, `finalize`,
// `isValidSignature` -- so the pin costs nothing and buys several years of
// toolchain.
import PackageDescription

let package = Package(
    name: "OVPOCKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "OVPOCKit", targets: ["OVPOCKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.12.3"),
    ],
    targets: [
        .target(
            name: "OVPOCKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "OVPOCKitTests",
            dependencies: [
                "OVPOCKit",
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
    ]
)
