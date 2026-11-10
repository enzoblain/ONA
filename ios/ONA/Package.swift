// swift-tools-version: 6.0
// Runs the app's platform-neutral code (protocol, payment check, pairing, remote model) and its tests on the Mac:
//   cd ios/ONA && swift test
// The app itself is built with ONA.xcodeproj; the views are not part of this package.
import PackageDescription

let package = Package(
    name: "ONA",
    platforms: [.macOS(.v15), .iOS(.v18)],
    targets: [
        .target(name: "ONA", path: "ONA", sources: ["Protocol", "Remote", "Pairing"]),
        .testTarget(name: "ONATests", dependencies: ["ONA"], path: "ONATests"),
    ]
)
