// swift-tools-version: 6.0
// The desktop app's logic (protocol, pairing, phone server, missions over ona-core) and its tests:
//   desktop/OnaCoreBridge/build.sh   (once: builds OnaCore.xcframework)
//   cd desktop/ONADesktop && swift test
// The app itself is built with ONADesktop.xcodeproj.
import PackageDescription

let package = Package(
    name: "ONADesktop",
    platforms: [.macOS("26.0")],
    products: [.library(name: "ONADesktopCore", targets: ["ONADesktopCore"])],
    targets: [
        .binaryTarget(name: "OnaCore", path: "../OnaCoreBridge/OnaCore.xcframework"),
        .target(
            name: "ONADesktopCore",
            dependencies: ["OnaCore"],
            path: "Core",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration"),
                             .linkedFramework("CoreFoundation")]
        ),
        .testTarget(name: "ONADesktopTests", dependencies: ["ONADesktopCore"], path: "Tests"),
    ]
)
