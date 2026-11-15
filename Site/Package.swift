// swift-tools-version: 6.0
import PackageDescription

// Foundation only: no third-party dependencies, no Node.js, no build step beyond `swift run`.
let package = Package(
    name: "viadere-site",
    products: [
        .executable(name: "viadere-site", targets: ["viadere-site"]),
        .library(name: "SiteKit", targets: ["SiteKit"]),
    ],
    targets: [
        .target(name: "SiteKit"),
        .executableTarget(name: "viadere-site", dependencies: ["SiteKit"]),
        .testTarget(name: "SiteKitTests", dependencies: ["SiteKit"]),
    ]
)
