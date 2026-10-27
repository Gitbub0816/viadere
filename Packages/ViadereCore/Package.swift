// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ViadereCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .watchOS(.v10),
    ],
    products: [
        .library(name: "ViadereCore", targets: ["ViadereCore"]),
    ],
    dependencies: [
        // Wide range so Vapor (Server/) and the app can resolve a common version.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.3"),
    ],
    targets: [
        .target(
            name: "ViadereCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "ViadereCoreTests",
            dependencies: ["ViadereCore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
