// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ViadereBusinessSDK",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .watchOS(.v10),
    ],
    products: [
        .library(name: "ViadereBusinessSDK", targets: ["ViadereBusinessSDK"]),
        .executable(name: "viadere-key-monitor", targets: ["viadere-key-monitor"]),
    ],
    dependencies: [
        .package(path: "../ViadereCore"),
    ],
    targets: [
        .target(
            name: "ViadereBusinessSDK",
            dependencies: [
                .product(name: "ViadereCore", package: "ViadereCore"),
            ]
        ),
        .executableTarget(
            name: "viadere-key-monitor",
            dependencies: [
                "ViadereBusinessSDK",
                .product(name: "ViadereCore", package: "ViadereCore"),
            ]
        ),
        .testTarget(
            name: "ViadereBusinessSDKTests",
            dependencies: ["ViadereBusinessSDK"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
