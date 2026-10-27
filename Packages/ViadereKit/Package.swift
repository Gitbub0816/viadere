// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ViadereKit",
    platforms: [
        .iOS(.v17),
        .watchOS(.v10),
        .macOS(.v14),
    ],
    products: [
        .library(name: "ViadereKit", targets: ["ViadereKit"]),
    ],
    dependencies: [
        .package(path: "../ViadereCore"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.3"),
    ],
    targets: [
        .target(
            name: "ViadereKit",
            dependencies: [
                .product(name: "ViadereCore", package: "ViadereCore"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "ViadereKitTests",
            dependencies: ["ViadereKit"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
