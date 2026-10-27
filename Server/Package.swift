// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ViadereServer",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ViadereServer", targets: ["ViadereServer"]),
        .library(name: "ViadereServerKit", targets: ["ViadereServerKit"]),
    ],
    dependencies: [
        .package(path: "../Packages/ViadereCore"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.110.0"),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.12.0"),
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.10.0"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.8.0"),
        .package(url: "https://github.com/swift-server/webauthn-swift.git", from: "1.0.0-beta.1"),
        .package(url: "https://github.com/swift-server-community/APNSwift.git", from: "6.0.0"),
        // 5.x does not compile with Swift 6.2; ViadereCore pins the same range.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "5.0.0"),
    ],
    targets: [
        .target(
            name: "ViadereServerKit",
            dependencies: [
                .product(name: "ViadereCore", package: "ViadereCore"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
                .product(name: "WebAuthn", package: "webauthn-swift"),
                .product(name: "APNS", package: "APNSwift"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "ViadereServer",
            dependencies: ["ViadereServerKit"]
        ),
        .testTarget(
            name: "ViadereServerKitTests",
            dependencies: [
                "ViadereServerKit",
                .product(name: "XCTVapor", package: "vapor"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
