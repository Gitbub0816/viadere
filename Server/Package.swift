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
        .package(url: "https://github.com/vapor/vapor.git", from: "4.122.3"),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.13.0"),
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.14.0"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.9.0"),
        // No tagged release allows swift-crypto 5 yet (1.0.0-beta.1 caps it below 5.0.0); pin the exact main commit that does (see CLAUDE.md exceptions).
        .package(url: "https://github.com/swift-server/webauthn-swift.git", revision: "030acd1eedaa835958ae3fcc0e491bec03b2abf1"),
        .package(url: "https://github.com/swift-server-community/APNSwift.git", from: "8.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.3"),
        // PKCS#7 (CMS) signing of Wallet passes, and the TLS identity APNs needs for pass-update pushes.
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.21.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.3"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.37.5"),
        // Webhook delivery pins the vetted IP address with `dnsOverride` (the SSRF defence against DNS rebinding).
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.36.2"),
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
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
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
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
