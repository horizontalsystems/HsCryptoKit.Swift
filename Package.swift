// swift-tools-version: 5.6

import PackageDescription

let package = Package(
    name: "HsCryptoKit.Swift",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "HsCryptoKit",
            targets: ["HsCryptoKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", .upToNextMajor(from: "5.0.0")),
        .package(url: "https://github.com/horizontalsystems/HsExtensions.Swift.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "3.0.0"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", exact: .init(0, 10, 0))
    ],
    targets: [
        .target(
            name: "HsCryptoKitC",
            path: "Sources/HsCryptoKitC"
        ),
        .target(
            name: "HsCryptoKit",
            dependencies: [
                .target(name: "HsCryptoKitC"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "HsExtensions", package: "HsExtensions.Swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ],
            path: "Sources/HsCryptoKit"
        ),
        .testTarget(
            name: "HsCryptoKitTests",
            dependencies: ["HsCryptoKit"]),
    ]
)
