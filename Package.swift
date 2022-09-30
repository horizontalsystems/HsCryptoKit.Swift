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
        .package(url: "https://github.com/horizontalsystems/HsExtensions.Swift.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "3.0.0"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", "0.8.0"..."0.8.1"),
    ],
    targets: [
        .target(
            name: "HsCryptoKit",
            dependencies: [
                .product(name: "HsExtensions", package: "HsExtensions.Swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ]),
        .testTarget(
            name: "HsCryptoKitTests",
            dependencies: ["HsCryptoKit"]),
    ]
)
