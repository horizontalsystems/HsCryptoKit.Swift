# HsCryptoKit.Swift

HsCryptoKit library include base cryptography. Hashing functions, secp256k1 curve.

## Requirements
iOS (13.0, *)

## Installation

### Swift Package Manager

The [Swift Package Manager](https://swift.org/package-manager/) is a tool for automating the distribution of Swift code
and is integrated into the `swift` compiler. It is in early development, but HsCryptoKit does support its use on
supported platforms.

Once you have your Swift package set up, adding HdWalletKit as a dependency is as easy as adding it to
the `dependencies` value of your `Package.swift`.

```swift
dependencies: [
    .package(url: "https://github.com/horizontalsystems/HsCryptoKit.Swift.git", .upToNextMajor(from: "1.0.0")),
]
```

for target: []
```swift
dependencies: [
    .product(name: "HsCryptoKit", package: "HsCryptoKit.Swift"),
]
```


## License

HsCryptoKit is available under the MIT license. See the LICENSE file for more info.
