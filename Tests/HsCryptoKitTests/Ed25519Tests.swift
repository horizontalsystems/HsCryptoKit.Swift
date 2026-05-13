@testable import HsCryptoKit
import HsExtensions
import XCTest

final class Ed25519Tests: XCTestCase {
    func testIsOnCurveForSolanaAddresses() {
        let addressSeed = Base58.decode("B9Lf9z5BfNPT4d5KMeaBFx8x1G4CULZYR1jA2kmxRDka")
        let pda = Base58.decode("46GZzzetjCURsdFPb7rcnspbEMnCBXe9kpjrsZAkKb6X")

        XCTAssertTrue(Crypto.Ed25519.isOnCurve(publicKeyData: addressSeed))
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: pda))
    }

    func testIsOnCurve() {
        XCTAssertTrue(Crypto.Ed25519.isOnCurve(publicKeyData: "5866666666666666666666666666666666666666666666666666666666666666".hs.hexData!))
        XCTAssertTrue(Crypto.Ed25519.isOnCurve(publicKeyData: "c58da76a5b48d832a8ee1dd05b85962064d9b60ab954466b2e65719a83b4e492".hs.hexData!))
        XCTAssertTrue(Crypto.Ed25519.isOnCurve(publicKeyData: "7a7050357e7d02e7ecfd75a45f854df63e156110286a63d76a521ddbf5f7fef7".hs.hexData!))
        XCTAssertTrue(Crypto.Ed25519.isOnCurve(publicKeyData: "217a14e9cfc6c49c38867a13af282c2706ddcb060ec402094f77163f1b790d40".hs.hexData!))

        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: "ce1b094bb9aa496f3166854f157d55adcf0a5760520421add81d31601c024fb3".hs.hexData!))
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: "95c2904c5ae7e4ad014855e9367217a3f1ed86a89ee1f3ad765666d57249bea6".hs.hexData!))
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: "98bfa1c277caff946c2a2d2c049947ec98088e838a9d2e1efbe6dadf06a08547".hs.hexData!))
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: "691aa034be0ed6ba5c97777e27f5ffa74d34bf54b7b489b4025eddf4bda41126".hs.hexData!))
    }

    func testIsOnCurveRejectsInvalidLength() {
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: Data()))
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: Data(repeating: 0, count: 31)))
        XCTAssertFalse(Crypto.Ed25519.isOnCurve(publicKeyData: Data(repeating: 0, count: 33)))
    }
}
