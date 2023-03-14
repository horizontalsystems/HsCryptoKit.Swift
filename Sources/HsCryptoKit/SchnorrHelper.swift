import Foundation
import secp256k1
import Crypto
import BigInt

public struct SchnorrHelper {
    
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#specification
    public static func liftX(x: Data) throws -> Data {
        let x = BigUInt(x)
        let p = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", radix: 16)! // secp256k1 field size
        
        guard x < p else {
            throw SchnorrError.liftXError
        }
        
        let c = (x.power(3, modulus: p) + BigUInt(7)) % p
        let y = c.power((p + BigUInt(1)) / BigUInt(4), modulus: p)
        
        guard c == y.power(2, modulus: p) else {
            throw SchnorrError.liftXError
        }
        
        let xCoordinate = x
        let yCoordinate = (y % 2 == 0) ? y : p - y

        return Data(from: SECP256K1_TAG_PUBKEY_UNCOMPRESSED)[0..<1] + Data(xCoordinate.serialize() + yCoordinate.serialize())
    }
    
    public static func hashTweak(data: Data, tag: String) -> Data {
        let tagHash = SHA256.hash(data: tag.data(using: .utf8)!.bytes)
        let hash = tagHash.bytes + tagHash.bytes + data
        
        return Data(SHA256.hash(data: hash).bytes)
    }
    
    // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#address-derivation
    public static func tweakedOutputKey(publicKey: Data, format: secp256k1.Format) throws -> Data {
        var pubKeyLen = format.length

        // internal_key = lift_x(derived_key)
        let internalKeyBytes = try liftX(x: publicKey[1..<33]).bytes
        var internalKey = secp256k1_pubkey()
        guard internalKeyBytes.withUnsafeBytes({ rawBytes -> Int32 in
            guard let rawPointer = rawBytes.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return secp256k1_ec_pubkey_parse(secp256k1.Context.raw, &internalKey, rawPointer, internalKeyBytes.count)
        }) == 1 else {
            throw SchnorrError.keyTweakError
        }

        // hashTapTweak(bytes(P))
        let tweakedHash = hashTweak(data: Data(internalKeyBytes[1..<33]), tag: "TapTweak")

        // int(hashTapTweak(bytes(P)))G
        var tweakedPublicKey = secp256k1_pubkey()
        guard secp256k1_ec_seckey_verify(secp256k1.Context.raw, tweakedHash.bytes) == 1,
              secp256k1_ec_pubkey_create(secp256k1.Context.raw, &tweakedPublicKey, tweakedHash.bytes) == 1
        else {
            throw SchnorrError.keyTweakError
        }

        // P + int(hashTapTweak(bytes(P)))G
        var outputKey = try Crypto.addEllipticCurvePoints(a: internalKey, b: tweakedPublicKey)
        var outputKeyBytes = [UInt8](repeating: 0, count: pubKeyLen)

        guard secp256k1_ec_pubkey_serialize(secp256k1.Context.raw, &outputKeyBytes, &pubKeyLen, &outputKey, format.rawValue) == 1 else {
            throw SchnorrError.keyTweakError
        }

        return Data(outputKeyBytes[1..<33])
    }

    public enum SchnorrError: Error {
        case liftXError
        case keyTweakError
    }
    
}
