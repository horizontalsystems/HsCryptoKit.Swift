import Foundation
import secp256k1
import Crypto
import BigInt
import HsCryptoKitC

public struct SchnorrHelper {
    static var magic: (UInt8, UInt8, UInt8, UInt8) { (218, 111, 179, 140) }

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

        let xBytes: [UInt8] = xCoordinate.serialize().bytes
        let yBytes: [UInt8] = yCoordinate.serialize().bytes
        let xCoordinateBytes = [UInt8](repeating: 0, count: 32 - xBytes.count) + xBytes
        let yCoordinateBytes = [UInt8](repeating: 0, count: 32 - yBytes.count) + yBytes
        var xCoordinateField = secp256k1_fe()
        var yCoordinateField = secp256k1_fe()

        defer {
            secp256k1_fe_clear(&xCoordinateField)
            secp256k1_fe_clear(&yCoordinateField)
        }

        guard xCoordinateBytes.withUnsafeBytes({ rawBytes -> Bool in
            guard let rawPointer = rawBytes.bindMemory(to: UInt8.self).baseAddress else { return false }
            return secp256k1_fe_set_b32(&xCoordinateField, rawPointer) == 1
        }) else {
            throw SchnorrError.liftXError
        }

        guard yCoordinateBytes.withUnsafeBytes({ rawBytes -> Bool in
            guard let rawPointer = rawBytes.bindMemory(to: UInt8.self).baseAddress else { return false }
            return secp256k1_fe_set_b32(&yCoordinateField, rawPointer) == 1
        }) else {
            throw SchnorrError.liftXError
        }

        secp256k1_fe_normalize_var(&xCoordinateField)
        secp256k1_fe_normalize_var(&yCoordinateField)
        
        var keyBytes = [UInt8](repeating: 0, count: 64)

        secp256k1_fe_get_b32(&keyBytes[0], &xCoordinateField)
        secp256k1_fe_get_b32(&keyBytes[32], &yCoordinateField)

        return Data(from: SECP256K1_TAG_PUBKEY_UNCOMPRESSED)[0..<1] + Data(keyBytes)
    }
    
    public static func hashTweak(data: Data, tag: String) throws -> Data {
        let tagBytes: [UInt8] = tag.data(using: .utf8)!.bytes

        return try Data(SHA256.taggedHash(tag: tagBytes, data: data).bytes)
    }

    // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#address-derivation
    public static func tweakedOutputKey(publicKey: Data) throws -> Data {
        // internal_key = lift_x(derived_key)
        // hashTapTweak(bytes(P))
        let internalKeyBytes: [UInt8] = try liftX(x: publicKey[1..<33]).bytes
        let tweakedHash = try hashTweak(data: Data(internalKeyBytes[1..<33]), tag: "TapTweak")

        // int(hashTapTweak(bytes(P)))G
        var tweakedPublicKey = secp256k1_pubkey()
        guard secp256k1_ec_seckey_verify(secp256k1.Context.raw, tweakedHash.bytes) == 1,
              secp256k1_ec_pubkey_create(secp256k1.Context.raw, &tweakedPublicKey, tweakedHash.bytes) == 1
        else {
            throw SchnorrError.keyTweakError
        }

        // P + int(hashTapTweak(bytes(P)))G
        var internalKey = secp256k1_pubkey()
        guard internalKeyBytes.withUnsafeBytes({ rawBytes -> Int32 in
            guard let rawPointer = rawBytes.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return secp256k1_ec_pubkey_parse(secp256k1.Context.raw, &internalKey, rawPointer, internalKeyBytes.count)
        }) == 1 else {
            throw SchnorrError.keyTweakError
        }

        var outputKey = try Crypto.addEllipticCurvePoints(a: internalKey, b: tweakedPublicKey)
        var pubKeyLen = 33
        var outputKeyBytes = [UInt8](repeating: 0, count: pubKeyLen)

        guard secp256k1_ec_pubkey_serialize(secp256k1.Context.raw, &outputKeyBytes, &pubKeyLen, &outputKey, secp256k1.Format.compressed.rawValue) == 1 else {
            throw SchnorrError.keyTweakError
        }

        return Data(outputKeyBytes[1..<33])
    }

    public static func tweakedPrivateKey(privateKey: Data, publicKey: Data) throws -> Data {
        // internal_key = lift_x(derived_key)
        // hashTapTweak(bytes(P))
        let internalKeyBytes: [UInt8] = try liftX(x: publicKey[1..<33]).bytes
        let tweakedHash = try hashTweak(data: Data(internalKeyBytes[1..<33]), tag: "TapTweak")

        // int(hashTapTweak(bytes(P)))G
        var tweakedPublicKey = secp256k1_pubkey()
        guard secp256k1_ec_seckey_verify(secp256k1.Context.raw, tweakedHash.bytes) == 1,
              secp256k1_ec_pubkey_create(secp256k1.Context.raw, &tweakedPublicKey, tweakedHash.bytes) == 1
        else {
            throw SchnorrError.privateKeyTweakError
        }

        // P + int(hashTapTweak(bytes(P)))G
        var internalKey = secp256k1_pubkey()
        guard internalKeyBytes.withUnsafeBytes({ rawBytes -> Int32 in
            guard let rawPointer = rawBytes.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return secp256k1_ec_pubkey_parse(secp256k1.Context.raw, &internalKey, rawPointer, internalKeyBytes.count)
        }) == 1 else {
            throw SchnorrError.privateKeyTweakError
        }

        let outputKey = try Crypto.addEllipticCurvePoints(a: internalKey, b: tweakedPublicKey)
        var privateBytes: [UInt8] = privateKey.bytes
        guard secp256k1_ec_seckey_tweak_add(secp256k1.Context.raw, &privateBytes, tweakedHash.bytes) == 1,
              secp256k1_ec_seckey_verify(secp256k1.Context.raw, privateBytes) == 1 else {
            throw SchnorrError.privateKeyTweakError
        }

        var _outputKey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_create(secp256k1.Context.raw, &_outputKey, privateBytes) == 1 else {
            throw SchnorrError.privateKeyTweakError
        }

        let keysEqual = withUnsafePointer(to: outputKey) { outputKeyPointer in
            withUnsafePointer(to: _outputKey) { _outputKeyPointer in
                secp256k1_ec_pubkey_cmp(secp256k1.Context.raw, outputKeyPointer, _outputKeyPointer)
            }
        }

        if keysEqual != 0 {
            privateBytes = privateKey.bytes
            guard secp256k1_ec_seckey_negate(secp256k1.Context.raw, &privateBytes) == 1 else {
                throw SchnorrError.privateKeyTweakError
            }

            guard secp256k1_ec_seckey_tweak_add(secp256k1.Context.raw, &privateBytes, tweakedHash.bytes) == 1,
                  secp256k1_ec_seckey_verify(secp256k1.Context.raw, privateBytes) == 1 else {
                throw SchnorrError.privateKeyTweakError
            }
        }

        return Data(privateBytes)
    }

    public static func sign(data: Data, privateKey: Data, publicKey: Data) throws -> Data {
        let tweakedPrivateKey = try tweakedPrivateKey(privateKey: privateKey, publicKey: publicKey)
        var message: [UInt8] = data.bytes

        let auxRandPointer = UnsafeMutableRawPointer.allocate(byteCount: 32, alignment: MemoryLayout<UInt8>.alignment)
        for i in 0..<32 {
            auxRandPointer.storeBytes(of: 0x00, toByteOffset: i, as: UInt8.self)
        }

        var keypair = secp256k1_keypair()
        var signature = [UInt8](repeating: 0, count: 64)
        var extraParams = secp256k1_schnorrsig_extraparams(magic: magic, noncefp: nil, ndata: auxRandPointer)

        guard secp256k1_keypair_create(secp256k1.Context.raw, &keypair, tweakedPrivateKey.bytes) == 1,
              secp256k1_schnorrsig_sign_custom(secp256k1.Context.raw, &signature, &message, message.count, &keypair, &extraParams) == 1
        else {
            throw SchnorrError.signError
        }

        return Data(signature)
    }

    public enum SchnorrError: Error {
        case liftXError
        case privateKeyTweakError
        case keyTweakError
        case signError
    }

}
