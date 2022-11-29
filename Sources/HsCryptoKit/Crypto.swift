import Foundation
import Crypto
import CommonCrypto
import secp256k1
import HsExtensions

public struct Crypto {

    public static func hmacSha512(_ data: Data, key: Data = "Bitcoin seed".data(using: .ascii)!) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
    }

    public static func deriveKey(password: String, salt: Data, iterations: Int = 2048, keyLength: Int = 64) -> Data? {
        let passwordData = password.data(using: .utf8)!
        var derivedKey = Data(repeating: 0, count: keyLength)

        if derivedKey.withUnsafeMutableBytes({ derivedKeyBytes -> Int32 in
            salt.withUnsafeBytes { saltBytes -> Int32 in
                guard let saltPointer = saltBytes.bindMemory(to: UInt8.self).baseAddress else { return 1 }
                guard let derivedKeyPointer = derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 1 }

                return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        password, passwordData.count,
                        saltPointer, salt.count,
                        CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(iterations),
                        derivedKeyPointer, keyLength)
            }
        }) != 0 {
            print("=> Can't derive key!")
            return nil
        }

        return derivedKey
    }

    public static func publicKey(_ publicKey: secp256k1_pubkey, compressed: Bool) -> Data {
        var outputLen: Int = compressed ? 33 : 65

        let context = secp256k1.Context.raw

        var publicKey = publicKey
        var output = Data(count: outputLen)
        let compressedFlags = compressed ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
        output.withUnsafeMutableBytes { pointer -> Void in
            guard let p = pointer.bindMemory(to: UInt8.self).baseAddress else {
                return
            }
            secp256k1_ec_pubkey_serialize(context, p, &outputLen, &publicKey, compressedFlags)
        }

        return output
    }

    public static func publicKey(privateKey: Data, compressed: Bool) -> Data {
        let privateKey = privateKey.hs.bytes
        var pubKeyPoint = secp256k1_pubkey()

        let context = secp256k1.Context.raw
        _ = SecpResult(secp256k1_ec_pubkey_create(context, &pubKeyPoint, privateKey))


        return publicKey(pubKeyPoint, compressed: compressed)
    }

    public static func sign(data: Data, privateKey: Data, compact: Bool = false) throws -> Data {
        precondition(data.count > 0, "Data must be non-zero size")
        precondition(privateKey.count > 0, "PrivateKey must be non-zero size")

        let ctx = secp256k1.Context.raw

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        let status = data.withUnsafeBytes { ptr in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr.baseAddress!.assumingMemoryBound(to: UInt8.self), $0.baseAddress!.assumingMemoryBound(to: UInt8.self), nil, nil) }
        }
        guard status == 1 else { throw SignError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer {
            signature.deallocate()
            normalizedsig.deallocate()
        }

        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = compact ? 64 : 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({
            if compact {
                return secp256k1_ecdsa_signature_serialize_compact(ctx, $0.baseAddress!.assumingMemoryBound(to: UInt8.self), normalizedsig)
            } else {
                return secp256k1_ecdsa_signature_serialize_der(ctx, $0.baseAddress!.assumingMemoryBound(to: UInt8.self), &length, normalizedsig)
            }
        }) == Int32(1) else {
            throw SignError.noEnoughSpace
            
        }
        der.count = length

        return der
    }

    public static func ellipticSign(_ hash: Data, privateKey: Data) throws -> Data {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        guard var signatureInInternalFormat = encrypter.sign(hash: hash, privateKey: privateKey) else {
            throw SignError.signFailed
        }
        return encrypter.export(signature: &signatureInInternalFormat)
    }

    public static func ellipticIsValid(signature: Data, of hash: Data, publicKey: Data, compressed: Bool) -> Bool {
        guard let recoveredPublicKey = self.ellipticPublicKey(signature: signature, of: hash, compressed: compressed) else { return false }
        return recoveredPublicKey == publicKey
    }

    public static func ellipticPublicKey(signature: Data, of hash: Data, compressed: Bool) -> Data? {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        var signatureInInternalFormat = encrypter.import(signature: signature)
        guard var publicKeyInInternalFormat = encrypter.publicKey(signature: &signatureInInternalFormat, hash: hash) else { return nil }
        return encrypter.export(publicKey: &publicKeyInInternalFormat, compressed: compressed)
    }

}

public extension Crypto {

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func ripeMd160(_ data: Data) -> Data {
        RIPEMD160.hash(data)
    }

    static func doubleSha256(_ data: Data) -> Data {
        sha256(sha256(data))
    }

    static func ripeMd160Sha256(_ data: Data) -> Data {
        ripeMd160(sha256(data))
    }

    static func sha3(_ data: Data) -> Data {
        Sha3.keccak256(data)
    }

}

enum SecpResult {
    case success
    case failure

    init(_ result: Int32) {
        switch result {
        case 1:
            self = .success
        default:
            self = .failure
        }
    }
}

public enum SignError: Error {
    case signFailed
    case noEnoughSpace
}
