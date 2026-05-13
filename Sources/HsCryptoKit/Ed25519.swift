import BigInt
import Foundation
import HsExtensions

public extension Crypto {
    enum Ed25519 {
        public static func isOnCurve(publicKeyData data: Data) -> Bool {
            guard data.count == 32 else {
                return false
            }

            var bytes = data.hs.bytes
            bytes[31] &= 0x7F

            let y = littleEndianBigUInt(bytes) % fieldPrime
            let ySquared = y.power(2, modulus: fieldPrime)
            let numerator = modSubtract(ySquared, BigUInt(1))
            let denominator = (curveD * ySquared + BigUInt(1)) % fieldPrime

            guard denominator != 0 else {
                return false
            }

            let xSquared = (numerator * denominator.power(fieldPrime - BigUInt(2), modulus: fieldPrime)) % fieldPrime
            return hasSquareRoot(xSquared)
        }
    }
}

private extension Crypto.Ed25519 {
    static let fieldPrime = (BigUInt(1) << 255) - BigUInt(19)

    static let curveD: BigUInt = {
        let denominatorInverse = BigUInt(121_666).power(fieldPrime - BigUInt(2), modulus: fieldPrime)
        return (fieldPrime - (BigUInt(121_665) * denominatorInverse) % fieldPrime) % fieldPrime
    }()

    static let squareRootMinusOne = BigUInt(2).power((fieldPrime - BigUInt(1)) / BigUInt(4), modulus: fieldPrime)

    static func littleEndianBigUInt(_ bytes: [UInt8]) -> BigUInt {
        var result = BigUInt(0)

        for (index, byte) in bytes.enumerated() {
            result += BigUInt(byte) << (index * 8)
        }

        return result
    }

    static func modSubtract(_ lhs: BigUInt, _ rhs: BigUInt) -> BigUInt {
        if lhs >= rhs {
            return (lhs - rhs) % fieldPrime
        }

        return fieldPrime - ((rhs - lhs) % fieldPrime)
    }

    static func hasSquareRoot(_ value: BigUInt) -> Bool {
        if value == 0 {
            return true
        }

        var root = value.power((fieldPrime + BigUInt(3)) / BigUInt(8), modulus: fieldPrime)

        if root.power(2, modulus: fieldPrime) == value {
            return true
        }

        root = (root * squareRootMinusOne) % fieldPrime
        return root.power(2, modulus: fieldPrime) == value
    }
}
