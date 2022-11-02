import Foundation
import secp256k1
public enum secp256k1 {}

/// Flags passed to secp256k1_context_create, secp256k1_context_preallocated_size, and secp256k1_context_preallocated_create.
public extension secp256k1 {
    struct Context: OptionSet {
        public let rawValue: UInt32
        public init(rawValue: UInt32) { self.rawValue = rawValue }
        init(rawValue: Int32) { self.rawValue = UInt32(rawValue) }
        public static let none = Context(rawValue: SECP256K1_CONTEXT_NONE)
        public static let sign = Context(rawValue: SECP256K1_CONTEXT_SIGN)
        public static let verify = Context(rawValue: SECP256K1_CONTEXT_VERIFY)

        public static func create(_ context: Context = [.verify, .sign]) throws -> OpaquePointer {
            guard let context = secp256k1_context_create(context.rawValue) else {
                throw Secp256k1Error.cantCreateSecp256k1Context
            }

            return context
        }

        public static let raw = try! secp256k1.Context.create()
    }
}

public enum Secp256k1Error: Error {
    case cantCreateSecp256k1Context
}
