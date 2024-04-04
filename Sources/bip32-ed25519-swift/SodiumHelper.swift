import Sodium
import Clibsodium
import Foundation

public struct SodiumHelper {

    public static let ED25519_SCALAR_SIZE = 32
    public static let ED25519_POINT_SIZE = 32


    public static func scalarMultEd25519BaseNoClamp(_ scalar: [UInt8]) -> [UInt8]? {
        guard scalar.count == ED25519_SCALAR_SIZE else {
            return nil
        }

        var q = [UInt8](repeating: 0, count: ED25519_POINT_SIZE)
        let result = q.withUnsafeMutableBufferPointer { qPtr in
            scalar.withUnsafeBufferPointer { scalarPtr in
                crypto_scalarmult_ed25519_base_noclamp(qPtr.baseAddress!, scalarPtr.baseAddress!)
            }
        }

        return result == 0 ? q : nil
    }

    // Overloading the function to accept Data
    public static func scalarMultEd25519BaseNoClamp(_ scalar: Data) -> Data {
        // Convert Data to [UInt8]
        let klArray = [UInt8](scalar)

        // Call the underlying function
        let resultArray = scalarMultEd25519BaseNoClamp(klArray)

        // Convert the result back to Data
        let result = Data(resultArray!)
        return result
    }

    public static func coreEd25519ScalarReduce(_ h: Data) -> Data {
        var output = Data(count: h.count)
        crypto_core_ed25519_scalar_reduce(&output, [UInt8](h))
        return output
    }

    public static func coreEd25519ScalarAdd(r: Data, k: Data) -> Data {
        var output = Data(count: r.count)
        crypto_core_ed25519_scalar_add(&output, [UInt8](r), [UInt8](k))
        return output
    }

    public static func coreEd25519ScalarMul(h: Data, scalar: Data) -> Data {
        var output = Data(count: h.count)
        crypto_core_ed25519_scalar_mul(&output, [UInt8](h), [UInt8](scalar))
        return output
    }

    public static func sodiumSignVerify(signature: Data, message: Data, publicKey: Data) -> Bool {
        let sodium = Sodium()
        let result = sodium.sign.verify(message: [UInt8](message), publicKey: [UInt8](publicKey), signature: [UInt8](signature))
    return result
    }

    // public static func cryptoSignEd25519PKtoCurve25519() {
    //     let sodium = Sodium()
        

    //     crypto_sign_ed25519_pk_to_curve25519
    // }

    // public static func cryptoCurve25519ScalarMult() -> [UInt8] {
    //     let sodium = Sodium()
    //     var sharedSecret = Data(count: 32)
    //     guard sodium.utils.crypto_scalarmult(sharedSecret: &sharedSecret, scalar: scalar, otherPartyPub: otherPartyPub) == 0 else {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Scalar multiplication failed"])
    //     }
    //     return result
    // }

}