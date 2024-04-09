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
        let array = [UInt8](scalar)

        // Call the underlying function
        let resultArray = scalarMultEd25519BaseNoClamp(array)

        // Convert the result back to Data
        let result = Data(resultArray!)
        return result
    }
}