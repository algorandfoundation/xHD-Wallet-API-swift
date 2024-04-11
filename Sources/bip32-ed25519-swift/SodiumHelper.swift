/*
 * Copyright (c) Algorand Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

    public static func cryptoCoreEd25519ScalarReduce(_ input: Data) -> Data {
        var output = [UInt8](repeating: 0, count: ED25519_SCALAR_SIZE)
        output.withUnsafeMutableBufferPointer { outputPtr in
            input.withUnsafeBytes { inputPtr in
                crypto_core_ed25519_scalar_reduce(outputPtr.baseAddress!, inputPtr.baseAddress!)
            }
        }
        return Data(output)
    }

    public static func cryptoCoreEd25519ScalarAdd(_ x: Data, _ y: Data) -> Data {
        var output = [UInt8](repeating: 0, count: ED25519_SCALAR_SIZE)
        output.withUnsafeMutableBufferPointer { outputPtr in
            x.withUnsafeBytes { xPtr in
                y.withUnsafeBytes { yPtr in
                    crypto_core_ed25519_scalar_add(outputPtr.baseAddress!, xPtr.baseAddress!, yPtr.baseAddress!)
                }
            }
        }
        return Data(output)
    }

    public static func cryptoCoreEd25519ScalarMul(_ x: Data, _ y: Data) -> Data {
        var output = [UInt8](repeating: 0, count: ED25519_SCALAR_SIZE)
        output.withUnsafeMutableBufferPointer { outputPtr in
            x.withUnsafeBytes { xPtr in
                y.withUnsafeBytes { yPtr in
                    crypto_core_ed25519_scalar_mul(outputPtr.baseAddress!, xPtr.baseAddress!, yPtr.baseAddress!)
                }
            }
        }
        return Data(output)
    }

    public static func cryptoSignVerifyDetached(_ signature: Data, _ message: Data, _ publicKey: Data) -> Bool {
        var result: Int32 = -1
        signature.withUnsafeBytes { signaturePtr in
            message.withUnsafeBytes { messagePtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    result = crypto_sign_verify_detached(signaturePtr.baseAddress!, messagePtr.baseAddress!, UInt64(message.count), publicKeyPtr.baseAddress!)
                }
            }
        }
        return result == 0
    }
}