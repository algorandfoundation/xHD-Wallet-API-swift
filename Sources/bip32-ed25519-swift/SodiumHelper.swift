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

import Clibsodium
import Foundation
import Sodium

public enum SodiumHelper {
    public static let ED25519_SCALAR_SIZE = 32
    public static let ED25519_POINT_SIZE = 32

    public static func scalarMultEd25519BaseNoClamp(_ scalar: Data) -> Data {
        var q = [UInt8](repeating: 0, count: ED25519_POINT_SIZE)
        _ = q.withUnsafeMutableBufferPointer { qPtr in
            scalar.withUnsafeBytes { scalarPtr in
                crypto_scalarmult_ed25519_base_noclamp(qPtr.baseAddress!, scalarPtr.baseAddress!)
            }
        }

        return Data(q)
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

    public static func convertPublicKeyEd25519ToCurve25519(_ publicKey: Data) -> Data {
        var curve25519_pk = [UInt8](repeating: 0, count: ED25519_POINT_SIZE)
        _ = publicKey.withUnsafeBytes { ed25519_pk in
            crypto_sign_ed25519_pk_to_curve25519(&curve25519_pk, ed25519_pk.baseAddress!)
        }
        return Data(curve25519_pk)
    }

    public static func cryptoX25519ScalarMult(scalar: Data, point: Data) -> Data {
        var q = [UInt8](repeating: 0, count: ED25519_POINT_SIZE)
        _ = scalar.withUnsafeBytes { n in
            point.withUnsafeBytes { p in
                crypto_scalarmult(&q, n.baseAddress!, p.baseAddress!)
            }
        }
        return Data(q)
    }

    public static func cryptoGenericHash(input: Data, outputLength: Int) -> Data {
        var out = [UInt8](repeating: 0, count: outputLength)
        _ = input.withUnsafeBytes { inPtr in
            crypto_generichash(&out, out.count, inPtr.baseAddress!, UInt64(input.count), nil, 0)
        }
        return Data(out)
    }
}
