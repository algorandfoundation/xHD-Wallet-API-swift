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

public struct TestUtils {
    public static func cryptoSecretBoxEasy(cleartext: String, nonce: Data, sharedSecret: Data) -> Data {
        guard let cleartextData = cleartext.data(using: .utf8) else { return Data() }
        var out = [UInt8](repeating: 0, count: cleartextData.count + Int(crypto_secretbox_MACBYTES))
        _ = cleartextData.withUnsafeBytes { inPtr in
            nonce.withUnsafeBytes { noncePtr in
                sharedSecret.withUnsafeBytes { sharedSecretPtr in
                    crypto_secretbox_easy(&out, inPtr.baseAddress!, UInt64(cleartextData.count), noncePtr.baseAddress!, sharedSecretPtr.baseAddress!)
                }
            }
        }
        return Data(out)
    }

    public static func cryptoSecretBoxOpenEasy(ciphertext: Data, nonce: Data, sharedSecret: Data) -> String {
        var out = [UInt8](repeating: 0, count: ciphertext.count - Int(crypto_secretbox_MACBYTES))
        _ = ciphertext.withUnsafeBytes { cPtr in
            nonce.withUnsafeBytes { noncePtr in
                sharedSecret.withUnsafeBytes { sharedSecretPtr in
                    crypto_secretbox_open_easy(&out, cPtr.baseAddress!, UInt64(ciphertext.count), noncePtr.baseAddress!, sharedSecretPtr.baseAddress!)
                }
            }
        }
        return String(bytes: out, encoding: .utf8) ?? ""
    }
}