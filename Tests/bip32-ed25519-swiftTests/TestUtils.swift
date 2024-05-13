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

import Base32
import Clibsodium
import Foundation
import Sodium

public enum TestUtils {
    public static func cryptoSecretBoxEasy(cleartext: String, nonce: Data, symmetricKey: Data) -> Data {
        guard let cleartextData = cleartext.data(using: .utf8) else { return Data() }
        var out = [UInt8](repeating: 0, count: cleartextData.count + Int(crypto_secretbox_MACBYTES))
        _ = cleartextData.withUnsafeBytes { inPtr in
            nonce.withUnsafeBytes { noncePtr in
                symmetricKey.withUnsafeBytes { symmetricKeyPtr in
                    crypto_secretbox_easy(&out, inPtr.baseAddress!, UInt64(cleartextData.count), noncePtr.baseAddress!, symmetricKeyPtr.baseAddress!)
                }
            }
        }
        return Data(out)
    }

    public static func cryptoSecretBoxOpenEasy(ciphertext: Data, nonce: Data, symmetricKey: Data) -> String {
        var out = [UInt8](repeating: 0, count: ciphertext.count - Int(crypto_secretbox_MACBYTES))
        _ = ciphertext.withUnsafeBytes { cPtr in
            nonce.withUnsafeBytes { noncePtr in
                symmetricKey.withUnsafeBytes { symmetricKeyPtr in
                    crypto_secretbox_open_easy(&out, cPtr.baseAddress!, UInt64(ciphertext.count), noncePtr.baseAddress!, symmetricKeyPtr.baseAddress!)
                }
            }
        }
        return String(bytes: out, encoding: .utf8) ?? ""
    }

    public static func sha512_256(data: Data) -> Data {
        return Data(SHA512_256().hash([UInt8](data)))
    }

    public static func encodeAddress(bytes: Data) throws -> String {
        let lenBytes = 32
        let checksumLenBytes = 4
        let expectedStrEncodedLen = 58

        // compute sha512/256 checksum
        let hash = sha512_256(data: bytes)
        let hashedAddr = hash[..<lenBytes] // Take the first 32 bytes

        // take the last 4 bytes of the hashed address, and append to original bytes
        let checksum = hashedAddr[(hashedAddr.count - checksumLenBytes)...]
        let checksumAddr = bytes + checksum

        // encodeToMsgPack addr+checksum as base32 and return. Strip padding.
        let res = Base32.base32Encode(checksumAddr).trimmingCharacters(in: ["="])
        if res.count != expectedStrEncodedLen {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "unexpected address length \(res.count)"])
        }
        return res
    }
}
