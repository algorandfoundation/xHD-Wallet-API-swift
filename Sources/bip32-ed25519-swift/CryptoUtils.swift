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

import CommonCrypto
import Foundation

public struct CryptoUtils {
    public static func sha512(data: Data) -> Data {
        var hash = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes { dataBytes in
            _ = hash.withUnsafeMutableBytes { hashBytes in
                CC_SHA512(dataBytes.baseAddress, CC_LONG(data.count), hashBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return hash
    }

    public static func hmacSha512(key: Data, data: Data) -> Data {
        var hmac = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
        key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                hmac.withUnsafeMutableBytes { hmacBytes in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA512), keyBytes.baseAddress, key.count, dataBytes.baseAddress, data.count, hmacBytes.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        return hmac
    }

    public static func sha256(data: Data) -> Data {
        var hash = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { dataBytes in
            _ = hash.withUnsafeMutableBytes { hashBytes in
                CC_SHA256(dataBytes.baseAddress, CC_LONG(data.count), hashBytes.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return hash
    }

    public static func sha512_256(data: Data) -> Data {
        return Data(SHA512_256.init().hash([UInt8](data)))
    }

    public static func encodeAddress(bytes: Data) throws -> String {
        let lenBytes = 32
        let checksumLenBytes = 4
        let expectedStrEncodedLen = 58

        // compute sha512/256 checksum
        let hash = sha512_256(data: bytes)
        let hashedAddr = hash[..<lenBytes]  // Take the first 32 bytes

        // take the last 4 bytes of the hashed address, and append to original bytes
        let checksum = hashedAddr[(hashedAddr.count - checksumLenBytes)...]
        let checksumAddr = bytes + checksum

        // encodeToMsgPack addr+checksum as base32 and return. Strip padding.
        let res = Base32.encode(data: checksumAddr).trimmingCharacters(in: ["="])
        if (res.count != expectedStrEncodedLen) {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "unexpected address length \(res.count)"])
        }
        return res
    }
}