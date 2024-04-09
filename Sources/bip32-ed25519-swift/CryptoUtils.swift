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
}