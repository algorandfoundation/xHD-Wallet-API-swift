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

import CryptoKit
import Foundation
import MessagePack

public struct CryptoUtils {
    public static func sha512(data: Data) -> Data {
        let hashed = SHA512.hash(data: data)
        return Data(hashed)
    }

    public static func hmacSha512(key: Data, data: Data) -> Data {
        let key256 = SymmetricKey(data: key)
        let hmac = HMAC<SHA512>.authenticationCode(for: data, using: key256)
        return Data(hmac)
    }

    public static func sha256(data: Data) -> Data {
        let hashed = SHA256.hash(data: data)
        return Data(hashed)
    }
}