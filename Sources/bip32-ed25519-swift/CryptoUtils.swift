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