import Foundation
import Base32
import MessagePack

public struct TestUtils {
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
        let res = Base32.base32Encode(checksumAddr).trimmingCharacters(in: ["="])
        if (res.count != expectedStrEncodedLen) {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "unexpected address length \(res.count)"])
        }
        return res
    }
}