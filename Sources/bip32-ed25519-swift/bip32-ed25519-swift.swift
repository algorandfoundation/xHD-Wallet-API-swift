import Sodium
import Clibsodium
import Foundation
import BigInt
import Foundation
//import MessagePackSwift
//import JSONSchema


enum KeyContext: UInt32 {
    case Address = 0
    case Identity = 1
}

enum Encoding {
    // case cbor
    case msgpack
    case base64
    case none
}

extension Data {
    init?(hexString: String) {
        let length = hexString.count / 2 // Two characters represent one byte
        var data = Data(capacity: length)
        for i in 0..<length {
            let j = hexString.index(hexString.startIndex, offsetBy: i*2)
            let k = hexString.index(j, offsetBy: 2)
            let bytes = hexString[j..<k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }
}

public class Bip32Ed25519 {

    var seed: Data

    // Overloaded initializer that accepts a seed
    public init?(seed: Data) {
        self.seed = seed
    }

    public init?(seed: String) {
        guard let data = Data(hexString: seed) else {
            return nil
        }
        self.seed = data
    }

    func harden(_ num: UInt32) -> UInt32 {
        return 0x80000000 + num
    }

    func getBIP44PathFromContext(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32) -> [UInt32] {
        switch context {
            case .Address:
                return [harden(44), harden(283), harden(account), change, keyIndex]
            case .Identity:
                return [harden(44), harden(0), harden(account), change, keyIndex]
        }
    }


    func fromSeed(_ seed: Data) -> Data {
        // k = H512(seed)
        var k = CryptoUtils.sha512(data: seed)
        var kL = k.subdata(in: 0..<32)
        var kR = k.subdata(in: 32..<64)

        // While the third highest bit of the last byte of kL is not zero
        while kL[31] & 0b00100000 != 0 {
            k = CryptoUtils.hmacSha512(key: kL, data: kR)
            kL = k.subdata(in: 0..<32)
            kR = k.subdata(in: 32..<64)
        }

        // clamp
        // Set the bits in kL as follows:
        // little Endianess
        kL[0] = kL[0] & 0b11111000 // the lowest 3 bits of the first byte of kL are cleared
        kL[31] = kL[31] & 0b01111111 // the highest bit of the last byte is cleared
        kL[31] = kL[31] | 0b01000000 // the second highest bit of the last byte is set

        // chain root code
        // SHA256(0x01||k)
        let c = CryptoUtils.sha256(data: Data([0x01]) + seed)
        return kL + kR + c
    }

    func derivedNonHardened(kl: Data, cc: Data, index: UInt32) -> (z: Data, childChainCode: Data) {
        var data = Data(count: 1 + 32 + 4)
        data[1 + 32] = UInt8(index & 0xFF)

        let pk = SodiumHelper.scalarMultEd25519BaseNoClamp(kl)
        data.replaceSubrange(1..<1+pk.count, with: pk)

        data[0] = 0x02
        let z = CryptoUtils.hmacSha512(key: cc, data: data)

        data[0] = 0x03
        let childChainCode = CryptoUtils.hmacSha512(key: cc, data: data)

        return (z, childChainCode)
    }

    func deriveHardened(kl: Data, kr: Data, cc: Data, index: UInt32) -> (z: Data, childChainCode: Data) {
        var data = Data(count: 1 + 64 + 4)
        data[1 + 64] = UInt8(index & 0xFF)

        data.replaceSubrange(1..<1+kl.count, with: kl)
        data.replaceSubrange(1+kl.count..<1+kl.count+kr.count, with: kr)

        data[0] = 0x00
        let z = CryptoUtils.hmacSha512(key: cc, data: data)

        data[0] = 0x01
        let childChainCode = CryptoUtils.hmacSha512(key: cc, data: data)

        return (z, childChainCode)
    }

    func deriveChildNodePrivate(extendedKey: Data, index: UInt32) -> Data {
        let kl = extendedKey.subdata(in: 0..<32)
        let kr = extendedKey.subdata(in: 32..<64)
        let cc = extendedKey.subdata(in: 64..<96)

        let (z, childChainCode) =
            (index < 0x80000000) ? derivedNonHardened(kl: kl, cc: cc, index: index) : deriveHardened(kl: kl, kr: kr, cc: cc, index: index)

        let chainCode = childChainCode.subdata(in: 32..<64)
        let zl = z.subdata(in: 0..<32)
        let zr = z.subdata(in: 32..<64)

        // left = kl + 8 * trunc28(zl)
        // right = zr + kr
        let left = BigInt(kl) + BigInt(zl.subdata(in: 0..<28)) * BigInt(8)
        var right = BigInt(kr) + BigInt(zr)

        // just padding
        if right.bitWidth / 8 < 32 {
            right <<= 8
        }

        var result = Data()
        result.append(left.serialize())
        result.append(right.serialize())
        result.append(chainCode)

        return result
    }

    func deriveKey(rootKey: Data, bip44Path: [UInt32], isPrivate: Bool = true) -> Data {
        var derived = deriveChildNodePrivate(extendedKey: rootKey, index: bip44Path[0])
        derived = deriveChildNodePrivate(extendedKey: derived, index: bip44Path[1])
        derived = deriveChildNodePrivate(extendedKey: derived, index: bip44Path[2])
        derived = deriveChildNodePrivate(extendedKey: derived, index: bip44Path[3])

        // Public Key SOFT derivations are possible without using the private key of the parent node
        // Could be an implementation choice.
        // Example:
        // let nodeScalar: Data = derived.subdata(in: 0..<32)
        // let nodePublic: Data = self.crypto_scalarmult_ed25519_base_noclamp(scalar: nodeScalar)
        // let nodeCC: Data = derived.subdata(in: 64..<96)

        // // [Public][ChainCode]
        // let extPub: Data = nodePublic + nodeCC
        // let publicKey: Data = deriveChildNodePublic(extendedKey: extPub, index: bip44Path[4]).subdata(in: 0..<32)

        derived = deriveChildNodePrivate(extendedKey: derived, index: bip44Path[4])

        let scalar = derived.subdata(in: 0..<32) // scalar == pvtKey

        return isPrivate ? scalar : SodiumHelper.scalarMultEd25519BaseNoClamp(scalar)
    }


    func keyGen(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32) -> Data {
        let rootKey: Data = fromSeed(self.seed)
        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)

        return self.deriveKey(rootKey: rootKey, bip44Path: bip44Path, isPrivate: false)
    }


    // TODO: Look into unifying the Sha512 hashing functions from CryptoKit and CommonCrypto (in CryptoUtils)
    // func signData(context: KeyContext, account: Int, keyIndex: Int, data: Data, metadata: SignMetadata) throws -> Data {
    func signData(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32, data: Data) throws -> Data {
        // validate data
        // let result = validateData(data: data, metadata: metadata)

        // if result is Error { // decoding errors
        //     throw result
        // }

        // if !result { // failed schema validation
        //     throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Bad data"])
        // }

        let rootKey: Data = fromSeed(seed)
        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)
        let raw: Data = deriveKey(rootKey: rootKey, bip44Path: bip44Path, isPrivate: true)

        let scalar = raw.subdata(in: 0..<32)
        let c = raw.subdata(in: 32..<64)

        // \(1): pubKey = scalar * G (base point, no clamp)
        let publicKey = SodiumHelper.scalarMultEd25519BaseNoClamp(scalar)

        // \(2): h = hash(c + msg) mod q
        let hash = CryptoUtils.sha512(data: c + data)
        let q = BigInt("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", radix: 16)
        let rBigInt = BigInt(hash) % q!

        // fill 32 bytes of r
        // convert to Data
        var r = Data(repeating: 0, count: 32)
        let rBString = String(rBigInt, radix: 16).padding(toLength: 64, withPad: "0", startingAt: 0) // convert to hex

        for i in 0..<32 {
            let start = rBString.index(rBString.startIndex, offsetBy: i*2)
            let end = rBString.index(start, offsetBy: 2)
            let bytes = rBString[start..<end]
            r[i] = UInt8(bytes, radix: 16)!
        }

        // \(4):  R = r * G (base point, no clamp)
        let R = SodiumHelper.scalarMultEd25519BaseNoClamp(r)

        var h = CryptoUtils.sha512(data: R + publicKey + data)
        h = SodiumHelper.coreEd25519ScalarReduce(h)

        // \(5): S = (r + h * k) mod q
        let S = SodiumHelper.coreEd25519ScalarAdd(r: r, k: SodiumHelper.coreEd25519ScalarMul(h: h, scalar: scalar))

        return R + S
    }

    private func hasAlgorandTags(message: Data) -> Bool {
        // Check that decoded doesn't include the following prefixes: TX, MX, progData, Program
        let tx = String(data: message[0...1], encoding: .ascii)
        let mx = String(data: message[0...1], encoding: .ascii)
        let progData = String(data: message[0...7], encoding: .ascii)
        let program = String(data: message[0...6], encoding: .ascii)

        return tx == "TX" || mx == "MX" || progData == "progData" || program == "Program"
    }

    func verifyWithPublicKey(signature: Data, message: Data, publicKey: Data) -> Bool {
        return SodiumHelper.sodiumSignVerify(signature: signature, message: message, publicKey: publicKey)
    }


    // func ECDH(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32, otherPartyPub: Data) async throws -> Data {

    //     guard let rootKey = fromSeed(self.seed) as Data? else {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Invalid seed"])
    //     }

    //     let bip44Path = GetBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)
        
    //     guard let childKey = self.deriveKey(rootKey: rootKey, bip44Path: bip44Path, hardened: true) else {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Key derivation failed"])
    //     }

    //     let scalar = childKey[0..<32]

        
    //     SodiumHelper.cryptoCurve25519ScalarMult()

    //     guard let otherPartyPubCurve25519 = sodium.sign.pkToCurve25519(ed25519Pk: otherPartyPub),
    //         let sharedSecret = sodium.scalarmult.base(n: scalar, p: otherPartyPubCurve25519) else {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Scalar multiplication failed"])
    //     }

    //     return sharedSecret
    // }



    // private func validateData(message: Data, metadata: SignMetadata) throws -> Bool {
    //     // Check that decoded doesn't include the following prefixes: TX, MX, progData, Program
    //     // These prefixes are reserved for the protocol

    //     if self.hasAlgorandTags(message: message) {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : ERROR_TAGS_FOUND])
    //     }

    //     let decoded: Data
    //     switch metadata.encoding {
    //     case .base64:
    //         guard let messageString = String(data: message, encoding: .utf8),
    //             let data = Data(base64Encoded: messageString) else {
    //             throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Invalid base64"])
    //         }
    //         decoded = data
    //     case .msgpack:
    //         decoded = try MessagePackSerialization.unpack(message)
    //     case .none:
    //         decoded = message
    //     default:
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Invalid encoding"])
    //     }

    //     // Check after decoding too
    //     // Some one might try to encode a regular transaction with the protocol reserved prefixes
    //     if self.hasAlgorandTags(message: decoded) {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : ERROR_TAGS_FOUND])
    //     }

    //     // validate with schema
    //     guard let decodedString = String(data: decoded, encoding: .utf8),
    //         let decodedJson = try? JSONSerialization.jsonObject(with: Data(decodedString.utf8), options: []) as? [String: Any],
    //         let schema = try? JSONSchema(metadata.schema),
    //         let report = try? schema.validate(decodedJson) else {
    //         throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey : "Invalid JSON or schema"])
    //     }

    //     if !report.isValid {
    //         print(report.errors)
    //     }

    //     return report.isValid
    // }

}

