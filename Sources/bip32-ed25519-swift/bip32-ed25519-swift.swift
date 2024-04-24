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
import BigInt
import Foundation
import JSONSchema
import MessagePack

public enum KeyContext: UInt32 {
    case Address = 0
    case Identity = 1
}

public enum Encoding {
    // case cbor
    case msgpack
    case base64
    case none
}

class DataValidationException: Error {
    var message: String
    init(message: String) {
        self.message = message
    }
}

public struct SignMetadata {
    var encoding: Encoding
    var schema: [String: Any] // Assuming JSONSchema is a type you've defined elsewhere
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

    private var seed: Data

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

    func deriveNonHardened(kl: Data, cc: Data, index: UInt32) -> (z: Data, childChainCode: Data) {
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
        
        var indexLE = index.littleEndian
        let indexData = Data(bytes: &indexLE, count: MemoryLayout.size(ofValue: indexLE))
        data.replaceSubrange(1 + 64..<1 + 64 + 4, with: indexData)
        
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
            (index < 0x80000000) ? deriveNonHardened(kl: kl, cc: cc, index: index) : deriveHardened(kl: kl, kr: kr, cc: cc, index: index)

        let chainCode = childChainCode.subdata(in: 32..<64)
        let zl = z.subdata(in: 0..<32)
        let zr = z.subdata(in: 32..<64)

        // left = kl + 8 * trunc28(zl)
        // right = zr + kr
        let left = BigUInt(Data(kl.reversed())) + BigUInt(Data(zl.subdata(in: 0..<28).reversed())) * BigUInt(8)
        let right = BigUInt(Data(kr.reversed())) + BigUInt(Data(zr.reversed()))

        // Reverse byte order back after calculations
        var leftData = Data(left.serialize().reversed())
        var rightData = Data(right.serialize().reversed())

        // Padding for left
        leftData = Data(repeating: 0, count: 32 - leftData.count) + leftData

        // Padding for right
        if rightData.count > 32 {
            rightData = rightData.subdata(in: 0..<32)
        }
        rightData = rightData + Data(repeating: 0, count: 32 - rightData.count)

        var result = Data()
        result.append(leftData)
        result.append(rightData)
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

        return isPrivate ? derived : SodiumHelper.scalarMultEd25519BaseNoClamp(derived.subdata(in: 0..<32))
    }


    func keyGen(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32) -> Data {
        let rootKey: Data = fromSeed(self.seed)
        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)

        return self.deriveKey(rootKey: rootKey, bip44Path: bip44Path, isPrivate: false)
    }

    private func rawSign(bip44Path: [UInt32], message: Data) -> Data {
        let rootKey: Data = fromSeed(self.seed)
        let raw: Data = deriveKey(rootKey: rootKey, bip44Path: bip44Path, isPrivate: true)
        
        let scalar = raw.subdata(in: 0..<32)
        let c = raw.subdata(in: 32..<64)

        // \(1): pubKey = scalar * G (base point, no clamp)
        let publicKey: Data = SodiumHelper.scalarMultEd25519BaseNoClamp(scalar)

        // \(2): r = hash(c + msg) mod q [LE]
        let r = SodiumHelper.cryptoCoreEd25519ScalarReduce(CryptoUtils.sha512(data: c + message))

        // \(3):  R = r * G (base point, no clamp)
        let R = SodiumHelper.scalarMultEd25519BaseNoClamp(r)

        // \(4): S = (r + h * k) mod q
        let h = SodiumHelper.cryptoCoreEd25519ScalarReduce(CryptoUtils.sha512(data: R + publicKey + message))

        let mulResult = Data(SodiumHelper.cryptoCoreEd25519ScalarMul(h, scalar))
        let S = SodiumHelper.cryptoCoreEd25519ScalarAdd(r, mulResult)
        
        return R + S
    }

    public func signAlgoTransaction(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32, prefixEncodedTx: Data) -> Data {
        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)
        return rawSign(bip44Path: bip44Path, message: prefixEncodedTx)
    }

    public func verifyWithPublicKey(signature: Data, message: Data, publicKey: Data) -> Bool {
        return SodiumHelper.cryptoSignVerifyDetached(signature, message,publicKey)
    }

    func hasAlgorandTags(data: Data) -> Bool {
        // Prefixes taken from go-algorand node software code
        // https://github.com/algorand/go-algorand/blob/master/protocol/hash.go

        let prefixes = ["appID", "arc", "aB", "aD", "aO", "aP", "aS", "AS", "BH", "B256", "BR", "CR", "GE", "KP", "MA", "MB", "MX", "NIC", "NIR", "NIV", "NPR", "OT1", "OT2", "PF", "PL", "Program", "ProgData", "PS", "PK", "SD", "SpecialAddr", "STIB", "spc", "spm", "spp", "sps", "spv", "TE", "TG", "TL", "TX", "VO"]
        let prefixBytes = prefixes.map { $0.data(using: .ascii)! }
        return prefixBytes.contains { data.starts(with: $0) }
    }

    public func validateData(data: Data, metadata: SignMetadata) throws -> Bool {

        if hasAlgorandTags(data: data) {
            return false
        }

        // Validate data based on the schema
        var rawData: Data
        switch metadata.encoding {
            case .base64:
                guard let string = String(data: data, encoding: .utf8),
                    let base64Data = Data(base64Encoded: string) else {
                    return false
                }
                rawData = base64Data
            case .msgpack:
                do {
                    rawData = try JSONSerialization.data(withJSONObject: messagePackValueToSwift(try MessagePack.unpack(data).value), options: [])
                } catch {
                    return false
                }
            case .none:
                rawData = data
        }

        do {
            let valid = try JSONSchema.validate(try JSONSerialization.jsonObject(with: rawData, options: []) as! [String: Any], schema: metadata.schema)
            return valid.valid
        } catch {
            return false
        }
    }

    public func signData(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32, data: Data, metadata: SignMetadata) throws -> Data {
        let valid = try validateData(data: data, metadata: metadata)

        if !valid{
            throw DataValidationException(message: "Data is not valid")
        }

        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)
        return rawSign(bip44Path: bip44Path, message: data)
    }

    func messagePackValueToSwift(_ value: MessagePackValue) -> Any {
        switch value {
            case .nil:
                return NSNull()
            case .bool(let bool):
                return bool
            case .int(let int):
                return int
            case .uint(let uint):
                return uint
            case .float(let float):
                return float
            case .double(let double):
                return double
            case .string(let string):
                return string
            case .binary(let data):
                return data
            case .array(let array):
                return array.compactMap { messagePackValueToSwift($0) }
            case .map(let dict):
                return dict.reduce(into: [String: Any]()) { result, pair in
                    if let key = pair.key.stringValue {
                        result[key] = messagePackValueToSwift(pair.value)
                    }
                }
            case .extended(let type, let data):
                return ["type": type, "data": data]
            }
        }
}

