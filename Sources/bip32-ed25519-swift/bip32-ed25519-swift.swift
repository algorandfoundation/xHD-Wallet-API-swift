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

import BigInt
import Clibsodium
import Foundation
import JSONSchema
import MessagePack
import Sodium

public enum KeyContext: UInt32 {
    case Address = 0
    case Identity = 1
}

public enum BIP32DerivationType: Int {
    // standard Ed25519 bip32 derivations based of: https://acrobat.adobe.com/id/urn:aaid:sc:EU:04fe29b0-ea1a-478b-a886-9bb558a5242a
    // Defines 32 bits to be zeroed from each derived zL
    case Khovratovich = 32
    // Derivations based on Peikert's ammendments to the original BIP32-Ed25519
    // Picking only 9 bits to be zeroed from each derived zL
    case Peikert = 9
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

public struct Schema {
    var jsonSchema: [String: Any]

    init(filePath: String) throws {
        let url = URL(fileURLWithPath: filePath)
        let data = try Data(contentsOf: url)
        let jsonObject = try JSONSerialization.jsonObject(with: data, options: [])

        guard let jsonSchema = jsonObject as? [String: Any] else {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid JSON schema"])
        }

        self.jsonSchema = jsonSchema
    }
}

public struct SignMetadata {
    var encoding: Encoding
    var schema: Schema
}

extension Data {
    init?(hexString: String) {
        let length = hexString.count / 2 // Two characters represent one byte
        var data = Data(capacity: length)
        for i in 0 ..< length {
            let j = hexString.index(hexString.startIndex, offsetBy: i * 2)
            let k = hexString.index(j, offsetBy: 2)
            let bytes = hexString[j ..< k]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }
}

let sharedSecretHashBufferSize = 32
let ED25519_SCALAR_SIZE = 32
let ED25519_POINT_SIZE = 32
let CHAIN_CODE_SIZE = 32

public class Bip32Ed25519 {
    private var seed: Data

    public init?(seed: String) {
        guard let data = Data(hexString: seed) else {
            return nil
        }
        self.seed = data
    }

    func harden(_ num: UInt32) -> UInt32 {
        0x8000_0000 + num
    }

    func getBIP44PathFromContext(context: KeyContext, account: UInt32, change: UInt32, keyIndex: UInt32) -> [UInt32] {
        switch context {
        case .Address:
            [harden(44), harden(283), harden(account), change, keyIndex]
        case .Identity:
            [harden(44), harden(0), harden(account), change, keyIndex]
        }
    }

    func fromSeed(_ seed: Data) -> Data {
        // k = H512(seed)
        var k = CryptoUtils.sha512(data: seed)
        var kL = k.subdata(in: 0 ..< ED25519_SCALAR_SIZE)
        var kR = k.subdata(in: ED25519_SCALAR_SIZE ..< 2 * ED25519_SCALAR_SIZE)

        // While the third highest bit of the last byte of kL is not zero
        while kL[31] & 0b0010_0000 != 0 {
            k = CryptoUtils.hmacSha512(key: kL, data: kR)
            kL = k.subdata(in: 0 ..< ED25519_SCALAR_SIZE)
            kR = k.subdata(in: ED25519_SCALAR_SIZE ..< 2 * ED25519_SCALAR_SIZE)
        }

        // clamp
        // Set the bits in kL as follows:
        // little Endianess
        kL[0] = kL[0] & 0b1111_1000 // the lowest 3 bits of the first byte of kL are cleared
        kL[31] = kL[31] & 0b0111_1111 // the highest bit of the last byte is cleared
        kL[31] = kL[31] | 0b0100_0000 // the second highest bit of the last byte is set

        // chain root code
        // SHA256(0x01||k)
        let c = CryptoUtils.sha256(data: Data([0x01]) + seed)
        return kL + kR + c
    }

    func deriveNonHardened(kl: Data, cc: Data, index: UInt32) -> (z: Data, childChainCode: Data) {
        var data = Data(count: 1 + ED25519_SCALAR_SIZE + 4)
        data[1 + ED25519_SCALAR_SIZE] = UInt8(index & 0xFF)

        let pk = SodiumHelper.scalarMultEd25519BaseNoClamp(kl)
        data.replaceSubrange(1 ..< 1 + pk.count, with: pk)

        data[0] = 0x02
        let z = CryptoUtils.hmacSha512(key: cc, data: data)

        data[0] = 0x03
        let childChainCode = CryptoUtils.hmacSha512(key: cc, data: data)

        return (z, childChainCode)
    }

    func deriveHardened(kl: Data, kr: Data, cc: Data, index: UInt32) -> (z: Data, childChainCode: Data) {
        var data = Data(count: 1 + 2 * ED25519_SCALAR_SIZE + 4)

        var indexLE = index.littleEndian
        let indexData = Data(bytes: &indexLE, count: MemoryLayout.size(ofValue: indexLE))
        data.replaceSubrange(1 + 2 * ED25519_SCALAR_SIZE ..< 1 + 2 * ED25519_SCALAR_SIZE + 4, with: indexData)

        data.replaceSubrange(1 ..< 1 + kl.count, with: kl)
        data.replaceSubrange(1 + kl.count ..< 1 + kl.count + kr.count, with: kr)

        data[0] = 0x00
        let z = CryptoUtils.hmacSha512(key: cc, data: data)

        data[0] = 0x01
        let childChainCode = CryptoUtils.hmacSha512(key: cc, data: data)

        return (z, childChainCode)
    }

    public func deriveChildNodePublic(extendedKey: Data, index: UInt32, g: BIP32DerivationType = BIP32DerivationType.Peikert) throws -> Data {
        guard index < 0x8000_0000 else {
            throw DataValidationException(message: "Cannot derive public key with harden")
        }

        let pk = extendedKey.subdata(in: 0 ..< ED25519_POINT_SIZE)
        let cc = extendedKey.subdata(in: ED25519_POINT_SIZE ..< ED25519_POINT_SIZE + CHAIN_CODE_SIZE)

        var indexLE = index.littleEndian
        let indexData = Data(bytes: &indexLE, count: MemoryLayout.size(ofValue: indexLE))

        var data = Data(count: 1 + ED25519_SCALAR_SIZE + indexData.count)
        data.replaceSubrange(1 + ED25519_SCALAR_SIZE ..< 1 + ED25519_SCALAR_SIZE + indexData.count, with: indexData)
        data.replaceSubrange(1 ..< 1 + pk.count, with: pk)
        data[0] = 0x02

        let z = CryptoUtils.hmacSha512(key: cc, data: data)
        let zL = trunc256MinusGBits(zl: z.subdata(in: 0 ..< ED25519_SCALAR_SIZE), g: g)

        // Step 2: Compute child public key
        let left = BigUInt(Data(zL.reversed())) * BigUInt(8)
        let leftData = Data(left.serialize().reversed())

        let p = SodiumHelper.scalarMultEd25519BaseNoClamp(leftData)

        // Step 3: Compute child chain code
        data[0] = 0x03
        let fullChildChainCode = CryptoUtils.hmacSha512(key: cc, data: data)
        let childChainCode = fullChildChainCode.subdata(in: 32 ..< 64)

        var result = Data()
        result.append(SodiumHelper.cryptoCoreEd25519Add(p, pk))
        result.append(childChainCode)
        return result
    }

    public func deriveChildNodePrivate(extendedKey: Data, index: UInt32, g: BIP32DerivationType) -> Data {
        let kl = extendedKey.subdata(in: 0 ..< ED25519_SCALAR_SIZE)
        let kr = extendedKey.subdata(in: ED25519_SCALAR_SIZE ..< 2 * ED25519_SCALAR_SIZE)
        let cc = extendedKey.subdata(in: 2 * ED25519_SCALAR_SIZE ..< 3 * ED25519_SCALAR_SIZE)

        let (z, childChainCode) =
            (index < 0x8000_0000) ? deriveNonHardened(kl: kl, cc: cc, index: index) : deriveHardened(kl: kl, kr: kr, cc: cc, index: index)

        let chainCode = childChainCode.subdata(in: ED25519_SCALAR_SIZE ..< 2 * ED25519_SCALAR_SIZE)
        let zl = z.subdata(in: 0 ..< ED25519_SCALAR_SIZE)
        let zr = z.subdata(in: ED25519_SCALAR_SIZE ..< 2 * ED25519_SCALAR_SIZE)

        // left = kl + 8 * trunc28(zl)
        // right = zr + kr

        let left = BigUInt(Data(kl.reversed())) + BigUInt(Data(trunc256MinusGBits(zl: zl, g: g).reversed())) * BigUInt(8)
        let right = BigUInt(Data(kr.reversed())) + BigUInt(Data(zr.reversed()))

        // Reverse byte order back after calculations
        var leftData = Data(left.serialize().reversed())
        var rightData = Data(right.serialize().reversed())

        // Padding for left
        leftData = Data(repeating: 0, count: ED25519_SCALAR_SIZE - leftData.count) + leftData

        // Padding for right
        if rightData.count > ED25519_SCALAR_SIZE {
            rightData = rightData.subdata(in: 0 ..< ED25519_SCALAR_SIZE)
        }
        rightData += Data(repeating: 0, count: ED25519_SCALAR_SIZE - rightData.count)

        var result = Data()
        result.append(leftData)
        result.append(rightData)
        result.append(chainCode)
        return result
    }

    func trunc256MinusGBits(zl: Data, g: BIP32DerivationType) -> Data {
        var truncated = zl
        var remainingBits = g.rawValue

        // start from the last byte and move backwards
        for i in (0 ..< truncated.count).reversed() {
            if remainingBits >= 8 {
                truncated[i] = 0
                remainingBits -= 8
            } else {
                // let mask = UInt8(0xFF << remainingBits)
                let mask = UInt8((1 << (8 - remainingBits)) - 1)
                truncated[i] &= mask
                break
            }
        }

        return truncated
    }

    public func deriveKey(rootKey: Data, bip44Path: [UInt32], isPrivate: Bool = true, derivationType: BIP32DerivationType) -> Data {
        // Public Key SOFT derivations are possible without using the private key of the parent node
        // Could be an implementation choice.
        // Example:
        // let nodeScalar: Data = derived.subdata(in: 0..<32)
        // let nodePublic: Data = self.crypto_scalarmult_ed25519_base_noclamp(scalar: nodeScalar)
        // let nodeCC: Data = derived.subdata(in: 64..<96)

        // // [Public][ChainCode]
        // let extPub: Data = nodePublic + nodeCC
        // let publicKey: Data = deriveChildNodePublic(extendedKey: extPub, index: bip44Path[4]).subdata(in: 0..<32)

        let g = derivationType

        var derived = rootKey
        for i in 0 ..< bip44Path.count {
            derived = deriveChildNodePrivate(extendedKey: derived, index: bip44Path[i], g: g)
        }

        return isPrivate ? derived : SodiumHelper.scalarMultEd25519BaseNoClamp(derived.subdata(in: 0 ..< ED25519_SCALAR_SIZE)) + derived.subdata(in: 2 * CHAIN_CODE_SIZE ..< 3 * CHAIN_CODE_SIZE)
    }

    public func keyGen(
        context: KeyContext,
        account: UInt32,
        change: UInt32,
        keyIndex: UInt32,
        derivationType: BIP32DerivationType = BIP32DerivationType.Peikert
    ) -> Data {
        let rootKey: Data = fromSeed(seed)
        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)

        return deriveKey(rootKey: rootKey, bip44Path: bip44Path, isPrivate: false, derivationType: derivationType).prefix(32)
    }

    private func rawSign(bip44Path: [UInt32], message: Data, derivationType: BIP32DerivationType) -> Data {
        let rootKey: Data = fromSeed(seed)
        let raw: Data = deriveKey(rootKey: rootKey, bip44Path: bip44Path, isPrivate: true, derivationType: derivationType)

        let scalar = raw.subdata(in: 0 ..< ED25519_SCALAR_SIZE)
        let c = raw.subdata(in: ED25519_SCALAR_SIZE ..< 2 * ED25519_SCALAR_SIZE)

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

    public func signAlgoTransaction(
        context: KeyContext,
        account: UInt32,
        change: UInt32,
        keyIndex: UInt32,
        prefixEncodedTx: Data,
        derivationType: BIP32DerivationType = BIP32DerivationType.Peikert
    ) -> Data {
        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)
        return rawSign(bip44Path: bip44Path, message: prefixEncodedTx, derivationType: derivationType)
    }

    public func verifyWithPublicKey(signature: Data, message: Data, publicKey: Data) -> Bool {
        SodiumHelper.cryptoSignVerifyDetached(signature, message, publicKey)
    }

    func hasAlgorandTags(data: Data) -> Bool {
        // Prefixes taken from go-algorand node software code
        // https://github.com/algorand/go-algorand/blob/master/protocol/hash.go

        // swiftlint:disable:next line_length
        let prefixes = ["appID", "arc", "aB", "aD", "aO", "aP", "aS", "AS", "BH", "B256", "BR", "CR", "GE", "KP", "MA", "MB", "MX", "NIC", "NIR", "NIV", "NPR", "OT1", "OT2", "PF", "PL", "Program", "ProgData", "PS", "PK", "SD", "SpecialAddr", "STIB", "spc", "spm", "spp", "sps", "spv", "TE", "TG", "TL", "TX", "VO"]
        let prefixBytes = prefixes.map { $0.data(using: .ascii)! }
        return prefixBytes.contains { data.starts(with: $0) }
    }

    public func validateData(data: Data, metadata: SignMetadata) throws -> Bool {
        if hasAlgorandTags(data: data) {
            return false
        }

        // Transform encoded data into the "raw" data format
        var rawData: Data
        switch metadata.encoding {
        case .base64:
            guard let base64String = String(data: data, encoding: .utf8),
                  let base64Data = Data(base64Encoded: base64String)
            else {
                return false
            }
            rawData = base64Data
        case .msgpack:
            do {
                rawData = try JSONSerialization.data(withJSONObject: messagePackValueToSwift(MessagePack.unpack(data).value), options: [])
            } catch {
                return false
            }
        case .none:
            rawData = data
        }

        do {
            if let jsonObject = try JSONSerialization.jsonObject(with: rawData, options: []) as? [String: Any] {
                let valid = try JSONSchema.validate(jsonObject, schema: metadata.schema.jsonSchema)
                return valid.valid
            } else {
                return false
            }
        } catch {
            return false
        }
    }

    public func signData(
        context: KeyContext,
        account: UInt32,
        change: UInt32,
        keyIndex: UInt32,
        data: Data,
        metadata: SignMetadata,
        derivationType: BIP32DerivationType = BIP32DerivationType.Peikert
    ) throws -> Data {
        let valid = try validateData(data: data, metadata: metadata)

        if !valid {
            throw DataValidationException(message: "Data is not valid")
        }

        let bip44Path: [UInt32] = getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex)
        return rawSign(bip44Path: bip44Path, message: data, derivationType: derivationType)
    }

    // Function to convert MessagePackValue to Swift types.
    // In particular, the .map case is relevant for transforming a JSON object encoded into MessagePack
    // into a valid Swift representation that can be checked against a JSON schema validator.
    public func messagePackValueToSwift(_ value: MessagePackValue) -> Any {
        switch value {
        case .nil:
            NSNull()
        case let .bool(bool):
            bool
        case let .int(int):
            int
        case let .uint(uint):
            uint
        case let .float(float):
            float
        case let .double(double):
            double
        case let .string(string):
            string
        case let .binary(data):
            data
        case let .array(array):
            array.compactMap { messagePackValueToSwift($0) }
        case let .map(dict):
            dict.reduce(into: [String: Any]()) { result, pair in
                if let key = pair.key.stringValue {
                    result[key] = messagePackValueToSwift(pair.value)
                }
            }
        case let .extended(type, data):
            ["type": type, "data": data]
        }
    }

    public func ECDH(
        context: KeyContext,
        account: UInt32,
        change: UInt32,
        keyIndex: UInt32,
        otherPartyPub: Data,
        meFirst: Bool,
        derivationType: BIP32DerivationType = BIP32DerivationType.Peikert
    ) -> Data {
        let rootKey = fromSeed(seed)
        let publicKey = keyGen(context: context, account: account, change: change, keyIndex: keyIndex, derivationType: derivationType)
        let privateKey = deriveKey(
            rootKey: rootKey,
            bip44Path: getBIP44PathFromContext(context: context, account: account, change: change, keyIndex: keyIndex),
            isPrivate: true,
            derivationType: derivationType
        )
        let scalar = privateKey.subdata(in: 0 ..< ED25519_SCALAR_SIZE)

        let myX25519Pub = SodiumHelper.convertPublicKeyEd25519ToCurve25519(publicKey)
        let otherX25519Pub = SodiumHelper.convertPublicKeyEd25519ToCurve25519(otherPartyPub)
        let sharedPoint = SodiumHelper.cryptoX25519ScalarMult(scalar: scalar, point: otherX25519Pub)

        let concatenated = meFirst ? sharedPoint + myX25519Pub + otherX25519Pub : sharedPoint + otherX25519Pub + myX25519Pub

        let sharedSecret = SodiumHelper.cryptoGenericHash(input: concatenated, outputLength: sharedSecretHashBufferSize)

        return sharedSecret
    }
}
