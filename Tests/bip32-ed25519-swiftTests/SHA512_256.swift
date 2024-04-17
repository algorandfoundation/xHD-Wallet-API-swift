// Modified off of Matan Lachmish's Cryptography repo 
// https://github.com/mlachmish/Cryptography/ MIT License
//  
// SHA2.swift
//  Cryptography
//
//  Created by Matan Lachmish on 25/07/2016.
//  Copyright © 2016 The Big Fat Ninja. All rights reserved.
//

import Foundation

// swiftlint:disable variable_name
// swiftlint:disable line_length
// swiftlint:disable comma

public struct SHA512_256 {
    public func hash(_ message: [UInt8]) -> [UInt8] {
            return SHA2.hash64Bit(message: message)
        }
    }

    public let blockSize: Int = 128

    let h: [UInt64] = [0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
         0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2]

    let k: [UInt64] = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
         0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
         0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
         0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
         0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
         0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
         0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
         0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
         0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
         0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
         0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
         0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
         0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
         0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
         0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
         0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

    func truncateResult<T>(h: [T]) -> ArraySlice<T> {
       return h[0..<4]
    }

// swiftlint:enable variable_name
// swiftlint:enable line_length
// swiftlint:enable comma

internal struct SHA2 {

    private static func preprocessMessage(message: Array<UInt8>,
                                          messageLengthBits: Int) -> Array<UInt8> {

        var preprocessedMessage = message
        // Pre-processing: adding a single 1 bit
        // Notice: the input bytes are considered as bits strings,
        // where the first bit is the most significant bit of the byte.
        preprocessedMessage.append(0x80)

        // Pre-processing: padding with zeros
        // append "0" bit until message length in bits ≡ 448 (mod 512)
        let desiredMessageLengthModulo = messageLengthBits - 8
        var messageLength = preprocessedMessage.count
        var paddingCounter = 0
        while messageLength % messageLengthBits != desiredMessageLengthModulo {
            paddingCounter += 1
            messageLength += 1
        }
        preprocessedMessage += Array<UInt8>(repeating: 0, count: paddingCounter)
        // append original length in bits mod (2 pow 64) to message
        preprocessedMessage.reserveCapacity(preprocessedMessage.count + 4)
        let lengthInBits = message.count * 8
        let lengthBytes = Representations.toUInt8Array(value: lengthInBits, length: 64/8)
        preprocessedMessage += lengthBytes
        return preprocessedMessage
    }

    // MARK: 64 bit version
    static func hash64Bit(message: [UInt8]) -> [UInt8] {
        // Initialize variables:
        var a0 = h[0]   // A
        var b0 = h[1]   // B
        var c0 = h[2]   // C
        var d0 = h[3]   // D
        var e0 = h[4]   // E
        var f0 = h[5]   // F
        var g0 = h[6]   // G
        var h0 = h[7]   // H

        // Pre-processing
        let preprocessedMessage = preprocessMessage(message: message,
                                                    messageLengthBits: blockSize)

        // Process the message in successive 512-bit chunks:
        let chunkSizeBytes = 1024 / 8
        for chunk in preprocessedMessage.splitToChuncks(chunkSizeBytes) {
            // Break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            // Extend the sixteen 32-bit words into eighty 32-bit words:
            var M: Array<UInt64> = Array<UInt64>(repeating: 0, count: k.count)

            for x in 0..<M.count {
                switch x {
                case 0...15:
                    let start = chunk.startIndex + (x * MemoryLayout.size(ofValue: M[x]))
                    let end = start + MemoryLayout.size(ofValue: M[x])
                    let le = Representations.mergeToUInt64Array(slice: chunk[start..<end])[0]
                    M[x] = le.bigEndian
                    break
                default:
                    let s0 = M[x-15].rotateRight(1) ^ M[x-15].rotateRight(8) ^ M[x-15] >> 7
                    let s1 = M[x-2].rotateRight(19) ^ M[x-2].rotateRight(61) ^ M[x-2] >> 6
                    M[x] = M[x-16] &+ s0 &+ M[x-7] &+ s1
                    break
                }
            }

            // Initialize hash value for this chunk:
            var A = a0
            var B = b0
            var C = c0
            var D = d0
            var E = e0
            var F = f0
            var G = g0
            var H = h0

            // Main loop:
            for i in 0..<k.count {
                let S1 = E.rotateRight(14) ^ E.rotateRight(18) ^ E.rotateRight(41)
                let ch = (E & F) ^ (~E & G)
                let temp1 = H &+ S1 &+ ch &+ UInt64(k[i]) &+ M[i]
                let S0 = A.rotateRight(28) ^ A.rotateRight(34) ^ A.rotateRight(39)
                let maj = (A & B) ^ (A & C) ^ (B & C)
                let temp2 = S0 &+ maj

                H = G
                G = F
                F = E
                E = D &+ temp1
                D = C
                C = B
                B = A
                A = temp1 &+ temp2
            }

            // Add this chunk's hash to result so far:
            a0 = (a0 &+ A)
            b0 = (b0 &+ B)
            c0 = (c0 &+ C)
            d0 = (d0 &+ D)
            e0 = (e0 &+ E)
            f0 = (f0 &+ F)
            g0 = (g0 &+ G)
            h0 = (h0 &+ H)
        }

        // Produce the final hash value (big-endian) as a 160 bit number:
        var result = Array<UInt8>()
        result.reserveCapacity(160/8)

        truncateResult(h: [a0, b0, c0, d0, e0, f0, g0, h0]).forEach {
            result += Representations.toUInt8Array(value: $0.bigEndian.reverseBytes())
        }

        return result
    }
    // swiftlint:enable function_body_length

    static func hash64Bit(message: String) -> String {
        return Representations.toHexadecimalString(
            bytes: self.hash64Bit(message: Array(message.utf8))
        )
    }
}

extension Array {

    public func splitToChuncks(_ chunkSize: Int) -> AnyIterator<ArraySlice<Element>> {
        var offset: Int = 0
        return AnyIterator {
            let end = Swift.min(chunkSize, self.count - offset)
            let result = self[offset..<offset + end]
            offset += result.count
            return !result.isEmpty ? result : nil
        }
    }

}

internal extension UInt64 {

    func rotateLeft(_ times: UInt64) -> UInt64 {
        return (self << times) | (self >> (64 - times))
    }

    func rotateRight(_ times: UInt64) -> UInt64 {
        return ((self >> times) | (self << (64 - times)))
    }

    func reverseBytes() -> UInt64 {
        let tmp1 = ((self & 0x00000000000000FF) << 56) |
            ((self & 0x000000000000FF00) << 40) |
            ((self & 0x0000000000FF0000) << 24) |
            ((self & 0x00000000FF000000) << 8)

        let tmp2 = ((self & 0x000000FF00000000) >> 8)  |
            ((self & 0x0000FF0000000000) >> 24) |
            ((self & 0x00FF000000000000) >> 40) |
            ((self & 0xFF00000000000000) >> 56)

        return tmp1 | tmp2
    }
}

internal class Representations {

    // Array of bytes with optional padding (little-endian)
    static func toUInt8Array<T>(value: T, length: Int? = nil) -> Array<UInt8> {
        let totalBytes = length ?? MemoryLayout<T>.size
        var copyOfValue = value

        return withUnsafePointer(to: &copyOfValue) {
            Array(UnsafeBufferPointer(start: UnsafePointer<UInt8>(OpaquePointer($0)), count: totalBytes)).reversed()
        }
    }

    // Merge Array of UInt8 to array of UInt32
    static func mergeToUInt32Array(slice: ArraySlice<UInt8>) -> Array<UInt32> {
        var result = Array<UInt32>()
        result.reserveCapacity(16)

        for idx in stride(from: slice.startIndex, to: slice.endIndex, by: MemoryLayout<UInt32>.size) {
            let val1: UInt32 = UInt32(slice[idx.advanced(by: 3)]) << 24
            let val2: UInt32 = UInt32(slice[idx.advanced(by: 2)]) << 16
            let val3: UInt32 = UInt32(slice[idx.advanced(by: 1)]) << 8
            let val4: UInt32 = UInt32(slice[idx])
            let val: UInt32 = val1 | val2 | val3 | val4
            result.append(val)
        }

        return result
    }

    // Merge Array of UInt8 to array of UInt64
    static func mergeToUInt64Array(slice: ArraySlice<UInt8>) -> Array<UInt64> {
        var result = Array<UInt64>()
        result.reserveCapacity(32)

        for idx in stride(from: slice.startIndex, to: slice.endIndex, by: MemoryLayout<UInt64>.size) {
            let val1: UInt64 = UInt64(slice[idx.advanced(by:7)]) << 56
            let val2: UInt64 = UInt64(slice[idx.advanced(by:6)]) << 48
            let val3: UInt64 = UInt64(slice[idx.advanced(by:5)]) << 40
            let val4: UInt64 = UInt64(slice[idx.advanced(by:4)]) << 32
            let val5: UInt64 = UInt64(slice[idx.advanced(by:3)]) << 24
            let val6: UInt64 = UInt64(slice[idx.advanced(by:2)]) << 16
            let val7: UInt64 = UInt64(slice[idx.advanced(by:1)]) << 8
            let val8: UInt64 = UInt64(slice[idx])
            let val: UInt64 = val1 | val2 | val3 | val4 | val5 | val6 | val7 | val8
            result.append(val)
        }

        return result
    }

    // Return hexadecimal string representation of Array<UInt8>
    static func toHexadecimalString(bytes: Array<UInt8>) -> String {
        var hexString = String()
        for byte in bytes {
            hexString += String(format: "%02x", byte)
        }

        return hexString
    }

}