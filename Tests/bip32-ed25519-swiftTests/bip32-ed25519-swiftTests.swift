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

import XCTest
@testable import bip32_ed25519_swift
import MnemonicSwift

final class Bip32Ed25519Tests: XCTestCase {
    var c: Bip32Ed25519?

    override func setUpWithError() throws {
        let seed = try Mnemonic.deterministicSeedString(from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
        c = Bip32Ed25519(seed: seed)
        guard c != nil else {
            throw NSError(domain: "Bip32Ed25519Tests", code: 1, userInfo: [NSLocalizedDescriptionKey: "Bip32Ed25519 not initialized"])
        }
    }

    func testInitializationWithSeed() throws {
        XCTAssertNotNil(c)
    }

    func testHarden() throws {
        XCTAssertEqual(c!.harden(0), 2147483648)
        XCTAssertEqual(c!.harden(1), 2147483649)
        XCTAssertEqual(c!.harden(44), 2147483692)
        XCTAssertEqual(c!.harden(283), 2147483931)
    }

    func testGetBIP44PathFromContext() throws {
        let addressPath = c!.getBIP44PathFromContext(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0)
        let identityPath = c!.getBIP44PathFromContext(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0)
        XCTAssertEqual(addressPath, [UInt32](arrayLiteral: 2147483692, 2147483931, 2147483648, 0, 0));
        XCTAssertEqual(identityPath,  [UInt32](arrayLiteral: 2147483692, 2147483648, 2147483648, 0, 0));
    }

    func testDeriveNonHardened() throws {

        let kl = Data([168,186,128,2,137,34,217,252,250,5,92,120,174,222,85,181,197,117,188,216,213,165,49,104,237,244,95,54,217,236,143,70])
        let cc = Data([121,107,146,6,236,48,225,66,233,75,121,10,152,128,91,249,153,4,43,85,4,105,99,23,78,230,206,226,208,55,89,70])

        let expectedZZ = Data([79,57,235,234,215,9,72,57,157,32,34,226,81,95,29,115,250,66,232,187,16,193,209,254,140,127,122,242,224,69,122,166,31,223,82,170,49,164,3,115,96,128,159,63,116,37,118,15,167,94,148,38,50,10,126,70,3,86,36,78,199,91,146,54])
        let expectedCCC = Data([98,42,235,140,228,232,27,136,136,143,220,220,32,187,77,47,254,209,231,13,224,226,108,113,167,234,93,101,160,32,37,152,216,141,148,178,77,222,78,201,150,148,186,65,223,76,237,113,104,229,170,167,224,222,193,99,251,94,222,14,82,185,232,206])
        
        let (z, childChainCode) = c!.deriveNonHardened(kl: kl, cc: cc, index: 0)

        XCTAssertEqual(z, expectedZZ)
        XCTAssertEqual(childChainCode, expectedCCC)
    }

    func testDeriveHardened() throws {

        let kl = Data([168,186,128,2,137,34,217,252,250,5,92,120,174,222,85,181,197,117,188,216,213,165,49,104,237,244,95,54,217,236,143,70])
        let kr = Data([148,89,43,75,200,146,144,117,131,226,38,105,236,223,27,4,9,169,243,189,85,73,242,221,117,27,81,54,9,9,205,5])
        let cc = Data([121,107,146,6,236,48,225,66,233,75,121,10,152,128,91,249,153,4,43,85,4,105,99,23,78,230,206,226,208,55,89,70])

        let expectedZZ = Data([241,155,222,63,177,102,52,174,88,241,56,59,144,16,74,143,9,66,66,43,208,144,253,154,211,54,107,135,59,57,54,101,184,111,121,207,178,74,118,177,0,10,69,137,96,97,246,116,206,37,118,201,90,48,254,232,249,234,191,143,116,13,40,109])
        let expectedCCC = Data([113,159,183,57,127,174,86,11,68,82,114,215,136,191,242,88,45,11,66,160,140,77,60,25,130,238,210,239,247,55,117,240,141,123,149,66,11,250,54,180,175,41,166,195,76,15,154,235,246,49,203,70,79,22,94,165,138,89,21,152,23,108,180,148])
        
        let (z, childChainCode) = c!.deriveHardened(kl: kl, kr: kr, cc: cc, index: c!.harden(44))
        XCTAssertEqual(z, expectedZZ)
        XCTAssertEqual(childChainCode, expectedCCC)
    }

    func testFromSeed() throws {
        let seed = Data([58,255,45,180,22,184,149,236,60,249,164,248,209,233,112,188,152,25,146,14,123,244,74,94,53,4,119,175,14,245,87,177,81,27,9,134,222,191,120,221,56,199,197,32,205,68,255,124,114,49,97,143,149,142,33,239,2,80,115,58,140,25,21,234])
        let expectedKL = Data([168,186,128,2,137,34,217,252,250,5,92,120,174,222,85,181,197,117,188,216,213,165,49,104,237,244,95,54,217,236,143,70])
        let expectedKR = Data([148,89,43,75,200,146,144,117,131,226,38,105,236,223,27,4,9,169,243,189,85,73,242,221,117,27,81,54,9,9,205,5])
        let  expectedC = Data([121,107,146,6,236,48,225,66,233,75,121,10,152,128,91,249,153,4,43,85,4,105,99,23,78,230,206,226,208,55,89,70])
        let expectedOutput = expectedKL + expectedKR + expectedC
        let output = c!.fromSeed(seed)
        XCTAssertEqual(output, expectedOutput)
    }

    func testDeriveChildNodePrivate() throws {

        let indices = [c!.harden(UInt32(283)), UInt32(2147483648)]
        let extendedKeys = [Data([48,154,117,1,19,88,124,110,192,144,35,82,48,99,166,47,18,134,206,50,87,44,30,64,138,171,185,113,221,236,143,70,76,201,164,26,123,221,6,39,132,236,107,242,76,65,18,121,215,206,105,135,176,121,240,198,111,6,17,198,125,22,245,114,141,123,149,66,11,250,54,180,175,41,166,195,76,15,154,235,246,49,203,70,79,22,94,165,138,89,21,152,23,108,180,148]), Data([152, 225, 53, 235, 111, 189, 16, 80, 5, 187, 222, 103, 51, 25, 9, 175, 172, 210, 205, 151, 195, 80, 249, 179, 162, 157, 197, 181, 222, 236, 143, 70, 235, 179, 35, 29, 125, 172, 171, 5, 131, 195, 126, 183, 57, 159, 45, 69, 232, 136, 154, 57, 174, 63, 130, 164, 117, 24, 105, 139, 121, 92, 17, 211, 107, 102, 4, 2, 204, 196, 48, 71, 244, 82, 253, 123, 214, 63, 171, 147, 161, 188, 133, 206, 203, 205, 213, 26, 83, 29, 133, 228, 82, 216, 30, 127])]
        let expectedOutputs = [Data([152,225,53,235,111,189,16,80,5,187,222,103,51,25,9,175,172,210,205,151,195,80,249,179,162,157,197,181,222,236,143,70, 235,179,35,29,125,172,171,5,131,195,126,183,57,159,45,69,232,136,154,57,174,63,130,164,117,24,105,139,121,92,17,211, 107,102,4,2,204,196,48,71,244,82,253,123,214,63,171,147,161,188,133,206,203,205,213,26,83,29,133,228,82,216,30,127]), Data([248, 91, 210, 62, 156, 144, 108, 177, 63, 167, 126, 1, 132, 58, 45, 178, 246, 252, 188, 221, 105, 104, 97, 54, 232, 92, 190, 228, 226, 236, 143, 70, 187, 122, 35, 69, 101, 182, 49, 122, 216, 252, 71, 107, 197, 176, 56, 18, 136, 95, 146, 175, 1, 151, 252, 83, 155, 22, 27, 106, 47, 67, 37, 75, 213, 25, 13, 246, 205, 204, 73, 226, 124, 111, 209, 124, 76, 32, 166, 121, 128, 234, 224, 65, 27, 230, 42, 228, 35, 106, 79, 138, 154, 149, 109, 227])]

        for i in 0..<indices.count {
            let output = c!.deriveChildNodePrivate(extendedKey: extendedKeys[i], index: indices[i])
            XCTAssertEqual(output, expectedOutputs[i])
            XCTAssertEqual(output.count, 96)
        }
    }

    func testDeriveKey() throws {

        let rootkey = Data([168,186,128,2,137,34,217,252,250,5,92,120,174,222,85,181,197,117,188,216,213,165,49,104,237,244,95,54,217,236,143,70,148,89,43,75,200,146,144,117,131,226,38,105,236,223,27,4,9,169,243,189,85,73,242,221,117,27,81,54,9,9,205,5,121,107,146,6,236,48,225,66,233,75,121,10,152,128,91,249,153,4,43,85,4,105,99,23,78,230,206,226,208,55,89,70])
        let bip44Path =  [UInt32]([2147483692, 2147483931, 2147483648, 0, 0])
        let expectedResultPublic = Data([98,254,131,43,122,209,5,68,190,131,55,166,112,67,94,80,100,174,74,102,231,123,215,137,9,118,91,70,181,118,166,243])

        let outputPublic = c!.deriveKey(rootKey: rootkey, bip44Path: bip44Path, isPrivate: false)
        XCTAssertEqual(outputPublic, expectedResultPublic)

        let expectedResultPrivate = Data([128,16,43,185,143,170,195,253,23,137,194,198,197,89,211,113,92,217,202,194,40,214,212,176,247,106,35,70,234,236,143,70,1,174,20,40,64,137,36,62,147,107,233,27,40,35,204,20,47,117,49,53,234,255,27,174,32,211,238,199,120,112,197,68,159,146,199,144,215,171,174,224,224,10,78,193,251,120,161,212,56,232,204,247,194,186,217,160,24,165,191,154,93,81,0,117])
        let outputPrivate = c!.deriveKey(rootKey: rootkey, bip44Path: bip44Path, isPrivate: true)   
        XCTAssertEqual(outputPrivate, expectedResultPrivate)
    }

    func testKeyGeneration() throws {
        let testVectors: Array<((KeyContext, UInt32, UInt32, UInt32), Data)> = [
            // derive key m'/44'/283'/0'/0/0
            ((KeyContext.Address, 0, 0, 0),Data([98,254,131,43,122,209,5,68,190,131,55,166,112,67,94,80,100,174,74,102,231,123,215,137,9,118,91,70,181,118,166,243])),
            // derive key m'/44'/283'/0'/0/1
            ((KeyContext.Address, 0, 0, 1),Data([83,4,97,0,46,172,206,192,199,181,121,89,37,170,16,74,127,180,95,133,239,10,169,91,187,91,233,59,111,133,55,173])),
            // derive key m'/44'/283'/0'/0/2
            ((KeyContext.Address, 0, 0, 2),Data([34,129,200,27,238,4,238,3,159,164,130,194,131,84,28,106,176,108,131,36,219,111,28,197,156,104,37,46,29,88,188,179])),
            // derive key m'/44'/283'/1'/0/0
            ((KeyContext.Address, 1, 0, 0),Data([158,18,100,63,108,0,104,220,245,59,4,218,206,214,248,193,169,10,210,28,149,74,102,223,65,64,215,147,3,22,106,103])),
            // derive key m'/44'/283'/1'/0/1
            ((KeyContext.Address, 1, 0, 1),Data([25,254,250,164,39,200,166,251,76,248,11,184,72,233,192,195,122,162,191,76,177,156,245,172,149,21,186,30,109,152,140,186])),
            // derive key m'/44'/283'/2'/0/1
            ((KeyContext.Address, 2, 0, 1),Data([138,93,223,98,213,26,44,80,229,29,186,212,99,67,86,204,114,49,74,129,237,217,23,172,145,218,150,71,122,159,181,176])),
            // derive key m'/44'/283'/3'/0/0
            ((KeyContext.Address, 3, 0, 0),Data([35,88,224,242,180,101,171,62,143,85,19,157,131,22,101,77,75,227,158,187,34,54,125,54,64,159,208,42,32,176,224,23])),
            // derive key m'/44'/0'/0'/0/0
            ((KeyContext.Identity, 0, 0, 0),Data([182,215,238,165,175,10,216,62,223,67,64,101,158,114,240,234,43,69,102,222,31,195,182,58,64,164,37,170,190,190,94,73])),
            // derive key m'/44'/0'/0'/0/1
            ((KeyContext.Identity, 0, 0, 1),Data([181,206,198,118,197,162,18,158,209,190,66,35,162,112,36,57,187,178,70,47,215,123,67,242,126,47,121,253,25,74,48,162])),
            // derive key m'/44'/0'/0'/0/2
            ((KeyContext.Identity, 0, 0, 2),Data([67,94,94,52,70,67,29,70,37,114,171,238,27,139,173,184,134,8,144,106,106,242,123,132,151,188,207,213,3,237,182,254])),
            // derive key m'/44'/0'/1'/0/0
            ((KeyContext.Identity, 1, 0, 0),Data([191,99,190,131,255,249,188,157,10,235,194,49,213,3,66,17,14,82,32,36,126,80,222,55,107,71,225,84,181,211,42,62])),
            // derive key m'/44'/0'/1'/0/2
            ((KeyContext.Identity, 1, 0, 2),Data([70,149,142,118,219,21,21,127,64,18,39,248,172,189,183,9,36,93,202,5,85,200,232,95,86,176,210,5,46,131,77,6])),
            // derive key m'/44'/0'/2'/0/1
            ((KeyContext.Identity, 2, 0, 1),Data([237,177,15,255,36,164,116,93,245,47,26,10,177,174,113,179,117,45,1,156,140,36,55,212,106,184,200,230,52,167,76,212]))
        ]

        for (input, expected) in testVectors {
            let pk = ((c?.keyGen(context: input.0, account: input.1, change: input.2, keyIndex: input.3))!)
            XCTAssertEqual(pk, expected)
        }
    }

    func testVerifyAlgoTx() throws {
        // this transaction wes successfully submitted to the network
        // https://testnet.explorer.perawallet.app/tx/UJG3NVCSCW5A63KPV35BPAABLXMXTTEM2CVUKNS4EML3H3EYGMCQ/
        let prefixEncodedTx = Data(base64Encoded: "VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==")

        let bip44Path = (KeyContext.Address, UInt32(0), UInt32(0), UInt32(0))
        guard let pk = c?.keyGen(context: bip44Path.0, account: bip44Path.1, change: bip44Path.2, keyIndex: bip44Path.3) else { return  }
        guard let sig = c?.signAlgoTransaction(context: bip44Path.0, account: bip44Path.1, change: bip44Path.2, keyIndex: bip44Path.3, prefixEncodedTx: prefixEncodedTx!) else { return  }

        XCTAssertEqual(c?.verifyWithPublicKey(signature: sig, message: prefixEncodedTx!, publicKey: pk), true)                
        XCTAssertEqual(try TestUtils.encodeAddress(bytes: pk), "ML7IGK322ECUJPUDG6THAQ26KBSK4STG4555PCIJOZNUNNLWU3Z3ZFXITA")
    }

    func testECDH() throws {
        let aliceSeed = try Mnemonic.deterministicSeedString(from: "exact remain north lesson program series excess lava material second riot error boss planet brick rotate scrap army riot banner adult fashion casino bamboo")
        let alice = Bip32Ed25519(seed: aliceSeed)
        guard alice != nil else {
            throw NSError(domain: "Bip32Ed25519ECDHTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "Bip32Ed25519 not initialized"])
        }

        let bobSeed = try Mnemonic.deterministicSeedString(from: "identify length ranch make silver fog much puzzle borrow relax occur drum blue oval book pledge reunion coral grace lamp recall fever route carbon")
        let bob = Bip32Ed25519(seed: bobSeed)
        guard bob != nil else {
            throw NSError(domain: "Bip32Ed25519ECDHTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "Bip32Ed25519 not initialized"])
        }

        let aliceKey = alice?.keyGen(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0)
        let bobKey = bob?.keyGen(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0)

        let aliceSharedSecret = alice?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: bobKey!, meFirst: true)
        let bobSharedSecret = bob?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: aliceKey!, meFirst: false)
        
        XCTAssertNotEqual(aliceKey, bobKey)
        XCTAssertEqual(aliceSharedSecret,bobSharedSecret)
        XCTAssertEqual(aliceSharedSecret, Data([202,114,20,173,185,153,18,48,253,145,160,157,145,158,198,130,178,172,151,129,183,110,32,107,75,135,244,221,110,246,66,127]))
    
        // Reverse concatenation order

        let aliceSharedSecret2 = alice?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: bobKey!, meFirst: false)
        let bobSharedSecret2 = bob?.ECDH(context: KeyContext.Identity, account: 0, change: 0, keyIndex: 0, otherPartyPub: aliceKey!, meFirst: true)
        
        XCTAssertNotEqual(aliceSharedSecret, aliceSharedSecret2)
        XCTAssertNotEqual(bobSharedSecret, bobSharedSecret2)
        XCTAssertEqual(aliceSharedSecret2, bobSharedSecret2)
        XCTAssertEqual(aliceSharedSecret2, Data([90,215,114,148,204,139,215,147,233,41,219,196,163,237,229,68,134,255,92,129,181,253,137,142,191,244,101,46,252,253,250,26]))

        // Encrypt/Decrypt with shared secret
        let message = "Hello, World!"
        let nonce = Data([16,197,142,8,174,91,118,244,202,136,43,200,97,242,104,99,42,154,191,32,67,30,6,123])
        let ciphertext = TestUtils.cryptoSecretBoxEasy(cleartext: message, nonce: nonce, symmetricKey: aliceSharedSecret!)
        XCTAssertEqual(ciphertext, Data(hexString: "FB07303A391687989674F28A1A9B88FCA3D107227D87DADE662DFA3722"))
        XCTAssertEqual(ciphertext, Data([251,7,48,58,57,22,135,152,150,116,242,138,26,155,136,252,163,209,7,34,125,135,218,222,102,45,250,55,34]))

        let cleartext = TestUtils.cryptoSecretBoxOpenEasy(ciphertext: ciphertext, nonce: nonce, symmetricKey: aliceSharedSecret!)
        XCTAssertEqual(cleartext, message)
    }
}
