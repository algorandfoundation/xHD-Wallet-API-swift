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

    func testDerivedNonHardened() throws {

        let kl = Data([168,186,128,2,137,34,217,252,250,5,92,120,174,222,85,181,197,117,188,216,213,165,49,104,237,244,95,54,217,236,143,70])
        let cc = Data([121,107,146,6,236,48,225,66,233,75,121,10,152,128,91,249,153,4,43,85,4,105,99,23,78,230,206,226,208,55,89,70])

        let expectedZZ = Data([79,57,235,234,215,9,72,57,157,32,34,226,81,95,29,115,250,66,232,187,16,193,209,254,140,127,122,242,224,69,122,166,31,223,82,170,49,164,3,115,96,128,159,63,116,37,118,15,167,94,148,38,50,10,126,70,3,86,36,78,199,91,146,54])
        let expectedCCC = Data([98,42,235,140,228,232,27,136,136,143,220,220,32,187,77,47,254,209,231,13,224,226,108,113,167,234,93,101,160,32,37,152,216,141,148,178,77,222,78,201,150,148,186,65,223,76,237,113,104,229,170,167,224,222,193,99,251,94,222,14,82,185,232,206])
        
        let (z: Data, childChainCode: Data) = c!.derivedNonHardened(kl: kl, cc: cc, index: 0)
    }

    func testKeyGeneration() throws {
        let pk = [UInt8]((c?.keyGen(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0))!)
        print(pk)
    }
}