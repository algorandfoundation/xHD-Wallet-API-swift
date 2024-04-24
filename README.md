# BIP32-Ed25519-Swift

A Swift implementation of ARC-0052 Algorand, in accordance with the paper BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace.

Note that this library has NOT undergone audit and is NOT recommended for production use.

## Generating Keys

To initialize a wallet (using MnemmonicSwift for BIP-39 support) from a seed phrase:

```swift
import bip32_ed25519_swift
import MnemonicSwift
let seed = try Mnemonic.deterministicSeedString(from: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice")
let c = Bip32Ed25519(seed: seed)
```

Now you can generate keys using a BIP-44 derivation path:

```swift
let pk = c.keyGen(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0)
```

To sign an Algorand transaction, you can use the signAlgoTransaction.

```swift
let prefixEncodedTx = Data(base64Encoded: "VFiJo2FtdM0D6KNmZWXNA+iiZnbOAkeSd6NnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds4CR5Zfo3JjdsQgYv6DK3rRBUS+gzemcENeUGSuSmbne9eJCXZbRrV2pvOjc25kxCBi/oMretEFRL6DN6ZwQ15QZK5KZud714kJdltGtXam86R0eXBlo3BheQ==")
let sig = c.signAlgoTransaction(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0, prefixEncodedTx: prefixEncodedTx)
```

Where prefixEncodedTx is a transaction that has been compiled with the SDK's transaction builder. The signature returned can be verified against the public key:

```swift
let pk = c.keyGen(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0)
let result = c.verifyWithPublicKey(signature: sig, message: prefixEncodedTx, publicKey: pk)
```

It is also possible to sign arbitrary data. You need to specify a JSON scehma and encoding type (none, base64, msgpack).

For example (with schema under "schemas/auth.request.json"):

```swift
let schema = try JSONSerialization.jsonObject(with: try Data(contentsOf: URL(fileURLWithPath: #file).deletingLastPathComponent().appendingPathComponent("schemas/auth.request.json")), options: []) as! [String: Any]
let challengeJSON = """
    {
        "0": 28, "1": 103, "2": 26, "3": 222, "4": 7, "5": 86, "6": 55, "7": 95,
        "8": 197, "9": 179, "10": 249, "11": 252, "12": 232, "13": 252, "14": 176,
        "15": 39, "16": 112, "17": 131, "18": 52, "19": 63, "20": 212, "21": 58,
        "22": 226, "23": 89, "24": 64, "25": 94, "26": 23, "27": 91, "28": 128,
        "29": 143, "30": 123, "31": 27
    }
    """
let sig = c.signData(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0, data: data, metadata: SignMetadata(encoding: Encoding.none, schema: schema))
let result = c.verifyWithPublicKey(signature: sig, message: Data(challengeJSON.utf8), publicKey: pk)
```

or using base64:

```swift
let challengeJSONB64 = "eyIwIjogMjgsICIxIjogMTAzLCAiMiI6IDI2LCAiMyI6IDIyMiwgIjQiOiA3LCAiNSI6IDg2LCAiNiI6IDU1LCAiNyI6IDk1LCAiOCI6IDE5NywgIjkiOiAxNzksICIxMCI6IDI0OSwgIjExIjogMjUyLCAiMTIiOiAyMzIsICIxMyI6IDI1MiwgIjE0IjogMTc2LCAiMTUiOiAzOSwgIjE2IjogMTEyLCAiMTciOiAxMzEsICIxOCI6IDUyLCAiMTkiOiA2MywgIjIwIjogMjEyLCAiMjEiOiA1OCwiMjIiOiAyMjYsICIyMyI6IDg5LCAiMjQiOiA2NCwgIjI1IjogOTQsICIyNiI6IDIzLCAiMjciOiA5MSwgIjI4IjogMTI4LCAiMjkiOiAxNDMsICIzMCI6IDEyMywgIjMxIjogMjd9"
let sig = c.signData(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0, data: data: Data(challengeJSONB64.utf8), metadata: SignMetadata(encoding: Encoding.base64, schema: schema))
let result = c.verifyWithPublicKey(signature: sig, message: Data(challengeJSONB64.utf8), publicKey: pk)
```

## License

Copyright 2024 Algorand Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
