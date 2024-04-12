# BIP32-Ed25519-Swift

A Swift implementation of ARC-0052 Algorand, in accordance with the paper BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace.

Note that this library has not undergone audit and is NOT recommended for production use.

## Generating Keys

To initialize a wallet (using MnemmonicSwift for bip39 support) from a seed phrase:

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
c.verifyWithPublicKey(signature: sig, message: prefixEncodedTx, publicKey: pk)
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
