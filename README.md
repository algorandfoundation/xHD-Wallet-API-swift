# ed25519-bip32-swift

Swift implementation of BIP32 Ed25519

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
