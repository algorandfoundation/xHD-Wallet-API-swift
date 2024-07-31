// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "bip32-ed25519-swift",
    platforms: [
        .iOS(.v15),
        .watchOS(.v9),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "bip32-ed25519-swift",
            targets: ["bip32-ed25519-swift"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/a2/MessagePack.swift.git", from: "4.0.0"),
        .package(url: "https://github.com/algorandfoundation/JSONSchema.swift.git", exact: "0.7.0"),
        .package(url: "https://github.com/algorandfoundation/swift-sodium-full.git", from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.1"),
        .package(url: "https://github.com/Electric-Coin-Company/MnemonicSwift.git", from: "2.2.4"),
        .package(url: "https://github.com/realm/SwiftLint", from: "0.55.0"),
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.53.9"),
        .package(url: "https://github.com/norio-nomura/Base32.git", from: "0.9.0"),
    ],
    targets: [
        .target(
            name: "bip32-ed25519-swift",
            dependencies: [
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "JSONSchema", package: "JSONSchema.swift"),
                .product(name: "MessagePack", package: "MessagePack.swift"),
                .product(name: "Sodium", package: "swift-sodium-full"),
                .product(name: "MnemonicSwift", package: "MnemonicSwift")
            ],
            plugins: [
                .plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLint"),
            ]
        ),
        .testTarget(
            name: "bip32-ed25519-swiftTests",
            dependencies: ["bip32-ed25519-swift",
                           .product(name: "MnemonicSwift", package: "MnemonicSwift"),
                           .product(name: "Base32", package: "Base32")],
            resources: [
                .process("schemas/auth.request.json"),
                .process("schemas/msg.schema.json"),
                .process("schemas/malformed.json"),
            ]
        ),
    ]
)
