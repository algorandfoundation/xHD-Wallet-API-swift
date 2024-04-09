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
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "bip32-ed25519-swift",
            targets: ["bip32-ed25519-swift"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/algorandfoundation/swift-sodium-full.git", branch:("master")),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.2.1"),
        .package(url: "https://github.com/Electric-Coin-Company/MnemonicSwift.git", from: "2.2.4"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "bip32-ed25519-swift",
            dependencies: [
                .product(name: "Sodium", package: "swift-sodium-full"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "MnemonicSwift", package: "MnemonicSwift"),
                ]),
        .testTarget(
            name: "bip32-ed25519-swiftTests",
            dependencies: ["bip32-ed25519-swift"]),
    ]
)
