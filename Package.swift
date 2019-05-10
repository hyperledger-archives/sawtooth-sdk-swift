// swift-tools-version:4.2

import PackageDescription

let package = Package(
    name: "SawtoothSigning",
    products: [
        .library(name: "SawtoothSigning", targets: ["SawtoothSigning"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/Boilertalk/secp256k1.swift",
            from: "0.0.0"),
    ],
    targets: [
        .target(
            name: "SawtoothSigning",
            dependencies: ["secp256k1"],
            path: "SawtoothSigning"),
    ]
)
