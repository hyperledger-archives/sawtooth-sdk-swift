//
//  Secp256k1PublicKey.swift
//  SawtoothSigning
//
//  Copyright 2018 Bitwise IO, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import Foundation

/// Public key implementation using the secp256k1 algorithm.
public class Secp256k1PublicKey: PublicKey {
    /// The algorithm name associated with this public key.
    public static var algorithmName = "secp256k1"
    let pubKey: [UInt8]

    init(pubKey: [UInt8]) {
        self.pubKey = pubKey
    }

    /**
        Return a PublicKey object from a hex encoded secp256k1 public key.

        - Returns: Secp256k1PublicKey object.
    */
    public static func fromHex(hexPubKey: String) -> Secp256k1PublicKey {
        return Secp256k1PublicKey(pubKey: hexPubKey.toBytes)
    }

    /**
        Return the public key, hex encoded.

        - Returns: Hex encoded private key.
    */
    public func hex() -> String {
        return Data(self.pubKey).toHex()
    }

    /**
        Return the bytes underlying the public key.

        - Returns: Bytes underlying the public key.
    */
    public func getBytes() -> [UInt8] {
        return self.pubKey
    }
}
