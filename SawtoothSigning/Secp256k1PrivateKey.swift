//
//  Secp256k1PrivateKey.swift
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

/// Private key implementation using the secp256k1 algorithm.
public class Secp256k1PrivateKey: PrivateKey {
    /// The algorithm name associated with this private key.
    public static var algorithmName = "secp256k1"
    let privKey: [UInt8]

    init(privKey: [UInt8]) {
        self.privKey = privKey
    }

    /**
        Return a PrivateKey object from a hex encoded secp256k1 public key.

        - Returns: Secp256k1PrivateKey object.
    */
    public static func fromHex(hexPrivKey: String) -> Secp256k1PrivateKey {
        return Secp256k1PrivateKey(privKey: hexPrivKey.toBytes)
    }

    /**
        Return the private key, hex encoded.

        - Returns: Hex encoded private key.
    */
    public func hex() -> String {
        return Data(self.privKey).toHex()
    }

    /**
        Return the bytes underlying the private key.

        - Returns: Bytes underlying the private key.
    */
    public func getBytes() -> [UInt8] {
        return self.privKey
    }
}
