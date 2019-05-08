//
//  PublicKey.swift
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

/// Public key protocol for any asymmetric key algorithm.
public protocol PublicKey {
    /// The algorithm name associated with this public key.
    static var algorithmName: String { get }

    /**
        Return the public key, hex encoded.

        - Returns: Hex encoded public key.
    */
    func hex() -> String

    /**
        Return the bytes underlying the public key.

        - Returns: Bytes underlying the public key.
    */
    func getBytes() -> [UInt8]
}
