//
//  MGObfuscator.swift
//  MGObfuscator
//
//  Created by Gupta, Mrigank on 13/09/18.
//  Copyright © 2018 Gupta, Mrigank. All rights reserved.
//

import Foundation
import CommonCrypto
/* for previous release, CommonCrypto is not shipped as a framework. So it needs to integrated for previous
 release
https://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework
*/
// A thin wrapper arround interfacing
public enum CrypticAlgo {
    case AlgoAES
    case AlgoDES

    func blockSize() -> Int {
        switch self {
        case .AlgoAES:
            return kCCBlockSizeAES128
        case .AlgoDES:
            return kCCBlockSizeDES
        }
    }

    func keySize() -> size_t {
        switch self {
        case .AlgoAES:
            return kCCKeySizeAES128
        case .AlgoDES:
            return kCCKeySizeDES
        }
    }

    func algo() -> UInt32 {
        switch self {
        case .AlgoAES:
            return CCAlgorithm(kCCAlgorithmAES)
        case .AlgoDES:
            return CCAlgorithm(kCCAlgorithmDES)
        }
    }
}

public final class MGObfuscate {

    private var ivData: [UInt8]?
    private var derivedKey: Data?
    private let crypticAlgo: CrypticAlgo

    public init(password: String, salt: String, algo: CrypticAlgo) {
        //Quickly get the data to release the password string
        let passwordData = password.data(using: .utf8)!
        //
        // Rounds require for 1 sec delay in generating hash.
        // Salt is a public attribute. If attacker somehow get the drivedKey and try to crack
        // the password via brute force, The delay due to Rounds will make it frustrating
        // to get actual password and deter his/her efforts.
        //
        let rounds = CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password.count,
                                      salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), Int(CC_SHA256_DIGEST_LENGTH), 1000)

        let saltData = salt.data(using: .utf8)!
        derivedKey = MGObfuscate.derivedKey(for: passwordData,
                                             saltData: saltData, rounds: rounds)
        self.crypticAlgo = algo
        var ivData = [UInt8](repeating: 0, count: algo.blockSize())
        // Random criptographically secure bytes for initialisation Vector
        let rStatus = SecRandomCopyBytes(kSecRandomDefault, ivData.count, &ivData)
        self.ivData = ivData
        //        print(ivData)
        guard rStatus == errSecSuccess else {
            fatalError("seed not generated \(rStatus)")
        }
    }

    @inline(__always) private static func derivedKey(for passwordData: Data, saltData: Data, rounds: UInt32) -> Data {
        var derivedData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        let result = derivedData.withUnsafeMutableBytes { (drivedBytes: UnsafeMutablePointer<UInt8>?) in
            passwordData.withUnsafeBytes({ (passwordBytes: UnsafePointer<Int8>!) in
                saltData.withUnsafeBytes({ (saltBytes: UnsafePointer<UInt8>!) in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordBytes, passwordData.count, saltBytes, saltData.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds, drivedBytes, Int(CC_SHA256_DIGEST_LENGTH))
                })
            })
        }
        if kCCSuccess != result {
            fatalError("failed to generate hash for password")
        }
        return derivedData
    }

    private func runCryptic(operation: Int, inputData: Data, keyData: Data, ivData: Data) -> Data {
        let cryptLength = size_t(inputData.count + crypticAlgo.blockSize())
        var cryptData = Data(count: cryptLength)
        let keyLength = crypticAlgo.keySize()

        var bytesProcessed: size_t = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            inputData.withUnsafeBytes { dataBytes in
                keyData.withUnsafeBytes { keyBytes in
                    ivData.withUnsafeBytes{ ivBytes in
                        CCCrypt(CCOperation(operation),
                                crypticAlgo.algo(),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, inputData.count,
                                cryptBytes, cryptLength,
                                &bytesProcessed)
                    }
                }
            }
        }
        if cryptStatus == CCCryptorStatus(kCCSuccess) {
            cryptData.removeSubrange(bytesProcessed..<cryptData.count)
        } else {
            fatalError("Error: \(cryptStatus)")
        }
        return cryptData
    }

    public func encriptAndPurge(inputString: inout String?) -> Data? {
        if let inputdata = inputString?.data(using: .utf8) {
            inputString = nil
            return runCryptic(operation: kCCEncrypt, inputData: inputdata, keyData: derivedKey!, ivData: Data(bytes: ivData!))
        }
        return nil
    }

    public func encript(inputString: String) -> Data {
        let inputdata = inputString.data(using: .utf8)!
        return runCryptic(operation: kCCEncrypt, inputData: inputdata, keyData: derivedKey!, ivData: Data(bytes: ivData!))
    }

    public func decript(data: Data, result: (String) -> Void) {
        let data = runCryptic(operation: kCCDecrypt, inputData: data, keyData: derivedKey!, ivData: Data(bytes: ivData!))
        result(String(data: data, encoding: .utf8)!)
    }

    public func purge() {
        ivData = nil
        derivedKey = nil
    }
}
