import Foundation
import CommonCrypto

func aesEncription(inputData: Data, keyData: Data, operation: Int) -> Data {
    let cryptLength = size_t(inputData.count + kCCBlockSizeAES128)
    var cryptData = Data(count: cryptLength)
    let keyLength = size_t(kCCKeySizeAES128)

    var bytesProcessed: size_t = 0
    let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
        inputData.withUnsafeBytes {dataBytes in
            keyData.withUnsafeBytes {keyBytes in
                CCCrypt(CCOperation(operation),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes, keyLength,
                        nil,
                        dataBytes, inputData.count,
                        cryptBytes, cryptLength,
                        &bytesProcessed)
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

let encrpted = aesEncription(inputData: "Mrigank".data(using: .utf8)!,
              keyData: "password".data(using: .utf8)!, operation: kCCEncrypt)

let decrpted = aesEncription(inputData: encrpted,
                               keyData: "password".data(using: .utf8)!, operation: kCCDecrypt)
String(data: decrpted, encoding: .utf8)!
