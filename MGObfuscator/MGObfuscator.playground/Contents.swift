import Foundation
import CommonCrypto

class MGObfuscator {

    private var ivData = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
    private var keyData: Data

    init(password: String) {
        keyData = password.data(using: .utf8)!
    }

    func aesEncription(inputData: Data, keyData: Data, ivData: Data, operation: Int) -> Data {
        let cryptLength = size_t(inputData.count + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        let keyLength = size_t(kCCKeySizeAES128)

        var bytesProcessed: size_t = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            inputData.withUnsafeBytes { dataBytes in
                keyData.withUnsafeBytes { keyBytes in
                    ivData.withUnsafeBytes{ ivBytes in
                        CCCrypt(CCOperation(operation),
                                CCAlgorithm(kCCAlgorithmAES),
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

    func encript(inputString: String) -> Data {
        let inputdata = inputString.data(using: .utf8)!
        return aesEncription(inputData: inputdata, keyData: keyData, ivData: Data(bytes: ivData), operation: kCCEncrypt)
    }

    func decript(data: Data, result: (String) -> Void) {
        let data = aesEncription(inputData: data, keyData: keyData, ivData: Data(bytes: ivData), operation: kCCDecrypt)
        result(String(data: data, encoding: .utf8)!)
    }
}

let obfs = MGObfuscator(password: "password")

let encrpted = obfs.encript(inputString: "Mrigank")

obfs.decript(data: encrpted) { (decripted) in
    print(decripted)
}
