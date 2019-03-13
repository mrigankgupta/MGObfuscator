# MGObfuscator

When we are working on apps which have lot of sensitive information (like Banking etc). We should be a lot of careful about strings. There is nice write up why (https://www.raywenderlich.com/2666-ios-app-security-and-analysis-part-1-2).

To prevent leaking of potentially sensitive data, it is not a good idea that certain strings be stored in the app's
memory in plain text longer than they need to be.
I want to create an obfuscation wrapper for strings. The purpose of such wrapper is to
prevent sensitive data from being present in memory in unobfuscated form all the time. It will be passed to classes and
functions where a string would normally be passed and when a wrapper is destroyed, the underlying obfuscated data must be completely purged from memory. it is also possible to use different obfuscation algorithms

Target MGObfuscate needs to be selected and build before running playground or Test target.
Project will only compile with Xcode 10 as it is using CommonCrpto which is not shipped in former versions.
I have not compiled CommonCrpto (I might do it later). Follow this link for compiling for previous versions (https://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework) 

Working:
When user enters a pin/passcode, as an initialiser we will provide a salt and algorithm type. It quickly takes password and generate DrivedKey (Salted stretched Hash from PBKDF2). We can always save this in keychain if we don't want user to enter pin again (generally not in case of banking app).

Encrypt Function:
public func encriptAndPurge(inputString: inout String) -> Data 
It takes inout parameter and quickly provide a encrypted data from derivedkey. Original string is erased after encryption.

Decrypt Function:
public func decript(data: Data, result: (String) -> Void) 
It provides a callback with decrypted string. the scope of string is limited to Clouser. For further use user has to save it to some variable.
