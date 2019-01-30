//
//  MGObfuscateTests.swift
//  MGObfuscateTests
//
//  Created by Gupta, Mrigank on 26/09/18.
//  Copyright © 2018 Gupta, Mrigank. All rights reserved.
//

import XCTest
import MGObfuscate

class MGObfuscateTests: XCTestCase {

    var obfsDES: MGObfuscate!
    var obfsAES: MGObfuscate!

    override func setUp() {
        super.setUp()
        obfsDES = MGObfuscate(password: "UserPinXXXX", salt: String(describing: MGObfuscate.self),
                          algo: .AlgoDES)
        obfsAES = MGObfuscate(password: "OtherUserPinXXXX", salt: String(describing: MGObfuscate.self),
                              algo: .AlgoAES)
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testDESAlgo() {
        var testString: String? = "Mrigank"
        let encrpted = obfsDES.encriptAndPurge(inputString: &testString)
        if let encrpted = encrpted {
            obfsDES.decript(data: encrpted) { (decripted) in
                XCTAssertEqual(decripted, "Mrigank")
            }
        }
        XCTAssertNotEqual(testString, "Mrigank")
    }

    func testAESAlgo() {
        var testString: String? = "Gupta"
        let encrpted = obfsAES.encriptAndPurge(inputString: &testString)
        if let encrpted = encrpted {
            obfsAES.decript(data: encrpted) { (decripted) in
                XCTAssertEqual(decripted, "Gupta")
            }
        }
        XCTAssertNotEqual(testString, "Gupta")
    }
    
}
