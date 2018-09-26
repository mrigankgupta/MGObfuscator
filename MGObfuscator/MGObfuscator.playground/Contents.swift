import Foundation
import MGObfuscate

let obfs = MGObfuscate(password: "password", salt: String(describing: MGObfuscate.self),
                        algo: .AlgoDES)
let encrpted = obfs.encript(inputString: "Mrigank")
obfs.decript(data: encrpted) { (decripted) in
    print(decripted)
}
var surname = "Gupta"
let encrptedSurname = obfs.encriptAndPurge(inputString: &surname)
obfs.decript(data: encrptedSurname) { (decripted) in
    print(decripted)
}
print(surname)
