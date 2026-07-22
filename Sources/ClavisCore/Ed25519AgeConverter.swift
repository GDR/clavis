import Foundation
import CryptoKit

public struct Ed25519AgeConverter {
    // Converts 32-byte Ed25519 seed to 32-byte X25519 KeyAgreement PrivateKey
    public static func ed25519SeedToX25519PrivateKey(seed: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
        guard seed.count == 32 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid seed length"])
        }
        
        let hash = SHA512.hash(data: seed)
        var clamped = Array(hash.prefix(32))
        
        clamped[0] &= 248
        clamped[31] &= 127
        clamped[31] |= 64

        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(clamped))
    }

    // Encodes public key to Bech32 age recipient string (age1clavis...)
    public static func ageRecipient(forPublicKey publicKeyData: Data) -> String {
        let hrp = "age1clavis"
        return Bech32.encode(hrp: hrp, data: publicKeyData)
    }
}

// Minimal Bech32 Encoder helper for age recipient strings
public struct Bech32 {
    private static let alphabet = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)

    public static func encode(hrp: String, data: Data) -> String {
        var checksummed = convertBits(data: Array(data), fromBits: 8, toBits: 5, pad: true)
        let chk = createChecksum(hrp: hrp, values: checksummed)
        checksummed.append(contentsOf: chk)

        var result = hrp + "1"
        for val in checksummed {
            result.append(Character(UnicodeScalar(alphabet[Int(val)])))
        }
        return result
    }

    private static func createChecksum(hrp: String, values: [UInt8]) -> [UInt8] {
        var valuesWithHrp = hrpExpand(hrp)
        valuesWithHrp.append(contentsOf: values)
        valuesWithHrp.append(contentsOf: [0, 0, 0, 0, 0, 0])
        let mod = polymod(valuesWithHrp) ^ 1
        var ret = [UInt8]()
        for i in 0..<6 {
            ret.append(UInt8((mod >> (5 * (5 - i))) & 31))
        }
        return ret
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var ret = [UInt8]()
        for code in hrp.utf8 {
            ret.append(UInt8(code >> 5))
        }
        ret.append(0)
        for code in hrp.utf8 {
            ret.append(UInt8(code & 31))
        }
        return ret
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let generator: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        var chk: UInt32 = 1
        for val in values {
            let top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ UInt32(val)
            for i in 0..<5 {
                if ((top >> i) & 1) != 0 {
                    chk ^= generator[i]
                }
            }
        }
        return chk
    }

    private static func convertBits(data: [UInt8], fromBits: Int, toBits: Int, pad: Bool) -> [UInt8] {
        var acc = 0
        var bits = 0
        let maxv = (1 << toBits) - 1
        var ret = [UInt8]()

        for value in data {
            acc = (acc << fromBits) | Int(value)
            bits += fromBits
            while bits >= toBits {
                bits -= toBits
                ret.append(UInt8((acc >> bits) & maxv))
            }
        }

        if pad {
            if bits > 0 {
                ret.append(UInt8((acc << (toBits - bits)) & maxv))
            }
        }
        return ret
    }
}
