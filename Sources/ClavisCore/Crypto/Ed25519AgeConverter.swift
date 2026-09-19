import Foundation
import CryptoKit

public struct Ed25519AgeConverter {
    // Converts 32-byte Ed25519 seed to 32-byte X25519 KeyAgreement PrivateKey
    public static func ed25519SeedToX25519PrivateKey(seed: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
        guard seed.count == 32 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid seed length"])
        }

        var seedCopy = seed
        defer {
            seedCopy.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    memset_s(baseAddress, ptr.count, 0, ptr.count)
                }
            }
        }
        
        let hash = SHA512.hash(data: seedCopy)
        var clamped = Array(hash.prefix(32))
        defer {
            for i in 0..<clamped.count {
                clamped[i] = 0
            }
        }
        
        clamped[0] &= 248
        clamped[31] &= 127
        clamped[31] |= 64

        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(clamped))
    }

    // Converts Ed25519 public key (32 bytes) to X25519 public key (32 bytes)
    // using birational equivalence u = (1 + y) / (1 - y) mod (2^255 - 19)
    public static func ed25519PublicKeyToX25519PublicKey(ed25519PubKey: Data) -> Data? {
        guard ed25519PubKey.count == 32 else { return nil }

        var yBytes = Array(ed25519PubKey)
        yBytes[31] &= 0x7F // Clear sign bit of x to get y

        let y0 = UInt64(yBytes[0]) | (UInt64(yBytes[1]) << 8) | (UInt64(yBytes[2]) << 16) | (UInt64(yBytes[3]) << 24) |
                 (UInt64(yBytes[4]) << 32) | (UInt64(yBytes[5]) << 40) | (UInt64(yBytes[6]) << 48) | (UInt64(yBytes[7]) << 56)
        let y1 = UInt64(yBytes[8]) | (UInt64(yBytes[9]) << 8) | (UInt64(yBytes[10]) << 16) | (UInt64(yBytes[11]) << 24) |
                 (UInt64(yBytes[12]) << 32) | (UInt64(yBytes[13]) << 40) | (UInt64(yBytes[14]) << 48) | (UInt64(yBytes[15]) << 56)
        let y2 = UInt64(yBytes[16]) | (UInt64(yBytes[17]) << 8) | (UInt64(yBytes[18]) << 16) | (UInt64(yBytes[19]) << 24) |
                 (UInt64(yBytes[20]) << 32) | (UInt64(yBytes[21]) << 40) | (UInt64(yBytes[22]) << 48) | (UInt64(yBytes[23]) << 56)
        let y3 = UInt64(yBytes[24]) | (UInt64(yBytes[25]) << 8) | (UInt64(yBytes[26]) << 16) | (UInt64(yBytes[27]) << 24) |
                 (UInt64(yBytes[28]) << 32) | (UInt64(yBytes[29]) << 40) | (UInt64(yBytes[30]) << 48) | (UInt64(yBytes[31]) << 56)

        let y = (y0, y1, y2, y3)
        let p = (0xFFFFFFFFFFFFFFED as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0x7FFFFFFFFFFFFFFF as UInt64)

        if ge(y, p) { return nil }

        let one = (1 as UInt64, 0 as UInt64, 0 as UInt64, 0 as UInt64)
        if y == one { return nil }

        let num = addModP(one, y)
        let den = subModP(one, y)

        let denInv = invModP(den)
        let u = mulModP(num, denInv)

        var uBytes = Data(capacity: 32)
        withUnsafeBytes(of: u.0.littleEndian) { uBytes.append(contentsOf: $0) }
        withUnsafeBytes(of: u.1.littleEndian) { uBytes.append(contentsOf: $0) }
        withUnsafeBytes(of: u.2.littleEndian) { uBytes.append(contentsOf: $0) }
        withUnsafeBytes(of: u.3.littleEndian) { uBytes.append(contentsOf: $0) }
        return uBytes
    }

    // Encodes public key to Bech32 age recipient string (age1clavis...)
    public static func ageRecipient(forPublicKey publicKeyData: Data) -> String {
        let hrp = "age1clavis"
        return Bech32.encode(hrp: hrp, data: publicKeyData)
    }
}

private typealias Fe25519 = (UInt64, UInt64, UInt64, UInt64)

private func ge(_ a: Fe25519, _ b: Fe25519) -> Bool {
    if a.3 != b.3 { return a.3 > b.3 }
    if a.2 != b.2 { return a.2 > b.2 }
    if a.1 != b.1 { return a.1 > b.1 }
    return a.0 >= b.0
}

private func addModP(_ a: Fe25519, _ b: Fe25519) -> Fe25519 {
    let p = (0xFFFFFFFFFFFFFFED as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0x7FFFFFFFFFFFFFFF as UInt64)

    let (r0, o0) = a.0.addingReportingOverflow(b.0)
    let (r1_tmp, o1_1) = a.1.addingReportingOverflow(b.1)
    let (r1, o1_2) = r1_tmp.addingReportingOverflow(o0 ? 1 : 0)
    let carry1 = o1_1 || o1_2

    let (r2_tmp, o2_1) = a.2.addingReportingOverflow(b.2)
    let (r2, o2_2) = r2_tmp.addingReportingOverflow(carry1 ? 1 : 0)
    let carry2 = o2_1 || o2_2

    let (r3_tmp, o3_1) = a.3.addingReportingOverflow(b.3)
    let (r3, o3_2) = r3_tmp.addingReportingOverflow(carry2 ? 1 : 0)
    let carry3 = o3_1 || o3_2

    let val = (r0, r1, r2, r3)
    if carry3 || ge(val, p) {
        let (s0, b0) = r0.subtractingReportingOverflow(p.0)
        let (s1_tmp, b1_1) = r1.subtractingReportingOverflow(p.1)
        let (s1, b1_2) = s1_tmp.subtractingReportingOverflow(b0 ? 1 : 0)
        let borrow1 = b1_1 || b1_2

        let (s2_tmp, b2_1) = r2.subtractingReportingOverflow(p.2)
        let (s2, b2_2) = s2_tmp.subtractingReportingOverflow(borrow1 ? 1 : 0)
        let borrow2 = b2_1 || b2_2

        let (s3_tmp, _) = r3.subtractingReportingOverflow(p.3)
        let (s3, _) = s3_tmp.subtractingReportingOverflow(borrow2 ? 1 : 0)

        return (s0, s1, s2, s3)
    }
    return val
}

private func subModP(_ a: Fe25519, _ b: Fe25519) -> Fe25519 {
    let p = (0xFFFFFFFFFFFFFFED as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0x7FFFFFFFFFFFFFFF as UInt64)
    if ge(a, b) {
        let (r0, b0) = a.0.subtractingReportingOverflow(b.0)
        let (r1_tmp, b1_1) = a.1.subtractingReportingOverflow(b.1)
        let (r1, b1_2) = r1_tmp.subtractingReportingOverflow(b0 ? 1 : 0)
        let borrow1 = b1_1 || b1_2

        let (r2_tmp, b2_1) = a.2.subtractingReportingOverflow(b.2)
        let (r2, b2_2) = r2_tmp.subtractingReportingOverflow(borrow1 ? 1 : 0)
        let borrow2 = b2_1 || b2_2

        let (r3_tmp, _) = a.3.subtractingReportingOverflow(b.3)
        let (r3, _) = r3_tmp.subtractingReportingOverflow(borrow2 ? 1 : 0)

        return (r0, r1, r2, r3)
    } else {
        let (pa0, c0) = a.0.addingReportingOverflow(p.0)
        let (pa1_tmp, c1_1) = a.1.addingReportingOverflow(p.1)
        let (pa1, c1_2) = pa1_tmp.addingReportingOverflow(c0 ? 1 : 0)
        let carry1 = c1_1 || c1_2

        let (pa2_tmp, c2_1) = a.2.addingReportingOverflow(p.2)
        let (pa2, c2_2) = pa2_tmp.addingReportingOverflow(carry1 ? 1 : 0)
        let carry2 = c2_1 || c2_2

        let (pa3_tmp, _) = a.3.addingReportingOverflow(p.3)
        let (pa3, _) = pa3_tmp.addingReportingOverflow(carry2 ? 1 : 0)

        let (r0, sb0) = pa0.subtractingReportingOverflow(b.0)
        let (r1_tmp, sb1_1) = pa1.subtractingReportingOverflow(b.1)
        let (r1, sb1_2) = r1_tmp.subtractingReportingOverflow(sb0 ? 1 : 0)
        let sborrow1 = sb1_1 || sb1_2

        let (r2_tmp, sb2_1) = pa2.subtractingReportingOverflow(b.2)
        let (r2, sb2_2) = r2_tmp.subtractingReportingOverflow(sborrow1 ? 1 : 0)
        let sborrow2 = sb2_1 || sb2_2

        let (r3_tmp, _) = pa3.subtractingReportingOverflow(b.3)
        let (r3, _) = r3_tmp.subtractingReportingOverflow(sborrow2 ? 1 : 0)

        return (r0, r1, r2, r3)
    }
}

private func mulModP(_ a: Fe25519, _ b: Fe25519) -> Fe25519 {
    var w = [UInt64](repeating: 0, count: 8)
    let aArr = [a.0, a.1, a.2, a.3]
    let bArr = [b.0, b.1, b.2, b.3]

    for i in 0..<4 {
        var carry: UInt64 = 0
        for j in 0..<4 {
            let (hi, lo) = aArr[i].multipliedFullWidth(by: bArr[j])
            let (s1, c1) = w[i + j].addingReportingOverflow(lo)
            let (s2, c2) = s1.addingReportingOverflow(carry)
            w[i + j] = s2
            carry = hi + (c1 ? 1 : 0) + (c2 ? 1 : 0)
        }
        w[i + 4] = carry
    }

    var h38 = [UInt64](repeating: 0, count: 5)
    var c: UInt64 = 0
    for i in 0..<4 {
        let (hi, lo) = w[i + 4].multipliedFullWidth(by: 38)
        let (s, c1) = lo.addingReportingOverflow(c)
        h38[i] = s
        c = hi + (c1 ? 1 : 0)
    }
    h38[4] = c

    let (s0, c0) = w[0].addingReportingOverflow(h38[0])
    let (s1_tmp, c1_1) = w[1].addingReportingOverflow(h38[1])
    let (s1, c1_2) = s1_tmp.addingReportingOverflow(c0 ? 1 : 0)
    let carry1 = c1_1 || c1_2

    let (s2_tmp, c2_1) = w[2].addingReportingOverflow(h38[2])
    let (s2, c2_2) = s2_tmp.addingReportingOverflow(carry1 ? 1 : 0)
    let carry2 = c2_1 || c2_2

    let (s3_tmp, c3_1) = w[3].addingReportingOverflow(h38[3])
    let (s3, c3_2) = s3_tmp.addingReportingOverflow(carry2 ? 1 : 0)
    let carry3 = c3_1 || c3_2

    let s4 = h38[4] + (carry3 ? 1 : 0)

    let (hi4, lo4) = s4.multipliedFullWidth(by: 38)
    let (r0, rc0) = s0.addingReportingOverflow(lo4)
    let (r1_tmp, rc1_1) = s1.addingReportingOverflow(hi4)
    let (r1, rc1_2) = r1_tmp.addingReportingOverflow(rc0 ? 1 : 0)
    let rcarry1 = rc1_1 || rc1_2

    let (r2_tmp, rc2_1) = s2.addingReportingOverflow(rcarry1 ? 1 : 0)
    let r2 = r2_tmp
    let rcarry2 = rc2_1

    let (r3_tmp, rc3_1) = s3.addingReportingOverflow(rcarry2 ? 1 : 0)
    let r3 = r3_tmp
    let rcarry3 = rc3_1

    var f0: UInt64
    var f1: UInt64
    var f2: UInt64
    var f3: UInt64

    if rcarry3 || (r3 >> 63 != 0) {
        let final3 = r3 & 0x7FFFFFFFFFFFFFFF
        let add19: UInt64 = 19 + (rcarry3 ? 38 : 0)
        let (n0, fc0) = r0.addingReportingOverflow(add19)
        f0 = n0
        let (n1, fc1) = r1.addingReportingOverflow(fc0 ? 1 : 0)
        f1 = n1
        let (n2, fc2) = r2.addingReportingOverflow(fc1 ? 1 : 0)
        f2 = n2
        let (n3, _) = final3.addingReportingOverflow(fc2 ? 1 : 0)
        f3 = n3
    } else {
        f0 = r0
        f1 = r1
        f2 = r2
        f3 = r3
    }

    let p = (0xFFFFFFFFFFFFFFED as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0xFFFFFFFFFFFFFFFF as UInt64, 0x7FFFFFFFFFFFFFFF as UInt64)
    let res = (f0, f1, f2, f3)
    if ge(res, p) {
        let (sub0, b0) = res.0.subtractingReportingOverflow(p.0)
        let (sub1_tmp, b1_1) = res.1.subtractingReportingOverflow(p.1)
        let (sub1, b1_2) = sub1_tmp.subtractingReportingOverflow(b0 ? 1 : 0)
        let borrow1 = b1_1 || b1_2

        let (sub2_tmp, b2_1) = res.2.subtractingReportingOverflow(p.2)
        let (sub2, b2_2) = sub2_tmp.subtractingReportingOverflow(borrow1 ? 1 : 0)
        let borrow2 = b2_1 || b2_2

        let (sub3_tmp, _) = res.3.subtractingReportingOverflow(p.3)
        let (sub3, _) = sub3_tmp.subtractingReportingOverflow(borrow2 ? 1 : 0)

        return (sub0, sub1, sub2, sub3)
    }
    return res
}

private func invModP(_ a: Fe25519) -> Fe25519 {
    let pMinus2: Fe25519 = (0xFFFFFFFFFFFFFFEB, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF)
    let pMinus2Limbs = [pMinus2.0, pMinus2.1, pMinus2.2, pMinus2.3]

    var res: Fe25519 = (1, 0, 0, 0)
    var base = a

    for i in 0..<255 {
        let limbIdx = i / 64
        let bitIdx = i % 64
        if ((pMinus2Limbs[limbIdx] >> bitIdx) & 1) != 0 {
            res = mulModP(res, base)
        }
        base = mulModP(base, base)
    }
    return res
}

// Minimal Bech32 Encoder & Decoder helper for age recipient strings
public struct Bech32 {
    public enum Bech32Error: Error, Equatable {
        case invalidCharacter
        case invalidChecksum
        case invalidLength
        case mixedCase
        case missingSeparator
        case invalidPadding
    }

    private static let alphabet = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    private static let charsetMap: [UInt8: UInt8] = {
        var map = [UInt8: UInt8]()
        for (i, char) in alphabet.enumerated() {
            map[char] = UInt8(i)
        }
        return map
    }()

    public static func encode(hrp: String, data: Data) -> String {
        let isUpper = hrp.contains { $0.isUppercase }
        let lowerHrp = hrp.lowercased()
        var checksummed = convertBits(data: Array(data), fromBits: 8, toBits: 5, pad: true) ?? []
        let chk = createChecksum(hrp: lowerHrp, values: checksummed)
        checksummed.append(contentsOf: chk)

        var result = lowerHrp + "1"
        for val in checksummed {
            result.append(Character(UnicodeScalar(alphabet[Int(val)])))
        }
        return isUpper ? result.uppercased() : result
    }

    public static func decode(bech32String: String) throws -> (hrp: String, data: Data) {
        guard !bech32String.isEmpty else { throw Bech32Error.invalidLength }

        var hasLower = false
        var hasUpper = false
        for scalar in bech32String.unicodeScalars {
            if scalar.value < 33 || scalar.value > 126 {
                throw Bech32Error.invalidCharacter
            }
            if UnicodeScalar("a").value...UnicodeScalar("z").value ~= scalar.value {
                hasLower = true
            } else if UnicodeScalar("A").value...UnicodeScalar("Z").value ~= scalar.value {
                hasUpper = true
            }
        }

        if hasLower && hasUpper {
            throw Bech32Error.mixedCase
        }

        guard let lastSepIndex = bech32String.lastIndex(of: "1") else {
            throw Bech32Error.missingSeparator
        }

        let rawHrp = String(bech32String[..<lastSepIndex])
        guard !rawHrp.isEmpty else { throw Bech32Error.invalidLength }

        let dataPart = String(bech32String[bech32String.index(after: lastSepIndex)...])
        guard dataPart.count >= 6 else { throw Bech32Error.invalidLength }

        let lowerHrp = rawHrp.lowercased()
        let lowerDataPart = dataPart.lowercased()

        var values5Bit = [UInt8]()
        for char in lowerDataPart.utf8 {
            guard let val = charsetMap[char] else {
                throw Bech32Error.invalidCharacter
            }
            values5Bit.append(val)
        }

        var valuesWithHrp = hrpExpand(lowerHrp)
        valuesWithHrp.append(contentsOf: values5Bit)

        if polymod(valuesWithHrp) != 1 {
            throw Bech32Error.invalidChecksum
        }

        let data5BitNoChecksum = Array(values5Bit.dropLast(6))
        guard let bytes8 = convertBits(data: data5BitNoChecksum, fromBits: 5, toBits: 8, pad: false) else {
            throw Bech32Error.invalidPadding
        }

        return (hrp: rawHrp, data: Data(bytes8))
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
        for code in hrp.lowercased().utf8 {
            ret.append(UInt8(code >> 5))
        }
        ret.append(0)
        for code in hrp.lowercased().utf8 {
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

    private static func convertBits(data: [UInt8], fromBits: Int, toBits: Int, pad: Bool) -> [UInt8]? {
        var acc = 0
        var bits = 0
        let maxv = (1 << toBits) - 1
        let max_acc = (1 << (fromBits + toBits - 1)) - 1
        var ret = [UInt8]()

        for value in data {
            if (Int(value) >> fromBits) != 0 { return nil }
            acc = ((acc << fromBits) | Int(value)) & max_acc
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
        } else {
            if bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0 {
                return nil
            }
        }
        return ret
    }
}
