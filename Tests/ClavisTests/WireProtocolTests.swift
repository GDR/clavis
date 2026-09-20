import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class WireProtocolTests: ClavisBaseTestCase {

    func testEd25519KeyInfoAndWireSerialization() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let keyInfo = try makeKeyManager().makeKeyInfo(label: "test-github-key", privateKey: privateKey)

        XCTAssertEqual(keyInfo.label, "test-github-key")
        XCTAssertTrue(keyInfo.publicKeyOpenSSH.hasPrefix("ssh-ed25519 "))
        XCTAssertTrue(keyInfo.publicKeyOpenSSH.hasSuffix(" test-github-key"))
        XCTAssertTrue(keyInfo.fingerprint.hasPrefix("SHA256:"))
        XCTAssertEqual(keyInfo.publicKeyBlob.count, 51) // 4 (len) + 11 (ssh-ed25519) + 4 (len) + 32 (pubkey)
    }


    func testWireDataAppending() {
        var data = Data()
        data.appendWireString("ssh-ed25519")
        
        // 4 bytes big-endian length (11) + 11 bytes UTF8 string
        XCTAssertEqual(data.count, 15)
        XCTAssertEqual(data.subdata(in: 0..<4), Data([0x00, 0x00, 0x00, 0x0B]))
        XCTAssertEqual(String(data: data.subdata(in: 4..<15), encoding: .utf8), "ssh-ed25519")
    }


    func testDataReaderSuccess() {
        var data = Data()
        data.appendWireString("hello")
        data.appendWireString("world")

        var reader = DataReader(data: data)
        let first = reader.readWireData()
        let second = reader.readWireData()

        XCTAssertNotNil(first)
        XCTAssertNotNil(second)
        XCTAssertEqual(String(data: first!, encoding: .utf8), "hello")
        XCTAssertEqual(String(data: second!, encoding: .utf8), "world")
        XCTAssertNil(reader.readWireData()) // EOF
    }


    func testDataReaderTruncatedHeader() {
        let data = Data([0x00, 0x00]) // Only 2 bytes, needs 4
        var reader = DataReader(data: data)
        XCTAssertNil(reader.readWireData())
    }


    func testDataReaderTruncatedPayload() {
        var data = Data([0x00, 0x00, 0x00, 0x10]) // Header claims 16 bytes payload
        data.append(Data([0x01, 0x02, 0x03]))     // Only 3 bytes supplied
        var reader = DataReader(data: data)
        XCTAssertNil(reader.readWireData())
    }


    func testDataHexStringInitialization() {
        let validHex = "48656c6c6f" // "Hello"
        let data = Data(hexString: validHex)
        XCTAssertNotNil(data)
        XCTAssertEqual(String(data: data!, encoding: .utf8), "Hello")

        let invalidOddHex = "12345"
        XCTAssertNil(Data(hexString: invalidOddHex))

        let invalidCharHex = "123G"
        XCTAssertNil(Data(hexString: invalidCharHex))
    }


    func testDataReaderUInt32Parsing() {
        let data = Data([0x00, 0x00, 0x00, 0x2A]) // UInt32(42) big endian
        var reader = DataReader(data: data)
        let val = reader.readUInt32()
        XCTAssertEqual(val, 42)
    }


    func testDataReaderUnalignedAccess() {
        var data = Data([0xFF]) // 1 byte prefix to make offset unaligned (1)
        let num: UInt32 = 0x12345678
        var bigNum = num.bigEndian
        Swift.withUnsafeBytes(of: &bigNum) { data.append(contentsOf: $0) }

        // Skip prefix byte
        let slice = data.subdata(in: 1..<data.count)
        var unalignedReader = DataReader(data: slice)
        let val = unalignedReader.readUInt32()
        XCTAssertEqual(val, 0x12345678)
    }


    func testSSHMPintEncoding() {
        let posBytes = Data([0x12, 0x34])
        let encodedPos = KeychainManager.encodeSSHMPint(posBytes)
        // 4 bytes len (2) + 2 bytes
        XCTAssertEqual(encodedPos.count, 6)

        // If high bit set, must prepend 0x00
        let negBytes = Data([0x85, 0x12])
        let encodedNeg = KeychainManager.encodeSSHMPint(negBytes)
        // 4 bytes len (3) + 0x00 + 2 bytes
        XCTAssertEqual(encodedNeg.count, 7)
        XCTAssertEqual(encodedNeg[4], 0x00)
        XCTAssertEqual(encodedNeg[5], 0x85)
    }


}
