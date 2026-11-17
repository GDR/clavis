import Foundation
import Testing
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite
final class WireProtocolTests {
    private let fixture: ClavisTestFixture
    private var testRootURL: URL { fixture.testRootURL }

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    private func makeKeyManager(
        authenticator: UserAuthenticating = AllowingAuthenticator(),
        privateKeyStore: PrivateKeyStoring = InMemoryPrivateKeyStore(),
        vaultStore: EncryptedVaultStore? = nil,
        auditRecorder: AuditRecording = InMemoryAuditRecorder(),
        signingProvider: SecureEnclaveSigningProviding? = nil,
        gitSigningGraceManager: GitSigningGraceManager = .shared
    ) -> KeychainManager {
        fixture.makeKeyManager(
            authenticator: authenticator,
            privateKeyStore: privateKeyStore,
            vaultStore: vaultStore,
            auditRecorder: auditRecorder,
            signingProvider: signingProvider,
            gitSigningGraceManager: gitSigningGraceManager
        )
    }

    @Test func testP256KeyInfoAndWireSerialization() throws {
        let keyManager = makeKeyManager()
        let keyInfo = try keyManager.generateKey(label: "test-github-key")

        #expect(keyInfo.label == "test-github-key")
        #expect(keyInfo.publicKeyOpenSSH.hasPrefix("ecdsa-sha2-nistp256 "))
        #expect(keyInfo.publicKeyOpenSSH.hasSuffix(" test-github-key"))
        #expect(keyInfo.fingerprint.hasPrefix("SHA256:"))
        #expect(keyInfo.algorithmName == "ECDSA P-256")
        #expect(keyInfo.storage == .secureEnclave)
    }

    @Test func testWireDataAppending() {
        var data = Data()
        data.appendWireString("ssh-ed25519")
        
        // 4 bytes big-endian length (11) + 11 bytes UTF8 string
        #expect(data.count == 15)
        #expect(data.subdata(in: 0..<4) == Data([0x00, 0x00, 0x00, 0x0B]))
        #expect(String(data: data.subdata(in: 4..<15), encoding: .utf8) == "ssh-ed25519")
    }

    @Test func testDataReaderSuccess() {
        var data = Data()
        data.appendWireString("hello")
        data.appendWireString("world")

        var reader = DataReader(data: data)
        let first = reader.readWireData()
        let second = reader.readWireData()

        #expect(first != nil)
        #expect(second != nil)
        #expect(String(data: first!, encoding: .utf8) == "hello")
        #expect(String(data: second!, encoding: .utf8) == "world")
        #expect(reader.readWireData() == nil) // EOF
    }

    @Test func testDataReaderTruncatedHeader() {
        let data = Data([0x00, 0x00]) // Only 2 bytes, needs 4
        var reader = DataReader(data: data)
        #expect(reader.readWireData() == nil)
    }

    @Test func testDataReaderTruncatedPayload() {
        var data = Data([0x00, 0x00, 0x00, 0x10]) // Header claims 16 bytes payload
        data.append(Data([0x01, 0x02, 0x03]))     // Only 3 bytes supplied
        var reader = DataReader(data: data)
        #expect(reader.readWireData() == nil)
    }

    @Test func testDataHexStringInitialization() {
        let validHex = "48656c6c6f" // "Hello"
        let data = Data(hexString: validHex)
        #expect(data != nil)
        #expect(String(data: data!, encoding: .utf8) == "Hello")

        let invalidOddHex = "12345"
        #expect(Data(hexString: invalidOddHex) == nil)

        let invalidCharHex = "123G"
        #expect(Data(hexString: invalidCharHex) == nil)
    }

    @Test func testDataReaderUInt32Parsing() {
        let data = Data([0x00, 0x00, 0x00, 0x2A]) // UInt32(42) big endian
        var reader = DataReader(data: data)
        let val = reader.readUInt32()
        #expect(val == 42)
    }

    @Test func testDataReaderUnalignedAccess() {
        var data = Data([0xFF]) // 1 byte prefix to make offset unaligned (1)
        let num: UInt32 = 0x12345678
        var bigNum = num.bigEndian
        Swift.withUnsafeBytes(of: &bigNum) { data.append(contentsOf: $0) }

        // Skip prefix byte
        let slice = data.subdata(in: 1..<data.count)
        var unalignedReader = DataReader(data: slice)
        let val = unalignedReader.readUInt32()
        #expect(val == 0x12345678)
    }

    @Test func testSSHMPintEncoding() {
        let posBytes = Data([0x12, 0x34])
        let encodedPos = KeychainManager.encodeSSHMPint(posBytes)
        // 4 bytes len (2) + 2 bytes
        #expect(encodedPos.count == 6)

        // If high bit set, must prepend 0x00
        let negBytes = Data([0x85, 0x12])
        let encodedNeg = KeychainManager.encodeSSHMPint(negBytes)
        // 4 bytes len (3) + 0x00 + 2 bytes
        #expect(encodedNeg.count == 7)
        #expect(encodedNeg[4] == 0x00)
        #expect(encodedNeg[5] == 0x85)
    }
}
