import Foundation
import Testing
import CryptoKit
@testable import ClavisCore

@Suite
final class KeyPurposeAgentTests {
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

    @Test func test_005_T1_recordRoundTripsAgentPurpose() throws {
        let keyData = Data(repeating: 0x42, count: 32)
        let record = StoredPrivateKeyRecord(
            label: "test-agent-key",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .agent,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let encoded = try record.encode()
        #expect(encoded.starts(with: Data("CLVPKR02".utf8)))

        // Purpose byte is at offset 11:
        // magic (8) + version (1) + algorithm (1) + storage (1) = 11
        #expect(encoded[11] == 3, "Agent purpose must be encoded as byte 3")

        let decoded = try StoredPrivateKeyRecord.decode(from: encoded)
        #expect(decoded == record)
        #expect(decoded.purpose == .agent)
        #expect(decoded.keyPurpose == .agent)
    }

    @Test func test_005_T1_oldRecordsDecodeUnchanged() throws {
        let keyData = Data(repeating: 0x24, count: 32)
        let generalRecord = StoredPrivateKeyRecord(
            label: "general-key",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let encodedGeneral = try generalRecord.encode()
        #expect(encodedGeneral[11] == 1, "General purpose must be byte 1")
        let decodedGeneral = try StoredPrivateKeyRecord.decode(from: encodedGeneral)
        #expect(decodedGeneral.purpose == .general)

        let gitOnlyRecord = StoredPrivateKeyRecord(
            label: "git-key",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .gitSigningOnly,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let encodedGit = try gitOnlyRecord.encode()
        #expect(encodedGit[11] == 2, "GitSigningOnly purpose must be byte 2")
        let decodedGit = try StoredPrivateKeyRecord.decode(from: encodedGit)
        #expect(decodedGit.purpose == .gitSigningOnly)

        // Legacy v1 JSON decode is rejected
        let legacyJSON = """
        {
            "version": 1,
            "label": "legacy-key",
            "algorithm": "ECDSA P-256",
            "storageType": "Secure Enclave",
            "keyData": "\(keyData.base64EncodedString())"
        }
        """.data(using: .utf8)!
        #expect {
            try StoredPrivateKeyRecord.decode(from: legacyJSON)
        } throws: { error in
            guard case PrivateKeyRecordError.corruptedRecord = error else {
                return false
            }
            return true
        }
    }

    @Test func test_005_T1_unknownPurposeByteThrows() throws {
        let keyData = Data(repeating: 0x11, count: 32)
        let record = StoredPrivateKeyRecord(
            label: "key-unknown-purpose",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        var encoded = try record.encode()
        // Corrupt purpose byte (offset 11) to an invalid value
        encoded[11] = 99

        #expect {
            try StoredPrivateKeyRecord.decode(from: encoded)
        } throws: { error in
            guard case PrivateKeyRecordError.corruptedRecord(let reason) = error else {
                return false
            }
            return reason.contains("Unknown purpose identifier")
        }

        // Also test byte 0
        encoded[11] = 0
        #expect(throws: (any Error).self) {
            try StoredPrivateKeyRecord.decode(from: encoded)
        }

        // Also test byte 4
        encoded[11] = 4
        #expect(throws: (any Error).self) {
            try StoredPrivateKeyRecord.decode(from: encoded)
        }
    }

    @Test func test_005_T1_agentIsNotPersonal() {
        #expect(!KeyPurpose.agent.isPersonal)
        #expect(KeyPurpose.general.isPersonal)
        #expect(KeyPurpose.gitSigningOnly.isPersonal)
    }

    @Test func test_005_T1_auditKindMapping() {
        #expect(KeyPurpose.agent.auditKind == .agent)
        #expect(KeyPurpose.general.auditKind == .personal)
        #expect(KeyPurpose.gitSigningOnly.auditKind == .personal)
    }

    @Test func test_005_AC1_generateAgentKeyIsListedAsAgent() throws {
        let keyManager = makeKeyManager()
        let label = "agent-test-key-\(UUID().uuidString)"

        let info = try keyManager.generateKey(label: label, keyPurpose: .agent)
        #expect(info.purpose == .agent)
        #expect(!info.purpose.isPersonal)

        let fetched = try #require(try keyManager.fetchKeyInfo(label: label), "Failed to fetch generated key info")
        #expect(fetched.purpose == .agent)
        #expect(!fetched.purpose.isPersonal)

        let allKeys = try keyManager.listKeys()
        #expect(allKeys.contains { $0.label == label && $0.purpose == .agent })
    }

    @Test func test_005_AC2_kindFilterShowsOnlyMatchingKeys() throws {
        let keyManager = makeKeyManager()
        let generalKey = try keyManager.generateKey(label: "filter-general", keyPurpose: .general)
        let gitKey = try keyManager.generateKey(label: "filter-git", keyPurpose: .gitSigningOnly)
        let agentKey = try keyManager.generateKey(label: "filter-agent", keyPurpose: .agent)

        let allKeys = [generalKey, gitKey, agentKey]

        let allFiltered = KeyKindFilter.apply(.all, to: allKeys)
        #expect(allFiltered.count == 3)

        let personalFiltered = KeyKindFilter.apply(.personal, to: allKeys)
        #expect(personalFiltered.count == 2)
        #expect(personalFiltered.contains { $0.label == "filter-general" })
        #expect(personalFiltered.contains { $0.label == "filter-git" })
        #expect(!personalFiltered.contains { $0.label == "filter-agent" })

        let agentFiltered = KeyKindFilter.apply(.agent, to: allKeys)
        #expect(agentFiltered.count == 1)
        #expect(agentFiltered.first?.label == "filter-agent")
    }

    @Test func test_005_AC6_deployKeyIsValidOpenSSH() throws {
        let keyManager = makeKeyManager()
        let agentKey = try keyManager.generateKey(label: "deploy-key-test", keyPurpose: .agent)

        let tempFile = testRootURL.appendingPathComponent("deploy_key.pub")
        try agentKey.publicKeyOpenSSH.write(to: tempFile, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-l", "-f", tempFile.path]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        try process.run()
        process.waitUntilExit()

        #expect(process.terminationStatus == 0, "ssh-keygen -l must validate public key format successfully")

        let outputData = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: outputData, as: UTF8.self)

        let rawFingerprint = agentKey.fingerprint.replacingOccurrences(of: "SHA256:", with: "")
        #expect(
            output.contains(rawFingerprint) || output.contains(agentKey.fingerprint),
            "ssh-keygen output '\(output)' must contain key fingerprint '\(agentKey.fingerprint)'"
        )
    }
}
