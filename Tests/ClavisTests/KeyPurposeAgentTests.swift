import XCTest
import CryptoKit
@testable import ClavisCore

final class KeyPurposeAgentTests: ClavisBaseTestCase {

    func test_005_T1_recordRoundTripsAgentPurpose() throws {
        let keyData = Data(repeating: 0x42, count: 32)
        let record = StoredPrivateKeyRecord(
            label: "test-agent-key",
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let encoded = try record.encode()
        XCTAssertTrue(encoded.starts(with: Data("CLVPKR02".utf8)))

        // Purpose byte is at offset 11:
        // magic (8) + version (1) + algorithm (1) + storage (1) = 11
        XCTAssertEqual(encoded[11], 3, "Agent purpose must be encoded as byte 3")

        let decoded = try StoredPrivateKeyRecord.decode(from: encoded)
        XCTAssertEqual(decoded, record)
        XCTAssertEqual(decoded.purpose, .agent)
        XCTAssertEqual(decoded.keyPurpose, .agent)
    }

    func test_005_T1_oldRecordsDecodeUnchanged() throws {
        let keyData = Data(repeating: 0x24, count: 32)
        let generalRecord = StoredPrivateKeyRecord(
            label: "general-key",
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let encodedGeneral = try generalRecord.encode()
        XCTAssertEqual(encodedGeneral[11], 1, "General purpose must be byte 1")
        let decodedGeneral = try StoredPrivateKeyRecord.decode(from: encodedGeneral)
        XCTAssertEqual(decodedGeneral.purpose, .general)

        let gitOnlyRecord = StoredPrivateKeyRecord(
            label: "git-key",
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyPurpose: .gitSigningOnly,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let encodedGit = try gitOnlyRecord.encode()
        XCTAssertEqual(encodedGit[11], 2, "GitSigningOnly purpose must be byte 2")
        let decodedGit = try StoredPrivateKeyRecord.decode(from: encodedGit)
        XCTAssertEqual(decodedGit.purpose, .gitSigningOnly)

        // Legacy v1 JSON decode without purpose defaults to .general
        let legacyJSON = """
        {
            "version": 1,
            "label": "legacy-key",
            "algorithm": "Ed25519",
            "storageType": "Login Keychain",
            "keyData": "\(keyData.base64EncodedString())"
        }
        """.data(using: .utf8)!
        let decodedLegacy = try StoredPrivateKeyRecord.decode(from: legacyJSON)
        XCTAssertEqual(decodedLegacy.purpose, .general)
    }

    func test_005_T1_unknownPurposeByteThrows() throws {
        let keyData = Data(repeating: 0x11, count: 32)
        let record = StoredPrivateKeyRecord(
            label: "key-unknown-purpose",
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        var encoded = try record.encode()
        // Corrupt purpose byte (offset 11) to an invalid value
        encoded[11] = 99

        XCTAssertThrowsError(try StoredPrivateKeyRecord.decode(from: encoded)) { error in
            guard case PrivateKeyRecordError.corruptedRecord(let reason) = error else {
                XCTFail("Expected corruptedRecord error, got: \(error)")
                return
            }
            XCTAssertTrue(reason.contains("Unknown purpose identifier"))
        }

        // Also test byte 0
        encoded[11] = 0
        XCTAssertThrowsError(try StoredPrivateKeyRecord.decode(from: encoded))

        // Also test byte 4
        encoded[11] = 4
        XCTAssertThrowsError(try StoredPrivateKeyRecord.decode(from: encoded))
    }

    func test_005_T1_agentIsNotPersonal() {
        XCTAssertFalse(KeyPurpose.agent.isPersonal)
        XCTAssertTrue(KeyPurpose.general.isPersonal)
        XCTAssertTrue(KeyPurpose.gitSigningOnly.isPersonal)
    }

    func test_005_T1_auditKindMapping() {
        XCTAssertEqual(KeyPurpose.agent.auditKind, .agent)
        XCTAssertEqual(KeyPurpose.general.auditKind, .personal)
        XCTAssertEqual(KeyPurpose.gitSigningOnly.auditKind, .personal)
    }

    func test_005_AC1_generateAgentKeyIsListedAsAgent() throws {
        let keyManager = makeKeyManager()
        let label = "agent-test-key-\(UUID().uuidString)"

        let info = try keyManager.generateKey(label: label, keyPurpose: .agent)
        XCTAssertEqual(info.purpose, .agent)
        XCTAssertFalse(info.purpose.isPersonal)

        guard let fetched = try keyManager.fetchKeyInfo(label: label) else {
            XCTFail("Failed to fetch generated key info")
            return
        }
        XCTAssertEqual(fetched.purpose, .agent)
        XCTAssertFalse(fetched.purpose.isPersonal)

        let allKeys = try keyManager.listKeys()
        XCTAssertTrue(allKeys.contains { $0.label == label && $0.purpose == .agent })
    }
}
