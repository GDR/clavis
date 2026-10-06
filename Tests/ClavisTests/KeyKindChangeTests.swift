import XCTest
import LocalAuthentication
@testable import ClavisCore

final class KeyKindChangeTests: ClavisBaseTestCase {

    private struct RejectingAuthenticator: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
            throw LAError(.authenticationFailed)
        }

        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
            throw LAError(.authenticationFailed)
        }
    }

    func test_005_AC5_changeKindRequiresUserPresence() async throws {
        let auth = CountingAuthenticator()
        let cache = makeSessionCache()
        let keyManager = makeKeyManager(sessionCache: cache, authenticator: auth)

        let key = try keyManager.generateKey(label: "presence-test", keyPurpose: .general)

        // Unlock key into session cache
        try await keyManager.unlock(label: key.label)
        XCTAssertEqual(auth.authenticationCount, 1)
        XCTAssertTrue(cache.isKeyUnlocked(label: key.label))

        // Change kind must require fresh authentication even though key is in session cache
        try keyManager.changeKind(label: key.label, to: .agent)
        XCTAssertEqual(auth.authenticationCount, 2, "changeKind must require fresh user presence authentication")

        // Verifies the key was also revoked from the session cache
        XCTAssertFalse(cache.isKeyUnlocked(label: key.label))
    }

    func test_005_AC5_changeKindAuthFailureLeavesKeyUnchanged() throws {
        let recorder = InMemoryAuditRecorder()
        let keyStore = InMemoryPrivateKeyStore()
        let initialManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache(),
            secureBufferFactory: { data in SecureBuffer(consuming: &data) },
            agentGrantRevoker: { _ in },
            auditRecorder: recorder
        )

        let key = try initialManager.generateKey(label: "auth-fail-test", keyPurpose: .general)

        // Create manager with rejecting authenticator
        let failingManager = KeychainManager(
            authenticator: RejectingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache(),
            secureBufferFactory: { data in SecureBuffer(consuming: &data) },
            agentGrantRevoker: { _ in },
            auditRecorder: recorder
        )

        XCTAssertThrowsError(try failingManager.changeKind(label: key.label, to: .agent))

        // Index remains unchanged
        let fetchedKey = try initialManager.fetchKeyInfo(label: key.label)
        XCTAssertEqual(fetchedKey?.purpose, .general)

        // Record in store remains unchanged
        guard let rawData = try keyStore.load(label: key.label, context: LAContext(), prompt: "") else {
            XCTFail("Record not found in keyStore")
            return
        }
        let record = try StoredPrivateKeyRecord.decode(from: rawData)
        XCTAssertEqual(record.purpose, .general)

        // Audit log records denied / authenticationFailed
        let changeEvents = recorder.events.filter { $0.type == .keyKindChange }
        XCTAssertEqual(changeEvents.count, 1)
        let event = changeEvents[0]
        XCTAssertEqual(event.result, .denied)
        XCTAssertEqual(event.reason, .authenticationFailed)
        XCTAssertEqual(event.keyKind, .agent)
        XCTAssertEqual(event.keyFingerprint, key.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, key.label)
    }

    func test_005_T4_changeKindUpdatesRecordAndIndex() throws {
        let keyStore = InMemoryPrivateKeyStore()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache(),
            secureBufferFactory: { data in SecureBuffer(consuming: &data) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try keyManager.generateKey(label: "roundtrip-test", keyPurpose: .general)
        XCTAssertEqual(key.purpose, .general)

        // Change .general -> .agent
        try keyManager.changeKind(label: key.label, to: .agent)

        // Check index
        let keysAfterFirst = try keyManager.listKeys()
        let matchingFirst = keysAfterFirst.first { $0.label == key.label }
        XCTAssertEqual(matchingFirst?.purpose, .agent)

        // Check decoded record
        guard let rawDataFirst = try keyStore.load(label: key.label, context: LAContext(), prompt: "") else {
            XCTFail("Record not found in keyStore")
            return
        }
        let recordFirst = try StoredPrivateKeyRecord.decode(from: rawDataFirst)
        XCTAssertEqual(recordFirst.purpose, .agent)

        // Change .agent -> .general
        try keyManager.changeKind(label: key.label, to: .general)

        // Check index
        let keysAfterSecond = try keyManager.listKeys()
        let matchingSecond = keysAfterSecond.first { $0.label == key.label }
        XCTAssertEqual(matchingSecond?.purpose, .general)

        // Check decoded record
        guard let rawDataSecond = try keyStore.load(label: key.label, context: LAContext(), prompt: "") else {
            XCTFail("Record not found in keyStore")
            return
        }
        let recordSecond = try StoredPrivateKeyRecord.decode(from: rawDataSecond)
        XCTAssertEqual(recordSecond.purpose, .general)
    }

    func test_005_T4_gitOnlyCannotChangeKind() throws {
        let auth = CountingAuthenticator()
        let keyManager = makeKeyManager(authenticator: auth)

        let key = try keyManager.generateKey(label: "git-only-test", keyPurpose: .gitSigningOnly)

        // Attempting to change to .agent must throw kindChangeNotAllowed without prompt
        XCTAssertThrowsError(try keyManager.changeKind(label: key.label, to: .agent)) { error in
            XCTAssertEqual(error as? KeyPurposeError, .kindChangeNotAllowed)
        }

        // Attempting to change to .general must throw kindChangeNotAllowed without prompt
        XCTAssertThrowsError(try keyManager.changeKind(label: key.label, to: .general)) { error in
            XCTAssertEqual(error as? KeyPurposeError, .kindChangeNotAllowed)
        }

        XCTAssertEqual(auth.authenticationCount, 0, "No authentication prompt should occur for gitSigningOnly key")
    }

    func test_005_T4_changeKindRecordsAudit() throws {
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(auditRecorder: recorder)

        let key = try keyManager.generateKey(label: "audit-test", keyPurpose: .general)

        try keyManager.changeKind(label: key.label, to: .agent)

        let changeEvents = recorder.events.filter { $0.type == .keyKindChange }
        XCTAssertEqual(changeEvents.count, 1)
        let event = changeEvents[0]
        XCTAssertEqual(event.result, .allowed)
        XCTAssertEqual(event.keyKind, .agent)
        XCTAssertEqual(event.keyFingerprint, key.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, key.label)
    }

    func test_005_T4_indexWriteFailureRollsBackRecord() throws {
        let keyStore = InMemoryPrivateKeyStore()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache(),
            secureBufferFactory: { data in SecureBuffer(consuming: &data) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try keyManager.generateKey(label: "rollback-test", keyPurpose: .general)

        PublicKeyStore.forcedSaveErrorForTesting = NSError(domain: "test", code: 999, userInfo: nil)
        defer { PublicKeyStore.forcedSaveErrorForTesting = nil }

        XCTAssertThrowsError(try keyManager.changeKind(label: key.label, to: .agent))

        // Index remains .general
        let fetchedKey = try keyManager.fetchKeyInfo(label: key.label)
        XCTAssertEqual(fetchedKey?.purpose, .general)

        // Keychain record was rolled back to .general
        guard let rawData = try keyStore.load(label: key.label, context: LAContext(), prompt: "") else {
            XCTFail("Record not found in keyStore")
            return
        }
        let record = try StoredPrivateKeyRecord.decode(from: rawData)
        XCTAssertEqual(record.purpose, .general, "Keychain record should be rolled back to general")

        // Vault record was rolled back to .general
        let vaultRecord = try EncryptedVaultStore.shared.loadRecord(label: key.label)
        XCTAssertEqual(vaultRecord?.purpose, .general, "Vault record should be rolled back to general")
    }
}
