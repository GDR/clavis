import XCTest
import Security
import LocalAuthentication
@testable import ClavisCore

final class KeychainManagerTests: ClavisBaseTestCase {

    private final class FailingProtectionPrivateKeyStore: PrivateKeyStoring {
        var saveCallCount = 0
        func contains(label: String) -> Bool { false }
        func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags) throws {
            saveCallCount += 1
            throw PrivateKeyStoreError.protectionUnavailable(errSecMissingEntitlement)
        }
        func load(label: String, context: LAContext, prompt: String) throws -> Data? { nil }
        func remove(label: String, context: LAContext?, prompt: String) throws {}
    }

    private final class RejectingAuthenticator: UserAuthenticating {
        enum AuthError: LocalizedError {
            case denied
            var errorDescription: String? { "Authentication rejected" }
        }
        var promptCount = 0
        func authenticate(reason: String, policy: LAPolicy) throws -> LAContext {
            promptCount += 1
            throw AuthError.denied
        }
        func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext {
            promptCount += 1
            throw AuthError.denied
        }
    }

    func testGenerateKeyFailsClosedWhenPrivateKeyStoreThrowsProtectionUnavailable() throws {
        let store = FailingProtectionPrivateKeyStore()
        let manager = makeKeyManager(privateKeyStore: store)
        let label = "test-fail-closed-\(UUID().uuidString)"

        XCTAssertThrowsError(try manager.generateKey(label: label)) { error in
            guard case PrivateKeyStoreError.protectionUnavailable(let status) = error else {
                return XCTFail("Expected PrivateKeyStoreError.protectionUnavailable, got \(error)")
            }
            XCTAssertEqual(status, errSecMissingEntitlement)
        }

        XCTAssertEqual(store.saveCallCount, 1)
        XCTAssertNil(try manager.fetchKeyInfo(label: label))
        XCTAssertFalse(PublicKeyStore.loadAll().contains { $0.label == label })
        XCTAssertFalse(EncryptedVaultStore.shared.containsRecord(label: label))
    }

    func testDeleteKeyRequiresAuthenticationBeforeModifyingStores() throws {
        let inMemoryStore = InMemoryPrivateKeyStore()
        let audit = InMemoryAuditRecorder()
        let allowingManager = makeKeyManager(authenticator: AllowingAuthenticator(), privateKeyStore: inMemoryStore, auditRecorder: audit)
        let label = "test-del-auth-\(UUID().uuidString)"

        let keyInfo = try allowingManager.generateKey(label: label)
        XCTAssertNotNil(try allowingManager.fetchKeyInfo(label: label))
        XCTAssertTrue(inMemoryStore.contains(label: label))

        let rejectingAuth = RejectingAuthenticator()
        let rejectingManager = makeKeyManager(authenticator: rejectingAuth, privateKeyStore: inMemoryStore, auditRecorder: audit)

        XCTAssertThrowsError(try rejectingManager.deleteKey(label: label)) { error in
            XCTAssertEqual(error as? RejectingAuthenticator.AuthError, .denied)
        }

        XCTAssertEqual(rejectingAuth.promptCount, 1)
        // Verify stores were NOT modified when authentication was denied
        XCTAssertNotNil(try rejectingManager.fetchKeyInfo(label: label), "PublicKeyStore must not be deleted when auth fails")
        XCTAssertTrue(inMemoryStore.contains(label: label), "PrivateKeyStore must not be deleted when auth fails")

        let lastEvent = audit.events.last
        XCTAssertEqual(lastEvent?.type, .keyDelete)
        XCTAssertEqual(lastEvent?.result, .denied)
        XCTAssertEqual(lastEvent?.keyFingerprint, keyInfo.fingerprint)

        // Now authenticate successfully and ensure deletion succeeds
        try allowingManager.deleteKey(label: label)
        XCTAssertNil(try allowingManager.fetchKeyInfo(label: label))
        XCTAssertFalse(inMemoryStore.contains(label: label))
    }
}
