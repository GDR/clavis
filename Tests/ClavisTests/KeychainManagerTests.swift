import Testing
import Foundation
import Security
import LocalAuthentication
@testable import ClavisCore

@Suite struct KeychainManagerTests {

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

    @Test func testGenerateKeyFailsClosedWhenPrivateKeyStoreThrowsProtectionUnavailable() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = FailingProtectionPrivateKeyStore()
            let manager = fixture.makeKeyManager(privateKeyStore: store)
            let label = "test-fail-closed-\(UUID().uuidString)"

            #expect {
                try manager.generateKey(label: label)
            } throws: { error in
                guard case PrivateKeyStoreError.protectionUnavailable(let status) = error else {
                    return false
                }
                return status == errSecMissingEntitlement
            }

            #expect(store.saveCallCount == 1)
            let fetched = try manager.fetchKeyInfo(label: label)
            #expect(fetched == nil)
            #expect(!PublicKeyStore.loadAll().contains { $0.label == label })
            #expect(!EncryptedVaultStore.shared.containsRecord(label: label))
        }
    }

    @Test func testDeleteKeyRequiresAuthenticationBeforeModifyingStores() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let inMemoryStore = InMemoryPrivateKeyStore()
            let audit = InMemoryAuditRecorder()
            let allowingManager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), privateKeyStore: inMemoryStore, auditRecorder: audit)
            let label = "test-del-auth-\(UUID().uuidString)"

            let keyInfo = try allowingManager.generateKey(label: label)
            let allowingFetched = try allowingManager.fetchKeyInfo(label: label)
            #expect(allowingFetched != nil)
            #expect(inMemoryStore.contains(label: label))

            let rejectingAuth = RejectingAuthenticator()
            let rejectingManager = fixture.makeKeyManager(authenticator: rejectingAuth, privateKeyStore: inMemoryStore, auditRecorder: audit)

            #expect {
                try rejectingManager.deleteKey(label: label)
            } throws: { error in
                error as? RejectingAuthenticator.AuthError == .denied
            }

            #expect(rejectingAuth.promptCount == 1)
            // Verify stores were NOT modified when authentication was denied
            let rejectingFetched = try rejectingManager.fetchKeyInfo(label: label)
            #expect(rejectingFetched != nil, "PublicKeyStore must not be deleted when auth fails")
            #expect(inMemoryStore.contains(label: label), "PrivateKeyStore must not be deleted when auth fails")

            let lastEvent = audit.events.last
            #expect(lastEvent?.type == .keyDelete)
            #expect(lastEvent?.result == .denied)
            #expect(lastEvent?.keyFingerprint == keyInfo.fingerprint)

            // Now authenticate successfully and ensure deletion succeeds
            try allowingManager.deleteKey(label: label)
            let afterDelete = try allowingManager.fetchKeyInfo(label: label)
            #expect(afterDelete == nil)
            #expect(!inMemoryStore.contains(label: label))
        }
    }
}
