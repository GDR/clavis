import Testing
import Foundation
import LocalAuthentication
@testable import ClavisCore

@Suite(.serialized)
struct KeyKindChangeTests {

    private struct RejectingAuthenticator: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
            throw LAError(.authenticationFailed)
        }

        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
            throw LAError(.authenticationFailed)
        }
    }

    @Test func test_005_AC5_changeKindRequiresUserPresence() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let keyManager = fixture.makeKeyManager(authenticator: auth)

            let key = try keyManager.generateKey(label: "presence-test", keyPurpose: .general)

            // Change kind must require user presence authentication
            try keyManager.changeKind(label: key.label, to: .agent)
            #expect(auth.authenticationCount == 1, "changeKind must require user presence authentication")
        }
    }

    @Test func test_005_AC5_changeKindAuthFailureLeavesKeyUnchanged() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyStore = InMemoryPrivateKeyStore()
            let initialManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore,
                auditRecorder: recorder
            )

            let key = try initialManager.generateKey(label: "auth-fail-test", keyPurpose: .general)

            // Create manager with rejecting authenticator
            let failingManager = fixture.makeKeyManager(
                authenticator: RejectingAuthenticator(),
                privateKeyStore: keyStore,
                auditRecorder: recorder
            )

            #expect(throws: (any Error).self) {
                try failingManager.changeKind(label: key.label, to: .agent)
            }

            // Index remains unchanged
            let fetchedKey = try initialManager.fetchKeyInfo(label: key.label)
            #expect(fetchedKey?.keyPurpose == .general)

            // Record in store remains unchanged
            let rawData = try #require(try keyStore.load(label: key.label, context: LAContext(), prompt: ""))
            let record = try StoredPrivateKeyRecord.decode(from: rawData)
            #expect(record.keyPurpose == .general)

            // Audit log records denied / authenticationFailed
            let changeEvents = recorder.events.filter { $0.type == .keyKindChange }
            #expect(changeEvents.count == 1)
            let event = changeEvents[0]
            #expect(event.result == .denied)
            #expect(event.reason == .authenticationFailed)
            #expect(event.keyKind == .agent)
            #expect(event.keyFingerprint == key.fingerprint)
            #expect(event.sensitive.keyLabel == key.label)
        }
    }

    @Test func test_005_T4_changeKindUpdatesRecordAndIndex() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try keyManager.generateKey(label: "roundtrip-test", keyPurpose: .general)
            #expect(key.keyPurpose == .general)

            // Change .general -> .agent
            try keyManager.changeKind(label: key.label, to: .agent)

            // Check index
            let keysAfterFirst = try keyManager.listKeys()
            let matchingFirst = keysAfterFirst.first { $0.label == key.label }
            #expect(matchingFirst?.keyPurpose == .agent)

            // Check decoded record
            let rawDataFirst = try #require(try keyStore.load(label: key.label, context: LAContext(), prompt: ""))
            let recordFirst = try StoredPrivateKeyRecord.decode(from: rawDataFirst)
            #expect(recordFirst.keyPurpose == .agent)

            // Change .agent -> .general
            try keyManager.changeKind(label: key.label, to: .general)

            // Check index
            let keysAfterSecond = try keyManager.listKeys()
            let matchingSecond = keysAfterSecond.first { $0.label == key.label }
            #expect(matchingSecond?.keyPurpose == .general)

            // Check decoded record
            let rawDataSecond = try #require(try keyStore.load(label: key.label, context: LAContext(), prompt: ""))
            let recordSecond = try StoredPrivateKeyRecord.decode(from: rawDataSecond)
            #expect(recordSecond.keyPurpose == .general)
        }
    }

    @Test func test_005_T4_gitOnlyCannotChangeKind() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let keyManager = fixture.makeKeyManager(authenticator: auth)

            let key = try keyManager.generateKey(label: "git-only-test", keyPurpose: .gitSigningOnly)

            // Attempting to change to .agent must throw kindChangeNotAllowed without prompt
            #expect {
                try keyManager.changeKind(label: key.label, to: .agent)
            } throws: { error in
                error as? KeyPurposeError == .kindChangeNotAllowed
            }

            // Attempting to change to .general must throw kindChangeNotAllowed without prompt
            #expect {
                try keyManager.changeKind(label: key.label, to: .general)
            } throws: { error in
                error as? KeyPurposeError == .kindChangeNotAllowed
            }

            #expect(auth.authenticationCount == 0, "No authentication prompt should occur for gitSigningOnly key")
        }
    }

    @Test func test_005_T4_changeKindRecordsAudit() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(auditRecorder: recorder)

            let key = try keyManager.generateKey(label: "audit-test", keyPurpose: .general)

            try keyManager.changeKind(label: key.label, to: .agent)

            let changeEvents = recorder.events.filter { $0.type == .keyKindChange }
            #expect(changeEvents.count == 1)
            let event = changeEvents[0]
            #expect(event.result == .allowed)
            #expect(event.keyKind == .agent)
            #expect(event.keyFingerprint == key.fingerprint)
            #expect(event.sensitive.keyLabel == key.label)
        }
    }

    @Test func test_005_T4_indexWriteFailureRollsBackRecord() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try keyManager.generateKey(label: "rollback-test", keyPurpose: .general)

            PublicKeyStore.forcedSaveErrorForTesting = NSError(domain: "test", code: 999, userInfo: nil)
            defer { PublicKeyStore.forcedSaveErrorForTesting = nil }

            #expect(throws: (any Error).self) {
                try keyManager.changeKind(label: key.label, to: .agent)
            }

            // Index remains .general
            let fetchedKey = try keyManager.fetchKeyInfo(label: key.label)
            #expect(fetchedKey?.keyPurpose == .general)

            // Keychain record was rolled back to .general
            let rawData = try #require(try keyStore.load(label: key.label, context: LAContext(), prompt: ""))
            let record = try StoredPrivateKeyRecord.decode(from: rawData)
            #expect(record.keyPurpose == .general, "Keychain record should be rolled back to general")

            // Vault record was rolled back to .general
            let vaultRecord = try EncryptedVaultStore.shared.loadRecord(label: key.label)
            #expect(vaultRecord?.keyPurpose == .general, "Vault record should be rolled back to general")
        }
    }
}
