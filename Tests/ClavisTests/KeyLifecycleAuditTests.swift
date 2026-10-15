import Testing
import Foundation
import LocalAuthentication
@testable import ClavisCore

@Suite struct KeyLifecycleAuditTests {

    private struct RejectingAuthenticator: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
            throw UserAuthenticationError.rejected(nil)
        }

        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
            throw UserAuthenticationError.rejected(nil)
        }
    }

    @Test func test_002_T5_generateRecordsKeyCreate() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(auditRecorder: recorder)

            let keyInfo = try keyManager.generateKey(label: "create-key")

            #expect(recorder.events.count == 1)
            let event = recorder.events[0]
            #expect(event.type == .keyCreate)
            #expect(event.result == .allowed)
            #expect(event.reason == nil)
            #expect(event.keyFingerprint == keyInfo.fingerprint)
            #expect(event.sensitive.keyLabel == "create-key")
        }
    }

    @Test func test_002_T5_deleteRecordsKeyDeleteWithFingerprint() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(auditRecorder: recorder)

            let keyInfo = try keyManager.generateKey(label: "delete-key")
            try keyManager.deleteKey(label: "delete-key")

            let deleteEvents = recorder.events.filter { $0.type == .keyDelete }
            #expect(deleteEvents.count == 1)
            let event = deleteEvents[0]
            #expect(event.result == .allowed)
            #expect(event.reason == nil)
            #expect(event.keyFingerprint == keyInfo.fingerprint)
            #expect(event.sensitive.keyLabel == "delete-key")
        }
    }

    @Test func test_002_T5_deleteAuthFailureRecordsDenied() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(authenticator: RejectingAuthenticator(), auditRecorder: recorder)

            let keyInfo = try keyManager.generateKey(label: "fail-delete-key")
            #expect(throws: (any Error).self) {
                try keyManager.deleteKey(label: "fail-delete-key")
            }

            let deleteEvents = recorder.events.filter { $0.type == .keyDelete }
            #expect(deleteEvents.count == 1)
            let event = deleteEvents[0]
            #expect(event.result == .denied)
            #expect(event.reason == .authenticationFailed)
            #expect(event.keyFingerprint == keyInfo.fingerprint)
            #expect(event.sensitive.keyLabel == "fail-delete-key")
        }
    }

    @Test func test_002_T5_lockAllRecordsLock() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let server = SSHAgentServer(
                keyManager: fixture.makeKeyManager(),
                auditRecorder: recorder
            )

            let response = server.processAgentRequest(
                payload: Data([SSHAgentServer.lockAllRequest]),
                isTrustedControlPeer: { true }
            )

            #expect(response == Data([6]))
            #expect(recorder.events.count == 1)
            let event = recorder.events[0]
            #expect(event.type == .lock)
            #expect(event.result == .info)
            #expect(event.reason == .lockNow)
        }
    }
}
