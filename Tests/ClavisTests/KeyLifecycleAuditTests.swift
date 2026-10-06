import XCTest
import LocalAuthentication
@testable import ClavisCore

final class KeyLifecycleAuditTests: ClavisBaseTestCase {

    private struct RejectingAuthenticator: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
            throw UserAuthenticationError.rejected(nil)
        }

        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
            throw UserAuthenticationError.rejected(nil)
        }
    }

    func test_002_T5_generateRecordsKeyCreate() throws {
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(auditRecorder: recorder)

        let keyInfo = try keyManager.generateKey(label: "create-key")

        XCTAssertEqual(recorder.events.count, 1)
        let event = recorder.events[0]
        XCTAssertEqual(event.type, .keyCreate)
        XCTAssertEqual(event.result, .allowed)
        XCTAssertNil(event.reason)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, "create-key")
    }

    func test_002_T5_deleteRecordsKeyDeleteWithFingerprint() throws {
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(auditRecorder: recorder)

        let keyInfo = try keyManager.generateKey(label: "delete-key")
        try keyManager.deleteKey(label: "delete-key")

        let deleteEvents = recorder.events.filter { $0.type == .keyDelete }
        XCTAssertEqual(deleteEvents.count, 1)
        let event = deleteEvents[0]
        XCTAssertEqual(event.result, .allowed)
        XCTAssertNil(event.reason)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, "delete-key")
    }

    func test_002_T5_deleteAuthFailureRecordsDenied() throws {
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(authenticator: RejectingAuthenticator(), auditRecorder: recorder)

        let keyInfo = try keyManager.generateKey(label: "fail-delete-key")
        XCTAssertThrowsError(try keyManager.deleteKey(label: "fail-delete-key"))

        let deleteEvents = recorder.events.filter { $0.type == .keyDelete }
        XCTAssertEqual(deleteEvents.count, 1)
        let event = deleteEvents[0]
        XCTAssertEqual(event.result, .denied)
        XCTAssertEqual(event.reason, .authenticationFailed)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, "fail-delete-key")
    }

    func test_002_T5_lockAllRecordsLock() throws {
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(
            keyManager: makeKeyManager(),
            auditRecorder: recorder
        )

        let response = server.processAgentRequest(
            payload: Data([SSHAgentServer.lockAllRequest]),
            isTrustedControlPeer: { true }
        )

        XCTAssertEqual(response, Data([6]))
        XCTAssertEqual(recorder.events.count, 1)
        let event = recorder.events[0]
        XCTAssertEqual(event.type, .lock)
        XCTAssertEqual(event.result, .info)
        XCTAssertEqual(event.reason, .lockNow)
    }

    func test_002_T5_importRecordsKeyImport() throws {
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(auditRecorder: recorder)

        var seed = Data(repeating: 0x42, count: 32)
        let keyInfo = try keyManager.importKey(label: "import-key", consuming: &seed)

        XCTAssertEqual(recorder.events.count, 1)
        let event = recorder.events[0]
        XCTAssertEqual(event.type, .keyImport)
        XCTAssertEqual(event.result, .allowed)
        XCTAssertNil(event.reason)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, "import-key")
    }
}
