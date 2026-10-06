import XCTest
import LocalAuthentication
@testable import ClavisCore

final class SSHAgentServerAuditTests: ClavisBaseTestCase {

    private struct CancellingAuthenticator: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
            throw UserAuthenticationError.rejected(LAError(.userCancel))
        }

        func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
            throw UserAuthenticationError.rejected(LAError(.userCancel))
        }
    }

    private func makeSignRequest(keyBlob: Data, dataToSign: Data = Data("test challenge".utf8)) -> Data {
        var request = Data([13]) // SSH2_AGENTC_SIGN_REQUEST
        request.appendWireData(keyBlob)
        request.appendWireData(dataToSign)
        request.appendWireUInt32(0) // flags = 0
        return request
    }

    func test_002_AC1_allowedSignatureIsRecorded() throws {
        let keyManager = makeKeyManager()
        let keyInfo = try keyManager.generateKey(label: "allowed-key")
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(
            keyManager: keyManager,
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: recorder
        )

        let request = makeSignRequest(keyBlob: keyInfo.publicKeyBlob)
        let response = server.processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/usr/bin/ssh"
        )

        XCTAssertFalse(response.isEmpty)
        XCTAssertEqual(response[0], 14) // SSH2_AGENT_SIGN_RESPONSE
        XCTAssertEqual(recorder.events.count, 1)

        let event = recorder.events[0]
        XCTAssertEqual(event.type, .signature)
        XCTAssertEqual(event.result, .allowed)
        XCTAssertEqual(event.reason, .viaPrompt)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, "allowed-key")
        XCTAssertEqual(event.sensitive.processChain.first?.pid, getpid())
        XCTAssertEqual(event.sensitive.processChain.first?.executablePath, "/usr/bin/ssh")
    }

    func test_002_AC2_unknownKeyIsRecordedAsDenied() throws {
        let keyManager = makeKeyManager()
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(keyManager: keyManager, auditRecorder: recorder)

        let fakeBlob = Data([0x00, 0x01, 0x02, 0x03])
        let request = makeSignRequest(keyBlob: fakeBlob)
        let response = server.processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/usr/bin/ssh"
        )

        XCTAssertEqual(response, Data([5])) // SSH_AGENT_FAILURE
        XCTAssertEqual(recorder.events.count, 1)

        let event = recorder.events[0]
        XCTAssertEqual(event.type, .signature)
        XCTAssertEqual(event.result, .denied)
        XCTAssertEqual(event.reason, .unknownKey)
    }

    func test_002_AC2_gitOnlyKeyMisuseIsRecordedAsDenied() throws {
        let keyManager = makeKeyManager()
        let keyInfo = try keyManager.generateKey(label: "git-only-key", keyPurpose: .gitSigningOnly)
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(keyManager: keyManager, auditRecorder: recorder)

        let request = makeSignRequest(keyBlob: keyInfo.publicKeyBlob, dataToSign: Data("not sshsig".utf8))
        let response = server.processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/usr/bin/ssh"
        )

        XCTAssertEqual(response, Data([5]))
        XCTAssertEqual(recorder.events.count, 1)

        let event = recorder.events[0]
        XCTAssertEqual(event.type, .signature)
        XCTAssertEqual(event.result, .denied)
        XCTAssertEqual(event.reason, .gitOnlyKeyNonGitPayload)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
        XCTAssertEqual(event.sensitive.keyLabel, "git-only-key")
    }

    func test_002_AC2_cancelledPromptIsRecordedAsCancelled() throws {
        let keyManager = makeKeyManager(authenticator: CancellingAuthenticator())
        let keyInfo = try keyManager.generateKey(label: "cancel-key")
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(keyManager: keyManager, auditRecorder: recorder)

        let request = makeSignRequest(keyBlob: keyInfo.publicKeyBlob)
        let response = server.processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/usr/bin/ssh"
        )

        XCTAssertEqual(response, Data([5]))
        XCTAssertEqual(recorder.events.count, 1)

        let event = recorder.events[0]
        XCTAssertEqual(event.type, .signature)
        XCTAssertEqual(event.result, .cancelled)
        XCTAssertEqual(event.reason, .userCancelled)
        XCTAssertEqual(event.keyFingerprint, keyInfo.fingerprint)
    }

    func test_002_T4_exactlyOneEventPerRequest() throws {
        let keyManager = makeKeyManager()
        let keyInfo = try keyManager.generateKey(label: "multi-key")
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(
            keyManager: keyManager,
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: recorder
        )

        // 1. Malformed payload
        _ = server.processAgentRequest(payload: Data([13, 0x01, 0x02]))
        XCTAssertEqual(recorder.events.count, 1)
        XCTAssertEqual(recorder.events.last?.result, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .malformedRequest)

        // 2. Unknown key
        let fakeRequest = makeSignRequest(keyBlob: Data([0xDE, 0xAD, 0xBE, 0xEF]))
        _ = server.processAgentRequest(payload: fakeRequest, clientPid: getpid(), clientExecutablePath: "/usr/bin/ssh")
        XCTAssertEqual(recorder.events.count, 2)
        XCTAssertEqual(recorder.events.last?.result, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .unknownKey)

        // 3. No peer attribution
        let validRequest = makeSignRequest(keyBlob: keyInfo.publicKeyBlob)
        _ = server.processAgentRequest(payload: validRequest, clientPid: nil, clientExecutablePath: nil)
        XCTAssertEqual(recorder.events.count, 3)
        XCTAssertEqual(recorder.events.last?.result, .denied)
        XCTAssertEqual(recorder.events.last?.reason, .noPeerAttribution)

        // 4. Allowed sign
        _ = server.processAgentRequest(payload: validRequest, clientPid: getpid(), clientExecutablePath: "/usr/bin/ssh")
        XCTAssertEqual(recorder.events.count, 4)
        XCTAssertEqual(recorder.events.last?.result, .allowed)
    }

    func test_002_C3_personalKeysAreRecorded() throws {
        let keyManager = makeKeyManager()
        let keyInfo = try keyManager.generateKey(label: "personal-key")
        let recorder = InMemoryAuditRecorder()
        let server = SSHAgentServer(
            keyManager: keyManager,
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: recorder
        )

        let request = makeSignRequest(keyBlob: keyInfo.publicKeyBlob)
        _ = server.processAgentRequest(
            payload: request,
            clientPid: getpid(),
            clientExecutablePath: "/usr/bin/ssh"
        )

        XCTAssertEqual(recorder.events.count, 1)
        XCTAssertEqual(recorder.events[0].keyKind, .personal)
    }

    func test_002_T4_processChainStopsAtDepthLimit() {
        // Mock a deep process tree: pid N has parent N+1
        let deepLookup: (pid_t) -> (parent: pid_t, path: String)? = { pid in
            if pid >= 100 { return nil }
            return (parent: pid + 1, path: "/path/proc_\(pid + 1)")
        }

        let chain = AuditProcessChain.build(
            pid: 10,
            executablePath: "/path/proc_10",
            maxDepth: 16,
            processInfo: deepLookup
        )
        XCTAssertEqual(chain.count, 16)
        XCTAssertEqual(chain.first?.pid, 10)
        XCTAssertEqual(chain.last?.pid, 25)

        // Mock a circular process tree: 10 -> 20 -> 10
        let circularLookup: (pid_t) -> (parent: pid_t, path: String)? = { pid in
            if pid == 10 { return (parent: 20, path: "/path/20") }
            if pid == 20 { return (parent: 10, path: "/path/10") }
            return nil
        }

        let loopChain = AuditProcessChain.build(
            pid: 10,
            executablePath: "/path/10",
            maxDepth: 16,
            processInfo: circularLookup
        )
        XCTAssertEqual(loopChain.count, 2)
        XCTAssertEqual(loopChain[0].pid, 10)
        XCTAssertEqual(loopChain[1].pid, 20)

        // Mock a tree reaching launchd (PID 1)
        let launchdLookup: (pid_t) -> (parent: pid_t, path: String)? = { pid in
            if pid == 50 { return (parent: 1, path: "/sbin/launchd") }
            return nil
        }

        let launchdChain = AuditProcessChain.build(
            pid: 50,
            executablePath: "/path/50",
            maxDepth: 16,
            processInfo: launchdLookup
        )
        XCTAssertEqual(launchdChain.count, 1)
        XCTAssertEqual(launchdChain[0].pid, 50)
    }
}
