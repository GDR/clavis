import Foundation
import Testing
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite(.serialized)
final class SSHAgentServerAuditTests {
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
        gitSigningGraceManager: GitSigningGraceManager = GitSigningGraceManager(observeSystemEvents: false)
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

    private func makeServer(
        keyManager: KeychainManager,
        peerProcessValidator: ((pid_t, String, UInt64) -> Bool)? = nil,
        auditRecorder: AuditRecording
    ) -> SSHAgentServer {
        SSHAgentServer(
            keyManager: keyManager,
            promptGate: SigningPromptGate(),
            gitSigningGraceManager: GitSigningGraceManager(observeSystemEvents: false),
            peerProcessValidator: peerProcessValidator,
            auditRecorder: auditRecorder,
            testContext: fixture.context
        )
    }

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

    @Test func test_002_AC1_allowedSignatureIsRecorded() throws {
        try fixture.runSync {
            let keyManager = makeKeyManager()
            let keyInfo = try keyManager.generateKey(label: "allowed-key")
            let recorder = InMemoryAuditRecorder()
            let server = makeServer(
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

            #expect(!response.isEmpty)
            #expect(response[0] == 14) // SSH2_AGENT_SIGN_RESPONSE
            #expect(recorder.events.count == 1)

            let event = recorder.events[0]
            #expect(event.type == .signature)
            #expect(event.result == .allowed)
            #expect(event.reason == .viaPrompt)
            #expect(event.keyFingerprint == keyInfo.fingerprint)
            #expect(event.sensitive.keyLabel == "allowed-key")
            #expect(event.sensitive.processChain.first?.pid == getpid())
            #expect(event.sensitive.processChain.first?.executablePath == "/usr/bin/ssh")
        }
    }

    @Test func test_002_AC2_unknownKeyIsRecordedAsDenied() {
        fixture.runSync {
            let keyManager = makeKeyManager()
            let recorder = InMemoryAuditRecorder()
            let server = makeServer(keyManager: keyManager, auditRecorder: recorder)

            let fakeBlob = Data([0x00, 0x01, 0x02, 0x03])
            let request = makeSignRequest(keyBlob: fakeBlob)
            let response = server.processAgentRequest(
                payload: request,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5])) // SSH_AGENT_FAILURE
            #expect(recorder.events.count == 1)

            let event = recorder.events[0]
            #expect(event.type == .signature)
            #expect(event.result == .denied)
            #expect(event.reason == .unknownKey)
        }
    }

    @Test func test_002_AC2_gitOnlyKeyMisuseIsRecordedAsDenied() throws {
        try fixture.runSync {
            let keyManager = makeKeyManager()
            let keyInfo = try keyManager.generateKey(label: "git-only-key", keyPurpose: .gitSigningOnly)
            let recorder = InMemoryAuditRecorder()
            let server = makeServer(keyManager: keyManager, auditRecorder: recorder)

            let request = makeSignRequest(keyBlob: keyInfo.publicKeyBlob, dataToSign: Data("not sshsig".utf8))
            let response = server.processAgentRequest(
                payload: request,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5]))
            #expect(recorder.events.count == 1)

            let event = recorder.events[0]
            #expect(event.type == .signature)
            #expect(event.result == .denied)
            #expect(event.reason == .gitOnlyKeyNonGitPayload)
            #expect(event.keyFingerprint == keyInfo.fingerprint)
            #expect(event.sensitive.keyLabel == "git-only-key")
        }
    }

    @Test func test_002_AC2_cancelledPromptIsRecordedAsCancelled() throws {
        try fixture.runSync {
            let keyManager = makeKeyManager(authenticator: CancellingAuthenticator())
            let keyInfo = try keyManager.generateKey(label: "cancel-key")
            let recorder = InMemoryAuditRecorder()
            let server = makeServer(keyManager: keyManager, auditRecorder: recorder)

            let request = makeSignRequest(keyBlob: keyInfo.publicKeyBlob)
            let response = server.processAgentRequest(
                payload: request,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5]))
            #expect(recorder.events.count == 1)

            let event = recorder.events[0]
            #expect(event.type == .signature)
            #expect(event.result == .cancelled)
            #expect(event.reason == .userCancelled)
            #expect(event.keyFingerprint == keyInfo.fingerprint)
        }
    }

    @Test func test_002_T4_exactlyOneEventPerRequest() throws {
        try fixture.runSync {
            let keyManager = makeKeyManager()
            let keyInfo = try keyManager.generateKey(label: "multi-key")
            let recorder = InMemoryAuditRecorder()
            let server = makeServer(
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: recorder
            )

            // 1. Malformed payload
            _ = server.processAgentRequest(payload: Data([13, 0x01, 0x02]))
            #expect(recorder.events.count == 1)
            #expect(recorder.events.last?.result == .denied)
            #expect(recorder.events.last?.reason == .malformedRequest)

            // 2. Unknown key
            let fakeRequest = makeSignRequest(keyBlob: Data([0xDE, 0xAD, 0xBE, 0xEF]))
            _ = server.processAgentRequest(payload: fakeRequest, clientPid: getpid(), clientExecutablePath: "/usr/bin/ssh")
            #expect(recorder.events.count == 2)
            #expect(recorder.events.last?.result == .denied)
            #expect(recorder.events.last?.reason == .unknownKey)

            // 3. No peer attribution
            let validRequest = makeSignRequest(keyBlob: keyInfo.publicKeyBlob)
            _ = server.processAgentRequest(payload: validRequest, clientPid: nil, clientExecutablePath: nil)
            #expect(recorder.events.count == 3)
            #expect(recorder.events.last?.result == .denied)
            #expect(recorder.events.last?.reason == .noPeerAttribution)

            // 4. Allowed sign
            _ = server.processAgentRequest(payload: validRequest, clientPid: getpid(), clientExecutablePath: "/usr/bin/ssh")
            #expect(recorder.events.count == 4)
            #expect(recorder.events.last?.result == .allowed)
        }
    }

    @Test func test_002_C3_personalKeysAreRecorded() throws {
        try fixture.runSync {
            let keyManager = makeKeyManager()
            let keyInfo = try keyManager.generateKey(label: "personal-key")
            let recorder = InMemoryAuditRecorder()
            let server = makeServer(
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

            #expect(recorder.events.count == 1)
            #expect(recorder.events[0].keyKind == .personal)
        }
    }

    @Test func test_002_T4_processChainStopsAtDepthLimit() {
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
        #expect(chain.count == 16)
        #expect(chain.first?.pid == 10)
        #expect(chain.last?.pid == 25)

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
        #expect(loopChain.count == 2)
        #expect(loopChain[0].pid == 10)
        #expect(loopChain[1].pid == 20)

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
        #expect(launchdChain.count == 1)
        #expect(launchdChain[0].pid == 50)
    }
}
