import Testing
import LocalAuthentication
import Foundation
@testable import ClavisCore

@Suite("AgentPathSeparationTests")
struct AgentPathSeparationTests {
    private let fixture: ClavisTestFixture

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    private func makeSignRequest(keyBlob: Data, dataToSign: Data = Data("test challenge".utf8)) -> Data {
        var request = Data([13]) // SSH2_AGENTC_SIGN_REQUEST
        request.appendWireData(keyBlob)
        request.appendWireData(dataToSign)
        request.appendWireUInt32(0) // flags = 0
        return request
    }

    @Test
    func test_005_AC3_personalSocketDoesNotListAgentKeys() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyManager = fixture.makeKeyManager()
            let generalKey = try keyManager.generateKey(label: "personal-general", keyPurpose: .general)
            _ = try keyManager.generateKey(label: "personal-git-only", keyPurpose: .gitSigningOnly)
            _ = try keyManager.generateKey(label: "agent-key", keyPurpose: .agent)

            let server = SSHAgentServer(
                role: .personal,
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true }
            )

            let response = server.processAgentRequest(
                payload: Data([11]), // SSH2_AGENTC_REQUEST_IDENTITIES
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(!response.isEmpty)
            #expect(response[0] == 12) // SSH2_AGENT_IDENTITIES_ANSWER

            var reader = DataReader(data: response.dropFirst())
            let rawCount = reader.readUInt32()
            let count = try #require(rawCount, "Failed to read identity count")
            #expect(count == 1, "Personal socket should only list general keys")

            let rawBlob = reader.readWireData()
            let blob = try #require(rawBlob, "Failed to read identity data")
            let rawComment = reader.readWireString()
            let comment = try #require(rawComment, "Failed to read identity data")
            #expect(blob == generalKey.publicKeyBlob)
            #expect(comment == "personal-general")
        }
    }

    @Test
    func test_005_C1_personalSocketDeniesAgentKeyWithoutPrompt() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(authenticator: auth, auditRecorder: recorder)
            let agentKey = try keyManager.generateKey(label: "agent-key-prompt-test", keyPurpose: .agent)

            let server = SSHAgentServer(
                role: .personal,
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: recorder
            )

            let signRequest = makeSignRequest(keyBlob: agentKey.publicKeyBlob)
            let response = server.processAgentRequest(
                payload: signRequest,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5]), "Agent key signature on personal socket must return failure")
            #expect(auth.authenticationCount == 0, "No authentication prompt should be presented")

            let signEvents = recorder.events.filter { $0.type == .signature }
            #expect(signEvents.count == 1)
            let event = signEvents[0]
            #expect(event.result == .denied)
            #expect(event.reason == .wrongKeyKind)
            #expect(event.keyKind == .agent)
        }
    }

    @Test
    func test_005_C1_tamperedIndexCannotMoveAgentKeyToPersonalPath() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(authenticator: auth, auditRecorder: recorder)
            let agentKey = try keyManager.generateKey(label: "tampered-agent-key", keyPurpose: .agent)

            // Tamper the public index to claim purpose is .general
            let tampered = SSHKeyInfo(
                label: agentKey.label,
                publicKeyOpenSSH: agentKey.publicKeyOpenSSH,
                publicKeyBlob: agentKey.publicKeyBlob,
                fingerprint: agentKey.fingerprint,
                createdAt: agentKey.createdAt,
                algorithmName: agentKey.algorithmName,
                storage: agentKey.storage,
                biometricPolicy: agentKey.biometricPolicy,
                keyPurpose: .general
            )
            PublicKeyStore.save(tampered)

            // 1. Direct signSSH on personal path must fail
            #expect {
                try keyManager.signSSH(
                    key: tampered,
                    data: Data("test".utf8),
                    prompt: "Test",
                    useCache: false
                )
            } throws: { error in
                (error as? KeyPurposeError) == .notAllowedOnThisPath(.agent)
            }

            // 2. SSHAgentServer on personal socket must deny and audit wrongKeyKind
            let server = SSHAgentServer(
                role: .personal,
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: recorder
            )

            let signRequest = makeSignRequest(keyBlob: agentKey.publicKeyBlob)
            let response = server.processAgentRequest(
                payload: signRequest,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5]))
            let signEvents = recorder.events.filter { $0.type == .signature }
            let lastEvent = try #require(signEvents.last, "Expected audit event for denied sign")
            #expect(lastEvent.result == .denied)
            #expect(lastEvent.reason == .wrongKeyKind)
        }
    }

    @Test
    func test_005_D2_gitGrantRefusesAgentKey() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let keyManager = fixture.makeKeyManager(authenticator: auth)
            let agentKey = try keyManager.generateKey(label: "git-grant-agent-key", keyPurpose: .agent)

            // Refuses before prompt
            #expect {
                try keyManager.authorizeGitSigningGrant(
                    key: agentKey,
                    prompt: "Git grant",
                    clientIdentity: "/usr/bin/git"
                )
            } throws: { error in
                (error as? KeyPurposeError) == .notAllowedOnThisPath(.agent)
            }
            #expect(auth.authenticationCount == 0)

            // Tampered index: refuses after authoritative record check
            let tampered = SSHKeyInfo(
                label: agentKey.label,
                publicKeyOpenSSH: agentKey.publicKeyOpenSSH,
                publicKeyBlob: agentKey.publicKeyBlob,
                fingerprint: agentKey.fingerprint,
                createdAt: agentKey.createdAt,
                algorithmName: agentKey.algorithmName,
                storage: agentKey.storage,
                biometricPolicy: agentKey.biometricPolicy,
                keyPurpose: .general
            )
            PublicKeyStore.save(tampered)

            #expect {
                try keyManager.authorizeGitSigningGrant(
                    key: tampered,
                    prompt: "Git grant",
                    clientIdentity: "/usr/bin/git"
                )
            } throws: { error in
                (error as? KeyPurposeError) == .notAllowedOnThisPath(.agent)
            }
        }
    }

    @Test
    func test_005_AC4_agentSocketListsOnlyAgentKeys() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyManager = fixture.makeKeyManager()
            _ = try keyManager.generateKey(label: "personal-general", keyPurpose: .general)
            _ = try keyManager.generateKey(label: "personal-git-only", keyPurpose: .gitSigningOnly)
            let agentKey = try keyManager.generateKey(label: "agent-specific", keyPurpose: .agent)

            let server = SSHAgentServer(
                role: .agent,
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true }
            )

            let response = server.processAgentRequest(
                payload: Data([11]), // SSH2_AGENTC_REQUEST_IDENTITIES
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(!response.isEmpty)
            #expect(response[0] == 12) // SSH2_AGENT_IDENTITIES_ANSWER

            var reader = DataReader(data: response.dropFirst())
            let rawCount = reader.readUInt32()
            let count = try #require(rawCount, "Failed to read identity count")
            #expect(count == 1, "Agent socket should only list agent keys")

            let rawBlob = reader.readWireData()
            let blob = try #require(rawBlob, "Failed to read identity data")
            let rawComment = reader.readWireString()
            let comment = try #require(rawComment, "Failed to read identity data")
            #expect(blob == agentKey.publicKeyBlob)
            #expect(comment == "agent-specific")
        }
    }

    @Test
    func test_005_T3_agentSocketDeniesSignWithoutSession() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(auditRecorder: recorder)
            let agentKey = try keyManager.generateKey(label: "agent-nosession", keyPurpose: .agent)

            let server = SSHAgentServer(
                role: .agent,
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: recorder
            )

            let signRequest = makeSignRequest(keyBlob: agentKey.publicKeyBlob)
            let response = server.processAgentRequest(
                payload: signRequest,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5]))
            let signEvents = recorder.events.filter { $0.type == .signature }
            #expect(signEvents.count == 1)
            let event = signEvents[0]
            #expect(event.result == .denied)
            #expect(event.reason == .noAgentSession)
            #expect(event.keyKind == .agent)
        }
    }

    @Test
    func test_005_C1_agentSocketDeniesPersonalKey() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let recorder = InMemoryAuditRecorder()
            let keyManager = fixture.makeKeyManager(auditRecorder: recorder)
            let personalKey = try keyManager.generateKey(label: "personal-on-agent", keyPurpose: .general)

            let server = SSHAgentServer(
                role: .agent,
                keyManager: keyManager,
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: recorder
            )

            let signRequest = makeSignRequest(keyBlob: personalKey.publicKeyBlob)
            let response = server.processAgentRequest(
                payload: signRequest,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh"
            )

            #expect(response == Data([5]))
            let signEvents = recorder.events.filter { $0.type == .signature }
            #expect(signEvents.count == 1)
            let event = signEvents[0]
            #expect(event.result == .denied)
            #expect(event.reason == .wrongKeyKind)
            #expect(event.keyKind == .personal)
        }
    }

    @Test
    func test_005_T3_agentSocketRefusesControlOpcodes() throws {
        let server = SSHAgentServer(role: .agent)

        for opcode: UInt8 in [240, 241, 242] {
            var payload = Data([opcode])
            payload.appendWireString("test-label")
            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientExecutablePath: "/usr/bin/ssh",
                isTrustedControlPeer: { true }
            )
            #expect(response == Data([5]), "Agent socket must reject control opcode \(opcode)")
        }
    }

    @Test
    func test_005_T3_startAllFailsClosedAndStopsPersonalWhenAgentFails() throws {
        defer { fixture.cleanup() }
        let personalSock = fixture.testRootURL.appendingPathComponent("p.sock").path
        let invalidAgentSock = "/dev/null/impossible/agent.sock"

        let personalServer = SSHAgentServer(socketPath: personalSock, role: .personal)
        let failingAgentServer = SSHAgentServer(socketPath: invalidAgentSock, role: .agent)

        defer {
            AgentServers.stopAll(personal: personalServer, agent: failingAgentServer)
        }

        #expect(throws: (any Error).self) {
            try AgentServers.startAll(personal: personalServer, agent: failingAgentServer)
        }
        #expect(!personalServer.isSocketActive, "Personal server must be stopped when agent socket fails to start")
        #expect(!SSHAgentServer.isSocketListening(atPath: personalSock), "Personal socket must not remain listening")
        #expect(!FileManager.default.fileExists(atPath: personalSock), "Personal socket file must be unlinked")
    }
}
