import XCTest
import LocalAuthentication
@testable import ClavisCore

final class AgentPathSeparationTests: ClavisBaseTestCase {

    private func makeSignRequest(keyBlob: Data, dataToSign: Data = Data("test challenge".utf8)) -> Data {
        var request = Data([13]) // SSH2_AGENTC_SIGN_REQUEST
        request.appendWireData(keyBlob)
        request.appendWireData(dataToSign)
        request.appendWireUInt32(0) // flags = 0
        return request
    }

    func test_005_AC3_personalSocketDoesNotListAgentKeys() throws {
        let keyManager = makeKeyManager()
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

        XCTAssertFalse(response.isEmpty)
        XCTAssertEqual(response[0], 12) // SSH2_AGENT_IDENTITIES_ANSWER

        var reader = DataReader(data: response.dropFirst())
        guard let count = reader.readUInt32() else {
            XCTFail("Failed to read identity count")
            return
        }
        XCTAssertEqual(count, 1, "Personal socket should only list general keys")

        guard let blob = reader.readWireData(),
              let comment = reader.readWireString() else {
            XCTFail("Failed to read identity data")
            return
        }
        XCTAssertEqual(blob, generalKey.publicKeyBlob)
        XCTAssertEqual(comment, "personal-general")
    }

    func test_005_C1_personalSocketDeniesAgentKeyWithoutPrompt() throws {
        let auth = CountingAuthenticator()
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(authenticator: auth, auditRecorder: recorder)
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

        XCTAssertEqual(response, Data([5]), "Agent key signature on personal socket must return failure")
        XCTAssertEqual(auth.authenticationCount, 0, "No authentication prompt should be presented")

        let signEvents = recorder.events.filter { $0.type == .signature }
        XCTAssertEqual(signEvents.count, 1)
        let event = signEvents[0]
        XCTAssertEqual(event.result, .denied)
        XCTAssertEqual(event.reason, .wrongKeyKind)
        XCTAssertEqual(event.keyKind, .agent)
    }

    func test_005_C1_tamperedIndexCannotMoveAgentKeyToPersonalPath() throws {
        let auth = CountingAuthenticator()
        let recorder = InMemoryAuditRecorder()
        let keyManager = makeKeyManager(authenticator: auth, auditRecorder: recorder)
        let agentKey = try keyManager.generateKey(label: "tampered-agent-key", keyPurpose: .agent)

        // Tamper the public index to claim purpose is .general
        let tampered = Ed25519KeyInfo(
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
        XCTAssertThrowsError(
            try keyManager.signSSH(
                key: tampered,
                data: Data("test".utf8),
                prompt: "Test",
                useCache: false
            )
        ) { error in
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.agent))
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

        XCTAssertEqual(response, Data([5]))
        let signEvents = recorder.events.filter { $0.type == .signature }
        guard let lastEvent = signEvents.last else {
            XCTFail("Expected audit event for denied sign")
            return
        }
        XCTAssertEqual(lastEvent.result, .denied)
        XCTAssertEqual(lastEvent.reason, .wrongKeyKind)
    }

    func test_005_C1_unlockRefusesAgentKey() async throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .fifteenMinutes
        let auth = CountingAuthenticator()
        let keyManager = makeKeyManager(sessionCache: cache, authenticator: auth)

        let agentKey = try keyManager.generateKey(label: "unlock-agent-key", keyPurpose: .agent)

        // Preliminary check rejects before auth prompt
        do {
            try await keyManager.unlock(label: agentKey.label)
            XCTFail("unlock should refuse agent key")
        } catch {
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.agent))
        }
        XCTAssertEqual(auth.authenticationCount, 0)

        // Tampered public index: authoritative record check rejects after auth
        let tampered = Ed25519KeyInfo(
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

        do {
            try await keyManager.unlock(label: agentKey.label)
            XCTFail("unlock should refuse agent key even with tampered index")
        } catch {
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.agent))
        }
        XCTAssertEqual(cache.cachedCount, 0)
    }

    func test_005_D2_gitGrantRefusesAgentKey() throws {
        let auth = CountingAuthenticator()
        let keyManager = makeKeyManager(authenticator: auth)
        let agentKey = try keyManager.generateKey(label: "git-grant-agent-key", keyPurpose: .agent)

        // Refuses before prompt
        XCTAssertThrowsError(
            try keyManager.authorizeGitSigningGrant(
                key: agentKey,
                prompt: "Git grant",
                clientIdentity: "/usr/bin/git"
            )
        ) { error in
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.agent))
        }
        XCTAssertEqual(auth.authenticationCount, 0)

        // Tampered index: refuses after authoritative record check
        let tampered = Ed25519KeyInfo(
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

        XCTAssertThrowsError(
            try keyManager.authorizeGitSigningGrant(
                key: tampered,
                prompt: "Git grant",
                clientIdentity: "/usr/bin/git"
            )
        ) { error in
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.agent))
        }
    }
}
