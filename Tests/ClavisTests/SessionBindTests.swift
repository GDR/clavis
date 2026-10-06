import XCTest
import CryptoKit
@testable import ClavisCore

final class SessionBindTests: ClavisBaseTestCase {
    private var auditRecorder: InMemoryAuditRecorder!
    private var manager: KeychainManager!

    override func setUpWithError() throws {
        try super.setUpWithError()
        auditRecorder = InMemoryAuditRecorder()
        manager = makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
    }

    private func makeHostKeyAndSig(priv: Curve25519.Signing.PrivateKey, sessionID: Data) throws -> (keyBlob: Data, sigBlob: Data) {
        var keyBlob = Data()
        keyBlob.appendWireString("ssh-ed25519")
        keyBlob.appendWireData(priv.publicKey.rawRepresentation)

        let sigRaw = try priv.signature(for: sessionID)
        var sigBlob = Data()
        sigBlob.appendWireString("ssh-ed25519")
        sigBlob.appendWireData(sigRaw)

        return (keyBlob, sigBlob)
    }

    private func makeSessionBindPayload(
        extensionType: String = "session-bind@openssh.com",
        hostKeyBlob: Data,
        sessionID: Data,
        signatureBlob: Data,
        isForwarding: Bool
    ) -> Data {
        var payload = Data([27]) // SSH_AGENTC_EXTENSION
        payload.appendWireString(extensionType)
        payload.appendWireData(hostKeyBlob)
        payload.appendWireData(sessionID)
        payload.appendWireData(signatureBlob)
        payload.append(isForwarding ? 1 : 0)
        return payload
    }

    private func makeRegisterPayload(keyLabel: String, toolName: String, leaseMinutes: UInt32) -> Data {
        var payload = Data([SSHAgentServer.registerAgentSessionRequest])
        payload.appendWireString(keyLabel)
        payload.appendWireString(toolName)
        payload.appendWireUInt32(leaseMinutes)
        return payload
    }

    private func makeSignPayload(publicKeyBlob: Data, dataToSign: Data) -> Data {
        var payload = Data([13]) // SSH2_AGENTC_SIGN_REQUEST
        payload.appendWireData(publicKeyBlob)
        payload.appendWireData(dataToSign)
        payload.appendWireUInt32(0) // flags = 0
        return payload
    }

    func test_006_T5_verifiesEd25519AndEcdsa() throws {
        let msg = Data("session-bind-challenge-data".utf8)

        // 1. Ed25519
        let edPriv = Curve25519.Signing.PrivateKey()
        var edKeyBlob = Data()
        edKeyBlob.appendWireString("ssh-ed25519")
        edKeyBlob.appendWireData(edPriv.publicKey.rawRepresentation)

        let edSigRaw = try edPriv.signature(for: msg)
        var edSigBlob = Data()
        edSigBlob.appendWireString("ssh-ed25519")
        edSigBlob.appendWireData(edSigRaw)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: edSigBlob, message: msg))

        // 2. P-256
        let p256Priv = P256.Signing.PrivateKey()
        var p256KeyBlob = Data()
        p256KeyBlob.appendWireString("ecdsa-sha2-nistp256")
        p256KeyBlob.appendWireString("nistp256")
        p256KeyBlob.appendWireData(p256Priv.publicKey.x963Representation)

        let p256Sig = try p256Priv.signature(for: msg)
        var p256SigInner = Data()
        p256SigInner.append(Data.encodeSSHMPint(p256Sig.rawRepresentation.prefix(32)))
        p256SigInner.append(Data.encodeSSHMPint(p256Sig.rawRepresentation.suffix(32)))
        var p256SigBlob = Data()
        p256SigBlob.appendWireString("ecdsa-sha2-nistp256")
        p256SigBlob.appendWireData(p256SigInner)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: p256KeyBlob, signatureBlob: p256SigBlob, message: msg))

        // 3. P-384
        let p384Priv = P384.Signing.PrivateKey()
        var p384KeyBlob = Data()
        p384KeyBlob.appendWireString("ecdsa-sha2-nistp384")
        p384KeyBlob.appendWireString("nistp384")
        p384KeyBlob.appendWireData(p384Priv.publicKey.x963Representation)

        let p384Sig = try p384Priv.signature(for: msg)
        var p384SigInner = Data()
        p384SigInner.append(Data.encodeSSHMPint(p384Sig.rawRepresentation.prefix(48)))
        p384SigInner.append(Data.encodeSSHMPint(p384Sig.rawRepresentation.suffix(48)))
        var p384SigBlob = Data()
        p384SigBlob.appendWireString("ecdsa-sha2-nistp384")
        p384SigBlob.appendWireData(p384SigInner)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: p384KeyBlob, signatureBlob: p384SigBlob, message: msg))

        // 4. P-521
        let p521Priv = P521.Signing.PrivateKey()
        var p521KeyBlob = Data()
        p521KeyBlob.appendWireString("ecdsa-sha2-nistp521")
        p521KeyBlob.appendWireString("nistp521")
        p521KeyBlob.appendWireData(p521Priv.publicKey.x963Representation)

        let p521Sig = try p521Priv.signature(for: msg)
        var p521SigInner = Data()
        p521SigInner.append(Data.encodeSSHMPint(p521Sig.rawRepresentation.prefix(66)))
        p521SigInner.append(Data.encodeSSHMPint(p521Sig.rawRepresentation.suffix(66)))
        var p521SigBlob = Data()
        p521SigBlob.appendWireString("ecdsa-sha2-nistp521")
        p521SigBlob.appendWireData(p521SigInner)

        XCTAssertTrue(SSHHostKeyVerifier.verify(hostKeyBlob: p521KeyBlob, signatureBlob: p521SigBlob, message: msg))
    }

    func test_006_T5_rejectsBadSignature() throws {
        let msg = Data("session-bind-challenge-data".utf8)
        let edPriv = Curve25519.Signing.PrivateKey()
        var edKeyBlob = Data()
        edKeyBlob.appendWireString("ssh-ed25519")
        edKeyBlob.appendWireData(edPriv.publicKey.rawRepresentation)

        // Corrupted signature
        var badSigBlob = Data()
        badSigBlob.appendWireString("ssh-ed25519")
        badSigBlob.appendWireData(Data(repeating: 0xEE, count: 64))

        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: badSigBlob, message: msg))

        // Wrong message
        let validSig = try edPriv.signature(for: msg)
        var validSigBlob = Data()
        validSigBlob.appendWireString("ssh-ed25519")
        validSigBlob.appendWireData(validSig)
        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: validSigBlob, message: Data("different-msg".utf8)))
    }

    func test_006_T5_rejectsTypeMismatch() throws {
        let msg = Data("session-bind-challenge-data".utf8)
        let edPriv = Curve25519.Signing.PrivateKey()
        var edKeyBlob = Data()
        edKeyBlob.appendWireString("ssh-ed25519")
        edKeyBlob.appendWireData(edPriv.publicKey.rawRepresentation)

        // Signature says ecdsa-sha2-nistp256
        var mismatchSigBlob = Data()
        mismatchSigBlob.appendWireString("ecdsa-sha2-nistp256")
        mismatchSigBlob.appendWireData(Data(repeating: 0x00, count: 64))

        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: mismatchSigBlob, message: msg))
    }

    func test_006_T5_rejectsRSA() {
        let msg = Data("session-bind-challenge-data".utf8)
        var rsaKeyBlob = Data()
        rsaKeyBlob.appendWireString("ssh-rsa")
        rsaKeyBlob.appendWireData(Data(repeating: 0x01, count: 3)) // e
        rsaKeyBlob.appendWireData(Data(repeating: 0x02, count: 256)) // n

        var rsaSigBlob = Data()
        rsaSigBlob.appendWireString("ssh-rsa")
        rsaSigBlob.appendWireData(Data(repeating: 0x03, count: 256))

        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: rsaKeyBlob, signatureBlob: rsaSigBlob, message: msg))

        var rsaSha2KeyBlob = Data()
        rsaSha2KeyBlob.appendWireString("rsa-sha2-256")
        rsaSha2KeyBlob.appendWireData(Data(repeating: 0x01, count: 3))
        rsaSha2KeyBlob.appendWireData(Data(repeating: 0x02, count: 256))
        XCTAssertFalse(SSHHostKeyVerifier.verify(hostKeyBlob: rsaSha2KeyBlob, signatureBlob: rsaSigBlob, message: msg))
    }

    func test_006_T5_rejectsDuplicateSessionAndRebind() throws {
        let state = AgentConnectionState()
        let priv1 = Curve25519.Signing.PrivateKey()
        let sessionID1 = Data("session-1".utf8)
        let (keyBlob1, sig1) = try makeHostKeyAndSig(priv: priv1, sessionID: sessionID1)

        // 1. Initial auth binding succeeds
        let b1 = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID1, isForwarding: false)
        XCTAssertTrue(state.bind(b1, signature: sig1))
        XCTAssertEqual(state.bindings.count, 1)
        XCTAssertEqual(state.authBinding, b1)
        XCTAssertFalse(state.hasForwarding)

        // 2. Duplicate session id is rejected
        let bDup = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID1, isForwarding: true)
        XCTAssertFalse(state.bind(bDup, signature: sig1))

        // 3. Rebinding non-forwarding (auth) connection is rejected
        let sessionID2 = Data("session-2".utf8)
        let (_, sig2) = try makeHostKeyAndSig(priv: priv1, sessionID: sessionID2)
        let bAuth2 = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID2, isForwarding: false)
        XCTAssertFalse(state.bind(bAuth2, signature: sig2))

        // 4. Forwarding binding with new session id succeeds
        let sessionID3 = Data("session-3".utf8)
        let (_, sig3) = try makeHostKeyAndSig(priv: priv1, sessionID: sessionID3)
        let bFwd = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID3, isForwarding: true)
        XCTAssertTrue(state.bind(bFwd, signature: sig3))
        XCTAssertTrue(state.hasForwarding)
        XCTAssertEqual(state.authBinding, b1)
        XCTAssertEqual(state.bindings.count, 2)
    }

    func test_006_AC5_signToUnlistedHostIsDenied() throws {
        let key = try manager.generateKey(label: "agent-host-key-1", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let hostA = Curve25519.Signing.PrivateKey()
        let hostB = Curve25519.Signing.PrivateKey()
        let sessionIDA = Data("session-host-a".utf8)
        let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)
        let (hostBKeyBlob, _) = try makeHostKeyAndSig(priv: hostB, sessionID: sessionIDA)

        let policyStore = InMemoryAgentPolicyStore()
        let policy = AgentKeyPolicy(allowedHosts: [
            AgentAllowedHost(name: "github.com", hostKeyBlob: hostBKeyBlob)
        ])
        try policyStore.save(policy, forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )
        let controlServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regResp = controlServer.processAgentRequest(
            payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Bind host A on connection
        let connection = AgentConnectionState()
        let bindPayload = makeSessionBindPayload(
            hostKeyBlob: hostAKeyBlob,
            sessionID: sessionIDA,
            signatureBlob: hostASig,
            isForwarding: false
        )
        let bindResp = server.processAgentRequest(
            payload: bindPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(bindResp.first, 6)

        // Try to sign to unlisted host A
        var dataToSign = Data()
        dataToSign.appendWireData(sessionIDA)
        dataToSign.append(Data("userauth-payload".utf8))
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(signResp.first, 5)

        let signAudit = auditRecorder.events.last { $0.type == .signature }
        XCTAssertEqual(signAudit?.result, .denied)
        XCTAssertEqual(signAudit?.reason, .hostNotAllowed)
    }

    func test_006_AC5_signToListedHostIsAllowed() throws {
        let key = try manager.generateKey(label: "agent-host-key-2", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let hostA = Curve25519.Signing.PrivateKey()
        let sessionIDA = Data("session-host-a".utf8)
        let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

        let policyStore = InMemoryAgentPolicyStore()
        let policy = AgentKeyPolicy(allowedHosts: [
            AgentAllowedHost(name: "github.com", hostKeyBlob: hostAKeyBlob)
        ])
        try policyStore.save(policy, forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )
        let controlServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regResp = controlServer.processAgentRequest(
            payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Bind host A on connection
        let connection = AgentConnectionState()
        let bindPayload = makeSessionBindPayload(
            hostKeyBlob: hostAKeyBlob,
            sessionID: sessionIDA,
            signatureBlob: hostASig,
            isForwarding: false
        )
        let bindResp = server.processAgentRequest(
            payload: bindPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(bindResp.first, 6)

        // Sign with data starting with sessionID
        var dataToSign = Data()
        dataToSign.appendWireData(sessionIDA)
        dataToSign.append(Data("userauth-payload".utf8))
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(signResp.first, 14) // SSH2_AGENT_SIGN_RESPONSE

        let signAudit = auditRecorder.events.last { $0.type == .signature }
        XCTAssertEqual(signAudit?.result, .allowed)
        XCTAssertEqual(signAudit?.reason, .viaAgentSession)
        XCTAssertEqual(signAudit?.sensitive.host, "github.com")
    }

    func test_006_AC5_unboundConnectionDeniedWhenHostsSet() throws {
        let key = try manager.generateKey(label: "agent-host-key-3", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let hostA = Curve25519.Signing.PrivateKey()
        let sessionIDA = Data("session-host-a".utf8)
        let (hostAKeyBlob, _) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

        let policyStore = InMemoryAgentPolicyStore()
        let policy = AgentKeyPolicy(allowedHosts: [
            AgentAllowedHost(name: "github.com", hostKeyBlob: hostAKeyBlob)
        ])
        try policyStore.save(policy, forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )
        let controlServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regResp = controlServer.processAgentRequest(
            payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Connection is unbound (no session-bind performed)
        let connection = AgentConnectionState()
        var dataToSign = Data()
        dataToSign.appendWireData(sessionIDA)
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(signResp.first, 5)

        let signAudit = auditRecorder.events.last { $0.type == .signature }
        XCTAssertEqual(signAudit?.result, .denied)
        XCTAssertEqual(signAudit?.reason, .hostNotAllowed)
    }

    func test_006_AC5_sessionIdMismatchDenied() throws {
        let key = try manager.generateKey(label: "agent-host-key-4", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let hostA = Curve25519.Signing.PrivateKey()
        let sessionIDA = Data("session-host-a".utf8)
        let sessionIDB = Data("session-host-b-mismatch".utf8)
        let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

        let policyStore = InMemoryAgentPolicyStore()
        let policy = AgentKeyPolicy(allowedHosts: [
            AgentAllowedHost(name: "github.com", hostKeyBlob: hostAKeyBlob)
        ])
        try policyStore.save(policy, forFingerprint: key.fingerprint)

        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )
        let controlServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regResp = controlServer.processAgentRequest(
            payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Bind host A with sessionIDA
        let connection = AgentConnectionState()
        let bindPayload = makeSessionBindPayload(
            hostKeyBlob: hostAKeyBlob,
            sessionID: sessionIDA,
            signatureBlob: hostASig,
            isForwarding: false
        )
        let bindResp = server.processAgentRequest(
            payload: bindPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(bindResp.first, 6)

        // Data to sign uses sessionIDB instead of sessionIDA
        var dataToSign = Data()
        dataToSign.appendWireData(sessionIDB)
        dataToSign.append(Data("userauth-payload".utf8))
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(signResp.first, 5)

        let signAudit = auditRecorder.events.last { $0.type == .signature }
        XCTAssertEqual(signAudit?.result, .denied)
        XCTAssertEqual(signAudit?.reason, .hostNotAllowed)
    }

    func test_006_T5_forwardingBindingRefusesSigning() throws {
        let key = try manager.generateKey(label: "agent-host-key-5", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let hostA = Curve25519.Signing.PrivateKey()
        let sessionIDA = Data("session-host-fwd".utf8)
        let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

        let policyStore = InMemoryAgentPolicyStore()
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )
        let controlServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regResp = controlServer.processAgentRequest(
            payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Bind forwarding session
        let connection = AgentConnectionState()
        let bindPayload = makeSessionBindPayload(
            hostKeyBlob: hostAKeyBlob,
            sessionID: sessionIDA,
            signatureBlob: hostASig,
            isForwarding: true
        )
        let bindResp = server.processAgentRequest(
            payload: bindPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(bindResp.first, 6)

        // Sign request should fail with forwardingRefused
        let dataToSign = Data("test-data".utf8)
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(signResp.first, 5)

        let signAudit = auditRecorder.events.last { $0.type == .signature }
        XCTAssertEqual(signAudit?.result, .denied)
        XCTAssertEqual(signAudit?.reason, .forwardingRefused)
    }

    func test_006_T5_emptyHostListAllowsUnbound() throws {
        let key = try manager.generateKey(label: "agent-host-key-6", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let policyStore = InMemoryAgentPolicyStore()
        let registry = AgentSessionRegistry(
            processInfo: { _ in (startTime: 1000, parentPid: 1) },
            auditRecorder: auditRecorder,
            watchRootExit: false
        )
        let server = SSHAgentServer(
            role: .agent,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )
        let controlServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            agentPolicies: policyStore
        )

        let regResp = controlServer.processAgentRequest(
            payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
            clientPid: getpid(),
            clientStartTime: 1000,
            isTrustedControlPeer: { true }
        )
        XCTAssertEqual(regResp.first, 6)

        // Clean unbound connection
        let connection = AgentConnectionState()
        let dataToSign = Data("test-data-for-unbound".utf8)
        let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

        let signResp = server.processAgentRequest(
            payload: signPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(signResp.first, 14)

        let signAudit = auditRecorder.events.last { $0.type == .signature }
        XCTAssertEqual(signAudit?.result, .allowed)
        XCTAssertEqual(signAudit?.reason, .viaAgentSession)
        XCTAssertNil(signAudit?.sensitive.host)
    }

    func test_006_T5_extensionOnPersonalSocketUnchanged() throws {
        let hostA = Curve25519.Signing.PrivateKey()
        let sessionIDA = Data("session-host-pers".utf8)
        let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

        let personalServer = SSHAgentServer(
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder
        )

        let connection = AgentConnectionState()
        let bindPayload = makeSessionBindPayload(
            hostKeyBlob: hostAKeyBlob,
            sessionID: sessionIDA,
            signatureBlob: hostASig,
            isForwarding: false
        )

        let resp = personalServer.processAgentRequest(
            payload: bindPayload,
            clientPid: getpid(),
            clientStartTime: 1000,
            connection: connection
        )
        XCTAssertEqual(resp.first, 5)
    }
}
