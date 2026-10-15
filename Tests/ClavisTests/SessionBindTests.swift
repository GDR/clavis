import Testing
import CryptoKit
import Foundation
@testable import ClavisCore

@Suite("SessionBindTests")
struct SessionBindTests {
    private let fixture: ClavisTestFixture
    private let auditRecorder: InMemoryAuditRecorder
    private let manager: KeychainManager

    init() throws {
        self.fixture = try ClavisTestFixture()
        let recorder = InMemoryAuditRecorder()
        self.auditRecorder = recorder
        self.manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: recorder)
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

    @Test
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

        #expect(SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: edSigBlob, message: msg))

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

        #expect(SSHHostKeyVerifier.verify(hostKeyBlob: p256KeyBlob, signatureBlob: p256SigBlob, message: msg))

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

        #expect(SSHHostKeyVerifier.verify(hostKeyBlob: p384KeyBlob, signatureBlob: p384SigBlob, message: msg))

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

        #expect(SSHHostKeyVerifier.verify(hostKeyBlob: p521KeyBlob, signatureBlob: p521SigBlob, message: msg))
    }

    @Test
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

        #expect(!SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: badSigBlob, message: msg))

        // Wrong message
        let validSig = try edPriv.signature(for: msg)
        var validSigBlob = Data()
        validSigBlob.appendWireString("ssh-ed25519")
        validSigBlob.appendWireData(validSig)
        #expect(!SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: validSigBlob, message: Data("different-msg".utf8)))
    }

    @Test
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

        #expect(!SSHHostKeyVerifier.verify(hostKeyBlob: edKeyBlob, signatureBlob: mismatchSigBlob, message: msg))
    }

    @Test
    func test_006_T5_rejectsRSA() {
        let msg = Data("session-bind-challenge-data".utf8)
        var rsaKeyBlob = Data()
        rsaKeyBlob.appendWireString("ssh-rsa")
        rsaKeyBlob.appendWireData(Data(repeating: 0x01, count: 3)) // e
        rsaKeyBlob.appendWireData(Data(repeating: 0x02, count: 256)) // n

        var rsaSigBlob = Data()
        rsaSigBlob.appendWireString("ssh-rsa")
        rsaSigBlob.appendWireData(Data(repeating: 0x03, count: 256))

        #expect(!SSHHostKeyVerifier.verify(hostKeyBlob: rsaKeyBlob, signatureBlob: rsaSigBlob, message: msg))

        var rsaSha2KeyBlob = Data()
        rsaSha2KeyBlob.appendWireString("rsa-sha2-256")
        rsaSha2KeyBlob.appendWireData(Data(repeating: 0x01, count: 3))
        rsaSha2KeyBlob.appendWireData(Data(repeating: 0x02, count: 256))
        #expect(!SSHHostKeyVerifier.verify(hostKeyBlob: rsaSha2KeyBlob, signatureBlob: rsaSigBlob, message: msg))
    }

    @Test
    func test_006_T5_rejectsDuplicateSessionAndRebind() throws {
        let state = AgentConnectionState()
        let priv1 = Curve25519.Signing.PrivateKey()
        let sessionID1 = Data("session-1".utf8)
        let (keyBlob1, sig1) = try makeHostKeyAndSig(priv: priv1, sessionID: sessionID1)

        // 1. Initial auth binding succeeds
        let b1 = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID1, isForwarding: false)
        #expect(state.bind(b1, signature: sig1))
        #expect(state.bindings.count == 1)
        #expect(state.authBinding == b1)
        #expect(!state.hasForwarding)

        // 2. Duplicate session id is rejected
        let bDup = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID1, isForwarding: true)
        #expect(!state.bind(bDup, signature: sig1))

        // 3. Rebinding non-forwarding (auth) connection is rejected
        let sessionID2 = Data("session-2".utf8)
        let (_, sig2) = try makeHostKeyAndSig(priv: priv1, sessionID: sessionID2)
        let bAuth2 = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID2, isForwarding: false)
        #expect(!state.bind(bAuth2, signature: sig2))

        // 4. Forwarding binding with new session id succeeds
        let sessionID3 = Data("session-3".utf8)
        let (_, sig3) = try makeHostKeyAndSig(priv: priv1, sessionID: sessionID3)
        let bFwd = SessionBinding(hostKeyBlob: keyBlob1, sessionID: sessionID3, isForwarding: true)
        #expect(state.bind(bFwd, signature: sig3))
        #expect(state.hasForwarding)
        #expect(state.authBinding == b1)
        #expect(state.bindings.count == 2)
    }

    @Test
    func test_006_AC5_signToUnlistedHostIsDenied() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-host-key-1", biometricPolicy: .userPresence, keyPurpose: .agent)
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
            #expect(regResp.first == 6)

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
            #expect(bindResp.first == 6)

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
            #expect(signResp.first == 5)

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .denied)
            #expect(signAudit?.reason == .hostNotAllowed)
        }
    }

    @Test
    func test_006_AC5_signToListedHostIsAllowed() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-host-key-2", biometricPolicy: .userPresence, keyPurpose: .agent)
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
            #expect(regResp.first == 6)

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
            #expect(bindResp.first == 6)

            // Sign with valid RFC 4252 data starting with sessionID
            let dataToSign = SSHAgentServerTests.makeSSH2UserAuthRequest(
                sessionID: sessionIDA,
                user: "git",
                service: "ssh-connection",
                method: "publickey",
                hasSig: true,
                algo: "ssh-ed25519",
                keyBlob: key.publicKeyBlob
            )
            let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

            let signResp = server.processAgentRequest(
                payload: signPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(signResp.first == 14) // SSH2_AGENT_SIGN_RESPONSE

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .allowed)
            #expect(signAudit?.reason == .viaAgentSession)
            #expect(signAudit?.sensitive.host == "github.com")
        }
    }

    @Test
    func test_006_AC5_unboundConnectionDeniedWhenHostsSet() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-host-key-3", biometricPolicy: .userPresence, keyPurpose: .agent)
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
            #expect(regResp.first == 6)

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
            #expect(signResp.first == 5)

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .denied)
            #expect(signAudit?.reason == .hostNotAllowed)
        }
    }

    @Test
    func test_006_AC5_sessionIdMismatchDenied() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-host-key-4", biometricPolicy: .userPresence, keyPurpose: .agent)
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
            #expect(regResp.first == 6)

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
            #expect(bindResp.first == 6)

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
            #expect(signResp.first == 5)

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .denied)
            #expect(signAudit?.reason == .hostNotAllowed)
        }
    }

    @Test
    func test_006_T5_forwardingBindingRefusesSigning() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-host-key-5", biometricPolicy: .userPresence, keyPurpose: .agent)
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
            #expect(regResp.first == 6)

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
            #expect(bindResp.first == 6)

            // Sign request should fail with forwardingRefused
            let dataToSign = Data("test-data".utf8)
            let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

            let signResp = server.processAgentRequest(
                payload: signPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(signResp.first == 5)

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .denied)
            #expect(signAudit?.reason == .forwardingRefused)
        }
    }

    @Test
    func test_006_T5_emptyHostListAllowsUnbound() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-host-key-6", biometricPolicy: .userPresence, keyPurpose: .agent)
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
            #expect(regResp.first == 6)

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
            #expect(signResp.first == 14)

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .allowed)
            #expect(signAudit?.reason == .viaAgentSession)
            #expect(signAudit?.sensitive.host == nil)
        }
    }

    @Test
    func test_F06_personalSocketAcceptsSessionBindOpcode27() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
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
            #expect(resp.first == 6, "Personal socket must accept session-bind@openssh.com")
            #expect(connection.authBinding?.sessionID == sessionIDA)
            #expect(connection.authBinding?.hostKeyBlob == hostAKeyBlob)
            #expect(!connection.hasForwarding)

            // Bind forwarding on personal socket
            let sessionIDFwd = Data("session-host-pers-fwd".utf8)
            let (_, hostAFwdSig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDFwd)
            let bindFwdPayload = makeSessionBindPayload(
                hostKeyBlob: hostAKeyBlob,
                sessionID: sessionIDFwd,
                signatureBlob: hostAFwdSig,
                isForwarding: true
            )
            let respFwd = personalServer.processAgentRequest(
                payload: bindFwdPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(respFwd.first == 6)
            #expect(connection.hasForwarding)
        }
    }

    @Test
    func test_F06_agentSocketRejectsForwardingUnconditionallyEvenWithEmptyAllowedHosts() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-fwd-unconditional", biometricPolicy: .userPresence, keyPurpose: .agent)
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

            // Session registered with default policy (allowedHosts is empty)
            let regResp = controlServer.processAgentRequest(
                payload: makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60),
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(regResp.first == 6)

            // Connection has forwarding
            let hostA = Curve25519.Signing.PrivateKey()
            let sessionIDA = Data("session-fwd-empty-hosts".utf8)
            let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

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
            #expect(bindResp.first == 6)
            #expect(connection.hasForwarding)

            // Even though allowedHosts is empty, agent socket rejects forwarding unconditionally
            let dataToSign = Data("test-data".utf8)
            let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: dataToSign)

            let signResp = server.processAgentRequest(
                payload: signPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(signResp.first == 5, "Agent socket must reject signing when connection has forwarding, even with empty allowedHosts")

            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .denied)
            #expect(signAudit?.reason == .forwardingRefused)
        }
    }

    @Test
    func test_F06_agentSocketVerifiesRFC4252PacketStructureWhenAllowedHostsNonEmpty() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-rfc4252-verify", biometricPolicy: .userPresence, keyPurpose: .agent)
            let hostA = Curve25519.Signing.PrivateKey()
            let sessionIDA = Data("session-host-rfc4252".utf8)
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
            #expect(regResp.first == 6)

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
            #expect(bindResp.first == 6)

            // 1. dataToSign starts with sessionID prefix, but body is raw string (NOT RFC 4252)
            var rawDataToSign = Data()
            rawDataToSign.appendWireData(sessionIDA)
            rawDataToSign.append(Data("raw-non-rfc4252-payload".utf8))
            let rawSignPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: rawDataToSign)

            let rawSignResp = server.processAgentRequest(
                payload: rawSignPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(rawSignResp.first == 5, "Non-RFC 4252 payload must be rejected when allowedHosts is non-empty")
            let rawAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(rawAudit?.result == .denied)
            #expect(rawAudit?.reason == .hostNotAllowed)

            // 2. dataToSign is valid RFC 4252 userauth request
            let validUserAuthData = SSHAgentServerTests.makeSSH2UserAuthRequest(
                sessionID: sessionIDA,
                user: "git",
                service: "ssh-connection",
                method: "publickey",
                hasSig: true,
                algo: "ssh-ed25519",
                keyBlob: key.publicKeyBlob
            )
            let validSignPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: validUserAuthData)

            let validSignResp = server.processAgentRequest(
                payload: validSignPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(validSignResp.first == 14, "Valid RFC 4252 payload matching sessionID and keyBlob must be allowed")
            let validAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(validAudit?.result == .allowed)
            #expect(validAudit?.sensitive.host == "github.com")
        }
    }

    // MARK: - F2 & F5 Security Audit Tests

    private func makeRSAHostKeyAndSig(
        privKey existingPrivKey: SecKey? = nil,
        keyType: String = "ssh-rsa",
        sigType: String = "rsa-sha2-512",
        algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA512,
        message: Data
    ) throws -> (privKey: SecKey, keyBlob: Data, sigBlob: Data) {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privKey = existingPrivKey ?? SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let pubKey = SecKeyCopyPublicKey(privKey),
              let derCFData = SecKeyCopyExternalRepresentation(pubKey, &error) else {
            throw NSError(domain: "SessionBindTests", code: 1)
        }
        let der = derCFData as Data
        let (nBytes, eBytes) = try Self.parsePKCS1RSAPublicKeyDER(der)

        var keyBlob = Data()
        keyBlob.appendWireString(keyType)
        keyBlob.append(Data.encodeSSHMPint(eBytes))
        keyBlob.append(Data.encodeSSHMPint(nBytes))

        guard let rawSig = SecKeyCreateSignature(privKey, algorithm, message as CFData, &error) as Data? else {
            throw NSError(domain: "SessionBindTests", code: 2)
        }
        var sigBlob = Data()
        sigBlob.appendWireString(sigType)
        sigBlob.appendWireData(rawSig)

        return (privKey, keyBlob, sigBlob)
    }

    private static func parsePKCS1RSAPublicKeyDER(_ der: Data) throws -> (n: Data, e: Data) {
        var idx = 0
        func readTagAndLength(expectedTag: UInt8) throws -> Int {
            guard idx < der.count, der[idx] == expectedTag else {
                throw NSError(domain: "DER", code: 1)
            }
            idx += 1
            guard idx < der.count else { throw NSError(domain: "DER", code: 2) }
            let firstLen = Int(der[idx])
            idx += 1
            if (firstLen & 0x80) == 0 {
                return firstLen
            }
            let numBytes = firstLen & 0x7F
            guard numBytes > 0, numBytes <= 2, idx + numBytes <= der.count else {
                throw NSError(domain: "DER", code: 3)
            }
            var len = 0
            for _ in 0..<numBytes {
                len = (len << 8) | Int(der[idx])
                idx += 1
            }
            return len
        }

        let seqLen = try readTagAndLength(expectedTag: 0x30)
        guard idx + seqLen == der.count else { throw NSError(domain: "DER", code: 4) }
        let nLen = try readTagAndLength(expectedTag: 0x02)
        guard idx + nLen <= der.count else { throw NSError(domain: "DER", code: 5) }
        let n = der.subdata(in: idx..<(idx + nLen))
        idx += nLen
        let eLen = try readTagAndLength(expectedTag: 0x02)
        guard idx + eLen == der.count else { throw NSError(domain: "DER", code: 6) }
        let e = der.subdata(in: idx..<(idx + eLen))
        return (n, e)
    }

    @Test
    func test_F2_verifiesRSAHostKeyWithSHA256AndSHA512() throws {
        let sessionID = Data("rsa-session-bind-challenge".utf8)

        // OpenSSH server with "ssh-rsa" key blob signing with "rsa-sha2-512"
        let (privKey, key512, sig512) = try makeRSAHostKeyAndSig(
            keyType: "ssh-rsa",
            sigType: "rsa-sha2-512",
            algorithm: .rsaSignatureMessagePKCS1v15SHA512,
            message: sessionID
        )
        #expect(SSHHostKeyVerifier.verify(hostKeyBlob: key512, signatureBlob: sig512, message: sessionID))

        let state512 = AgentConnectionState()
        let binding512 = SessionBinding(hostKeyBlob: key512, sessionID: sessionID, isForwarding: false)
        #expect(state512.bind(binding512, signature: sig512))
        #expect(!state512.hasFailedBind)
        #expect(state512.authBinding == binding512)

        // OpenSSH server with "ssh-rsa" key blob signing with "rsa-sha2-256"
        let (_, key256, sig256) = try makeRSAHostKeyAndSig(
            privKey: privKey,
            keyType: "ssh-rsa",
            sigType: "rsa-sha2-256",
            algorithm: .rsaSignatureMessagePKCS1v15SHA256,
            message: sessionID
        )
        #expect(SSHHostKeyVerifier.verify(hostKeyBlob: key256, signatureBlob: sig256, message: sessionID))

        // Corrupted RSA signature must fail
        var badSig = sig256
        badSig[badSig.count - 1] ^= 0xFF
        #expect(!SSHHostKeyVerifier.verify(hostKeyBlob: key256, signatureBlob: badSig, message: sessionID))
    }

    @Test
    func test_F2_failedSessionBindFailsClosedOnAgentAndPersonalSockets() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let agentKey = try manager.generateKey(label: "agent-fail-closed-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let hostA = Curve25519.Signing.PrivateKey()
            let sessionIDA = Data("session-fail-closed".utf8)
            let (hostAKeyBlob, _) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)

            // Bad signature for session-bind
            var badSigBlob = Data()
            badSigBlob.appendWireString("ssh-ed25519")
            badSigBlob.appendWireData(Data(repeating: 0xAA, count: 64))

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
                payload: makeRegisterPayload(keyLabel: agentKey.label, toolName: "agent-tool", leaseMinutes: 60),
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(regResp.first == 6)

            // Attempt session-bind with bad signature (e.g. forwarding bind that fails verification)
            let connection = AgentConnectionState()
            let bindPayload = makeSessionBindPayload(
                hostKeyBlob: hostAKeyBlob,
                sessionID: sessionIDA,
                signatureBlob: badSigBlob,
                isForwarding: true
            )
            let bindResp = server.processAgentRequest(
                payload: bindPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(bindResp.first == 5)
            #expect(connection.hasFailedBind)
            #expect(!connection.hasForwarding)

            // Subsequent sign on agent socket MUST be denied with .forwardingRefused even when allowedHosts is empty
            let signPayload = makeSignPayload(publicKeyBlob: agentKey.publicKeyBlob, dataToSign: Data("some-data".utf8))
            let signResp = server.processAgentRequest(
                payload: signPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(signResp.first == 5)
            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .denied)
            #expect(signAudit?.reason == .forwardingRefused)
        }
    }

    @Test
    func test_F5_hostboundUserAuthRequestAcceptedAndHostKeyVerified() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let key = try manager.generateKey(label: "agent-hostbound-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let hostA = Curve25519.Signing.PrivateKey()
            let hostB = Curve25519.Signing.PrivateKey()
            let sessionIDA = Data("session-hostbound-a".utf8)
            let (hostAKeyBlob, hostASig) = try makeHostKeyAndSig(priv: hostA, sessionID: sessionIDA)
            let (hostBKeyBlob, _) = try makeHostKeyAndSig(priv: hostB, sessionID: sessionIDA)

            // Build publickey-hostbound-v00@openssh.com userauth request
            var hostboundData = SSHAgentServerTests.makeSSH2UserAuthRequest(
                sessionID: sessionIDA,
                user: "git",
                service: "ssh-connection",
                method: "publickey-hostbound-v00@openssh.com",
                hasSig: true,
                algo: "ssh-ed25519",
                keyBlob: key.publicKeyBlob
            )
            hostboundData.appendWireData(hostAKeyBlob)

            // 1. Unit check on SessionBind.isValidSSH2UserAuthRequest
            #expect(
                SessionBind.isValidSSH2UserAuthRequest(
                    hostboundData,
                    expectedSessionID: sessionIDA,
                    expectedKeyBlob: key.publicKeyBlob,
                    expectedHostKeyBlob: hostAKeyBlob
                )
            )
            #expect(
                !SessionBind.isValidSSH2UserAuthRequest(
                    hostboundData,
                    expectedSessionID: sessionIDA,
                    expectedKeyBlob: key.publicKeyBlob,
                    expectedHostKeyBlob: hostBKeyBlob
                ),
                "Mismatched expectedHostKeyBlob must be rejected"
            )

            // 2. End-to-end check on agent socket with allowedHosts
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
            #expect(regResp.first == 6)

            let connection = AgentConnectionState()
            let bindPayload = makeSessionBindPayload(
                hostKeyBlob: hostAKeyBlob,
                sessionID: sessionIDA,
                signatureBlob: hostASig,
                isForwarding: false
            )
            #expect(
                server.processAgentRequest(
                    payload: bindPayload,
                    clientPid: getpid(),
                    clientStartTime: 1000,
                    connection: connection
                ).first == 6
            )

            let signResp = server.processAgentRequest(
                payload: makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: hostboundData),
                clientPid: getpid(),
                clientStartTime: 1000,
                connection: connection
            )
            #expect(signResp.first == 14, "publickey-hostbound-v00@openssh.com must be allowed when hostKeyBlob matches authBinding")
            let signAudit = auditRecorder.events.last { $0.type == .signature }
            #expect(signAudit?.result == .allowed)
            #expect(signAudit?.sensitive.host == "github.com")
        }
    }
}
