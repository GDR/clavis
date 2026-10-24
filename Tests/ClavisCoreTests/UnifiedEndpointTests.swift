import Foundation
import LocalAuthentication
import CryptoKit
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct UnifiedEndpointTests {
    private func access(_ classification: ApplicationClassification?, paused: Bool = false) throws -> ApplicationRequestAuthorization {
        let identity = try ApplicationIdentity(kind: .designatedRequirement, value: "verified-caller")
        let app = RegisteredApplication(identity: identity, name: "Verified Bot", path: "/verified", classification: classification ?? .block)
        let store = EndpointRegistry(.init(applications: classification == nil ? [] : [app], requestsPaused: paused))
        return ApplicationRequestAuthorization(store: store, resolver: ApplicationCallerResolver(
            inspect: { pid in .init(pid: pid, parent: 1, start: ProcessInspector.processStartTime(pid: pid) ?? 7, path: "/verified") },
            verify: { _, _ in true }, transparentHelper: { _ in false }))
    }

    @Test(arguments: ApplicationClassification.allCases, KeyType.allCases)
    func bothOperationsRespectMatrixOnBothEndpoints(classification: ApplicationClassification, type: KeyType) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "matrix", accessProfile: .init(type: type, capabilities: .init(ssh: true, signature: true)))
            let gate = try access(classification)
            for role in [AgentSocketRole.personal, .agent] {
                let grants = GitSigningGraceManager(observeSystemEvents: false)
                let evaluator = SigningPolicyEvaluator(applicationAccess: gate, keyManager: manager,
                    gitSigningGraceManager: grants, auditRecorder: InMemoryAuditRecorder(), authenticator: auth,
                    peerProcessValidator: { _, _, _ in true })
                for operation in KeyOperation.allCases {
                    let payload = operation == .ssh ? Data("ssh".utf8) : SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 1, count: 32)).serialize()
                    let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: payload, flags: 0, role: role, clientPid: getpid(), clientExecutablePath: "/verified", clientStartTime: ProcessInspector.processStartTime(pid: getpid()))
                    let permitted = classification != .block && (classification == .personal || type == .bot) && (role == .personal || type == .bot)
                    if permitted {
                        guard case .approved = result else { Issue.record("Expected approval for \(classification), \(type), \(role), \(operation)"); continue }
                    } else { #expect(result == .denied) }
                }
            }
        }
    }

    @Test(arguments: [AgentSocketRole.personal, .agent])
    func disabledOperationDeniesBeforeAuthentication(role: AgentSocketRole) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "disabled", accessProfile: .init(type: .bot, capabilities: .init(ssh: false, signature: false)))
            let evaluator = SigningPolicyEvaluator(applicationAccess: try access(.personal), keyManager: manager, auditRecorder: InMemoryAuditRecorder(), authenticator: auth)
            for payload in [Data("ssh".utf8), Data("SSHSIGanything".utf8)] {
                #expect(try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: payload, flags: 0, role: role, clientPid: getpid(), clientExecutablePath: "/verified", clientStartTime: 7) == .denied)
            }
            #expect(auth.authenticationCount == 0)
        }
    }

    @Test func compatibilityDoesNotRequireWrapperForNewBotProfile() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "new-bot", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
            let evaluator = SigningPolicyEvaluator(applicationAccess: try access(.bot), keyManager: manager, auditRecorder: InMemoryAuditRecorder(), peerProcessValidator: { _, _, _ in true })
            let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0, role: .agent, clientPid: getpid(), clientExecutablePath: "/verified", clientStartTime: ProcessInspector.processStartTime(pid: getpid()))
            guard case .approved = result else { Issue.record("New Bot profiles must work without a legacy registered session"); return }
        }
    }

    @Test(arguments: [AgentSocketRole.personal, .agent])
    func pauseDeniesEnumerationAndDirectRequests(role: AgentSocketRole) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "paused", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
            let gate = try access(.personal, paused: true)
            let server = SSHAgentServer(applicationAccess: gate, role: role, keyManager: manager)
            let response = server.handleRequestIdentities(clientPid: getpid(), clientExecutablePath: "/verified")
            var reader = DataReader(data: Data(response.dropFirst()))
            #expect(reader.readUInt32() == 0)
            let evaluator = SigningPolicyEvaluator(applicationAccess: gate, keyManager: manager, auditRecorder: InMemoryAuditRecorder(), authenticator: auth)
            #expect(try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0, role: role, clientPid: getpid(), clientExecutablePath: "/verified", clientStartTime: 7) == .denied)
            #expect(auth.authenticationCount == 0)
        }
    }

    @Test func keyFiltersUseTypeRatherThanLegacyPurpose() {
        let bot = SSHKeyInfo(label: "bot", publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: "bot", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
        #expect(KeyKindFilter.apply(.agent, to: [bot]) == [bot])
        #expect(KeyKindFilter.apply(.personal, to: [bot]).isEmpty)
        #expect(AgentSocketRole.agent.permits(bot))
    }
    @Test(arguments: [AgentSocketRole.personal, .agent])
    func uncertainCallerIsAlwaysOneShotOnBotKeys(role: AgentSocketRole) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let grants = GitSigningGraceManager(observeSystemEvents: false)
            let manager = fixture.makeKeyManager(authenticator: auth, gitSigningGraceManager: grants)
            let key = try manager.generateKey(label: "exact-requested-key", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
            let evaluator = SigningPolicyEvaluator(applicationAccess: try access(nil), keyManager: manager,
                gitSigningGraceManager: grants, auditRecorder: InMemoryAuditRecorder(), authenticator: auth, peerProcessValidator: { _, _, _ in true })
            for _ in 0..<2 {
                let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob,
                    dataToSign: Data("ssh".utf8), flags: 0, role: role, clientPid: getpid(),
                    clientExecutablePath: "/verified", clientStartTime: ProcessInspector.processStartTime(pid: getpid()))
                guard case .approved = result else { Issue.record("Expected authenticated once-only approval"); return }
            }
            #expect(auth.authenticationCount == 2)
            #expect(auth.lastReason?.contains(key.label) == true)
            #expect(auth.lastReason?.contains("uncertain") == true)
            #expect(grants.allActiveGrants().isEmpty)
        }
    }

    @Test func verifiedPromptNamesCallerAndRequestedKey() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let recorder = InMemoryAuditRecorder()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "bot-signature", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
            let evaluator = SigningPolicyEvaluator(applicationAccess: try access(.bot), keyManager: manager,
                auditRecorder: recorder, authenticator: auth, peerProcessValidator: { _, _, _ in true })
            _ = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0,
                role: .personal, clientPid: getpid(), clientExecutablePath: "/verified", clientStartTime: ProcessInspector.processStartTime(pid: getpid()))
            #expect(auth.lastReason?.contains("Verified Bot") == true)
            #expect(auth.lastReason?.contains(key.label) == true)
            #expect(recorder.events.last?.keyKind == .agent)
        }
    }

    @Test func compatibilityRejectsForwardingForIndependentProfiles() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "forwarded", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
            let evaluator = SigningPolicyEvaluator(applicationAccess: try access(.bot), keyManager: manager, auditRecorder: InMemoryAuditRecorder(), authenticator: auth)
            let connection = ClientConnectionContext()
            let host = Curve25519.Signing.PrivateKey()
            let sessionID = Data("forwarded-session".utf8)
            var hostBlob = Data()
            hostBlob.appendWireString("ssh-ed25519")
            hostBlob.appendWireData(host.publicKey.rawRepresentation)
            var signature = Data()
            signature.appendWireString("ssh-ed25519")
            signature.appendWireData(try host.signature(for: sessionID))
            #expect(connection.bind(.init(hostKeyBlob: hostBlob, sessionID: sessionID, isForwarding: true), signature: signature))
            #expect(try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0,
                role: .agent, clientPid: getpid(), connection: connection, clientExecutablePath: "/verified", clientStartTime: 7) == .denied)
            #expect(auth.authenticationCount == 0)
        }
    }

    @Test func compatibilityEnumerationUsesIndependentType() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let bot = try manager.generateKey(label: "new-bot", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
            _ = try manager.generateKey(label: "personal")
            _ = try manager.generateKey(label: "signature-only", accessProfile: .init(type: .bot, capabilities: .init(ssh: false, signature: true)))
            let server = SSHAgentServer(applicationAccess: try access(.personal), role: .agent, keyManager: manager)
            let response = server.handleRequestIdentities(clientPid: getpid(), clientExecutablePath: "/verified")
            var reader = DataReader(data: Data(response.dropFirst()))
            #expect(reader.readUInt32() == 1)
            #expect(reader.readWireData() == bot.publicKeyBlob)
            #expect(reader.readWireString() == bot.label)
            #expect(reader.isEOF)
        }
    }

    @Test func compatibilityRejectsEveryControlOpcodeEvenFromTrustedPeer() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let server = SSHAgentServer(applicationAccess: try access(.personal), role: .agent, keyManager: fixture.makeKeyManager())
            for opcode in UInt8.min...UInt8.max where AgentControlDispatcher.isControlOpcode(opcode) {
                #expect(server.processAgentRequest(payload: Data([opcode]), clientPid: getpid(),
                    clientExecutablePath: "/verified", clientStartTime: 7, isTrustedControlPeer: { true }) == Data([5]))
            }
        }
    }

}

private final class EndpointRegistry: ApplicationRegistryStoring, @unchecked Sendable {
    let snapshot: ApplicationRegistrySnapshot
    init(_ snapshot: ApplicationRegistrySnapshot) { self.snapshot = snapshot }
    func load() throws -> ApplicationRegistrySnapshot { snapshot }
    func save(_ snapshot: ApplicationRegistrySnapshot, replacing revision: UUID) throws { throw ApplicationRegistryError.staleRevision }
}
