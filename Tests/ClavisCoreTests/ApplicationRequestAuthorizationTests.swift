import Foundation
import LocalAuthentication
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct ApplicationRequestAuthorizationTests {
    private func setup(_ classification: ApplicationClassification?, start: UInt64 = 7) throws -> (RequestRegistry, ApplicationRequestAuthorization) {
        let identity = try ApplicationIdentity(kind: .designatedRequirement, value: "test-caller")
        let app = RegisteredApplication(identity: identity, name: "Caller", path: "/caller", classification: classification ?? .block)
        let store = RequestRegistry(.init(applications: classification == nil ? [] : [app]))
        let resolver = ApplicationCallerResolver(
            inspect: { pid in .init(pid: pid, parent: 1, start: start, path: "/caller") },
            verify: { _, _ in true }, transparentHelper: { _ in false }
        )
        return (store, ApplicationRequestAuthorization(store: store, resolver: resolver))
    }

    @Test(arguments: ApplicationClassification.allCases, [KeyPurpose.general, .agent])
    func directSigningMatrix(_ classification: ApplicationClassification, _ purpose: KeyPurpose) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let (_, access) = try setup(classification)
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "matrix", keyPurpose: purpose)
            let evaluator = SigningPolicyEvaluator(applicationAccess: access, keyManager: manager, authenticator: auth, peerProcessValidator: { _, _, _ in true })
            let decision = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0, role: .personal, clientPid: getpid(), clientExecutablePath: "/caller", clientStartTime: 7)
            let allowed = classification == .personal || (classification == .bot && purpose == .agent)
            if allowed {
                guard case .approved = decision else { Issue.record("Expected approved direct request"); return }
            } else {
                #expect(decision == .denied)
                #expect(auth.authenticationCount == 0)
            }
        }
    }

    @Test func uncertainCallerAuthenticatesEveryRequestWithoutCreatingGrant() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let (_, access) = try setup(nil)
            let auth = CountingAuthenticator()
            let grants = GitSigningGraceManager(observeSystemEvents: false)
            let manager = fixture.makeKeyManager(authenticator: auth, gitSigningGraceManager: grants)
            let key = try manager.generateKey(label: "once")
            let evaluator = SigningPolicyEvaluator(applicationAccess: access, keyManager: manager, gitSigningGraceManager: grants, authenticator: auth, peerProcessValidator: { _, _, _ in true })
            for _ in 0..<2 {
                let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0, role: .personal, clientPid: getpid(), clientExecutablePath: "/caller", clientStartTime: 7)
                guard case .approved = result else { Issue.record("Expected authenticated one-shot request"); return }
            }
            #expect(auth.authenticationCount == 2)
            #expect(auth.lastPolicy == .deviceOwnerAuthentication)
            #expect(auth.lastReason?.contains("identity is uncertain") == true)
            #expect(grants.allActiveGrants().isEmpty)
        }
    }

    @Test(arguments: [ApplicationClassification.personal, .bot, .block])
    func identitiesAreFilteredByVerifiedCaller(_ classification: ApplicationClassification) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let pid = getpid()
            let start = try #require(ProcessInspector.processStartTime(pid: pid))
            let (_, access) = try setup(classification, start: start)
            let manager = fixture.makeKeyManager()
            _ = try manager.generateKey(label: "personal")
            _ = try manager.generateKey(label: "bot", keyPurpose: .agent)
            let server = SSHAgentServer(applicationAccess: access, keyManager: manager)
            let response = server.handleRequestIdentities(clientPid: pid, clientExecutablePath: "/caller")
            var reader = DataReader(data: Data(response.dropFirst()))
            let expected: UInt32 = classification == .personal ? 2 : (classification == .bot ? 1 : 0)
            #expect(reader.readUInt32() == expected)
            let unknown = SSHAgentServer(applicationAccess: try setup(nil, start: start).1, keyManager: manager)
            let unknownResponse = unknown.handleRequestIdentities(clientPid: pid, clientExecutablePath: "/caller")
            var unknownReader = DataReader(data: Data(unknownResponse.dropFirst()))
            #expect(unknownReader.readUInt32() == 0)
        }
    }

    @Test func compatibilityEndpointDeniesPersonalEvenForPersonalCaller() throws {
        let (_, access) = try setup(.personal)
        let key = SSHKeyInfo(label: "personal", publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: "")
        #expect(try access.authorize(key: key, operation: .ssh, role: .agent, pid: 100, path: "/caller", start: 7).eligibility == .denied)
    }

    @Test func policyChangeDuringPromptDropsSignature() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let (store, access) = try setup(nil)
            let auth = ChangingRequestAuthenticator { store.replace(.init()) }
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "changed")
            let evaluator = SigningPolicyEvaluator(applicationAccess: access, keyManager: manager, authenticator: auth, peerProcessValidator: { _, _, _ in true })
            #expect(try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0, role: .personal, clientPid: getpid(), clientExecutablePath: "/caller", clientStartTime: 7) == .dropConnection)
        }
    }

    @Test func uncertainCallerCannotReuseExistingGrantOrEscalationHistory() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let (_, access) = try setup(nil)
            let auth = CountingAuthenticator()
            let grants = GitSigningGraceManager(observeSystemEvents: false)
            let manager = fixture.makeKeyManager(authenticator: auth, gitSigningGraceManager: grants)
            let key = try manager.generateKey(label: "no-cache")
            let pid = getpid()
            let snapshot = try #require(ProcessInspector.processParentSnapshot(pid: pid))
            grants.recordGrant(keyLabel: key.label, clientIdentity: "/caller", duration: 300, maxOperations: 100, context: LAContext(), approvedProcess: .init(pid: pid, startTime: snapshot.startTime, path: "/caller"))
            grants.recordGitSignature(for: key.label, clientIdentity: "/caller")
            let evaluator = SigningPolicyEvaluator(applicationAccess: access, keyManager: manager, gitSigningGraceManager: grants, authenticator: auth, peerProcessValidator: { _, _, _ in true })
            let payload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 0x42, count: 32)).serialize()
            _ = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: payload, flags: 0, role: .personal, clientPid: pid, clientExecutablePath: "/caller", clientStartTime: 7)
            #expect(auth.authenticationCount == 1)
            #expect(grants.allActiveGrants().first?.remainingOperations == 100)
        }
    }
}

private final class RequestRegistry: ApplicationRegistryStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: ApplicationRegistrySnapshot
    init(_ snapshot: ApplicationRegistrySnapshot) { self.snapshot = snapshot }
    func load() throws -> ApplicationRegistrySnapshot { lock.lock(); defer { lock.unlock() }; return snapshot }
    func save(_ snapshot: ApplicationRegistrySnapshot, replacing revision: UUID) throws { replace(snapshot) }
    func replace(_ snapshot: ApplicationRegistrySnapshot) { lock.lock(); defer { lock.unlock() }; self.snapshot = snapshot }
}
private struct ChangingRequestAuthenticator: UserAuthenticating {
    let action: () -> Void
    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext { action(); return LAContext() }
    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext { action(); return LAContext() }
}
