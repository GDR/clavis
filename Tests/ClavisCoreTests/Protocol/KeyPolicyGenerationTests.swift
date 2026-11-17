import Foundation
import Testing
import LocalAuthentication
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite struct KeyPolicyGenerationTests {
    private func key(label: String = "key", fingerprint: String = "fp") -> SSHKeyInfo {
        SSHKeyInfo(label: label, publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: fingerprint)
    }

    private func access(_ generations: KeyPolicyGenerations) -> ApplicationRequestAuthorization {
        ApplicationRequestAuthorization(store: GenerationRegistry(), resolver: .init(
            inspect: { _ in nil }, verify: { _, _ in false }, transparentHelper: { _ in false }), generations: generations)
    }

    @Test func copiedGenerationDoesNotValidateAnotherFingerprint() {
        let generations = KeyPolicyGenerations()
        let token = generations.current(for: key())
        #expect(!generations.matches(fingerprint: "different-key", generation: token))
    }

    @Test func unchangedKeyKeepsGeneration() {
        let generations = KeyPolicyGenerations()
        let key = key()
        let initial = generations.current(for: key)
        #expect(generations.current(for: key) == initial)
        #expect(generations.matches(fingerprint: key.fingerprint, generation: initial))
    }

    @Test func invalidatingOneKeyDoesNotChangeAnotherKey() {
        let generations = KeyPolicyGenerations()
        let first = key(label: "first", fingerprint: "one")
        let second = key(label: "second", fingerprint: "two")
        let original = generations.current(for: first)
        let unaffected = generations.current(for: second)
        generations.invalidate(label: first.label)
        #expect(!generations.matches(fingerprint: first.fingerprint, generation: original))
        #expect(generations.matches(fingerprint: second.fingerprint, generation: unaffected))
    }

    @Test func renameCannotRestoreOldGeneration() {
        let generations = KeyPolicyGenerations()
        let old = key(label: "old")
        let initial = generations.current(for: old)
        _ = generations.current(for: key(label: "new"))
        generations.invalidate(label: "old")
        #expect(generations.current(for: key(label: "new")) != initial)
        #expect(!generations.matches(fingerprint: old.fingerprint, generation: initial))
    }

    @Test func changingAwayAndBackNeverRevalidatesPendingLease() throws {
        let generations = KeyPolicyGenerations()
        let authorizer = access(generations)
        let key = key()
        let lease = try authorizer.authorize(key: key, operation: .ssh, role: .personal, pid: 2, path: "/peer", start: 7)
        #expect(try authorizer.validate(lease, pid: 2, path: "/peer", start: 7))
        generations.invalidate(label: key.label)
        generations.invalidate(label: key.label)
        #expect(try !authorizer.validate(lease, pid: 2, path: "/peer", start: 7))
        let fresh = try authorizer.authorize(key: key, operation: .ssh, role: .personal, pid: 2, path: "/peer", start: 7)
        #expect(try authorizer.validate(fresh, pid: 2, path: "/peer", start: 7))
    }

    @Test func generationsAreSharedAcrossEndpointAuthorizers() throws {
        let generations = KeyPolicyGenerations()
        let primary = access(generations)
        let compatibility = access(generations)
        let bot = SSHKeyInfo(label: "bot", publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: "fp", accessProfile: .init(type: .bot, capabilities: .init(ssh: true, signature: true)))
        let first = try primary.authorize(key: bot, operation: .ssh, role: .personal, pid: 2, path: "/peer", start: 7)
        let second = try compatibility.authorize(key: bot, operation: .signature, role: .agent, pid: 2, path: "/peer", start: 7)
        generations.invalidate(label: bot.label)
        #expect(try !primary.validate(first, pid: 2, path: "/peer", start: 7))
        #expect(try !compatibility.validate(second, pid: 2, path: "/peer", start: 7))
    }

    @Test func leaseWithoutGenerationCannotPassProductionValidation() throws {
        let authorizer = access(KeyPolicyGenerations())
        let lease = ApplicationRequestLease(eligibility: .authenticatedOnceOnly, revision: GenerationRegistry.revision, caller: nil)
        #expect(try !authorizer.validate(lease, pid: 2, path: "/peer", start: 7))
    }

    @Test func trustedKeyRevocationAdvancesGenerationWithoutChangingRegistry() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let generations = KeyPolicyGenerations()
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "revoked-key")
            let registry = GenerationRegistry()
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), applicationRegistry: registry,
                keyPolicyGenerations: generations, keyManager: manager, auditRecorder: InMemoryAuditRecorder())
            let old = generations.current(for: key)
            var payload = Data([SSHAgentServer.invalidateKeyRequest])
            payload.appendWireString(key.label)
            #expect(server.processAgentRequest(payload: payload, isTrustedControlPeer: { true }) == Data([6]))
            #expect(!generations.matches(fingerprint: key.fingerprint, generation: old))
            #expect(try registry.load().revision == GenerationRegistry.revision)
        }
    }

    @Test func untrustedRevocationCannotAdvanceGeneration() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let generations = KeyPolicyGenerations()
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "untrusted-revoke")
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(), keyPolicyGenerations: generations,
                keyManager: manager, auditRecorder: InMemoryAuditRecorder())
            let old = generations.current(for: key)
            var payload = Data([SSHAgentServer.invalidateKeyRequest])
            payload.appendWireString(key.label)
            #expect(server.processAgentRequest(payload: payload, isTrustedControlPeer: { false }) == Data([5]))
            #expect(generations.matches(fingerprint: key.fingerprint, generation: old))
        }
    }
    @Test(arguments: [false, true])
    func actualPolicyABADuringPromptDropsOldRequestAndAllowsFreshRetry(capabilities: Bool) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let generations = KeyPolicyGenerations()
            let manager = fixture.makeKeyManager(agentGrantRevoker: { generations.invalidate(label: $0) })
            let key = try manager.generateKey(label: "policy-aba")
            var changed = false
            let auth = GenerationMutationAuthenticator {
                guard !changed else { return }
                changed = true
                if capabilities {
                    try manager.changeAccessProfile(label: key.label, capabilities: .init(ssh: false, signature: true))
                    try manager.changeAccessProfile(label: key.label, capabilities: key.effectiveAccessProfile.capabilities)
                } else {
                    try manager.changeAccessProfile(label: key.label, type: .bot)
                    try manager.changeAccessProfile(label: key.label, type: .personal)
                }
            }
            let recorder = InMemoryAuditRecorder()
            let evaluator = SigningPolicyEvaluator(applicationAccess: access(generations), keyManager: manager,
                auditRecorder: recorder, authenticator: auth, peerProcessValidator: { _, _, _ in true })
            let old = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0,
                role: .personal, clientPid: getpid(), clientExecutablePath: "/peer", clientStartTime: 7)
            #expect(old == .dropConnection)
            #expect(try manager.fetchKeyInfo(label: key.label)?.effectiveAccessProfile == key.effectiveAccessProfile)
            let retry = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: Data("ssh".utf8), flags: 0,
                role: .personal, clientPid: getpid(), clientExecutablePath: "/peer", clientStartTime: 7)
            guard case .approved = retry else { Issue.record("Fresh request should use current generation"); return }
            #expect(recorder.events.filter { $0.type == .signature }.map(\.result) == [.denied, .allowed])
        }
    }

    @Test func daemonRestartCannotAcceptPriorProcessLease() throws {
        let oldAuthorizer = access(KeyPolicyGenerations())
        let lease = try oldAuthorizer.authorize(key: key(), operation: .ssh, role: .personal, pid: 2, path: "/peer", start: 7)
        let restarted = access(KeyPolicyGenerations())
        _ = try restarted.authorize(key: key(), operation: .ssh, role: .personal, pid: 2, path: "/peer", start: 7)
        #expect(try !restarted.validate(lease, pid: 2, path: "/peer", start: 7))
    }

    @Test func concurrentInvalidationAlwaysRejectsOriginalGeneration() async {
        let generations = KeyPolicyGenerations()
        let key = key()
        let original = generations.current(for: key)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<32 {
                group.addTask {
                    generations.invalidate(label: key.label)
                    _ = generations.current(for: key)
                }
            }
        }
        #expect(!generations.matches(fingerprint: key.fingerprint, generation: original))
        let final = generations.current(for: key)
        #expect(generations.matches(fingerprint: key.fingerprint, generation: final))
    }

    @Test func renameRevocationWorksAfterOldPublicIndexDisappears() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let generations = KeyPolicyGenerations()
            let old = key(label: "old-label")
            let epoch = generations.current(for: old)
            let server = SSHAgentServer(applicationAccess: TestApplicationAccess(),
                keyPolicyGenerations: generations, keyManager: fixture.makeKeyManager(),
                auditRecorder: InMemoryAuditRecorder())
            var payload = Data([SSHAgentServer.invalidateKeyRequest])
            payload.appendWireString(old.label)
            #expect(server.processAgentRequest(payload: payload, isTrustedControlPeer: { true }) == Data([6]))
            #expect(!generations.matches(fingerprint: old.fingerprint, generation: epoch))
            #expect(generations.current(for: key(label: "new-label")) != epoch)
        }
    }

}

private struct GenerationRegistry: ApplicationRegistryStoring {
    static let revision = UUID()
    func load() throws -> ApplicationRegistrySnapshot { .init(revision: Self.revision) }
    func save(_ snapshot: ApplicationRegistrySnapshot, replacing revision: UUID) throws { throw ApplicationRegistryError.staleRevision }
}

private struct GenerationMutationAuthenticator: UserAuthenticating {
    let action: () throws -> Void
    func authenticate(reason: String, policy: LAPolicy) throws -> LAContext {
        try action()
        return LAContext()
    }
    func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext {
        try action()
        return LAContext()
    }
}
