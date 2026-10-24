import Foundation
import LocalAuthentication
import Testing
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite(.serialized) struct KeyProfileMutationTests {
    private struct Rejecting: UserAuthenticating {
        func authenticate(reason: String, policy: LAPolicy) throws -> LAContext { throw LAError(.userCancel) }
        func authenticate(reason: String, policy: LAPolicy) async throws -> LAContext { throw LAError(.userCancel) }
    }

    @Test(arguments: KeyType.allCases)
    func generationPersistsIndependentProfile(type: KeyType) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(privateKeyStore: store)
            let profile = KeyAccessProfile(type: type, capabilities: .init(ssh: false, signature: true))
            let key = try manager.generateKey(label: "new-profile", accessProfile: profile)
            let raw = try #require(try store.load(label: key.label, context: LAContext(), prompt: ""))
            let record = try StoredPrivateKeyRecord.decode(from: raw)
            #expect(record.accessProfile == profile)
            #expect(key.effectiveAccessProfile == profile)
            #expect(try manager.fetchKeyInfo(label: key.label)?.effectiveAccessProfile == profile)
            #expect(throws: KeyAccessError.operationDisabled(.ssh)) {
                try manager.signSSH(key: key, data: Data("ssh".utf8), prompt: "")
            }
        }
    }

    @Test(arguments: KeyPurpose.allCases)
    func typeChangePreservesCapabilitiesAndMaterial(purpose: KeyPurpose) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth, privateKeyStore: store)
            let key = try manager.generateKey(label: "type-change", keyPurpose: purpose)
            let raw = try #require(try store.load(label: key.label, context: LAContext(), prompt: ""))
            let original = try StoredPrivateKeyRecord.decode(from: raw)
            let target: KeyType = key.effectiveAccessProfile.type == .bot ? .personal : .bot
            try manager.changeAccessProfile(label: key.label, type: target)
            let changed = try #require(try manager.fetchKeyInfo(label: key.label))
            let updated = try StoredPrivateKeyRecord.decode(from: #require(try store.load(label: key.label, context: LAContext(), prompt: "")))
            #expect(auth.authenticationCount == 1)
            #expect(changed.effectiveAccessProfile.type == target)
            #expect(changed.effectiveAccessProfile.capabilities == key.effectiveAccessProfile.capabilities)
            #expect(updated.accessProfile == changed.effectiveAccessProfile)
            #expect(updated.keyData == original.keyData)
            #expect(updated.createdAt == original.createdAt)
            #expect(changed.fingerprint == key.fingerprint)
            #expect(changed.publicKeyBlob == key.publicKeyBlob)
            if purpose == .gitSigningOnly { #expect(changed.purpose == .gitSigningOnly) }
        }
    }

    @Test func everyActualChangeAuthenticatesAndNoOpDoesNot() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth)
            let key = try manager.generateKey(label: "fresh-auth")
            try manager.changeAccessProfile(label: key.label, type: .personal)
            #expect(auth.authenticationCount == 0)
            try manager.changeAccessProfile(label: key.label, type: .bot)
            try manager.changeAccessProfile(label: key.label, capabilities: .init(ssh: true, signature: false))
            try manager.changeAccessProfile(label: key.label, type: .personal)
            #expect(auth.authenticationCount == 3)
            let fresh = try #require(try manager.fetchKeyInfo(label: key.label))
            #expect(fresh.effectiveAccessProfile.type == .personal)
            #expect(!fresh.effectiveAccessProfile.capabilities.signature)
        }
    }

    @Test func cancellationPreservesAllStoredPolicy() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(privateKeyStore: store)
            let key = try manager.generateKey(label: "cancel-policy")
            let raw = try store.load(label: key.label, context: LAContext(), prompt: "")
            let failing = fixture.makeKeyManager(authenticator: Rejecting(), privateKeyStore: store)
            #expect(throws: (any Error).self) {
                try failing.changeAccessProfile(label: key.label, type: .bot, capabilities: .init(ssh: false, signature: false))
            }
            #expect(try manager.fetchKeyInfo(label: key.label) == key)
            #expect(try store.load(label: key.label, context: LAContext(), prompt: "") == raw)
        }
    }

    @Test func disablingBothOperationsIsARealPersistedPolicy() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let manager = fixture.makeKeyManager()
            let key = try manager.generateKey(label: "disabled")
            try manager.changeAccessProfile(label: key.label, capabilities: .init(ssh: false, signature: false))
            let fresh = try #require(try manager.fetchKeyInfo(label: key.label))
            for operation in KeyOperation.allCases {
                #expect(throws: KeyAccessError.operationDisabled(operation)) {
                    try fresh.effectiveAccessProfile.require(operation)
                }
            }
        }
    }

    @Test func indexFailureRollsBackPrivateRecord() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(privateKeyStore: store)
            let key = try manager.generateKey(label: "rollback-profile")
            let raw = try store.load(label: key.label, context: LAContext(), prompt: "")
            PublicKeyStore.forcedSaveErrorForTesting = NSError(domain: "test", code: 1)
            defer { PublicKeyStore.forcedSaveErrorForTesting = nil }
            #expect(throws: (any Error).self) { try manager.changeAccessProfile(label: key.label, type: .bot) }
            #expect(try store.load(label: key.label, context: LAContext(), prompt: "") == raw)
            #expect(try manager.fetchKeyInfo(label: key.label) == key)
        }
    }
    @Test func revocationFailureDoesNotCommitNewPolicy() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let initial = fixture.makeKeyManager(privateKeyStore: store)
            let key = try initial.generateKey(label: "revoke-failure")
            let raw = try store.load(label: key.label, context: LAContext(), prompt: "")
            let manager = fixture.makeKeyManager(privateKeyStore: store,
                agentGrantRevoker: { _ in throw NSError(domain: "revocation", code: 1) })
            #expect(throws: (any Error).self) { try manager.changeAccessProfile(label: key.label, type: .bot) }
            #expect(try store.load(label: key.label, context: LAContext(), prompt: "") == raw)
            #expect(try initial.fetchKeyInfo(label: key.label) == key)
        }
    }

    @Test(arguments: [false, true])
    func strictKeyPolicyChangesUseSystemFallbackWithoutRelaxingSigningPolicy(legacy: Bool) async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InMemoryPrivateKeyStore()
            let auth = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: auth, privateKeyStore: store)
            let key = try manager.generateKey(label: "strict-policy", biometricPolicy: .biometryCurrentSet)
            if legacy { try manager.changeKind(label: key.label, to: .agent) }
            else { try manager.changeAccessProfile(label: key.label, type: .bot) }
            #expect(auth.lastPolicy == .deviceOwnerAuthentication)
            #expect(auth.authenticationCount == 1)
            let changed = try #require(try manager.fetchKeyInfo(label: key.label))
            #expect(changed.effectiveBiometricPolicy == .biometryCurrentSet)
            #expect(changed.effectiveAccessProfile.type == .bot)
            let raw = try #require(try store.load(label: key.label, context: LAContext(), prompt: ""))
            let record = try StoredPrivateKeyRecord.decode(from: raw)
            #expect(record.biometricPolicy == .biometryCurrentSet)
            #expect(record.accessProfile == changed.effectiveAccessProfile)
        }
    }

    @Test func explicitSignatureCapabilityOnLegacyBotDoesNotRequireOrReuseSSHSession() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auth = CountingAuthenticator()
            let grants = GitSigningGraceManager(observeSystemEvents: false)
            let manager = fixture.makeKeyManager(authenticator: auth, gitSigningGraceManager: grants)
            let original = try manager.generateKey(label: "legacy-bot-signature")
            try manager.changeKind(label: original.label, to: .agent)
            let key = try #require(try manager.fetchKeyInfo(label: original.label))
            #expect(key.effectiveAccessProfile.capabilities.signature)
            let evaluator = SigningPolicyEvaluator(applicationAccess: TestApplicationAccess(), keyManager: manager,
                gitSigningGraceManager: grants, auditRecorder: InMemoryAuditRecorder(), peerProcessValidator: { _, _, _ in true })
            let payload = SSHSIGPayload(namespace: "git", hashAlgorithm: "sha256", messageHash: Data(repeating: 1, count: 32)).serialize()
            let result = try evaluator.evaluateSigningRequest(keyBlob: key.publicKeyBlob, dataToSign: payload, flags: 0,
                role: .agent, clientPid: getpid(), clientExecutablePath: "/peer", clientStartTime: 7)
            guard case .approved = result else { Issue.record("Signature must use its own approval instead of a legacy SSH session"); return }
            #expect(auth.authenticationCount == 2)
            let grant = try manager.authorizeGitSigningGrant(key: key, prompt: "Approve Signature", clientIdentity: "caller")
            #expect(try !grant.sign(payload).isEmpty)
            try manager.changeAccessProfile(label: key.label, capabilities: .init(ssh: true, signature: false))
            #expect(grants.allActiveGrants().isEmpty)
        }
    }

}
