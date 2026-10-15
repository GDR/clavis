import Testing
import CryptoKit
import LocalAuthentication
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport

final class InteractionCheckingPrivateKeyStore: PrivateKeyStoring, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()
    private(set) var loadCallCount = 0

    func contains(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values[label] != nil
    }

    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = []) throws {
        lock.lock()
        defer { lock.unlock() }
        values[label] = data
    }

    func load(label: String, context: LAContext, prompt: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        loadCallCount += 1
        if context.interactionNotAllowed {
            // Emulate Keychain failure when interaction is not allowed: errSecInteractionNotAllowed (-25308)
            throw PrivateKeyStoreError.keychain(errSecInteractionNotAllowed)
        }
        return values[label]
    }

    func remove(label: String, context: LAContext?, prompt: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: label)
    }
}

@Suite("AgentSessionTests")
struct AgentSessionTests {

    @Test
    func test_F02_authorizedSessionGrantSignsWithoutKeychainOrVaultReRead() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InteractionCheckingPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: store,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try manager.generateKey(
                label: "agent-grant-test-key",
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(
                key: key,
                prompt: "Authorize agent session"
            )

            #expect(store.loadCallCount == 1, "Initial authorization should load record exactly once")

            // Multiple signings during grant lease
            for i in 1...5 {
                let data = Data("payload-\(i)".utf8)
                let sigBlob = try grant.sign(data, using: manager)

                var reader = DataReader(data: sigBlob)
                #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
                let rawSigData = reader.readWireData()
                let rawSig = try #require(rawSigData, "Missing signature in wire blob")
                #expect(rawSig.count > 64)
            }

            // Must NOT have re-read privateKeyStore or EncryptedVaultStore for each signature
            #expect(
                store.loadCallCount == 1,
                "Authorized grant must sign using grant-scoped hardware signer without re-invoking privateKeyStore.load"
            )
        }
    }

    @Test
    func test_F02_grantZeroizesBufferOnInvalidate() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InteractionCheckingPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: store,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try manager.generateKey(
                label: "agent-grant-zeroize-key",
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(
                key: key,
                prompt: "Authorize agent session"
            )

            #expect(grant.isValid, "Grant must be active before invalidation")

            grant.invalidate()

            #expect(!grant.isValid, "Grant must be invalidated on invalidate()")
            #expect {
                try grant.sign(Data("test".utf8), using: manager)
            } throws: { error in
                (error as? AgentSessionGrantError) == .grantInvalidated
            }
        }
    }

    @Test
    func test_F02_concurrentSigningsDoNotMutateLAContextLocalizedReason() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try fixture.runSync {
            let store = InteractionCheckingPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: store,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try manager.generateKey(
                label: "agent-grant-concurrent-key",
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(
                key: key,
                prompt: "Authorize agent session"
            )

            let iterationCount = 20
            let group = DispatchGroup()
            let failureLock = NSLock()
            var failures: [String] = []

            let context = fixture.context
            for i in 0..<iterationCount {
                group.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    defer { group.leave() }
                    TestContextScope.$current.withValue(context) {
                        do {
                            let payload = Data("concurrent-payload-\(i)".utf8)
                            let sigBlob = try grant.sign(payload, using: manager)
                            var reader = DataReader(data: sigBlob)
                            guard reader.readWireString() == "ecdsa-sha2-nistp256",
                                  let rawSig = reader.readWireData(),
                                  rawSig.count > 64 else {
                                failureLock.lock()
                                failures.append("Invalid signature in worker \(i)")
                                failureLock.unlock()
                                return
                            }
                        } catch {
                            failureLock.lock()
                            failures.append("Worker \(i) threw: \(error)")
                            failureLock.unlock()
                        }
                    }
                }
            }

            #expect(group.wait(timeout: .now() + 5.0) == .success)
            #expect(failures.isEmpty, "Concurrent signings failed: \(failures.joined(separator: ", "))")
            #expect(store.loadCallCount == 1, "Concurrent signings must not re-query privateKeyStore")
        }
    }

    @Test
    func test_F02_ecdsaP256SessionGrantSignsUsingHardwareSigner() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InteractionCheckingPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: store,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try manager.generateKey(
                label: "p256-grant-test-key",
                algorithm: "ECDSA P-256",
                storageType: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(
                key: key,
                prompt: "Authorize agent session"
            )

            #expect(store.loadCallCount == 1, "Initial authorization should load record exactly once")
            #expect(grant.isValid, "Grant must be active before invalidation")

            for i in 1...5 {
                let data = Data("p256-payload-\(i)".utf8)
                let sigBlob = try grant.sign(data, using: manager)

                var reader = DataReader(data: sigBlob)
                #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
                let innerData = reader.readWireData()
                #expect(innerData != nil)
                #expect((innerData?.count ?? 0) > 64)
            }

            #expect(store.loadCallCount == 1, "ECDSA P-256 grant signing must use grant-scoped signer without store reload")

            grant.invalidate()
            #expect(!grant.isValid)
            #expect(throws: (any Error).self) {
                try grant.sign(Data("fail".utf8), using: manager)
            }
        }
    }

    @Test
    func test_F02_hardwareGrantSignsViaHardwareSignerWithoutKeychainReRead() throws {
        final class Counter: @unchecked Sendable {
            var value = 0
        }
        let counter = Counter()
        let hardwareSigner: @Sendable (Data) throws -> Data = { payload in
            counter.value += 1
            var sigBlob = Data()
            sigBlob.appendWireString("ecdsa-sha2-nistp256")
            sigBlob.appendWireData(Data(repeating: 0x77, count: 64))
            return sigBlob
        }
        let grant = AgentSessionGrant(
            key: SSHKeyInfo(
                label: "mock-se-key",
                publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA...",
                publicKeyBlob: Data(repeating: 0x11, count: 65),
                fingerprint: "SHA256:mock",
                createdAt: Date(),
                algorithmName: "ECDSA P-256",
                storage: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            ),
            context: LAContext(),
            hardwareSigner: hardwareSigner
        )

        for i in 1...3 {
            let sig = try grant.sign(Data("payload-\(i)".utf8))
            var reader = DataReader(data: sig)
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
        }

        #expect(counter.value == 3)

        grant.invalidate()
        #expect(throws: (any Error).self) {
            try grant.sign(Data("fail".utf8))
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["CLAVIS_RUN_SECURE_ENCLAVE_INTEGRATION_TESTS"] == "1" && PlatformSupport.hasSecureEnclave))
    func test_F02_secureEnclaveSessionGrantSignsWithoutKeychainOrVaultReRead() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let store = InteractionCheckingPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: store,
                auditRecorder: InMemoryAuditRecorder()
            )

            let key = try manager.generateKey(
                label: "se-grant-test-key",
                storageType: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(
                key: key,
                prompt: "Authorize SE agent session"
            )

            #expect(store.loadCallCount == 1, "Initial authorization should load record once")

            for i in 1...3 {
                let data = Data("se-payload-\(i)".utf8)
                let sigBlob = try grant.sign(data, using: manager)

                var reader = DataReader(data: sigBlob)
                #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
                let innerData = reader.readWireData()
                #expect(innerData != nil)
            }

            #expect(store.loadCallCount == 1, "SE grant signing must sign directly without uncached keychain re-reads")

            grant.invalidate()
            #expect(throws: (any Error).self) {
                try grant.sign(Data("fail".utf8), using: manager)
            }
        }
    }

    @Test
    func testAgentSessionGrantEnforcesInteractionNotAllowedAndInvalidationAtSigningBoundary() async throws {
        let fixture = try ClavisTestFixture()
        defer {
            KeychainManager.customSigningProvider = nil
            fixture.cleanup()
        }
        try await fixture.run {
            final class TrackableAuthenticator: UserAuthenticating, @unchecked Sendable {
                let context: TrackableLAContext
                init(context: TrackableLAContext) {
                    self.context = context
                }
                func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) throws -> LAContext {
                    context
                }
                func authenticate(reason: String, policy: LAPolicy = .deviceOwnerAuthentication) async throws -> LAContext {
                    context
                }
            }

            final class ContextRecorder: @unchecked Sendable {
                private let lock = NSLock()
                private(set) var contexts: [LAContext?] = []

                func append(_ context: LAContext?) {
                    lock.lock()
                    defer { lock.unlock() }
                    contexts.append(context)
                }
            }

            let recorder = ContextRecorder()
            let trackableContext = TrackableLAContext()
            let signingProvider = InMemorySecureEnclaveSigningProvider { context in
                recorder.append(context)
                if context == nil
                    || context?.interactionNotAllowed != true
                    || (context as? TrackableLAContext)?.isInvalidated == true {
                    throw LAError(.invalidContext)
                }
            }
            KeychainManager.customSigningProvider = signingProvider

            let keyManager = fixture.makeKeyManager(
                authenticator: TrackableAuthenticator(context: trackableContext),
                privateKeyStore: InteractionCheckingPrivateKeyStore(),
                signingProvider: signingProvider
            )

            let key = try keyManager.generateKey(
                label: "agent-grant-boundary-validation-key",
                storageType: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try keyManager.authorizeAgentSession(
                key: key,
                prompt: "Authorize agent session"
            )

            let sigBlob = try grant.sign(Data("payload".utf8))
            var reader = DataReader(data: sigBlob)
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            #expect(reader.readWireData() != nil)
            #expect(recorder.contexts.count == 1)
            #expect(recorder.contexts.first as? TrackableLAContext === trackableContext)
            #expect(trackableContext.interactionNotAllowed)
            #expect(!trackableContext.isInvalidated)

            grant.invalidate()
            #expect(trackableContext.isInvalidated)
            #expect(throws: (any Error).self) {
                try grant.sign(Data("payload".utf8))
            }
        }
    }
}
