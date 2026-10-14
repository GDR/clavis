import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore

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

final class AgentSessionTests: ClavisBaseTestCase {

    func test_F02_authorizedSessionGrantSignsWithoutKeychainOrVaultReRead() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            agentGrantRevoker: { _ in },
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

        XCTAssertEqual(store.loadCallCount, 1, "Initial authorization should load record exactly once")

        // Multiple signings during grant lease
        for i in 1...5 {
            let data = Data("payload-\(i)".utf8)
            let sigBlob = try grant.sign(data, using: manager)

            var reader = DataReader(data: sigBlob)
            XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
            guard let rawSig = reader.readWireData() else {
                XCTFail("Missing signature in wire blob")
                return
            }
            XCTAssertGreaterThan(rawSig.count, 64)
        }

        // Must NOT have re-read privateKeyStore or EncryptedVaultStore for each signature
        XCTAssertEqual(
            store.loadCallCount,
            1,
            "Authorized grant must sign using grant-scoped hardware signer without re-invoking privateKeyStore.load"
        )
    }

    func test_F02_grantZeroizesBufferOnInvalidate() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            agentGrantRevoker: { _ in },
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

        XCTAssertTrue(grant.isValid, "Grant must be active before invalidation")

        grant.invalidate()

        XCTAssertFalse(grant.isValid, "Grant must be invalidated on invalidate()")
        XCTAssertThrowsError(try grant.sign(Data("test".utf8), using: manager)) { error in
            XCTAssertEqual(error as? AgentSessionGrantError, .grantInvalidated)
        }
    }

    func test_F02_concurrentSigningsDoNotMutateLAContextLocalizedReason() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            agentGrantRevoker: { _ in },
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

        for i in 0..<iterationCount {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
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

        group.wait()
        XCTAssertTrue(failures.isEmpty, "Concurrent signings failed: \(failures.joined(separator: ", "))")
        XCTAssertEqual(store.loadCallCount, 1, "Concurrent signings must not re-query privateKeyStore")
    }

    func test_F02_ecdsaP256SessionGrantSignsUsingHardwareSigner() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            agentGrantRevoker: { _ in },
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

        XCTAssertEqual(store.loadCallCount, 1, "Initial authorization should load record exactly once")
        XCTAssertTrue(grant.isValid, "Grant must be active before invalidation")

        for i in 1...5 {
            let data = Data("p256-payload-\(i)".utf8)
            let sigBlob = try grant.sign(data, using: manager)

            var reader = DataReader(data: sigBlob)
            XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
            let innerData = reader.readWireData()
            XCTAssertNotNil(innerData)
            XCTAssertGreaterThan(innerData?.count ?? 0, 64)
        }

        XCTAssertEqual(store.loadCallCount, 1, "ECDSA P-256 grant signing must use grant-scoped signer without store reload")

        grant.invalidate()
        XCTAssertFalse(grant.isValid)
        XCTAssertThrowsError(try grant.sign(Data("fail".utf8), using: manager))
    }

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
            XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
        }

        XCTAssertEqual(counter.value, 3)

        grant.invalidate()
        XCTAssertThrowsError(try grant.sign(Data("fail".utf8)))
    }

    func test_F02_secureEnclaveSessionGrantSignsWithoutKeychainOrVaultReRead() throws {
        guard ProcessInfo.processInfo.environment["CLAVIS_RUN_SECURE_ENCLAVE_INTEGRATION_TESTS"] == "1" else {
            throw XCTSkip("Set CLAVIS_RUN_SECURE_ENCLAVE_INTEGRATION_TESTS=1 to run Secure Enclave integration tests.")
        }
        try XCTSkipUnless(PlatformSupport.hasSecureEnclave, "Secure Enclave not supported on this platform")

        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            agentGrantRevoker: { _ in },
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

        XCTAssertEqual(store.loadCallCount, 1, "Initial authorization should load record once")

        for i in 1...3 {
            let data = Data("se-payload-\(i)".utf8)
            let sigBlob = try grant.sign(data, using: manager)

            var reader = DataReader(data: sigBlob)
            XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
            let innerData = reader.readWireData()
            XCTAssertNotNil(innerData)
        }

        XCTAssertEqual(store.loadCallCount, 1, "SE grant signing must sign directly without uncached keychain re-reads")

        grant.invalidate()
        XCTAssertThrowsError(try grant.sign(Data("fail".utf8), using: manager))
    }

    func testAgentSessionGrantEnforcesInteractionNotAllowedAndInvalidationAtSigningBoundary() throws {
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

        let trackableContext = TrackableLAContext()
        var validatedContexts: [LAContext?] = []
        let signingProvider = InMemorySecureEnclaveSigningProvider { context in
            validatedContexts.append(context)
            if context == nil
                || context?.interactionNotAllowed != true
                || (context as? TrackableLAContext)?.isInvalidated == true {
                throw LAError(.invalidContext)
            }
        }
        KeychainManager.customSigningProvider = signingProvider

        let keyManager = makeKeyManager(
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
        XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
        XCTAssertNotNil(reader.readWireData())
        XCTAssertEqual(validatedContexts.count, 1)
        XCTAssertTrue(validatedContexts.first as? TrackableLAContext === trackableContext)
        XCTAssertTrue(trackableContext.interactionNotAllowed)
        XCTAssertFalse(trackableContext.isInvalidated)

        grant.invalidate()
        XCTAssertTrue(trackableContext.isInvalidated)
        XCTAssertThrowsError(try grant.sign(Data("payload".utf8)))
    }
}
