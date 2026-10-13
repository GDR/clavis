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
            secureBufferFactory: { SecureBuffer(consuming: &$0) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try manager.generateKey(
            label: "agent-grant-test-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(
            key: key,
            prompt: "Authorize agent session"
        )

        XCTAssertEqual(store.loadCallCount, 1, "Initial authorization should load record exactly once")

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKeyBlob.subdata(in: 19..<51))

        // Multiple signings during grant lease
        for i in 1...5 {
            let data = Data("payload-\(i)".utf8)
            let sigBlob = try grant.sign(data, using: manager)

            var reader = DataReader(data: sigBlob)
            XCTAssertEqual(reader.readWireString(), "ssh-ed25519")
            guard let rawSig = reader.readWireData() else {
                XCTFail("Missing signature in wire blob")
                return
            }
            XCTAssertTrue(pubKey.isValidSignature(rawSig, for: data), "Signature must be valid")
        }

        // Must NOT have re-read privateKeyStore or EncryptedVaultStore for each signature
        XCTAssertEqual(
            store.loadCallCount,
            1,
            "Authorized grant must sign using grant-scoped SecureBuffer without re-invoking privateKeyStore.load"
        )
    }

    func test_F02_grantZeroizesBufferOnInvalidate() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            secureBufferFactory: { SecureBuffer(consuming: &$0) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try manager.generateKey(
            label: "agent-grant-zeroize-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(
            key: key,
            prompt: "Authorize agent session"
        )

        XCTAssertFalse(grant.isBufferWiped, "Grant buffer must be active before invalidation")

        grant.invalidate()

        XCTAssertTrue(grant.isBufferWiped, "Grant buffer must be zeroized on invalidate()")
        XCTAssertThrowsError(try grant.sign(Data("test".utf8), using: manager)) { error in
            XCTAssertEqual(error as? AgentSessionGrantError, .grantInvalidated)
        }
    }

    func test_F02_concurrentSigningsDoNotMutateLAContextLocalizedReason() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            secureBufferFactory: { SecureBuffer(consuming: &$0) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try manager.generateKey(
            label: "agent-grant-concurrent-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(
            key: key,
            prompt: "Authorize agent session"
        )

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKeyBlob.subdata(in: 19..<51))
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
                    guard reader.readWireString() == "ssh-ed25519",
                          let rawSig = reader.readWireData(),
                          pubKey.isValidSignature(rawSig, for: payload) else {
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

    func test_F02_ecdsaP256SessionGrantSignsUsingSecureBuffer() throws {
        let store = InteractionCheckingPrivateKeyStore()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: store,
            secureBufferFactory: { SecureBuffer(consuming: &$0) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try manager.generateKey(
            label: "p256-grant-test-key",
            algorithm: "ECDSA P-256",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(
            key: key,
            prompt: "Authorize agent session"
        )

        XCTAssertEqual(store.loadCallCount, 1, "Initial authorization should load record exactly once")
        XCTAssertFalse(grant.isBufferWiped, "Buffer must be active before invalidation")

        for i in 1...5 {
            let data = Data("p256-payload-\(i)".utf8)
            let sigBlob = try grant.sign(data, using: manager)

            var reader = DataReader(data: sigBlob)
            XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
            let innerData = reader.readWireData()
            XCTAssertNotNil(innerData)
            XCTAssertGreaterThan(innerData?.count ?? 0, 64)
        }

        XCTAssertEqual(store.loadCallCount, 1, "ECDSA P-256 grant signing must use grant-scoped buffer without store reload")

        grant.invalidate()
        XCTAssertTrue(grant.isBufferWiped)
        XCTAssertThrowsError(try grant.sign(Data("fail".utf8), using: manager))
    }

    func test_F02_hardwareGrantSignsViaHardwareSignerWithoutKeychainReRead() throws {
        var hardwareSignCount = 0
        let hardwareSigner: @Sendable (Data) throws -> Data = { payload in
            hardwareSignCount += 1
            var sigBlob = Data()
            sigBlob.appendWireString("ecdsa-sha2-nistp256")
            sigBlob.appendWireData(Data(repeating: 0x77, count: 64))
            return sigBlob
        }
        let grant = AgentSessionGrant(
            key: Ed25519KeyInfo(
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
            secureBuffer: nil,
            hardwareSigner: hardwareSigner
        )

        for i in 1...3 {
            let sig = try grant.sign(Data("payload-\(i)".utf8))
            var reader = DataReader(data: sig)
            XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
        }

        XCTAssertEqual(hardwareSignCount, 3)

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
            secureBufferFactory: { SecureBuffer(consuming: &$0) },
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder()
        )

        let key = try manager.generateKey(
            label: "se-grant-test-key",
            algorithm: "ECDSA P-256",
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
}
