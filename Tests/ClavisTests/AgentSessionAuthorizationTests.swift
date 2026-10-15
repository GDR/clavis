import Testing
import CryptoKit
import LocalAuthentication
import Foundation
@testable import ClavisCore

@Suite("AgentSessionAuthorizationTests")
struct AgentSessionAuthorizationTests {
    private let fixture: ClavisTestFixture

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    @Test
    func test_001_T2_approvalPromptsOnce() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: authenticator)
            let key = try manager.generateKey(
                label: "test-agent-key",
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(
                key: key,
                prompt: ClavisUIStrings.AgentSession.approvePrompt(tool: "/usr/local/bin/agent-tool", keyLabel: key.label, minutes: 480)
            )

            #expect(authenticator.authenticationCount == 1)

            for i in 1...5 {
                let data = Data("payload-\(i)".utf8)
                let sigBlob = try grant.sign(data, using: manager)

                var reader = DataReader(data: sigBlob)
                #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
                let signatureData = reader.readWireData()
                let rawSig = try #require(signatureData, "Missing signature in wire blob")
                #expect(rawSig.count > 64)
            }

            // Still exactly 1 prompt after 5 signatures
            #expect(authenticator.authenticationCount == 1)
        }
    }

    @Test
    func test_001_T2_approvalRefusesPersonalKey() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: authenticator)
            let personalKey = try manager.generateKey(
                label: "test-personal-key",
                biometricPolicy: .userPresence,
                keyPurpose: .general
            )

            #expect {
                try manager.authorizeAgentSession(key: personalKey, prompt: "approve prompt")
            } throws: { error in
                (error as? KeyPurposeError) == .notAllowedOnThisPath(.general)
            }

            // Never prompted
            #expect(authenticator.authenticationCount == 0)
        }
    }

    @Test
    func test_001_T2_tamperedIndexAgentPurposeIsRefused() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: authenticator)
            let personalKey = try manager.generateKey(
                label: "test-tampered-key",
                biometricPolicy: .userPresence,
                keyPurpose: .general
            )

            // Tamper with public index so index claims it is an agent key
            let tamperedKey = SSHKeyInfo(
                label: personalKey.label,
                publicKeyOpenSSH: personalKey.publicKeyOpenSSH,
                publicKeyBlob: personalKey.publicKeyBlob,
                fingerprint: personalKey.fingerprint,
                createdAt: personalKey.createdAt,
                algorithmName: personalKey.algorithmName,
                storage: personalKey.storage,
                biometricPolicy: personalKey.biometricPolicy,
                keyPurpose: .agent
            )
            PublicKeyStore.save(tamperedKey)

            #expect {
                try manager.authorizeAgentSession(key: tamperedKey, prompt: "approve prompt")
            } throws: { error in
                (error as? KeyPurposeError) == .notAllowedOnThisPath(.general)
            }
        }
    }

    @Test
    func test_001_T2_invalidatedGrantFails() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = AllowingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: authenticator)
            let key = try manager.generateKey(
                label: "test-invalidation-key",
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(key: key, prompt: "approve prompt")
            grant.invalidate()

            #expect {
                try grant.sign(Data("test".utf8), using: manager)
            } throws: { error in
                (error as? AgentSessionGrantError) == .grantInvalidated
            }
        }
    }

    @Test
    func test_001_C1_grantExposesNoKeyMaterial() async throws {
        defer { fixture.cleanup() }
        try await fixture.run {
            let authenticator = AllowingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: authenticator)
            let key = try manager.generateKey(
                label: "test-c1-key",
                biometricPolicy: .userPresence,
                keyPurpose: .agent
            )

            let grant = try manager.authorizeAgentSession(key: key, prompt: "approve prompt")
            let mirror = Mirror(reflecting: grant)

            for child in mirror.children {
                guard let label = child.label else { continue }
                #expect(!(child.value is Data), "Property \(label) must not be Data")
                #expect(!String(describing: type(of: child.value)).contains("StoredPrivateKeyRecord"), "Property \(label) must not expose StoredPrivateKeyRecord")
                #expect(!String(describing: type(of: child.value)).contains("PrivateKey"), "Property \(label) must not expose PrivateKey")
            }
        }
    }
}
