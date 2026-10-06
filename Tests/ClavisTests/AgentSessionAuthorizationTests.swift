import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore

final class AgentSessionAuthorizationTests: ClavisBaseTestCase {
    func test_001_T2_approvalPromptsOnce() throws {
        let authenticator = CountingAuthenticator()
        let manager = makeKeyManager(authenticator: authenticator)
        let key = try manager.generateKey(
            label: "test-agent-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(
            key: key,
            prompt: ClavisUIStrings.AgentSession.approvePrompt(tool: "/usr/local/bin/agent-tool", keyLabel: key.label, minutes: 480)
        )

        XCTAssertEqual(authenticator.authenticationCount, 1)

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKeyBlob.subdata(in: 19..<51))

        for i in 1...5 {
            let data = Data("payload-\(i)".utf8)
            let sigBlob = try grant.sign(data, using: manager)

            var reader = DataReader(data: sigBlob)
            XCTAssertEqual(reader.readWireString(), "ssh-ed25519")
            guard let rawSig = reader.readWireData() else {
                XCTFail("Missing signature in wire blob")
                return
            }
            XCTAssertTrue(pubKey.isValidSignature(rawSig, for: data))
        }

        // Still exactly 1 prompt after 5 signatures
        XCTAssertEqual(authenticator.authenticationCount, 1)
    }

    func test_001_T2_approvalRefusesPersonalKey() throws {
        let authenticator = CountingAuthenticator()
        let manager = makeKeyManager(authenticator: authenticator)
        let personalKey = try manager.generateKey(
            label: "test-personal-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        XCTAssertThrowsError(try manager.authorizeAgentSession(key: personalKey, prompt: "approve prompt")) { error in
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.general))
        }

        // Never prompted
        XCTAssertEqual(authenticator.authenticationCount, 0)
    }

    func test_001_T2_tamperedIndexAgentPurposeIsRefused() throws {
        let authenticator = CountingAuthenticator()
        let manager = makeKeyManager(authenticator: authenticator)
        let personalKey = try manager.generateKey(
            label: "test-tampered-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        // Tamper with public index so index claims it is an agent key
        let tamperedKey = Ed25519KeyInfo(
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

        XCTAssertThrowsError(try manager.authorizeAgentSession(key: tamperedKey, prompt: "approve prompt")) { error in
            XCTAssertEqual(error as? KeyPurposeError, .notAllowedOnThisPath(.general))
        }
    }

    func test_001_T2_invalidatedGrantFails() throws {
        let authenticator = AllowingAuthenticator()
        let manager = makeKeyManager(authenticator: authenticator)
        let key = try manager.generateKey(
            label: "test-invalidation-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(key: key, prompt: "approve prompt")
        grant.invalidate()

        XCTAssertThrowsError(try grant.sign(Data("test".utf8), using: manager)) { error in
            XCTAssertEqual(error as? AgentSessionGrantError, .grantInvalidated)
        }
    }

    func test_001_C1_grantExposesNoKeyMaterial() throws {
        let authenticator = AllowingAuthenticator()
        let manager = makeKeyManager(authenticator: authenticator)
        let key = try manager.generateKey(
            label: "test-c1-key",
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(key: key, prompt: "approve prompt")
        let mirror = Mirror(reflecting: grant)

        for child in mirror.children {
            guard let label = child.label else { continue }
            XCTAssertFalse(child.value is Data, "Property \(label) must not be Data")
            XCTAssertFalse(String(describing: type(of: child.value)).contains("StoredPrivateKeyRecord"), "Property \(label) must not expose StoredPrivateKeyRecord")
            XCTAssertFalse(String(describing: type(of: child.value)).contains("PrivateKey"), "Property \(label) must not expose PrivateKey")
        }
    }
}
