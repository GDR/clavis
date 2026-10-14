import XCTest
import Foundation
import CryptoKit
import Security
import LocalAuthentication
@testable import ClavisCore

final class KeySignerTests: ClavisBaseTestCase {

    // MARK: - Mock KeySigner

    private final class MockKeySigner: KeySigner, @unchecked Sendable {
        var generateKeyPairCalled = false
        var derivePublicKeyBlobCalled = false
        var verifyPublicKeyCalled = false
        var signSSHCalled = false

        var algorithm: KeyAlgorithm { .ecdsaP256 }
        var sshKeyType: String { "mock-key-type" }

        func generateKeyPair(
            label: String,
            accessControl: SecAccessControl,
            provider: SecureEnclaveSigningProviding
        ) throws -> GeneratedKeyPair {
            generateKeyPairCalled = true
            return GeneratedKeyPair(
                keyData: Data("mock-key-data".utf8),
                publicKeyBlob: Data("mock-public-blob".utf8)
            )
        }

        func derivePublicKeyBlob(
            record: StoredPrivateKeyRecord,
            context: LAContext?,
            provider: SecureEnclaveSigningProviding
        ) throws -> Data {
            derivePublicKeyBlobCalled = true
            return Data("mock-public-blob".utf8)
        }

        func verifyPublicKey(
            record: StoredPrivateKeyRecord,
            against key: SSHKeyInfo,
            context: LAContext,
            provider: SecureEnclaveSigningProviding
        ) throws {
            verifyPublicKeyCalled = true
            guard key.publicKeyBlob == Data("mock-public-blob".utf8) else {
                throw PrivateKeyRecordError.publicKeyMismatch
            }
        }

        func formatSSHSignatureBlob(rawSignature: Data) throws -> Data {
            var blob = Data()
            blob.appendWireString(sshKeyType)
            blob.appendWireData(rawSignature)
            return blob
        }

        func signSSH(
            data: Data,
            keyData: Data,
            context: LAContext?,
            provider: SecureEnclaveSigningProviding
        ) throws -> Data {
            signSSHCalled = true
            return try formatSSHSignatureBlob(rawSignature: Data("mock-signature".utf8))
        }
    }

    // MARK: - 1. KeySignerRegistry Tests

    func testKeySignerRegistryReturnsDefaultP256() throws {
        let signer = try KeySignerRegistry.shared.signer(for: .ecdsaP256)
        XCTAssertEqual(signer.algorithm, .ecdsaP256)
        XCTAssertEqual(signer.sshKeyType, "ecdsa-sha2-nistp256")
        XCTAssertTrue(signer is ECDSAP256KeySigner)
    }

    func testKeySignerRegistryResolvesByString() throws {
        let signerByName = try KeySignerRegistry.shared.signer(forAlgorithmName: "ECDSA P-256")
        XCTAssertEqual(signerByName.algorithm, .ecdsaP256)

        let signerByRawValue = try KeySignerRegistry.shared.signer(forAlgorithmName: KeyAlgorithm.ecdsaP256.rawValue)
        XCTAssertEqual(signerByRawValue.algorithm, .ecdsaP256)
    }

    func testKeySignerRegistryRejectsUnsupportedAlgorithms() {
        XCTAssertThrowsError(try KeySignerRegistry.shared.signer(forAlgorithmName: "Ed25519")) { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, let storage) = error else {
                XCTFail("Expected unsupportedConfiguration error, got: \(error)")
                return
            }
            XCTAssertEqual(algo, "Ed25519")
            XCTAssertEqual(storage, KeyStorageType.secureEnclave.rawValue)
        }

        XCTAssertThrowsError(try KeySignerRegistry.shared.signer(forAlgorithmName: "RSA 4096")) { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, _) = error else {
                XCTFail("Expected unsupportedConfiguration error, got: \(error)")
                return
            }
            XCTAssertEqual(algo, "RSA 4096")
        }

        XCTAssertThrowsError(try KeySignerRegistry.shared.signer(forAlgorithmName: "UnknownAlgorithm")) { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, _) = error else {
                XCTFail("Expected unsupportedConfiguration error, got: \(error)")
                return
            }
            XCTAssertEqual(algo, "UnknownAlgorithm")
        }
    }

    func testKeySignerRegistryCustomSignerRegistrationAndReset() throws {
        let registry = KeySignerRegistry()
        let mockSigner = MockKeySigner()

        registry.register(mockSigner)
        let resolved = try registry.signer(for: .ecdsaP256)
        XCTAssertEqual(resolved.sshKeyType, "mock-key-type")

        registry.resetToDefaults()
        let defaultSigner = try registry.signer(for: .ecdsaP256)
        XCTAssertEqual(defaultSigner.sshKeyType, "ecdsa-sha2-nistp256")
    }

    func testKeySignerRegistryRegisteredAlgorithms() {
        let registry = KeySignerRegistry.shared
        XCTAssertTrue(registry.registeredAlgorithms.contains(.ecdsaP256))
    }

    // MARK: - 2. ECDSAP256KeySigner Key Generation & Public Key Derivation

    func testECDSAP256KeyGenerationAndDerivationConsistency() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let signer = ECDSAP256KeySigner.shared
        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage])

        let keyPair = try signer.generateKeyPair(
            label: "test-consistency",
            accessControl: accessControl,
            provider: provider
        )
        XCTAssertFalse(keyPair.keyData.isEmpty)
        XCTAssertFalse(keyPair.publicKeyBlob.isEmpty)

        var record = StoredPrivateKeyRecord(
            label: "test-consistency",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            keyData: keyPair.keyData
        )
        defer { record.wipe() }

        let derivedBlob = try signer.derivePublicKeyBlob(
            record: record,
            context: nil,
            provider: provider
        )
        XCTAssertEqual(derivedBlob, keyPair.publicKeyBlob)
    }

    func testECDSAP256FormatOpenSSHPublicKey() {
        let signer = ECDSAP256KeySigner.shared
        let dummyBlob = Data([0x01, 0x02, 0x03, 0x04])
        let label = "user@example.com"

        let openSSH = signer.formatOpenSSHPublicKey(publicKeyBlob: dummyBlob, label: label)
        let expected = "ecdsa-sha2-nistp256 \(dummyBlob.base64EncodedString()) \(label)"
        XCTAssertEqual(openSSH, expected)
    }

    func testECDSAP256VerifyPublicKeyMatchesAuthenticRecord() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let signer = ECDSAP256KeySigner.shared
        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage])

        let keyPair = try signer.generateKeyPair(
            label: "authentic-key",
            accessControl: accessControl,
            provider: provider
        )
        var record = StoredPrivateKeyRecord(
            label: "authentic-key",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            keyData: keyPair.keyData
        )
        defer { record.wipe() }

        let keyInfo = SSHKeyInfo(
            label: "authentic-key",
            publicKeyOpenSSH: signer.formatOpenSSHPublicKey(publicKeyBlob: keyPair.publicKeyBlob, label: "authentic-key"),
            publicKeyBlob: keyPair.publicKeyBlob,
            fingerprint: "SHA256:dummy",
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        XCTAssertNoThrow(try signer.verifyPublicKey(
            record: record,
            against: keyInfo,
            context: LAContext(),
            provider: provider
        ))
    }

    func testECDSAP256VerifyPublicKeyThrowsOnTamperedBlob() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let signer = ECDSAP256KeySigner.shared
        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage])

        let keyPair = try signer.generateKeyPair(
            label: "tampered-key",
            accessControl: accessControl,
            provider: provider
        )
        var record = StoredPrivateKeyRecord(
            label: "tampered-key",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            keyData: keyPair.keyData
        )
        defer { record.wipe() }

        var tamperedBlob = keyPair.publicKeyBlob
        tamperedBlob[tamperedBlob.count - 1] ^= 0xFF

        let keyInfo = SSHKeyInfo(
            label: "tampered-key",
            publicKeyOpenSSH: signer.formatOpenSSHPublicKey(publicKeyBlob: tamperedBlob, label: "tampered-key"),
            publicKeyBlob: tamperedBlob,
            fingerprint: "SHA256:dummy",
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        XCTAssertThrowsError(try signer.verifyPublicKey(
            record: record,
            against: keyInfo,
            context: LAContext(),
            provider: provider
        )) { error in
            guard case PrivateKeyRecordError.publicKeyMismatch = error else {
                XCTFail("Expected publicKeyMismatch, got \(error)")
                return
            }
        }
    }

    func testECDSAP256DerivePublicKeyBlobRejectsCorruptedStorage() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let signer = ECDSAP256KeySigner.shared

        // Record with corrupted data representation
        var record = StoredPrivateKeyRecord(
            label: "corrupt-record",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            keyData: Data([0xDE, 0xAD, 0xBE, 0xEF])
        )
        defer { record.wipe() }

        XCTAssertThrowsError(try signer.derivePublicKeyBlob(
            record: record,
            context: nil,
            provider: provider
        ))
    }

    // MARK: - 3. Signature Wire Formatting & RFC 4251 MPINT Encoding

    func testECDSAP256FormatSSHSignatureBlobWireStructure() throws {
        let signer = ECDSAP256KeySigner.shared

        // Construct 64-byte raw signature: r has MSB unset (0x01), s has MSB set (0x82)
        var r = Data(repeating: 0x01, count: 32)
        r[0] = 0x01
        var s = Data(repeating: 0x82, count: 32)
        s[0] = 0x82
        let rawSig = r + s
        XCTAssertEqual(rawSig.count, 64)

        let sigBlob = try signer.formatSSHSignatureBlob(rawSignature: rawSig)

        var reader = DataReader(data: sigBlob)
        let keyType = reader.readWireString()
        XCTAssertEqual(keyType, "ecdsa-sha2-nistp256")

        guard let innerData = reader.readWireData() else {
            XCTFail("Failed to read inner signature data")
            return
        }
        XCTAssertTrue(reader.isEOF)

        var innerReader = DataReader(data: innerData)
        guard let rEncoded = innerReader.readWireData(),
              let sEncoded = innerReader.readWireData() else {
            XCTFail("Failed to read r and s mpints from inner signature")
            return
        }
        XCTAssertTrue(innerReader.isEOF)

        // r has high bit 0, so mpint length is 32 bytes without prefix
        XCTAssertEqual(rEncoded.count, 32)
        XCTAssertEqual(rEncoded, r)

        // s has high bit 1 (0x82), so RFC 4251 requires 0x00 padding byte -> 33 bytes
        XCTAssertEqual(sEncoded.count, 33)
        XCTAssertEqual(sEncoded.first, 0x00)
        XCTAssertEqual(sEncoded.dropFirst(), s)
    }

    func testECDSAP256FormatSSHSignatureBlobRejectsInvalidLengths() {
        let signer = ECDSAP256KeySigner.shared

        let lengths = [0, 32, 63, 65, 128]
        for len in lengths {
            let buffer = Data(repeating: 0x55, count: len)
            XCTAssertThrowsError(try signer.formatSSHSignatureBlob(rawSignature: buffer)) { error in
                guard case KeychainManagerError.invalidSignatureLength(let count) = error else {
                    XCTFail("Expected invalidSignatureLength, got \(error)")
                    return
                }
                XCTAssertEqual(count, len)
            }
        }
    }

    func testECDSAP256SignSSHProducesValidOpenSSHWireSignature() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let signer = ECDSAP256KeySigner.shared
        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage])

        let keyPair = try signer.generateKeyPair(
            label: "test-signing",
            accessControl: accessControl,
            provider: provider
        )

        let payload = Data("challenge-data-to-sign".utf8)
        let sigBlob = try signer.signSSH(
            data: payload,
            keyData: keyPair.keyData,
            context: nil,
            provider: provider
        )

        var reader = DataReader(data: sigBlob)
        let keyType = reader.readWireString()
        XCTAssertEqual(keyType, "ecdsa-sha2-nistp256")

        let innerData = reader.readWireData()
        XCTAssertNotNil(innerData)
        XCTAssertTrue(reader.isEOF)
    }

    // MARK: - 4. KeychainManager Integration & Strategy Dispatch

    func testKeychainManagerUsesInjectedRegistry() throws {
        let customRegistry = KeySignerRegistry()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder(),
            signingProvider: InMemorySecureEnclaveSigningProvider(),
            signerRegistry: customRegistry
        )

        XCTAssertTrue(manager.signerRegistry === customRegistry)
    }

    func testKeychainManagerStrategyDispatchToCustomKeySigner() throws {
        let mockSigner = MockKeySigner()
        let customRegistry = KeySignerRegistry()
        customRegistry.register(mockSigner)

        let provider = InMemorySecureEnclaveSigningProvider()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder(),
            signingProvider: provider,
            signerRegistry: customRegistry
        )

        let keyInfo = try manager.generateKey(
            label: "mock-dispatch-key",
            algorithm: "ECDSA P-256",
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        XCTAssertTrue(mockSigner.generateKeyPairCalled, "generateKey must dispatch to registered KeySigner")
        XCTAssertEqual(keyInfo.publicKeyBlob, Data("mock-public-blob".utf8))

        let payload = Data("challenge-data".utf8)
        let signature = try manager.signSSH(
            key: keyInfo,
            data: payload,
            prompt: "Sign",
            useCache: false
        )
        XCTAssertTrue(mockSigner.verifyPublicKeyCalled, "verifyPublicKey must dispatch to registered KeySigner")
        XCTAssertTrue(mockSigner.signSSHCalled, "signSSH must dispatch to registered KeySigner")

        var reader = DataReader(data: signature)
        XCTAssertEqual(reader.readWireString(), "mock-key-type")
        XCTAssertEqual(reader.readWireData(), Data("mock-signature".utf8))
    }

    func testKeychainManagerSignSSHDispatchesThroughSigner() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder(),
            signingProvider: provider
        )

        let keyInfo = try manager.generateKey(
            label: "dispatch-sign-key",
            algorithm: "ECDSA P-256",
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        let payload = Data("ssh-agent-challenge".utf8)
        let signature = try manager.signSSH(
            key: keyInfo,
            data: payload,
            prompt: "Sign SSH challenge",
            useCache: false
        )

        var reader = DataReader(data: signature)
        XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
        XCTAssertNotNil(reader.readWireData())
        XCTAssertTrue(reader.isEOF)
    }

    func testKeychainManagerAuthorizeGitSigningGrantDispatchesThroughSigner() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder(),
            signingProvider: provider
        )

        let keyInfo = try manager.generateKey(
            label: "dispatch-git-key",
            algorithm: "ECDSA P-256",
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .gitSigningOnly
        )

        let grant = try manager.authorizeGitSigningGrant(
            key: keyInfo,
            prompt: "Authorize Git signing",
            clientIdentity: "git-test"
        )

        let payload = Data("commit-payload-data".utf8)
        let signature = try grant.sign(payload)

        var reader = DataReader(data: signature)
        XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
        XCTAssertNotNil(reader.readWireData())
        XCTAssertTrue(reader.isEOF)
    }

    func testKeychainManagerAuthorizeAgentSessionDispatchesThroughSigner() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder(),
            signingProvider: provider
        )

        let keyInfo = try manager.generateKey(
            label: "dispatch-agent-key",
            algorithm: "ECDSA P-256",
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let grant = try manager.authorizeAgentSession(
            key: keyInfo,
            prompt: "Authorize agent session"
        )

        let payload = Data("agent-session-challenge".utf8)
        let signature = try grant.sign(payload)

        var reader = DataReader(data: signature)
        XCTAssertEqual(reader.readWireString(), "ecdsa-sha2-nistp256")
        XCTAssertNotNil(reader.readWireData())
        XCTAssertTrue(reader.isEOF)
    }

    func testKeychainManagerDerivePublicKeyBlobInstanceAndStatic() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let manager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: InMemoryPrivateKeyStore(),
            agentGrantRevoker: { _ in },
            auditRecorder: InMemoryAuditRecorder(),
            signingProvider: provider
        )

        let keyInfo = try manager.generateKey(label: "derive-both-key")
        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage])
        let (keyData, _) = try provider.generateKey(accessControl: accessControl)

        var record = StoredPrivateKeyRecord(
            label: keyInfo.label,
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            keyData: keyData
        )
        defer { record.wipe() }

        let instanceBlob = try manager.derivePublicKeyBlob(record: record)
        let staticBlob = try KeychainManager.derivePublicKeyBlob(record: record, provider: provider)
        XCTAssertEqual(instanceBlob, staticBlob)
    }

    func testKeychainManagerFailsClosedOnUnsupportedAlgorithm() {
        let manager = makeKeyManager()
        XCTAssertThrowsError(try manager.generateKey(
            label: "unsupported-key",
            algorithm: "Ed25519",
            storageType: .secureEnclave
        )) { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, let storage) = error else {
                XCTFail("Expected unsupportedConfiguration error, got \(error)")
                return
            }
            XCTAssertEqual(algo, "Ed25519")
            XCTAssertEqual(storage, KeyStorageType.secureEnclave.rawValue)
        }
    }

    func testKeychainManagerStaticFormatECDSASignatureBlobForwarding() throws {
        let p256Key = P256.Signing.PrivateKey()
        let testData = Data("forwarding-test-data".utf8)
        let sig = try p256Key.signature(for: testData)

        let managerFormatted = KeychainManager.formatECDSASignatureBlob(sig)
        let signerFormatted = try ECDSAP256KeySigner.shared.formatSSHSignatureBlob(rawSignature: sig.rawRepresentation)

        XCTAssertEqual(managerFormatted, signerFormatted)
    }
}
