import Testing
import Foundation
import CryptoKit
import Security
import LocalAuthentication
@testable import ClavisCore

@Suite struct KeySignerTests {

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

    @Test func testKeySignerRegistryReturnsDefaultP256() throws {
        let signer = try KeySignerRegistry.shared.signer(for: .ecdsaP256)
        #expect(signer.algorithm == .ecdsaP256)
        #expect(signer.sshKeyType == "ecdsa-sha2-nistp256")
        #expect(signer is ECDSAP256KeySigner)
    }

    @Test func testKeySignerRegistryResolvesByString() throws {
        let signerByName = try KeySignerRegistry.shared.signer(forAlgorithmName: "ECDSA P-256")
        #expect(signerByName.algorithm == .ecdsaP256)

        let signerByRawValue = try KeySignerRegistry.shared.signer(forAlgorithmName: KeyAlgorithm.ecdsaP256.rawValue)
        #expect(signerByRawValue.algorithm == .ecdsaP256)
    }

    @Test func testKeySignerRegistryRejectsUnsupportedAlgorithms() {
        #expect {
            try KeySignerRegistry.shared.signer(forAlgorithmName: "Ed25519")
        } throws: { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, let storage) = error else {
                return false
            }
            return algo == "Ed25519" && storage == KeyStorageType.secureEnclave.rawValue
        }

        #expect {
            try KeySignerRegistry.shared.signer(forAlgorithmName: "RSA 4096")
        } throws: { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, _) = error else {
                return false
            }
            return algo == "RSA 4096"
        }

        #expect {
            try KeySignerRegistry.shared.signer(forAlgorithmName: "UnknownAlgorithm")
        } throws: { error in
            guard case KeychainManagerError.unsupportedConfiguration(let algo, _) = error else {
                return false
            }
            return algo == "UnknownAlgorithm"
        }
    }

    @Test func testKeySignerRegistryCustomSignerRegistrationAndReset() throws {
        let registry = KeySignerRegistry()
        let mockSigner = MockKeySigner()

        registry.register(mockSigner)
        let resolved = try registry.signer(for: .ecdsaP256)
        #expect(resolved.sshKeyType == "mock-key-type")

        registry.resetToDefaults()
        let defaultSigner = try registry.signer(for: .ecdsaP256)
        #expect(defaultSigner.sshKeyType == "ecdsa-sha2-nistp256")
    }

    @Test func testKeySignerRegistryRegisteredAlgorithms() {
        let registry = KeySignerRegistry.shared
        #expect(registry.registeredAlgorithms.contains(.ecdsaP256))
    }

    // MARK: - 2. ECDSAP256KeySigner Key Generation & Public Key Derivation

    @Test func testECDSAP256KeyGenerationAndDerivationConsistency() throws {
        let provider = InMemorySecureEnclaveSigningProvider()
        let signer = ECDSAP256KeySigner.shared
        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage])

        let keyPair = try signer.generateKeyPair(
            label: "test-consistency",
            accessControl: accessControl,
            provider: provider
        )
        #expect(!keyPair.keyData.isEmpty)
        #expect(!keyPair.publicKeyBlob.isEmpty)

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
        #expect(derivedBlob == keyPair.publicKeyBlob)
    }

    @Test func testECDSAP256FormatOpenSSHPublicKey() {
        let signer = ECDSAP256KeySigner.shared
        let dummyBlob = Data([0x01, 0x02, 0x03, 0x04])
        let label = "user@example.com"

        let openSSH = signer.formatOpenSSHPublicKey(publicKeyBlob: dummyBlob, label: label)
        let expected = "ecdsa-sha2-nistp256 \(dummyBlob.base64EncodedString()) \(label)"
        #expect(openSSH == expected)
    }

    @Test func testECDSAP256VerifyPublicKeyMatchesAuthenticRecord() throws {
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

        #expect(throws: Never.self) {
            try signer.verifyPublicKey(
                record: record,
                against: keyInfo,
                context: LAContext(),
                provider: provider
            )
        }
    }

    @Test func testECDSAP256VerifyPublicKeyThrowsOnTamperedBlob() throws {
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

        #expect {
            try signer.verifyPublicKey(
                record: record,
                against: keyInfo,
                context: LAContext(),
                provider: provider
            )
        } throws: { error in
            guard case PrivateKeyRecordError.publicKeyMismatch = error else { return false }
            return true
        }
    }

    @Test func testECDSAP256DerivePublicKeyBlobRejectsCorruptedStorage() throws {
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

        #expect(throws: (any Error).self) {
            try signer.derivePublicKeyBlob(
                record: record,
                context: nil,
                provider: provider
            )
        }
    }

    // MARK: - 3. Signature Wire Formatting & RFC 4251 MPINT Encoding

    @Test func testECDSAP256FormatSSHSignatureBlobWireStructure() throws {
        let signer = ECDSAP256KeySigner.shared

        // Construct 64-byte raw signature: r has MSB unset (0x01), s has MSB set (0x82)
        var r = Data(repeating: 0x01, count: 32)
        r[0] = 0x01
        var s = Data(repeating: 0x82, count: 32)
        s[0] = 0x82
        let rawSig = r + s
        #expect(rawSig.count == 64)

        let sigBlob = try signer.formatSSHSignatureBlob(rawSignature: rawSig)

        var reader = DataReader(data: sigBlob)
        let keyType = reader.readWireString()
        #expect(keyType == "ecdsa-sha2-nistp256")

        let rawInner = reader.readWireData()
        let innerData = try #require(rawInner)
        #expect(reader.isEOF)

        var innerReader = DataReader(data: innerData)
        let rawR = innerReader.readWireData()
        let rEncoded = try #require(rawR)
        let rawS = innerReader.readWireData()
        let sEncoded = try #require(rawS)
        #expect(innerReader.isEOF)

        // r has high bit 0, so mpint length is 32 bytes without prefix
        #expect(rEncoded.count == 32)
        #expect(rEncoded == r)

        // s has high bit 1 (0x82), so RFC 4251 requires 0x00 padding byte -> 33 bytes
        #expect(sEncoded.count == 33)
        #expect(sEncoded.first == 0x00)
        #expect(sEncoded.dropFirst() == s)
    }

    @Test func testECDSAP256FormatSSHSignatureBlobRejectsInvalidLengths() {
        let signer = ECDSAP256KeySigner.shared

        let lengths = [0, 32, 63, 65, 128]
        for len in lengths {
            let buffer = Data(repeating: 0x55, count: len)
            #expect {
                try signer.formatSSHSignatureBlob(rawSignature: buffer)
            } throws: { error in
                guard case KeychainManagerError.invalidSignatureLength(let count) = error else {
                    return false
                }
                return count == len
            }
        }
    }

    @Test func testECDSAP256SignSSHProducesValidOpenSSHWireSignature() throws {
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
        #expect(keyType == "ecdsa-sha2-nistp256")

        let innerData = reader.readWireData()
        #expect(innerData != nil)
        #expect(reader.isEOF)
    }

    // MARK: - 4. KeychainManager Integration & Strategy Dispatch

    @Test func testKeychainManagerUsesInjectedRegistry() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        await fixture.run {
            let customRegistry = KeySignerRegistry()
            let manager = fixture.makeKeyManager(
                signerRegistry: customRegistry
            )

            #expect(manager.signerRegistry === customRegistry)
        }
    }

    @Test func testKeychainManagerStrategyDispatchToCustomKeySigner() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let mockSigner = MockKeySigner()
            let customRegistry = KeySignerRegistry()
            customRegistry.register(mockSigner)

            let provider = InMemorySecureEnclaveSigningProvider()
            let manager = fixture.makeKeyManager(
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

            #expect(mockSigner.generateKeyPairCalled, "generateKey must dispatch to registered KeySigner")
            #expect(keyInfo.publicKeyBlob == Data("mock-public-blob".utf8))

            let payload = Data("challenge-data".utf8)
            let signature = try manager.signSSH(
                key: keyInfo,
                data: payload,
                prompt: "Sign",
                useCache: false
            )
            #expect(mockSigner.verifyPublicKeyCalled, "verifyPublicKey must dispatch to registered KeySigner")
            #expect(mockSigner.signSSHCalled, "signSSH must dispatch to registered KeySigner")

            var reader = DataReader(data: signature)
            #expect(reader.readWireString() == "mock-key-type")
            let wireSig = reader.readWireData()
            #expect(wireSig == Data("mock-signature".utf8))
        }
    }

    @Test func testKeychainManagerSignSSHDispatchesThroughSigner() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let provider = InMemorySecureEnclaveSigningProvider()
            let manager = fixture.makeKeyManager(
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
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let wireData = reader.readWireData()
            #expect(wireData != nil)
            #expect(reader.isEOF)
        }
    }

    @Test func testKeychainManagerAuthorizeGitSigningGrantDispatchesThroughSigner() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let provider = InMemorySecureEnclaveSigningProvider()
            let manager = fixture.makeKeyManager(
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
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let wireData = reader.readWireData()
            #expect(wireData != nil)
            #expect(reader.isEOF)
        }
    }

    @Test func testKeychainManagerAuthorizeAgentSessionDispatchesThroughSigner() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let provider = InMemorySecureEnclaveSigningProvider()
            let manager = fixture.makeKeyManager(
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
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let wireData = reader.readWireData()
            #expect(wireData != nil)
            #expect(reader.isEOF)
        }
    }

    @Test func testKeychainManagerDerivePublicKeyBlobInstanceAndStatic() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let provider = InMemorySecureEnclaveSigningProvider()
            let manager = fixture.makeKeyManager(
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
            #expect(instanceBlob == staticBlob)
        }
    }

    @Test func testKeychainManagerFailsClosedOnUnsupportedAlgorithm() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        await fixture.run {
            let manager = fixture.makeKeyManager()
            #expect {
                try manager.generateKey(
                    label: "unsupported-key",
                    algorithm: "Ed25519",
                    storageType: .secureEnclave
                )
            } throws: { error in
                guard case KeychainManagerError.unsupportedConfiguration(let algo, let storage) = error else {
                    return false
                }
                return algo == "Ed25519" && storage == KeyStorageType.secureEnclave.rawValue
            }
        }
    }

    @Test func testKeychainManagerStaticFormatECDSASignatureBlobForwarding() throws {
        let p256Key = P256.Signing.PrivateKey()
        let testData = Data("forwarding-test-data".utf8)
        let sig = try p256Key.signature(for: testData)

        let managerFormatted = KeychainManager.formatECDSASignatureBlob(sig)
        let signerFormatted = try ECDSAP256KeySigner.shared.formatSSHSignatureBlob(rawSignature: sig.rawRepresentation)

        #expect(managerFormatted == signerFormatted)
    }
}
