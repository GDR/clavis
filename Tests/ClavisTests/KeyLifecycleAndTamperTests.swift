import Testing
import Foundation
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

struct KeyLifecycleAndTamperTests {


    @Test func testKeychainManagerListKeysSingleItemHandling() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyManager = fixture.makeKeyManager()
            let keys = try keyManager.listKeys()
            #expect(keys.isEmpty)

            let dummyKeyInfo = SSHKeyInfo(label: "dummy", publicKeyOpenSSH: "ssh-ed25519 AAA dummy", publicKeyBlob: Data(), fingerprint: "SHA256:dummy")
            let encodedData = try JSONEncoder().encode(dummyKeyInfo)

            let itemsSingle: AnyObject = encodedData as AnyObject
            let itemsArray: AnyObject = [encodedData] as AnyObject

            if let singleData = itemsSingle as? Data {
                let decoded = try JSONDecoder().decode(SSHKeyInfo.self, from: singleData)
                #expect(decoded.label == "dummy")
            }
            if let array = itemsArray as? [Data] {
                let decoded = try JSONDecoder().decode(SSHKeyInfo.self, from: array[0])
                #expect(decoded.label == "dummy")
            }

            let label = "list-and-tamper-\(UUID().uuidString)"
            let generatedKey = try keyManager.generateKey(label: label, keyPurpose: .agent)
            defer {
                PublicKeyStore.save(generatedKey)
                try? keyManager.deleteKey(label: label)
            }

            let listedKeys = try keyManager.listKeys()
            #expect(listedKeys.contains(where: { $0.label == label }))

            var tamperedBlob = generatedKey.publicKeyBlob
            tamperedBlob[tamperedBlob.count - 1] ^= 0xFF
            let tamperedKey = SSHKeyInfo(
                label: generatedKey.label,
                publicKeyOpenSSH: generatedKey.publicKeyOpenSSH,
                publicKeyBlob: tamperedBlob,
                fingerprint: generatedKey.fingerprint,
                createdAt: generatedKey.createdAt,
                algorithmName: generatedKey.algorithmName,
                storage: generatedKey.storage,
                biometricPolicy: generatedKey.biometricPolicy,
                keyPurpose: .agent
            )
            PublicKeyStore.save(tamperedKey)

            #expect {
                try keyManager.authorizeAgentSession(key: tamperedKey, prompt: "Authorize agent session")
            } throws: { error in
                error is PrivateKeyRecordError
            }

            #expect {
                try keyManager.changeKind(label: label, to: .general, prompt: "Change key kind")
            } throws: { error in
                error is PrivateKeyRecordError
            }
        }
    }

    @Test func testBiometricPolicyAccessControlAndSerialization() throws {
        #expect(BiometricPolicy.userPresence.accessControlFlags == [.privateKeyUsage, .userPresence])
        #expect(BiometricPolicy.biometryCurrentSet.accessControlFlags == [.privateKeyUsage, .biometryCurrentSet])

        let keyWithPolicy = SSHKeyInfo(
            label: "test-policy-\(UUID().uuidString)",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... test",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:fake",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: .biometryCurrentSet
        )

        #expect(keyWithPolicy.biometricPolicy == .biometryCurrentSet)
        #expect(keyWithPolicy.effectiveBiometricPolicy == .biometryCurrentSet)

        let encoded = try JSONEncoder().encode(keyWithPolicy)
        let decoded = try JSONDecoder().decode(SSHKeyInfo.self, from: encoded)
        #expect(decoded.biometricPolicy == .biometryCurrentSet)
        #expect(decoded.effectiveBiometricPolicy == .biometryCurrentSet)

        let legacyKey = SSHKeyInfo(
            label: "legacy-\(UUID().uuidString)",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... legacy",
            publicKeyBlob: Data([4, 5, 6]),
            fingerprint: "SHA256:other",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave
        )
        #expect(legacyKey.biometricPolicy == nil)
        #expect(legacyKey.effectiveBiometricPolicy == .userPresence)
    }

    @Test func testP256KeyGenerationAndSSHSigning() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyManager = fixture.makeKeyManager()
            let testLabel = "test_p256_\(UUID().uuidString)"
            defer {
                try? keyManager.deleteKey(label: testLabel)
            }

            let storage: KeyStorageType = .secureEnclave
            let keyInfo = try keyManager.generateKey(label: testLabel, algorithm: "ECDSA P-256", storageType: storage)

            #expect(keyInfo.algorithm == "ECDSA P-256")
            #expect(keyInfo.isHardware == true)
            #expect(keyInfo.publicKeyOpenSSH.hasPrefix("ecdsa-sha2-nistp256"))

            let testData = "Test SSH challenge payload".data(using: .utf8)!
            let sigBlob = try keyManager.signSSH(key: keyInfo, data: testData, prompt: "Test prompt")

            // Parse wire format: wire string "ecdsa-sha2-nistp256" + wire data
            var reader = DataReader(data: sigBlob)
            let sigAlgo = reader.readWireString()
            #expect(sigAlgo == "ecdsa-sha2-nistp256")
            let innerData = reader.readWireData()
            #expect(innerData != nil)
            #expect((innerData?.count ?? 0) > 64)
        }
    }

    @Test func testUnsupportedKeyConfigurationsFailClosed() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        await fixture.run {
            let keyManager = fixture.makeKeyManager()

            #expect(throws: (any Error).self) {
                try keyManager.generateKey(
                    label: "unsupported-rsa-\(UUID().uuidString)",
                    algorithm: "RSA 4096",
                    storageType: .secureEnclave
                )
            }
            #expect(throws: (any Error).self) {
                try keyManager.generateKey(
                    label: "unsupported-ed25519-\(UUID().uuidString)",
                    algorithm: "Ed25519",
                    storageType: .secureEnclave
                )
            }
        }
    }

    @Test func testKeyManagerRejectsControlCharactersInLabel() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        await fixture.run {
            let keyManager = fixture.makeKeyManager()
            #expect(throws: (any Error).self) {
                try keyManager.generateKey(label: "trusted\n[AUTH] forged")
            }
        }
    }

    @Test func testStoredPrivateKeyRecordSerializationAndWipe() throws {
        let dummyKeyData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        var record = StoredPrivateKeyRecord(
            version: StoredPrivateKeyRecord.currentVersion,
            label: "test-record",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: dummyKeyData
        )

        let encoded = try record.encode()
        #expect(encoded.starts(with: Data("CLVPKR02".utf8)))
        let decoded = try StoredPrivateKeyRecord.decode(from: encoded)

        #expect(decoded.version == StoredPrivateKeyRecord.currentVersion)
        #expect(decoded.label == "test-record")
        #expect(decoded.algorithm == .ecdsaP256)
        #expect(decoded.storageType == .secureEnclave)
        #expect(decoded.biometricPolicy == nil)
        #expect(decoded.keyPurpose == .general)
        #expect(decoded.keyData == dummyKeyData)

        // Test wiping
        record.wipe()
        #expect(record.keyData.count == 0)

        // Test unsupported version encode rejection
        let futureRecord = StoredPrivateKeyRecord(
            version: 999,
            label: "future",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            keyPurpose: .general,
            keyData: Data([0xAA])
        )
        #expect {
            try futureRecord.encode()
        } throws: { error in
            guard case PrivateKeyRecordError.unsupportedVersion(let v) = error else { return false }
            return v == 999
        }

        // Test binary decode version check
        var futureBinaryData = Data("CLVPKR02".utf8)
        futureBinaryData.append(99)
        futureBinaryData.append(contentsOf: encoded.dropFirst(9))
        #expect {
            try StoredPrivateKeyRecord.decode(from: futureBinaryData)
        } throws: { error in
            guard case PrivateKeyRecordError.unsupportedVersion(let v) = error else { return false }
            return v == 99
        }

        // Test non-binary data is rejected as corruptedRecord
        let legacyJSON = "{\"version\":1}".data(using: .utf8)!
        #expect {
            try StoredPrivateKeyRecord.decode(from: legacyJSON)
        } throws: { error in
            guard case PrivateKeyRecordError.corruptedRecord = error else { return false }
            return true
        }
    }

    @Test func testStoredPrivateKeyRecordV2UsesStrictBinaryEnvelope() throws {
        let keyData = Data(repeating: 0xA5, count: 32)
        let record = StoredPrivateKeyRecord(
            label: "binary-record",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .gitSigningOnly,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let encoded = try record.encode()
        #expect(encoded.starts(with: Data("CLVPKR02".utf8)))
        #expect(encoded.first != Character("{").asciiValue)
        let decoded = try StoredPrivateKeyRecord.decode(from: encoded)
        #expect(decoded == record)

        var trailingGarbage = encoded
        trailingGarbage.append(0x00)
        #expect {
            try StoredPrivateKeyRecord.decode(from: trailingGarbage)
        } throws: { error in
            guard case PrivateKeyRecordError.corruptedRecord = error else { return false }
            return true
        }
    }

    @Test func testTamperedAlgorithmInKeysJsonRefusesSigning() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "tamper-algo-\(UUID().uuidString)"
            let originalKey = try keyManager.generateKey(label: label, algorithm: "ECDSA P-256", storageType: .secureEnclave)

            // Attacker tampers with keys.json, claiming this ECDSA P-256 key is actually Ed25519
            let tamperedKey = SSHKeyInfo(
                label: originalKey.label,
                publicKeyOpenSSH: originalKey.publicKeyOpenSSH,
                publicKeyBlob: originalKey.publicKeyBlob,
                fingerprint: originalKey.fingerprint,
                createdAt: originalKey.createdAt,
                algorithmName: "Ed25519",
                storage: originalKey.storage,
                biometricPolicy: originalKey.biometricPolicy
            )
            PublicKeyStore.save(tamperedKey)

            // Attempting to sign with tampered metadata MUST fail closed with algorithmMismatch
            let testData = "payload".data(using: .utf8)!
            #expect {
                try keyManager.signSSH(key: tamperedKey, data: testData, prompt: "Sign")
            } throws: { error in
                guard case PrivateKeyRecordError.algorithmMismatch(let expected, let actual) = error else {
                    return false
                }
                return expected == "Ed25519" && actual == "ECDSA P-256"
            }
        }
    }

    @Test func testStoredPrivateKeyRecordRejectsLegacySoftwareStorage() throws {
        let fakeSEData = Data(repeating: 0xEE, count: 32)
        let record = StoredPrivateKeyRecord(
            version: StoredPrivateKeyRecord.currentVersion,
            label: "legacy-storage-test",
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general,
            keyData: fakeSEData
        )
        var encoded = try record.encode()
        encoded[10] = 0x01
        #expect {
            try StoredPrivateKeyRecord.decode(from: encoded)
        } throws: { error in
            guard case PrivateKeyRecordError.corruptedRecord = error else { return false }
            return true
        }
    }

    @Test func testDowngradedBiometricPolicyInKeysJsonRefusesSigning() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "tamper-policy-\(UUID().uuidString)"
            let record = StoredPrivateKeyRecord(
                version: StoredPrivateKeyRecord.currentVersion,
                label: label,
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: .biometryCurrentSet,
                keyPurpose: .general,
                keyData: Data(repeating: 0xEE, count: 64)
            )
            try keyStore.save(label: label, data: try record.encode())

            // Attacker edits keys.json to claim the key only needs the weaker default policy
            let downgraded = SSHKeyInfo(
                label: label,
                publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... \(label)",
                publicKeyBlob: Data([1, 2, 3]),
                fingerprint: "SHA256:fake",
                createdAt: Date(),
                algorithmName: "ECDSA P-256",
                storage: .secureEnclave,
                biometricPolicy: .userPresence
            )

            #expect {
                try keyManager.signSSH(key: downgraded, data: Data("payload".utf8), prompt: "Sign")
            } throws: { error in
                guard case PrivateKeyRecordError.metadataMismatch(let field, let expected, let actual) = error else {
                    return false
                }
                return field == "biometricPolicy" &&
                    expected == BiometricPolicy.userPresence.rawValue &&
                    actual == BiometricPolicy.biometryCurrentSet.rawValue
            }
        }
    }

    @Test func testStrengthenedBiometricPolicyInKeysJsonAlsoFailsClosed() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: InMemoryPrivateKeyStore()
            )
            let original = try keyManager.generateKey(
                label: "tamper-policy-up-\(UUID().uuidString)",
                algorithm: "ECDSA P-256",
                storageType: .secureEnclave
            )
            let tampered = SSHKeyInfo(
                label: original.label,
                publicKeyOpenSSH: original.publicKeyOpenSSH,
                publicKeyBlob: original.publicKeyBlob,
                fingerprint: original.fingerprint,
                createdAt: original.createdAt,
                algorithmName: original.algorithmName,
                storage: original.storage,
                biometricPolicy: .biometryCurrentSet
            )

            #expect {
                try keyManager.signSSH(key: tampered, data: Data("payload".utf8), prompt: "Sign")
            } throws: { error in
                guard case PrivateKeyRecordError.metadataMismatch(let field, _, _) = error else {
                    return false
                }
                return field == "biometricPolicy"
            }
            // The untampered key still signs: legacy nil policy == userPresence.
            #expect(throws: Never.self) {
                _ = try keyManager.signSSH(key: original, data: Data("payload".utf8), prompt: "Sign")
            }
        }
    }

    @Test func testTamperedPublicKeyBlobInKeysJsonRefusesSigning() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let keyManager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "tamper-pubblob-\(UUID().uuidString)"
            let originalKey = try keyManager.generateKey(label: label, algorithm: "ECDSA P-256", storageType: .secureEnclave)

            // Attacker tampers keys.json, replacing the public key blob with spoofed bytes
            var spoofedBlob = originalKey.publicKeyBlob
            spoofedBlob[20] ^= 0xFF
            let tamperedKey = SSHKeyInfo(
                label: originalKey.label,
                publicKeyOpenSSH: originalKey.publicKeyOpenSSH,
                publicKeyBlob: spoofedBlob,
                fingerprint: originalKey.fingerprint,
                createdAt: originalKey.createdAt,
                algorithmName: originalKey.algorithmName,
                storage: originalKey.storage,
                biometricPolicy: originalKey.biometricPolicy
            )
            PublicKeyStore.save(tamperedKey)

            // signSSH MUST fail closed with publicKeyMismatch
            let testData = "payload".data(using: .utf8)!
            #expect {
                try keyManager.signSSH(key: tamperedKey, data: testData, prompt: "Sign")
            } throws: { error in
                guard case PrivateKeyRecordError.publicKeyMismatch = error else { return false }
                return true
            }
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS"] == "1"))
    func testPublicIndexRoundTripsThroughKeychainWithoutAFile() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        await fixture.run {
            PublicKeyStore.disableKeychainMirrorForTesting = false
            defer { PublicKeyStore.disableKeychainMirrorForTesting = true }
            let keyInfo = SSHKeyInfo(
                label: "test-rebuild-\(UUID().uuidString)",
                publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA test",
                publicKeyBlob: Data(repeating: 0x11, count: 65),
                fingerprint: "SHA256:testfingerprint",
                createdAt: Date(),
                algorithmName: "ECDSA P-256",
                storage: .secureEnclave
            )
            defer { PublicKeyStore.remove(label: keyInfo.label) }

            PublicKeyStore.save(keyInfo)
            #expect(PublicKeyStore.loadAll().contains(where: { $0.label == keyInfo.label }))

            // A fresh process has an empty in-memory copy; it must find the key in the Keychain.
            PublicKeyStore.invalidateCache()
            #expect(PublicKeyStore.loadAll().contains(where: { $0.label == keyInfo.label }))

            PublicKeyStore.remove(label: keyInfo.label)
            #expect(!PublicKeyStore.loadAll().contains(where: { $0.label == keyInfo.label }))
        }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS"] == "1"))
    func testKeychainPrivateKeyStoreLifecycle() throws {
        let store = KeychainPrivateKeyStore(serviceName: "com.clavis.tests.\(UUID().uuidString)")
        let label = "test-store-lifecycle-\(UUID().uuidString)"
        let dummySecret = "SecurePayload_\(UUID().uuidString)".data(using: .utf8)!

        defer { try? store.remove(label: label) }

        #expect(!store.contains(label: label))

        // This opt-in integration test must preserve the requested access control.
        try store.save(label: label, data: dummySecret, accessControlFlags: [.privateKeyUsage, .userPresence])
        #expect(store.contains(label: label))

        let context = LAContext()
        let loaded = try store.load(label: label, context: context, prompt: "Test prompt")
        #expect(loaded == dummySecret)

        try store.remove(label: label)
        #expect(!store.contains(label: label))
    }

    @Test func testKeychainPrivateKeyStoreFailsClosedWhenProtectedAddIsUnavailable() throws {
        var addedItems: [CFDictionary] = []
        var deleteCallCount = 0
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.fail-closed",
            addItem: { item in
                addedItems.append(item)
                return errSecMissingEntitlement
            },
            deleteItem: { _ in
                deleteCallCount += 1
                return errSecItemNotFound
            },
            updateItem: { _, _ in errSecItemNotFound }
        )

        #expect {
            try store.save(
                label: "protected",
                data: Data([0x01, 0x02]),
                accessControlFlags: [.privateKeyUsage, .userPresence]
            )
        } throws: { error in
            guard case PrivateKeyStoreError.protectionUnavailable(let status) = error else { return false }
            return status == errSecMissingEntitlement
        }

        #expect(deleteCallCount == 0)
        #expect(addedItems.count == 1, "A protected add failure must never retry with weaker attributes")
        let added = addedItems[0] as NSDictionary
        #expect(added[kSecAttrAccessControl as String] != nil)
        #expect(added[kSecAttrAccessible as String] == nil)
    }

    @Test func testKeychainPrivateKeyStoreRejectsMissingAuthenticationConstraint() throws {
        var addCallCount = 0
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.missing-auth",
            addItem: { _ in
                addCallCount += 1
                return errSecSuccess
            },
            deleteItem: { _ in errSecItemNotFound },
            updateItem: { _, _ in
                Issue.record("Update must not be attempted without an authentication constraint")
                return errSecSuccess
            }
        )

        #expect {
            try store.save(
                label: "unprotected",
                data: Data([0x01]),
                accessControlFlags: [.privateKeyUsage]
            )
        } throws: { error in
            guard case PrivateKeyStoreError.accessControlCreation = error else { return false }
            return true
        }
        #expect(addCallCount == 0)
    }

    @Test func testKeychainPrivateKeyStoreFailedUpdateNeverDeletesExistingItem() throws {
        var addCallCount = 0
        var deleteCallCount = 0
        var updateCallCount = 0
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.atomic-update",
            addItem: { _ in
                addCallCount += 1
                return errSecSuccess
            },
            deleteItem: { _ in
                deleteCallCount += 1
                return errSecSuccess
            },
            updateItem: { _, _ in
                updateCallCount += 1
                return errSecAuthFailed
            }
        )

        #expect(throws: (any Error).self) {
            try store.save(
                label: "existing",
                data: Data([0x01]),
                accessControlFlags: [.userPresence]
            )
        }
        #expect(updateCallCount == 1)
        #expect(addCallCount == 0)
        #expect(deleteCallCount == 0, "A failed update must leave the existing item intact")
    }

    @Test func testKeychainPrivateKeyStoreWritesProtectedLoginKeychainItem() throws {
        var addedItems: [CFDictionary] = []
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.shared-group",
            addItem: { item in
                addedItems.append(item)
                return errSecSuccess
            },
            deleteItem: { _ in errSecItemNotFound },
            updateItem: { _, _ in errSecItemNotFound }
        )

        try store.save(label: "shared-key", data: Data([0xDE, 0xAD]), accessControlFlags: [.userPresence])

        #expect(addedItems.count == 1)
        let added = addedItems[0] as NSDictionary
        #expect(added[kSecAttrAccessControl as String] != nil)
        #expect(added[kSecUseDataProtectionKeychain as String] == nil)
        #expect(added[kSecAttrAccessGroup as String] == nil)
        #expect(added[kSecAttrAccess as String] == nil)
    }

    @Test func testKeychainPrivateKeyStoreStoresSecureEnclaveReferenceAsDeviceBoundMetadata() throws {
        var addedItems: [CFDictionary] = []
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.secure-enclave-reference",
            addItem: { item in
                addedItems.append(item)
                return errSecSuccess
            },
            deleteItem: { _ in errSecItemNotFound },
            updateItem: { _, _ in errSecItemNotFound }
        )

        try store.save(label: "hardware-key", data: Data([0xCA, 0xFE]), accessControlFlags: [.userPresence])

        #expect(addedItems.count == 1)
        let added = addedItems[0] as NSDictionary
        #expect(added[kSecAttrAccessControl as String] != nil)
        #expect(added[kSecAttrAccessible as String] == nil)
        #expect(added[kSecUseDataProtectionKeychain as String] == nil)
        #expect(added[kSecAttrAccessGroup as String] == nil)
    }

    @Test func testKeychainPrivateKeyStoreLoadsExistingItemWithoutRewritingIt() throws {
        let encoded = Data([0x01, 0x02, 0x03])
        var addCallCount = 0
        var deleteCallCount = 0
        var copyQueries: [CFDictionary] = []
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.existing-item",
            addItem: { _ in
                addCallCount += 1
                return errSecSuccess
            },
            deleteItem: { _ in
                deleteCallCount += 1
                return errSecSuccess
            },
            updateItem: { _, _ in errSecItemNotFound },
            copyItem: { query in
                copyQueries.append(query)
                return (errSecSuccess, encoded as AnyObject)
            }
        )

        let loaded = try store.load(label: "existing-key", context: LAContext(), prompt: "Use key")

        #expect(loaded == encoded)
        #expect(copyQueries.count == 1)
        #expect(addCallCount == 0)
        #expect(deleteCallCount == 0)
        let query = copyQueries[0] as NSDictionary
        #expect(query[kSecUseDataProtectionKeychain as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
    }

    @Test func testKeychainPrivateKeyStoreLoadFailureDoesNotRewriteOrDeleteItem() throws {
        var addCallCount = 0
        var deleteCallCount = 0
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.failed-load",
            addItem: { _ in
                addCallCount += 1
                return errSecSuccess
            },
            deleteItem: { _ in
                deleteCallCount += 1
                return errSecSuccess
            },
            updateItem: { _, _ in errSecItemNotFound },
            copyItem: { _ in (errSecAuthFailed, nil) }
        )

        #expect {
            try store.load(label: "existing-key", context: LAContext(), prompt: "Use key")
        } throws: { error in
            guard case PrivateKeyStoreError.keychain(let status) = error else { return false }
            return status == errSecAuthFailed
        }
        #expect(addCallCount == 0)
        #expect(deleteCallCount == 0)
    }

    @Test func testRestoreKeyFromEncryptedVaultWhenKeychainDeleted() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "shadow-restore-\(UUID().uuidString)"
            let keyInfo = try manager.generateKey(label: label)
            #expect(keyStore.contains(label: label))
            #expect(EncryptedVaultStore.shared.containsRecord(label: label))

            // Simulate third-party unauthenticated SecItemDelete bypassing Clavis
            try keyStore.remove(label: label, context: nil, prompt: "")
            #expect(!keyStore.contains(label: label))

            // Subsequent sign operation must transparently recover key from EncryptedVaultStore
            let payload = Data("audit-message".utf8)
            let sigBlob = try manager.signSSH(key: keyInfo, data: payload, prompt: "Sign with restored key")
            #expect(!sigBlob.isEmpty)

            // Verify key was restored back to Keychain
            #expect(keyStore.contains(label: label))

            // Verify signature against public key
            var reader = DataReader(data: sigBlob)
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let rawSig = reader.readWireData()
            let signature = try #require(rawSig)
            #expect(signature.count > 64)

            // Legitimate deletion must remove from both Keychain and EncryptedVaultStore
            try manager.deleteKey(label: label)
            #expect(!keyStore.contains(label: label))
            #expect(!EncryptedVaultStore.shared.containsRecord(label: label))
        }
    }

    @Test func testRestoreKeyFromEncryptedVaultWhenKeychainCorrupted() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let keyStore = InMemoryPrivateKeyStore()
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "shadow-corrupt-\(UUID().uuidString)"
            let keyInfo = try manager.generateKey(label: label)
            #expect(keyStore.contains(label: label))

            // Overwrite Keychain with garbage data
            try keyStore.save(label: label, data: Data("tampered-garbage-data".utf8))

            // Subsequent sign operation must recover key from EncryptedVaultStore
            let payload = Data("corrupted-key-test".utf8)
            let sigBlob = try manager.signSSH(key: keyInfo, data: payload, prompt: "Sign with restored key")
            #expect(!sigBlob.isEmpty)

            // Verify key was restored in Keychain
            let restoredData = try keyStore.load(label: label, context: LAContext(), prompt: "")
            #expect(restoredData != nil)
            let record = try StoredPrivateKeyRecord.decode(from: restoredData!)
            #expect(record.label == label)

            var reader = DataReader(data: sigBlob)
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let rawSig = reader.readWireData()
            let signature = try #require(rawSig)
            #expect(signature.count > 64)

            try manager.deleteKey(label: label)
        }
    }

    @Test func testPlantedKeychainRecordUsesMatchingVaultCopy() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let backing = ScriptedKeychainItems()
            let keyStore = backing.makeStore(serviceName: "com.clavis.tests.planted.\(UUID().uuidString)")
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "planted-keychain-\(UUID().uuidString)"
            let keyInfo = try manager.generateKey(label: label)

            let foreignKey = P256.Signing.PrivateKey()
            var foreignRecord = StoredPrivateKeyRecord(
                label: label,
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: nil,
                keyPurpose: .general,
                keyData: foreignKey.rawRepresentation
            )
            try keyStore.save(label: label, data: try foreignRecord.encode())
            foreignRecord.wipe()

            let payload = Data("planted-keychain-record".utf8)
            let sigBlob = try manager.signSSH(key: keyInfo, data: payload, prompt: "Sign with vault copy")
            var reader = DataReader(data: sigBlob)
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let rawSig = reader.readWireData()
            let signature = try #require(rawSig)
            #expect(signature.count > 64)

            let restoredData = try #require(try keyStore.load(label: label, context: LAContext(), prompt: ""))
            let restoredRecord = try StoredPrivateKeyRecord.decode(from: restoredData)
            #expect(try KeychainManager.derivePublicKeyBlob(record: restoredRecord) == keyInfo.publicKeyBlob)

            var replanted = StoredPrivateKeyRecord(
                label: label,
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: nil,
                keyPurpose: .general,
                keyData: foreignKey.rawRepresentation
            )
            try keyStore.save(label: label, data: try replanted.encode())
            replanted.wipe()

            #expect {
                try manager.deleteKey(label: label)
            } throws: { error in
                error as? KeyDeletionError == .partial(label: label)
            }
            #expect(!keyStore.contains(label: label))
            #expect(EncryptedVaultStore.shared.containsRecord(label: label))
            #expect(try manager.fetchKeyInfo(label: label)?.publicKeyBlob == keyInfo.publicKeyBlob)

            let restoredSigBlob = try manager.signSSH(key: keyInfo, data: payload, prompt: "Sign after planted item was removed")
            var restoredReader = DataReader(data: restoredSigBlob)
            #expect(restoredReader.readWireString() == "ecdsa-sha2-nistp256")
            let rawRestoredSig = restoredReader.readWireData()
            let restoredSignature = try #require(rawRestoredSig)
            #expect(restoredSignature.count > 64)
        }
    }

    @Test func testDeleteKeyThrowsPartialWhenVaultRecordMismatches() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let backing = ScriptedKeychainItems()
            let keyStore = backing.makeStore(serviceName: "com.clavis.tests.partial-delete.\(UUID().uuidString)")
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "partial-del-\(UUID().uuidString)"
            _ = try manager.generateKey(label: label)

            let foreignKey = P256.Signing.PrivateKey()
            var foreignRecord = StoredPrivateKeyRecord(
                label: label,
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: nil,
                keyPurpose: .general,
                keyData: foreignKey.rawRepresentation
            )
            try keyStore.save(label: label, data: try foreignRecord.encode())
            foreignRecord.wipe()

            #expect {
                try manager.deleteKey(label: label)
            } throws: { error in
                error as? KeyDeletionError == .partial(label: label)
            }

            // Key remains listed in public index
            #expect(try manager.fetchKeyInfo(label: label) != nil)
            #expect(try manager.listKeys().contains(where: { $0.label == label }))
            // Vault record remains intact
            #expect(EncryptedVaultStore.shared.containsRecord(label: label))
            // Keychain record was removed
            #expect(!keyStore.contains(label: label))
        }
    }

    @Test func testDeleteKeyLogsSecurityAlertWhenRevocationFailsOnPartialDeletion() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let backing = ScriptedKeychainItems()
            let keyStore = backing.makeStore(serviceName: "com.clavis.tests.partial-del-alert.\(UUID().uuidString)")
            let revocationFailure = NSError(domain: "test", code: 99, userInfo: [NSLocalizedDescriptionKey: "injected revocation error"])
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore,
                agentGrantRevoker: { _ in throw revocationFailure }
            )

            let label = "partial-del-alert-\(UUID().uuidString)"
            _ = try manager.generateKey(label: label)

            let foreignKey = P256.Signing.PrivateKey()
            var foreignRecord = StoredPrivateKeyRecord(
                label: label,
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: nil,
                keyPurpose: .general,
                keyData: foreignKey.rawRepresentation
            )
            try keyStore.save(label: label, data: try foreignRecord.encode())
            foreignRecord.wipe()

            #expect {
                try manager.deleteKey(label: label)
            } throws: { error in
                error as? KeyDeletionError == .partial(label: label)
            }

            let logURL = ClavisLogger.logFileURL
            let logContent = try String(contentsOf: logURL, encoding: .utf8)
            #expect(logContent.contains("SECURITY_ALERT"))
            #expect(logContent.contains(label))
            #expect(logContent.contains("injected revocation error"))
        }
    }

    @Test func testGenerateKeyRollsBackPrivateAndVaultRecordsWhenPublicStoreSaveFails() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        await fixture.run {
            let backing = ScriptedKeychainItems()
            let keyStore = backing.makeStore(serviceName: "com.clavis.tests.save-rollback.\(UUID().uuidString)")
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            struct InjectedSaveError: Error, Equatable {}

            PublicKeyStore.forcedSaveErrorForTesting = InjectedSaveError()
            defer { PublicKeyStore.forcedSaveErrorForTesting = nil }

            // Test ECDSA P-256 (in generateKey)
            let p256Label = "p256-save-fail-\(UUID().uuidString)"
            #expect {
                try manager.generateKey(label: p256Label, algorithm: "ECDSA P-256", storageType: .secureEnclave)
            } throws: { error in
                error is InjectedSaveError
            }
            #expect(!keyStore.contains(label: p256Label), "Keychain record must be removed on saveChecked failure")
            #expect(!EncryptedVaultStore.shared.containsRecord(label: p256Label), "Vault record must be removed on saveChecked failure")
        }
    }

    @Test func testValidationFailureInLoadAuthenticatedRecordLogsSecurityAlertBeforeVaultFallback() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let backing = ScriptedKeychainItems()
            let keyStore = backing.makeStore(serviceName: "com.clavis.tests.restore-alert.\(UUID().uuidString)")
            let manager = fixture.makeKeyManager(
                authenticator: AllowingAuthenticator(),
                privateKeyStore: keyStore
            )

            let label = "validation-alert-\(UUID().uuidString)"
            let keyInfo = try manager.generateKey(label: label)

            // Plant record with mismatched biometric policy to fail validateAuthenticatedRecord
            var tamperedRecord = StoredPrivateKeyRecord(
                label: label,
                algorithm: .ecdsaP256,
                storageType: .secureEnclave,
                biometricPolicy: .biometryCurrentSet,
                keyPurpose: .general,
                keyData: Data(repeating: 0x42, count: 32)
            )
            try keyStore.save(label: label, data: try tamperedRecord.encode())
            tamperedRecord.wipe()

            let payload = Data("restore-alert-payload".utf8)
            let sigBlob = try manager.signSSH(key: keyInfo, data: payload, prompt: "Sign with restored key")
            var reader = DataReader(data: sigBlob)
            #expect(reader.readWireString() == "ecdsa-sha2-nistp256")
            let rawSig = reader.readWireData()
            let signature = try #require(rawSig)
            #expect(signature.count > 64)

            let logURL = ClavisLogger.logFileURL
            let logContent = try String(contentsOf: logURL, encoding: .utf8)
            #expect(logContent.contains("SECURITY_ALERT"))
            #expect(logContent.contains(label))
            #expect(logContent.contains("Keychain record validation failed"))
        }
    }
}

private final class ScriptedKeychainItems: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    func makeStore(serviceName: String) -> KeychainPrivateKeyStore {
        KeychainPrivateKeyStore(
            serviceName: serviceName,
            addItem: { self.add($0) },
            deleteItem: { self.delete($0) },
            updateItem: { self.update($0, attributes: $1) },
            copyItem: { self.copy($0) }
        )
    }

    private func add(_ item: CFDictionary) -> OSStatus {
        guard let account = account(in: item), let data = valueData(in: item) else {
            return errSecParam
        }
        lock.lock()
        defer { lock.unlock() }
        guard items[account] == nil else { return errSecDuplicateItem }
        items[account] = data
        return errSecSuccess
    }

    private func delete(_ query: CFDictionary) -> OSStatus {
        guard let account = account(in: query) else { return errSecParam }
        lock.lock()
        defer { lock.unlock() }
        guard items.removeValue(forKey: account) != nil else { return errSecItemNotFound }
        return errSecSuccess
    }

    private func update(_ query: CFDictionary, attributes: CFDictionary) -> OSStatus {
        guard let account = account(in: query), let data = valueData(in: attributes) else {
            return errSecParam
        }
        lock.lock()
        defer { lock.unlock() }
        guard items[account] != nil else { return errSecItemNotFound }
        items[account] = data
        return errSecSuccess
    }

    private func copy(_ query: CFDictionary) -> (OSStatus, AnyObject?) {
        guard let account = account(in: query) else { return (errSecParam, nil) }
        lock.lock()
        defer { lock.unlock() }
        guard let data = items[account] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, data as AnyObject)
    }

    private func account(in query: CFDictionary) -> String? {
        (query as NSDictionary)[kSecAttrAccount as String] as? String
    }

    private func valueData(in query: CFDictionary) -> Data? {
        (query as NSDictionary)[kSecValueData as String] as? Data
    }
}
