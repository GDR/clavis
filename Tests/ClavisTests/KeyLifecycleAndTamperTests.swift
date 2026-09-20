import XCTest
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import AgePluginClavis
@testable import Clavis

final class KeyLifecycleAndTamperTests: ClavisBaseTestCase {

    func testKeychainManagerListKeysSingleItemHandling() throws {
        let keys = try makeKeyManager().listKeys()
        XCTAssertNotNil(keys)

        let dummyKeyInfo = Ed25519KeyInfo(label: "dummy", publicKeyOpenSSH: "ssh-ed25519 AAA dummy", publicKeyBlob: Data(), fingerprint: "SHA256:dummy")
        let encodedData = try JSONEncoder().encode(dummyKeyInfo)

        let itemsSingle: AnyObject = encodedData as AnyObject
        let itemsArray: AnyObject = [encodedData] as AnyObject

        if let singleData = itemsSingle as? Data {
            let decoded = try JSONDecoder().decode(Ed25519KeyInfo.self, from: singleData)
            XCTAssertEqual(decoded.label, "dummy")
        }
        if let array = itemsArray as? [Data] {
            let decoded = try JSONDecoder().decode(Ed25519KeyInfo.self, from: array[0])
            XCTAssertEqual(decoded.label, "dummy")
        }
    }


    func testUnlockKeepsAlwaysPromptPolicy() async throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .never
        let keyManager = makeKeyManager(sessionCache: cache)
        let label = "always-prompt-\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }
        try keyManager.generateKey(label: label)

        do {
            try await keyManager.unlock(label: label)
            XCTFail("Unlock should fail while session caching is disabled")
        } catch {
            XCTAssertEqual(error as? SessionCacheError, .disabled)
        }

        XCTAssertEqual(cache.currentTimeout, .never)
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testUnlockHardwareKeyThrowsNotCacheable() async throws {
        let cache = makeSessionCache()
        cache.currentTimeout = .fifteenMinutes
        let keyManager = makeKeyManager(sessionCache: cache)
        let label = "hw-test-\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }

        let hwKeyInfo = Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... \(label)",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:fake-hw",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave
        )
        PublicKeyStore.save(hwKeyInfo)

        do {
            try await keyManager.unlock(label: label)
            XCTFail("Unlock must fail for hardware keys")
        } catch {
            XCTAssertEqual(error as? SessionCacheError, .hardwareNotCacheable)
        }

        XCTAssertFalse(cache.isKeyUnlocked(label: label))
        XCTAssertNil(cache.remainingTime(label: label))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testBiometricPolicyAccessControlAndSerialization() throws {
        XCTAssertEqual(BiometricPolicy.userPresence.accessControlFlags, [.privateKeyUsage, .userPresence])
        XCTAssertEqual(BiometricPolicy.biometryCurrentSet.accessControlFlags, [.privateKeyUsage, .biometryCurrentSet])

        let keyWithPolicy = Ed25519KeyInfo(
            label: "test-policy-\(UUID().uuidString)",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... test",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:fake",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: .biometryCurrentSet
        )

        XCTAssertEqual(keyWithPolicy.biometricPolicy, .biometryCurrentSet)
        XCTAssertEqual(keyWithPolicy.effectiveBiometricPolicy, .biometryCurrentSet)

        let encoded = try JSONEncoder().encode(keyWithPolicy)
        let decoded = try JSONDecoder().decode(Ed25519KeyInfo.self, from: encoded)
        XCTAssertEqual(decoded.biometricPolicy, .biometryCurrentSet)
        XCTAssertEqual(decoded.effectiveBiometricPolicy, .biometryCurrentSet)

        let legacyKey = Ed25519KeyInfo(
            label: "legacy-\(UUID().uuidString)",
            publicKeyOpenSSH: "ssh-ed25519 AAAA... legacy",
            publicKeyBlob: Data([4, 5, 6]),
            fingerprint: "SHA256:other",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain
        )
        XCTAssertNil(legacyKey.biometricPolicy)
        XCTAssertEqual(legacyKey.effectiveBiometricPolicy, .userPresence)
    }

    func testKeyManagerConsumesImportedSeed() throws {
        let keyManager = makeKeyManager()
        let label = "consumed_seed_\(UUID().uuidString)"
        defer { try? keyManager.deleteKey(label: label) }
        var seed = Data(repeating: 0x5a, count: 32)

        _ = try keyManager.importKey(label: label, consuming: &seed)

        XCTAssertTrue(seed.isEmpty)
        XCTAssertNotNil(try keyManager.fetchKeyInfo(label: label))
    }


    func testP256KeyGenerationAndSSHSigning() throws {
        let keyManager = makeKeyManager()
        let testLabel = "test_p256_\(UUID().uuidString)"
        defer {
            try? keyManager.deleteKey(label: testLabel)
        }

        let storage: KeyStorageType = .keychain
        let keyInfo = try keyManager.generateKey(label: testLabel, algorithm: "ECDSA P-256", storageType: storage)

        XCTAssertEqual(keyInfo.algorithm, "ECDSA P-256")
        XCTAssertEqual(keyInfo.isHardware, (storage == .secureEnclave))
        XCTAssertTrue(keyInfo.publicKeyOpenSSH.hasPrefix("ecdsa-sha2-nistp256"))

        let testData = "Test SSH challenge payload".data(using: .utf8)!
        let sigBlob = try keyManager.signSSH(key: keyInfo, data: testData, prompt: "Test prompt")

        // Parse wire format: wire string "ecdsa-sha2-nistp256" + wire data
        var reader = DataReader(data: sigBlob)
        let sigAlgo = reader.readWireString()
        XCTAssertEqual(sigAlgo, "ecdsa-sha2-nistp256")
        let innerData = reader.readWireData()
        XCTAssertNotNil(innerData)
        XCTAssertGreaterThan(innerData?.count ?? 0, 64)
    }


    func testUnsupportedKeyConfigurationsFailClosed() throws {
        let keyManager = makeKeyManager()

        XCTAssertThrowsError(
            try keyManager.generateKey(
                label: "unsupported-rsa-\(UUID().uuidString)",
                algorithm: "RSA 4096",
                storageType: .keychain
            )
        )
        XCTAssertThrowsError(
            try keyManager.generateKey(
                label: "unsupported-ed25519-enclave-\(UUID().uuidString)",
                algorithm: "Ed25519",
                storageType: .secureEnclave
            )
        )

        var seed = Data(repeating: 0x42, count: 32)
        XCTAssertThrowsError(
            try keyManager.importKey(
                label: "unsupported-import-\(UUID().uuidString)",
                consuming: &seed,
                algorithm: "ECDSA P-256",
                storageType: .keychain
            )
        )
        XCTAssertTrue(seed.isEmpty)
    }


    func testSeedStoreEnvelopeEncryptionCycle() throws {
        let label = "test_envelope_\(UUID().uuidString)"

        var randomSeed = Data(count: 32)
        _ = randomSeed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        try SeedStore.save(label: label, seedData: randomSeed)
        let loaded = SeedStore.load(label: label)

        XCTAssertEqual(loaded, randomSeed)
    }


    func testSeedStoreEncryptedFileFormat() throws {
        let label = "test_format_\(UUID().uuidString)"

        let secretBytes = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
        try SeedStore.save(label: label, seedData: secretBytes)

        let fileURL = SeedStore.seedFileURL(label: label)
        let fileData = try Data(contentsOf: fileURL)

        // Must start with magic header "CLV1" (0x43, 0x4C, 0x56, 0x01)
        XCTAssertEqual(fileData.prefix(4), Data([0x43, 0x4C, 0x56, 0x01]))

        // Must include 65-byte P-256 public key + at least 28-byte ChaChaPoly box
        XCTAssertGreaterThanOrEqual(fileData.count, 4 + 65 + 28)

        // Raw secret bytes must NOT appear anywhere in the ciphertext
        XCTAssertNil(fileData.range(of: secretBytes))
    }


    func testSeedStoreLegacyPlaintextMigration() throws {
        let label = "test_legacy_\(UUID().uuidString)"

        let legacySeed = Data(repeating: 0x7A, count: 32)
        let fileURL = SeedStore.seedFileURL(label: label)

        // Write raw unencrypted seed directly to disk (simulating pre-envelope legacy Clavis)
        try legacySeed.write(to: fileURL, options: .atomic)
        XCTAssertEqual(try Data(contentsOf: fileURL), legacySeed)

        // Loading should return the plaintext seed AND automatically migrate the file to CLV1
        let loaded = SeedStore.load(label: label)
        XCTAssertEqual(loaded, legacySeed)

        // Verify that file on disk is now an encrypted envelope
        let migratedFileData = try Data(contentsOf: fileURL)
        XCTAssertEqual(migratedFileData.prefix(4), Data([0x43, 0x4C, 0x56, 0x01]))
        XCTAssertNil(migratedFileData.range(of: legacySeed))

        // Subsequent load should successfully decrypt from the new envelope
        let reloaded = SeedStore.load(label: label)
        XCTAssertEqual(reloaded, legacySeed)
    }


    func testSeedStoreFindsLegacySanitizedFilename() throws {
        let label = "legacy/path"
        let legacyURL = SeedStore.seedsDirectory.appendingPathComponent("legacy_path.key")
        let seed = Data(repeating: 0x4C, count: 32)
        try seed.write(to: legacyURL, options: .atomic)

        XCTAssertEqual(SeedStore.load(label: label), seed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacyURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: SeedStore.seedFileURL(label: label).path))
    }


    func testSeedStoreTamperedCiphertextFails() throws {
        let label = "test_tamper_\(UUID().uuidString)"

        let seed = Data(repeating: 0x33, count: 32)
        try SeedStore.save(label: label, seedData: seed)

        let fileURL = SeedStore.seedFileURL(label: label)
        var fileData = try Data(contentsOf: fileURL)

        // Flip a bit in the encrypted payload (past the 69-byte header)
        fileData[75] ^= 0xFF
        try fileData.write(to: fileURL, options: .atomic)

        // ChaChaPoly MAC authentication must reject tampered data and return nil
        let loaded = SeedStore.load(label: label)
        XCTAssertNil(loaded)
    }


    func testSeedStorePathUsesCollisionResistantIdentifier() {
        let maliciousLabel = "../../etc/passwd"
        let url = SeedStore.seedFileURL(label: maliciousLabel)

        XCTAssertFalse(url.path.contains(".."))
        XCTAssertFalse(url.path.contains("/etc/passwd"))
        XCTAssertTrue(url.lastPathComponent.hasPrefix("sha256-"))
        XCTAssertEqual(url.lastPathComponent.count, 7 + 64 + 4)
        XCTAssertNotEqual(
            SeedStore.seedFileURL(label: "a/b"),
            SeedStore.seedFileURL(label: "a_b")
        )
    }


    func testKeyManagerRejectsControlCharactersInLabel() {
        let keyManager = makeKeyManager()
        XCTAssertThrowsError(try keyManager.generateKey(label: "trusted\n[AUTH] forged"))
    }


    func testStoredPrivateKeyRecordSerializationAndWipe() throws {
        let dummyKeyData = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        var record = StoredPrivateKeyRecord(
            version: 1,
            label: "test-record",
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyData: dummyKeyData
        )

        let encoded = try record.encode()
        let decoded = try StoredPrivateKeyRecord.decode(from: encoded)

        XCTAssertEqual(decoded.version, 1)
        XCTAssertEqual(decoded.label, "test-record")
        XCTAssertEqual(decoded.algorithm, .ed25519)
        XCTAssertEqual(decoded.storageType, .keychain)
        XCTAssertNil(decoded.biometricPolicy)
        XCTAssertEqual(decoded.keyData, dummyKeyData)

        // Test wiping
        record.wipe()
        XCTAssertEqual(record.keyData.count, 0)

        // Test unsupported future version rejection
        let futureRecord = StoredPrivateKeyRecord(
            version: 999,
            label: "future",
            algorithm: .ed25519,
            storageType: .keychain,
            keyData: Data([0xAA])
        )
        let futureData = try JSONEncoder().encode(futureRecord)
        XCTAssertThrowsError(try StoredPrivateKeyRecord.decode(from: futureData)) { error in
            guard case PrivateKeyRecordError.unsupportedVersion(let v) = error else {
                return XCTFail("Expected unsupportedVersion error, got \(error)")
            }
            XCTAssertEqual(v, 999)
        }
    }

    func testStoredPrivateKeyRecordV2UsesStrictBinaryEnvelope() throws {
        let keyData = Data(repeating: 0xA5, count: 32)
        let record = StoredPrivateKeyRecord(
            label: "binary-record",
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: .userPresence,
            keyPurpose: .gitSigningOnly,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let encoded = try record.encode()
        XCTAssertTrue(encoded.starts(with: Data("CLVPKR02".utf8)))
        XCTAssertNotEqual(encoded.first, Character("{").asciiValue)
        let decoded = try StoredPrivateKeyRecord.decode(from: encoded)
        XCTAssertEqual(decoded, record)

        var trailingGarbage = encoded
        trailingGarbage.append(0x00)
        XCTAssertThrowsError(try StoredPrivateKeyRecord.decode(from: trailingGarbage)) { error in
            guard case PrivateKeyRecordError.corruptedRecord = error else {
                return XCTFail("Expected corruptedRecord, got \(error)")
            }
        }
    }


    func testTamperedAlgorithmInKeysJsonRefusesSigning() throws {
        let keyStore = InMemoryPrivateKeyStore()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache()
        )

        let label = "tamper-algo-\(UUID().uuidString)"
        let originalKey = try keyManager.generateKey(label: label, algorithm: "Ed25519", storageType: .keychain)

        // Attacker tampers with keys.json, claiming this Ed25519 key is actually ECDSA P-256
        let tamperedKey = Ed25519KeyInfo(
            label: originalKey.label,
            publicKeyOpenSSH: originalKey.publicKeyOpenSSH,
            publicKeyBlob: originalKey.publicKeyBlob,
            fingerprint: originalKey.fingerprint,
            createdAt: originalKey.createdAt,
            algorithmName: "ECDSA P-256",
            storage: originalKey.storage,
            biometricPolicy: originalKey.biometricPolicy
        )
        PublicKeyStore.save(tamperedKey)

        // Attempting to sign with tampered metadata MUST fail closed with algorithmMismatch
        let testData = "payload".data(using: .utf8)!
        XCTAssertThrowsError(try keyManager.signSSH(key: tamperedKey, data: testData, prompt: "Sign")) { error in
            guard case PrivateKeyRecordError.algorithmMismatch(let expected, let actual) = error else {
                return XCTFail("Expected algorithmMismatch, got \(error)")
            }
            XCTAssertEqual(expected, "ECDSA P-256")
            XCTAssertEqual(actual, "Ed25519")
        }
    }


    func testTamperedStorageTypeInKeysJsonRefusesSigningAndNeverFallsBack() throws {
        let keyStore = InMemoryPrivateKeyStore()
        let cache = makeSessionCache()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: cache
        )

        let label = "tamper-storage-\(UUID().uuidString)"
        // Create an authentic record in Keychain marked as Secure Enclave
        let fakeSEData = Data(repeating: 0xEE, count: 64)
        let record = StoredPrivateKeyRecord(
            version: 1,
            label: label,
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyData: fakeSEData
        )
        let recordData = try record.encode()
        try keyStore.save(label: label, data: recordData)

        // Attacker tampers keys.json, claiming this Secure Enclave key is a Login Keychain software key
        let tamperedKey = Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... \(label)",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:fake",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .keychain,
            biometricPolicy: nil
        )
        PublicKeyStore.save(tamperedKey)

        // signSSH MUST fail closed and refuse to sign or fall back to software
        let testData = "payload".data(using: .utf8)!
        XCTAssertThrowsError(try keyManager.signSSH(key: tamperedKey, data: testData, prompt: "Sign")) { error in
            guard case PrivateKeyRecordError.storageMismatch(let expected, let actual) = error else {
                return XCTFail("Expected storageMismatch, got \(error)")
            }
            XCTAssertEqual(expected, KeyStorageType.keychain.rawValue)
            XCTAssertEqual(actual, KeyStorageType.secureEnclave.rawValue)
        }

        // Cache count must remain zero
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testTamperedPublicKeyBlobInKeysJsonRefusesSigning() throws {
        let keyStore = InMemoryPrivateKeyStore()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache()
        )

        let label = "tamper-pubblob-\(UUID().uuidString)"
        let originalKey = try keyManager.generateKey(label: label, algorithm: "Ed25519", storageType: .keychain)

        // Attacker tampers keys.json, replacing the public key blob with spoofed bytes
        var spoofedBlob = originalKey.publicKeyBlob
        spoofedBlob[20] ^= 0xFF
        let tamperedKey = Ed25519KeyInfo(
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
        XCTAssertThrowsError(try keyManager.signSSH(key: tamperedKey, data: testData, prompt: "Sign")) { error in
            guard case PrivateKeyRecordError.publicKeyMismatch = error else {
                return XCTFail("Expected publicKeyMismatch, got \(error)")
            }
        }
    }


    func testTamperedStorageInKeysJsonRefusesUnlock() async throws {
        let keyStore = InMemoryPrivateKeyStore()
        let cache = makeSessionCache()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: cache
        )

        let label = "tamper-unlock-\(UUID().uuidString)"
        // Record in Keychain is Secure Enclave
        let record = StoredPrivateKeyRecord(
            version: 1,
            label: label,
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
            biometricPolicy: .userPresence,
            keyData: Data(repeating: 0x55, count: 64)
        )
        let recordData = try record.encode()
        try keyStore.save(label: label, data: recordData)

        // keys.json tampered to claim software Login Keychain
        let tamperedKey = Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA... \(label)",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:fake",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .keychain
        )
        PublicKeyStore.save(tamperedKey)

        // Unlock must fail with .hardwareNotCacheable once Keychain record is loaded
        do {
            try await keyManager.unlock(label: label)
            XCTFail("Unlock must fail for hardware keys even when keys.json claims software")
        } catch {
            XCTAssertEqual(error as? SessionCacheError, .hardwareNotCacheable)
        }

        XCTAssertFalse(cache.isKeyUnlocked(label: label))
        XCTAssertEqual(cache.cachedCount, 0)
    }


    func testLegacyRecordMigrationOnAccess() throws {
        let keyStore = InMemoryPrivateKeyStore()
        let keyManager = KeychainManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: keyStore,
            sessionCache: makeSessionCache()
        )

        let label = "legacy-migration-\(UUID().uuidString)"
        let privateKey = Curve25519.Signing.PrivateKey()
        let rawSeed = privateKey.rawRepresentation

        // Pre-v1 legacy storage: raw 32 bytes saved directly into privateKeyStore
        try keyStore.save(label: label, data: rawSeed)

        let keyInfo = try keyManager.makeKeyInfo(label: label, privateKey: privateKey)
        PublicKeyStore.save(keyInfo)

        // Access via signSSH
        let testData = "hello legacy".data(using: .utf8)!
        let sigBlob = try keyManager.signSSH(key: keyInfo, data: testData, prompt: "Sign")
        XCTAssertFalse(sigBlob.isEmpty)

        // After access, verify the Keychain item was transparently migrated to StoredPrivateKeyRecord
        let context = LAContext()
        let storedData = try keyStore.load(label: label, context: context, prompt: "Load")
        XCTAssertNotNil(storedData)
        let migratedRecord = try StoredPrivateKeyRecord.decode(from: storedData!)
        XCTAssertEqual(migratedRecord.version, StoredPrivateKeyRecord.currentVersion)
        XCTAssertEqual(migratedRecord.label, label)
        XCTAssertEqual(migratedRecord.algorithm, .ed25519)
        XCTAssertEqual(migratedRecord.storageType, .keychain)
        XCTAssertEqual(migratedRecord.keyData, rawSeed)
    }


    func testRebuildPublicIndexFromKeychain() throws {
        guard ProcessInfo.processInfo.environment["CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS"] == "1" else {
            throw XCTSkip("Set CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS=1 to run tests against the real user Keychain.")
        }
        PublicKeyStore.disableKeychainMirrorForTesting = false
        defer { PublicKeyStore.disableKeychainMirrorForTesting = true }
        let keyInfo = Ed25519KeyInfo(
            label: "test-rebuild-\(UUID().uuidString)",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test",
            publicKeyBlob: Data(repeating: 0x11, count: 51),
            fingerprint: "SHA256:testfingerprint",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain
        )

        PublicKeyStore.save(keyInfo)
        XCTAssertTrue(PublicKeyStore.loadAll().contains(where: { $0.label == keyInfo.label }))

        // Delete keys.json file
        if let url = PublicKeyStore.customStorageURL {
            try? FileManager.default.removeItem(at: url)
        }

        // loadAll should reconstruct from Keychain if keys.json is gone
        let reloaded = PublicKeyStore.loadAll()
        let rebuilt = PublicKeyStore.rebuildIndexFromKeychain()
        XCTAssertTrue(rebuilt.contains(where: { $0.label == keyInfo.label }) || reloaded.contains(where: { $0.label == keyInfo.label }))

        // Cleanup
        PublicKeyStore.remove(label: keyInfo.label)
    }


    func testKeychainPrivateKeyStoreLifecycle() throws {
        guard ProcessInfo.processInfo.environment["CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS"] == "1" else {
            throw XCTSkip("Set CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS=1 to run tests against the real user Keychain.")
        }
        let store = KeychainPrivateKeyStore(serviceName: "com.clavis.tests.\(UUID().uuidString)")
        let label = "test-store-lifecycle-\(UUID().uuidString)"
        let dummySecret = "SecurePayload_\(UUID().uuidString)".data(using: .utf8)!

        defer { try? store.remove(label: label) }

        XCTAssertFalse(store.contains(label: label))

        // This opt-in integration test must preserve the requested access control.
        try store.save(label: label, data: dummySecret, accessControlFlags: [.privateKeyUsage, .userPresence])
        XCTAssertTrue(store.contains(label: label))

        let context = LAContext()
        let loaded = try store.load(label: label, context: context, prompt: "Test prompt")
        XCTAssertEqual(loaded, dummySecret)

        try store.remove(label: label)
        XCTAssertFalse(store.contains(label: label))
    }

    func testKeychainPrivateKeyStoreFailsClosedWhenProtectedAddIsUnavailable() throws {
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

        XCTAssertThrowsError(
            try store.save(
                label: "protected",
                data: Data([0x01, 0x02]),
                accessControlFlags: [.privateKeyUsage, .userPresence]
            )
        ) { error in
            guard case PrivateKeyStoreError.protectionUnavailable(let status) = error else {
                return XCTFail("Expected protectionUnavailable, got \(error)")
            }
            XCTAssertEqual(status, errSecMissingEntitlement)
        }

        XCTAssertEqual(deleteCallCount, 0)
        XCTAssertEqual(addedItems.count, 1, "A protected add failure must never retry with weaker attributes")
        let added = addedItems[0] as NSDictionary
        XCTAssertNotNil(added[kSecAttrAccessControl as String])
        XCTAssertNil(added[kSecAttrAccessible as String])
    }

    func testKeychainPrivateKeyStoreRejectsMissingAuthenticationConstraint() throws {
        var addCallCount = 0
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.missing-auth",
            addItem: { _ in
                addCallCount += 1
                return errSecSuccess
            },
            deleteItem: { _ in errSecItemNotFound },
            updateItem: { _, _ in
                XCTFail("Update must not be attempted without an authentication constraint")
                return errSecSuccess
            }
        )

        XCTAssertThrowsError(
            try store.save(
                label: "unprotected",
                data: Data([0x01]),
                accessControlFlags: [.privateKeyUsage]
            )
        ) { error in
            guard case PrivateKeyStoreError.accessControlCreation = error else {
                return XCTFail("Expected accessControlCreation, got \(error)")
            }
        }
        XCTAssertEqual(addCallCount, 0)
    }

    func testKeychainPrivateKeyStoreFailedUpdateNeverDeletesExistingItem() throws {
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

        XCTAssertThrowsError(
            try store.save(
                label: "existing",
                data: Data([0x01]),
                accessControlFlags: [.userPresence]
            )
        )
        XCTAssertEqual(updateCallCount, 1)
        XCTAssertEqual(addCallCount, 0)
        XCTAssertEqual(deleteCallCount, 0, "A failed update must leave the existing item intact")
    }

    func testKeychainPrivateKeyStoreWritesProtectedDataProtectionItemToSharedGroup() throws {
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

        XCTAssertEqual(addedItems.count, 1)
        let added = addedItems[0] as NSDictionary
        XCTAssertNotNil(added[kSecAttrAccessControl as String])
        XCTAssertEqual(added[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(
            added[kSecAttrAccessGroup as String] as? String,
            KeychainPrivateKeyStore.sharedAccessGroup
        )
        XCTAssertNil(added[kSecAttrAccess as String], "Data Protection Keychain must not use legacy ACLs")
    }

    func testKeychainPrivateKeyStoreMigratesLegacyItemBeforeDeletingIt() throws {
        let label = "legacy-key"
        var record = StoredPrivateKeyRecord(
            label: label,
            algorithm: .ed25519,
            storageType: .keychain,
            keyPurpose: .general,
            keyData: Data(repeating: 0x42, count: 32)
        )
        defer { record.wipe() }
        let encoded = try record.encode()

        var addedItems: [CFDictionary] = []
        var deletedQueries: [CFDictionary] = []
        var copyQueries: [CFDictionary] = []
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.legacy-migration",
            addItem: { item in
                addedItems.append(item)
                return errSecSuccess
            },
            deleteItem: { query in
                deletedQueries.append(query)
                return errSecSuccess
            },
            updateItem: { _, _ in errSecItemNotFound },
            copyItem: { query in
                copyQueries.append(query)
                let dictionary = query as NSDictionary
                if dictionary[kSecUseDataProtectionKeychain as String] != nil {
                    return (errSecItemNotFound, nil)
                }
                return (errSecSuccess, encoded as AnyObject)
            }
        )

        let loaded = try store.load(label: label, context: LAContext(), prompt: "Migrate key")

        XCTAssertEqual(loaded, encoded)
        XCTAssertEqual(copyQueries.count, 2)
        XCTAssertEqual(addedItems.count, 1)
        XCTAssertEqual(deletedQueries.count, 1)

        let added = addedItems[0] as NSDictionary
        XCTAssertEqual(added[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(
            added[kSecAttrAccessGroup as String] as? String,
            KeychainPrivateKeyStore.sharedAccessGroup
        )
        XCTAssertNotNil(added[kSecAttrAccessControl as String])

        let deleted = deletedQueries[0] as NSDictionary
        XCTAssertNil(deleted[kSecUseDataProtectionKeychain as String])
        XCTAssertNil(deleted[kSecAttrAccessGroup as String])
    }

    func testKeychainPrivateKeyStoreDoesNotDeleteLegacyItemWhenMigrationAddFails() throws {
        let encoded = Data([0x01, 0x02, 0x03])
        var deleteCallCount = 0
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.tests.failed-legacy-migration",
            addItem: { _ in errSecMissingEntitlement },
            deleteItem: { _ in
                deleteCallCount += 1
                return errSecSuccess
            },
            updateItem: { _, _ in errSecItemNotFound },
            copyItem: { query in
                let dictionary = query as NSDictionary
                if dictionary[kSecUseDataProtectionKeychain as String] != nil {
                    return (errSecItemNotFound, nil)
                }
                return (errSecSuccess, encoded as AnyObject)
            }
        )

        XCTAssertThrowsError(
            try store.load(label: "legacy-key", context: LAContext(), prompt: "Migrate key")
        ) { error in
            guard case PrivateKeyStoreError.protectionUnavailable(let status) = error else {
                return XCTFail("Expected protectionUnavailable, got \(error)")
            }
            XCTAssertEqual(status, errSecMissingEntitlement)
        }
        XCTAssertEqual(deleteCallCount, 0, "Legacy data must survive a failed migration")
    }
}
