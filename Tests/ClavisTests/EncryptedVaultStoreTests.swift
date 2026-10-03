import XCTest
import CryptoKit
@testable import ClavisCore

final class EncryptedVaultStoreTests: ClavisBaseTestCase {
    override func tearDownWithError() throws {
        EncryptedVaultStore.customPinStore = nil
        try super.tearDownWithError()
    }

    private func makeRecord(label: String) -> StoredPrivateKeyRecord {
        StoredPrivateKeyRecord(
            version: 1,
            label: label,
            algorithm: .ed25519,
            storageType: .keychain,
            biometricPolicy: nil,
            keyPurpose: .general,
            keyData: Data(repeating: 0x42, count: 32)
        )
    }

    private func vaultFileURL(for label: String) -> URL {
        let hash = SHA256.hash(data: Data(label.utf8)).map { String(format: "%02x", $0) }.joined()
        return EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("\(hash).enc")
    }

    /// Reproduces the pre-AAD `CLVENV01` writer so the legacy read path stays covered.
    private func writeLegacyEnvelope(_ record: StoredPrivateKeyRecord) throws {
        let masterPublicKey = try EncryptedVaultStore.shared.ensureMasterKey()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: masterPublicKey)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.publicKey.rawRepresentation,
            sharedInfo: Data("clavis-vault-envelope-v1".utf8),
            outputByteCount: 32
        )
        let sealed = try ChaChaPoly.seal(try record.encode(), using: key)
        let epk = ephemeral.publicKey.rawRepresentation
        var envelope = Data("CLVENV01".utf8)
        envelope.append(UInt8(epk.count))
        envelope.append(epk)
        envelope.append(sealed.combined)
        try envelope.write(to: vaultFileURL(for: record.label), options: .atomic)
    }

    func testNewEnvelopesUseAuthenticatedFormatAndRoundTrip() throws {
        let label = "vault-roundtrip"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

        let raw = try Data(contentsOf: vaultFileURL(for: label))
        XCTAssertTrue(raw.starts(with: Data("CLVENV02".utf8)))

        let loaded = try XCTUnwrap(EncryptedVaultStore.shared.loadRecord(label: label))
        XCTAssertEqual(loaded.label, label)
        XCTAssertEqual(loaded.keyData, Data(repeating: 0x42, count: 32))
    }

    func testEnvelopeMovedToAnotherLabelSlotIsRejected() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "victim"))
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "decoy"))

        // Attacker with write access to the vault directory swaps one label's ciphertext in
        // place of another's. Without AAD this decrypts fine and relies on later label checks.
        let source = vaultFileURL(for: "decoy")
        let target = vaultFileURL(for: "victim")
        try FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(at: source, to: target)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: "victim"))
        XCTAssertNoThrow(try EncryptedVaultStore.shared.loadRecord(label: "decoy"))
    }

    func testTamperedCiphertextIsRejected() throws {
        let label = "vault-tamper"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))
        let url = vaultFileURL(for: label)
        var raw = try Data(contentsOf: url)
        raw[raw.count - 1] ^= 0x01
        try raw.write(to: url)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: label))
    }

    func testSwappingMasterPubAfterSetupCausesSaveRecordToThrowAndWriteNothing() throws {
        let initialLabel = "vault-initial"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: initialLabel))

        let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pubURL.path))

        // Attacker with write access to the filesystem swaps master.pub with their own public key
        let attackerKey = P256.KeyAgreement.PrivateKey()
        let attackerPub = attackerKey.publicKey.rawRepresentation
        try attackerPub.write(to: pubURL, options: .atomic)

        let victimLabel = "victim-record"
        let victimFileURL = vaultFileURL(for: victimLabel)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.saveRecord(makeRecord(label: victimLabel))) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyTampered)
        }
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: victimFileURL.path),
            "Must write nothing to disk when master.pub has been tampered"
        )
    }

    func testMissingPinWhenMasterFilesExistFailsClosed() throws {
        let initialLabel = "vault-pinned"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: initialLabel))

        let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
        let keyURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.key")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pubURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keyURL.path))

        // Simulate missing pin when master files already exist
        let pinStore = InMemoryMasterKeyPinStore(pin: nil)
        EncryptedVaultStore.customPinStore = pinStore

        XCTAssertThrowsError(try EncryptedVaultStore.shared.ensureMasterKey()) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyTampered)
        }

        let newLabel = "cannot-write-unpinned"
        let newFileURL = vaultFileURL(for: newLabel)
        XCTAssertThrowsError(try EncryptedVaultStore.shared.saveRecord(makeRecord(label: newLabel))) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyTampered)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: newFileURL.path))

        // Never silently re-pin
        XCTAssertNil(try pinStore.loadPin(), "Missing pin must never be silently re-pinned")
    }

    func testCLVENV01EnvelopeIsRejected() throws {
        let label = "vault-legacy"
        try writeLegacyEnvelope(makeRecord(label: label))
        XCTAssertTrue(try Data(contentsOf: vaultFileURL(for: label)).starts(with: Data("CLVENV01".utf8)))

        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: label))
    }

    func testTamperedPinValueFailsClosed() throws {
        let label = "vault-tampered-pin"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

        // Set a corrupted/mismatched pin in pinStore
        let wrongPin = Data(repeating: 0xee, count: 32)
        EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: wrongPin)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.ensureMasterKey()) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyTampered)
        }
        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: label)) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyTampered)
        }
    }

    func testLoadRecordFailsClosedWhenMasterPubIsTampered() throws {
        let label = "vault-load-tamper"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

        let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
        let attackerKey = P256.KeyAgreement.PrivateKey()
        try attackerKey.publicKey.rawRepresentation.write(to: pubURL, options: .atomic)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.loadRecord(label: label)) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyTampered)
        }
    }

    func testKeychainMasterKeyPinStoreWithMockClosures() throws {
        final class MockKeychainState: @unchecked Sendable {
            private let lock = NSLock()
            private var storage: [String: [String: Any]] = [:]

            func get(_ key: String) -> [String: Any]? {
                lock.lock(); defer { lock.unlock() }
                return storage[key]
            }

            func set(_ key: String, _ value: [String: Any]) {
                lock.lock(); defer { lock.unlock() }
                storage[key] = value
            }

            func remove(_ key: String) -> [String: Any]? {
                lock.lock(); defer { lock.unlock() }
                return storage.removeValue(forKey: key)
            }
        }

        let state = MockKeychainState()

        let store = KeychainMasterKeyPinStore(
            service: "com.clavis.vault-master-pin.test",
            account: "test-pin",
            addItem: { dict in
                let d = dict as! [String: Any]
                let s = d[kSecAttrService as String] as! String
                let a = d[kSecAttrAccount as String] as! String
                let key = "\(s)/\(a)"
                if state.get(key) != nil { return errSecDuplicateItem }
                state.set(key, d)
                return errSecSuccess
            },
            deleteItem: { dict in
                let d = dict as! [String: Any]
                let s = d[kSecAttrService as String] as! String
                let a = d[kSecAttrAccount as String] as! String
                let key = "\(s)/\(a)"
                if state.remove(key) != nil {
                    return errSecSuccess
                }
                return errSecItemNotFound
            },
            updateItem: { query, attrs in
                let q = query as! [String: Any]
                let a = attrs as! [String: Any]
                let s = q[kSecAttrService as String] as! String
                let acct = q[kSecAttrAccount as String] as! String
                let key = "\(s)/\(acct)"
                guard var item = state.get(key) else { return errSecItemNotFound }
                for (k, v) in a { item[k] = v }
                state.set(key, item)
                return errSecSuccess
            },
            copyItem: { query in
                let q = query as! [String: Any]
                let s = q[kSecAttrService as String] as! String
                let a = q[kSecAttrAccount as String] as! String
                let key = "\(s)/\(a)"
                guard let item = state.get(key), let data = item[kSecValueData as String] as? Data else {
                    return (errSecItemNotFound, nil)
                }
                return (errSecSuccess, data as AnyObject)
            }
        )

        // Initially empty
        XCTAssertNil(try store.loadPin())

        // Save pin
        let samplePin = Data(repeating: 0x55, count: 32)
        try store.savePin(samplePin)

        let loaded = try store.loadPin()
        XCTAssertEqual(loaded, samplePin)

        // Check attributes
        let item = state.get("com.clavis.vault-master-pin.test/test-pin")
        XCTAssertNotNil(item)
        let accessible = item?[kSecAttrAccessible as String] as? String
        XCTAssertEqual(accessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)

        // Update pin (save again)
        let updatedPin = Data(repeating: 0x77, count: 32)
        try store.savePin(updatedPin)
        XCTAssertEqual(try store.loadPin(), updatedPin)

        // Remove pin
        try store.removePin()
        XCTAssertNil(try store.loadPin())
    }
}
