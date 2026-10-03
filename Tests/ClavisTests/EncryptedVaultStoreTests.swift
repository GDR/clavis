import XCTest
import CryptoKit
@testable import ClavisCore

final class EncryptedVaultStoreTests: ClavisBaseTestCase {
    override func tearDownWithError() throws {
        EncryptedVaultStore.customPinStore = nil
        EncryptedVaultStore.masterKeyLockTimeout = 10.0
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
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyPinMissing)
        }

        let newLabel = "cannot-write-unpinned"
        let newFileURL = vaultFileURL(for: newLabel)
        XCTAssertThrowsError(try EncryptedVaultStore.shared.saveRecord(makeRecord(label: newLabel))) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyPinMissing)
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

    func testPinAbsentWithMasterFilesThrowsMasterKeyPinMissingWithRepairInstructions() throws {
        let label = "vault-initial-pin-test"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

        EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: nil)

        XCTAssertThrowsError(try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cannot-save-unpinned"))) { error in
            guard let vaultError = error as? EncryptedVaultStore.VaultError else {
                XCTFail("Expected VaultError, got \(error)")
                return
            }
            XCTAssertEqual(vaultError, .masterKeyPinMissing)
            XCTAssertTrue(
                vaultError.localizedDescription.contains("clavis vault repair"),
                "Error description must provide actionable recovery instruction 'clavis vault repair'"
            )
        }
    }

    func testAfterRepairSaveAndLoadRecordWork() throws {
        let initialLabel = "vault-pre-repair"
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: initialLabel))

        // Lost Keychain pin
        let pinStore = InMemoryMasterKeyPinStore(pin: nil)
        EncryptedVaultStore.customPinStore = pinStore

        // Operations fail closed with masterKeyPinMissing
        XCTAssertThrowsError(try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "blocked"))) { error in
            XCTAssertEqual(error as? EncryptedVaultStore.VaultError, .masterKeyPinMissing)
        }

        // Run repair
        let result = try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: false)
        XCTAssertFalse(result.fingerprint.isEmpty)
        XCTAssertNotNil(try pinStore.loadPin())

        // saveRecord and loadRecord work after repair
        let newLabel = "vault-post-repair"
        XCTAssertNoThrow(try EncryptedVaultStore.shared.saveRecord(makeRecord(label: newLabel)))
        let loadedNew = try EncryptedVaultStore.shared.loadRecord(label: newLabel)
        XCTAssertEqual(loadedNew?.label, newLabel)
        let loadedInitial = try EncryptedVaultStore.shared.loadRecord(label: initialLabel)
        XCTAssertEqual(loadedInitial?.label, initialLabel)
    }

    func testPinMismatchIsNotRepairedWithoutReplacePinFlag() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "vault-replace-test"))
        let wrongPin = Data(repeating: 0xee, count: 32)
        let pinStore = InMemoryMasterKeyPinStore(pin: wrongPin)
        EncryptedVaultStore.customPinStore = pinStore

        // Without replacePin: true, repair must fail and not overwrite pin
        XCTAssertThrowsError(try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: false))
        XCTAssertEqual(try pinStore.loadPin(), wrongPin, "Mismatched pin must not be overwritten without replacePin: true")

        // With replacePin: true, repair succeeds and updates pin
        XCTAssertNoThrow(try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: true))
        let pubData = try Data(contentsOf: EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub"))
        let expectedPin = Data(SHA256.hash(data: pubData))
        XCTAssertEqual(try pinStore.loadPin(), expectedPin)
    }

    func testSimulatedCrashLeavesNoPartialFilesAndSecondEnsureMasterKeySucceeds() throws {
        final class CrashSimulatingPinStore: MasterKeyPinStoring, @unchecked Sendable {
            let inner = InMemoryMasterKeyPinStore()
            var onSavePin: (() -> Void)?

            func loadPin() throws -> Data? {
                try inner.loadPin()
            }
            func savePin(_ pin: Data) throws {
                try inner.savePin(pin)
                onSavePin?()
            }
            func removePin() throws {
                try inner.removePin()
            }
        }

        let pinStore = CrashSimulatingPinStore()
        EncryptedVaultStore.customPinStore = pinStore

        let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
        let keyURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.key")

        pinStore.onSavePin = {
            // When pin is saved, simulate crash/failure during file write by creating master.pub as a directory
            try? FileManager.default.createDirectory(at: pubURL, withIntermediateDirectories: false)
        }

        // First attempt must fail because writing files fails
        XCTAssertThrowsError(try EncryptedVaultStore.shared.ensureMasterKey())

        // Verify no stale partial files remain and pin was rolled back
        XCTAssertFalse(FileManager.default.fileExists(atPath: keyURL.path), "master.key must not remain after failed write")
        XCTAssertFalse(FileManager.default.fileExists(atPath: pubURL.path), "master.pub must not remain after failed write")
        XCTAssertNil(try pinStore.loadPin(), "Pin must be rolled back on file write failure")

        // Second ensureMasterKey succeeds
        pinStore.onSavePin = nil
        XCTAssertNoThrow(try EncryptedVaultStore.shared.ensureMasterKey())
        XCTAssertTrue(FileManager.default.fileExists(atPath: pubURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keyURL.path))
        XCTAssertNotNil(try pinStore.loadPin())
    }

    func testNonTTYStdinRefusesRepairConfirmation() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "vault-tty-test"))
        EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: nil)

        let result = CLIService.handle(
            args: ["clavis", "vault", "repair"],
            isTTY: false
        )
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.exitCode, 1)
        XCTAssertTrue(
            result?.error?.contains("TTY") == true ||
            result?.error?.contains("terminal") == true ||
            result?.error?.contains("interactive") == true
        )
    }

    func testCLIVaultRepairInteractiveConfirmation() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cli-repair-test"))
        let pinStore = InMemoryMasterKeyPinStore(pin: nil)
        EncryptedVaultStore.customPinStore = pinStore

        // User enters "no" -> cancelled
        let cancelled = CLIService.handle(
            args: ["clavis", "vault", "repair"],
            isTTY: true,
            confirmationPrompt: { "no" }
        )
        XCTAssertEqual(cancelled?.exitCode, 1)
        XCTAssertTrue(cancelled?.error?.contains("cancelled") == true)
        XCTAssertNil(try pinStore.loadPin())

        // User enters "yes" -> succeeded
        let succeeded = CLIService.handle(
            args: ["clavis", "vault", "repair"],
            isTTY: true,
            confirmationPrompt: { "yes" }
        )
        XCTAssertEqual(succeeded?.exitCode, 0)
        XCTAssertTrue(succeeded?.output.contains("successfully repaired") == true)
        XCTAssertNotNil(try pinStore.loadPin())
    }

    func testCLIVaultRepairPinMismatchRequiresReplacePinFlag() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cli-mismatch-test"))
        let wrongPin = Data(repeating: 0xee, count: 32)
        let pinStore = InMemoryMasterKeyPinStore(pin: wrongPin)
        EncryptedVaultStore.customPinStore = pinStore

        // Mismatched pin without --replace-pin -> fails with warning
        let failed = CLIService.handle(
            args: ["clavis", "vault", "repair"],
            isTTY: true,
            confirmationPrompt: { "yes" }
        )
        XCTAssertEqual(failed?.exitCode, 1)
        XCTAssertTrue(failed?.error?.contains("--replace-pin") == true)
        XCTAssertEqual(try pinStore.loadPin(), wrongPin)

        // Mismatched pin with --replace-pin -> succeeds
        let succeeded = CLIService.handle(
            args: ["clavis", "vault", "repair", "--replace-pin"],
            isTTY: true,
            confirmationPrompt: { "yes" }
        )
        XCTAssertEqual(succeeded?.exitCode, 0)
        XCTAssertTrue(succeeded?.output.contains("WARNING: Replacing existing mismatched") == true)
        XCTAssertNotEqual(try pinStore.loadPin(), wrongPin)
    }

    /// R17: without a TTY the command must fail before verifyMasterKey() (Touch ID). With no vault on
    /// disk verification would fail with a different message, so the TTY error proves the order.
    func testVaultRepairWithoutTTYFailsBeforeVerification() throws {
        EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: nil)
        let result = CLIService.handle(args: ["clavis", "vault", "repair"], isTTY: false)
        XCTAssertEqual(result?.exitCode, 1)
        XCTAssertTrue(result?.error?.contains("TTY") == true)
        XCTAssertFalse(result?.error?.contains("verify") == true)
    }

    /// R17: the owner needs the pinned fingerprint as a baseline to tell a legitimate repair from a
    /// replaced master.key.
    func testVaultRepairShowsPinnedFingerprintBaselineAndWarning() throws {
        try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cli-baseline-test"))
        let wrongPin = Data(repeating: 0xee, count: 32)
        let oldFingerprint = EncryptedVaultStore.fingerprint(forPin: wrongPin)
        EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: wrongPin)

        // Even the refusal (no --replace-pin) prints the baseline.
        let refused = CLIService.handle(
            args: ["clavis", "vault", "repair"],
            isTTY: true,
            confirmationPrompt: { "yes" }
        )
        XCTAssertEqual(refused?.exitCode, 1)
        XCTAssertTrue(refused?.output.contains("Keychain pinned fingerprint: \(oldFingerprint)") == true)
        XCTAssertTrue(refused?.output.contains("master.key created:") == true)

        let replaced = CLIService.handle(
            args: ["clavis", "vault", "repair", "--replace-pin"],
            isTTY: true,
            confirmationPrompt: { "no" }
        )
        let output = replaced?.output ?? ""
        XCTAssertTrue(output.contains("Keychain pinned fingerprint: \(oldFingerprint)"))
        XCTAssertTrue(output.contains("Master key fingerprint: SHA256:"))
        XCTAssertTrue(output.contains("do not confirm"))
        XCTAssertNotEqual(oldFingerprint, try EncryptedVaultStore.shared.verifyMasterKey().fingerprint)
    }

    // MARK: - Finding N-4: Cross-Process Advisory File Lock Tests

    func testExternalHolderBlocksMasterKeyCreation() throws {
        let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
        try SecureFS.createDirectory(at: vaultDir)
        let lockURL = vaultDir.appendingPathComponent(".master.lock")
        let lockFd = SecureFS.openLockFile(path: lockURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
        XCTAssertGreaterThanOrEqual(lockFd, 0)
        XCTAssertEqual(flock(lockFd, LOCK_EX), 0)

        let exp = expectation(description: "ensureMasterKey completes after lock released")
        var returnedPubKey: P256.KeyAgreement.PublicKey?
        var callError: Error?

        let queue = DispatchQueue(label: "test.masterKey.block")
        queue.async {
            do {
                let key = try EncryptedVaultStore.shared.ensureMasterKey()
                returnedPubKey = key
            } catch {
                callError = error
            }
            exp.fulfill()
        }

        // Assert not finished after 0.3s
        usleep(300_000)
        XCTAssertNil(returnedPubKey)
        XCTAssertNil(callError)

        // Release lock
        XCTAssertEqual(flock(lockFd, LOCK_UN), 0)
        close(lockFd)

        // Assert it finishes and files exist
        wait(for: [exp], timeout: 2.0)
        XCTAssertNotNil(returnedPubKey)
        XCTAssertNil(callError)

        let pubURL = vaultDir.appendingPathComponent("master.pub")
        let keyURL = vaultDir.appendingPathComponent("master.key")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pubURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keyURL.path))
    }

    func testMasterKeyRecheckWorksWhenCreatedByAnotherProcess() throws {
        let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
        try SecureFS.createDirectory(at: vaultDir)
        let lockURL = vaultDir.appendingPathComponent(".master.lock")
        let lockFd = SecureFS.openLockFile(path: lockURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
        XCTAssertGreaterThanOrEqual(lockFd, 0)
        XCTAssertEqual(flock(lockFd, LOCK_EX), 0)

        final class CountingPinStore: MasterKeyPinStoring, @unchecked Sendable {
            private let lock = NSLock()
            var saveCount = 0
            var pin: Data?
            init(pin: Data? = nil) { self.pin = pin }
            func loadPin() throws -> Data? {
                lock.lock()
                defer { lock.unlock() }
                return pin
            }
            func savePin(_ p: Data) throws {
                lock.lock()
                defer { lock.unlock() }
                saveCount += 1
                pin = p
            }
            func removePin() throws {
                lock.lock()
                defer { lock.unlock() }
                pin = nil
            }
        }
        let pinStore = CountingPinStore()
        EncryptedVaultStore.customPinStore = pinStore

        let exp = expectation(description: "waiting call completes after lock released")
        var returnedPubKey: P256.KeyAgreement.PublicKey?
        var callError: Error?

        let queue = DispatchQueue(label: "test.masterKey.recheck")
        queue.async {
            do {
                let key = try EncryptedVaultStore.shared.ensureMasterKey()
                returnedPubKey = key
            } catch {
                callError = error
            }
            exp.fulfill()
        }

        // Wait briefly to ensure background call has started and is polling lock
        usleep(100_000)
        XCTAssertNil(returnedPubKey)

        // Create valid key pair via file writes while holding lock
        let swKey = P256.KeyAgreement.PrivateKey()
        let pubData = swKey.publicKey.rawRepresentation
        let pin = Data(SHA256.hash(data: pubData))
        try EncryptedVaultStore.shared.activePinStore.savePin(pin)
        XCTAssertEqual(pinStore.saveCount, 1)

        let pubURL = vaultDir.appendingPathComponent("master.pub")
        let keyURL = vaultDir.appendingPathComponent("master.key")
        try SecureFS.withUmask(0o077) {
            var keyFileBytes = Data([0x02])
            keyFileBytes.append(swKey.rawRepresentation)
            try keyFileBytes.write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

            try pubData.write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubURL.path)
        }

        // Release lock
        XCTAssertEqual(flock(lockFd, LOCK_UN), 0)
        close(lockFd)

        wait(for: [exp], timeout: 2.0)
        XCTAssertNil(callError)
        XCTAssertEqual(returnedPubKey?.rawRepresentation, swKey.publicKey.rawRepresentation)

        // Verify pin was not overwritten
        let storedPin = try EncryptedVaultStore.shared.activePinStore.loadPin()
        XCTAssertEqual(storedPin, pin)
        XCTAssertEqual(pinStore.saveCount, 1)
    }

    func testMasterKeyLockTimeoutThrowsError() throws {
        EncryptedVaultStore.masterKeyLockTimeout = 0.2
        defer { EncryptedVaultStore.masterKeyLockTimeout = 10.0 }

        let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
        try SecureFS.createDirectory(at: vaultDir)
        let lockURL = vaultDir.appendingPathComponent(".master.lock")
        let lockFd = SecureFS.openLockFile(path: lockURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
        XCTAssertGreaterThanOrEqual(lockFd, 0)
        XCTAssertEqual(flock(lockFd, LOCK_EX), 0)
        defer {
            flock(lockFd, LOCK_UN)
            close(lockFd)
        }

        let start = Date()
        XCTAssertThrowsError(try EncryptedVaultStore.shared.ensureMasterKey()) { error in
            let nsError = error as NSError
            XCTAssertEqual(nsError.domain, "Clavis")
            XCTAssertEqual(nsError.code, -1)
            XCTAssertEqual(nsError.localizedDescription, "Another Clavis process is creating the vault master key.")
        }
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertGreaterThanOrEqual(elapsed, 0.2)
    }
}


