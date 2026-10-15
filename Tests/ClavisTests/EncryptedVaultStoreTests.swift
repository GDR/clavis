import Testing
import Foundation
import CryptoKit
@testable import ClavisCore

struct EncryptedVaultStoreTests {


    private func makeRecord(label: String) -> StoredPrivateKeyRecord {
        StoredPrivateKeyRecord(
            version: StoredPrivateKeyRecord.currentVersion,
            label: label,
            algorithm: .ecdsaP256,
            storageType: .secureEnclave,
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

    @Test func testNewEnvelopesUseAuthenticatedFormatAndRoundTrip() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let label = "vault-roundtrip"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

            let raw = try Data(contentsOf: vaultFileURL(for: label))
            #expect(raw.starts(with: Data("CLVENV02".utf8)))

            let loaded = try #require(try EncryptedVaultStore.shared.loadRecord(label: label))
            #expect(loaded.label == label)
            #expect(loaded.keyData == Data(repeating: 0x42, count: 32))
        }
    }

    @Test func testEnvelopeMovedToAnotherLabelSlotIsRejected() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "victim"))
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "decoy"))

            // Attacker with write access to the vault directory swaps one label's ciphertext in
            // place of another's. Without AAD this decrypts fine and relies on later label checks.
            let source = vaultFileURL(for: "decoy")
            let target = vaultFileURL(for: "victim")
            try FileManager.default.removeItem(at: target)
            try FileManager.default.copyItem(at: source, to: target)

            #expect(throws: (any Error).self) {
                try EncryptedVaultStore.shared.loadRecord(label: "victim")
            }
            #expect(throws: Never.self) {
                _ = try EncryptedVaultStore.shared.loadRecord(label: "decoy")
            }
        }
    }

    @Test func testTamperedCiphertextIsRejected() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let label = "vault-tamper"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))
            let url = vaultFileURL(for: label)
            var raw = try Data(contentsOf: url)
            raw[raw.count - 1] ^= 0x01
            try raw.write(to: url)

            #expect(throws: (any Error).self) {
                try EncryptedVaultStore.shared.loadRecord(label: label)
            }
        }
    }

    @Test func testSwappingMasterPubAfterSetupCausesSaveRecordToThrowAndWriteNothing() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let initialLabel = "vault-initial"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: initialLabel))

            let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
            #expect(FileManager.default.fileExists(atPath: pubURL.path))

            // Attacker with write access to the filesystem swaps master.pub with their own public key
            let attackerKey = P256.KeyAgreement.PrivateKey()
            let attackerPub = attackerKey.publicKey.rawRepresentation
            try attackerPub.write(to: pubURL, options: .atomic)

            let victimLabel = "victim-record"
            let victimFileURL = vaultFileURL(for: victimLabel)

            #expect {
                try EncryptedVaultStore.shared.saveRecord(makeRecord(label: victimLabel))
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyTampered
            }
            #expect(
                !FileManager.default.fileExists(atPath: victimFileURL.path),
                "Must write nothing to disk when master.pub has been tampered"
            )
        }
    }

    @Test func testMissingPinWhenMasterFilesExistFailsClosed() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let initialLabel = "vault-pinned"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: initialLabel))

            let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
            let keyURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.key")
            #expect(FileManager.default.fileExists(atPath: pubURL.path))
            #expect(FileManager.default.fileExists(atPath: keyURL.path))

            // Simulate missing pin when master files already exist
            let pinStore = InMemoryMasterKeyPinStore(pin: nil)
            EncryptedVaultStore.customPinStore = pinStore
            defer { EncryptedVaultStore.customPinStore = nil }

            #expect {
                try EncryptedVaultStore.shared.ensureMasterKey()
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyPinMissing
            }

            let newLabel = "cannot-write-unpinned"
            let newFileURL = vaultFileURL(for: newLabel)
            #expect {
                try EncryptedVaultStore.shared.saveRecord(makeRecord(label: newLabel))
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyPinMissing
            }
            #expect(!FileManager.default.fileExists(atPath: newFileURL.path))

            // Never silently re-pin
            #expect(try pinStore.loadPin() == nil, "Missing pin must never be silently re-pinned")
        }
    }

    @Test func testCLVENV01EnvelopeIsRejected() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let label = "vault-legacy"
            try writeLegacyEnvelope(makeRecord(label: label))
            #expect(try Data(contentsOf: vaultFileURL(for: label)).starts(with: Data("CLVENV01".utf8)))

            #expect(throws: (any Error).self) {
                try EncryptedVaultStore.shared.loadRecord(label: label)
            }
        }
    }

    @Test func testTamperedPinValueFailsClosed() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let label = "vault-tampered-pin"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

            // Set a corrupted/mismatched pin in pinStore
            let wrongPin = Data(repeating: 0xee, count: 32)
            EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: wrongPin)
            defer { EncryptedVaultStore.customPinStore = nil }

            #expect {
                try EncryptedVaultStore.shared.ensureMasterKey()
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyTampered
            }
            #expect {
                try EncryptedVaultStore.shared.loadRecord(label: label)
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyTampered
            }
        }
    }

    @Test func testLoadRecordFailsClosedWhenMasterPubIsTampered() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let label = "vault-load-tamper"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

            let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
            let attackerKey = P256.KeyAgreement.PrivateKey()
            try attackerKey.publicKey.rawRepresentation.write(to: pubURL, options: .atomic)

            #expect {
                try EncryptedVaultStore.shared.loadRecord(label: label)
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyTampered
            }
        }
    }

    @Test func testKeychainMasterKeyPinStoreWithMockClosures() throws {
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
        #expect(try store.loadPin() == nil)

        // Save pin
        let samplePin = Data(repeating: 0x55, count: 32)
        try store.savePin(samplePin)

        let loaded = try store.loadPin()
        #expect(loaded == samplePin)

        // Check attributes
        let item = state.get("com.clavis.vault-master-pin.test/test-pin")
        #expect(item != nil)
        let accessible = item?[kSecAttrAccessible as String] as? String
        #expect(accessible == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String))

        // Update pin (save again)
        let updatedPin = Data(repeating: 0x77, count: 32)
        try store.savePin(updatedPin)
        #expect(try store.loadPin() == updatedPin)

        // Remove pin
        try store.removePin()
        #expect(try store.loadPin() == nil)
    }

    @Test func testPinAbsentWithMasterFilesThrowsMasterKeyPinMissingWithRepairInstructions() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let label = "vault-initial-pin-test"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: label))

            EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: nil)
            defer { EncryptedVaultStore.customPinStore = nil }

            #expect {
                try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cannot-save-unpinned"))
            } throws: { error in
                guard let vaultError = error as? EncryptedVaultStore.VaultError else { return false }
                return vaultError == .masterKeyPinMissing &&
                    vaultError.localizedDescription.contains("clavis vault repair")
            }
        }
    }

    @Test func testAfterRepairSaveAndLoadRecordWork() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let initialLabel = "vault-pre-repair"
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: initialLabel))

            // Lost Keychain pin
            let pinStore = InMemoryMasterKeyPinStore(pin: nil)
            EncryptedVaultStore.customPinStore = pinStore
            defer { EncryptedVaultStore.customPinStore = nil }

            // Operations fail closed with masterKeyPinMissing
            #expect {
                try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "blocked"))
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyPinMissing
            }

            // Run repair
            let result = try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: false)
            #expect(!result.fingerprint.isEmpty)
            #expect(try pinStore.loadPin() != nil)

            // saveRecord and loadRecord work after repair
            let newLabel = "vault-post-repair"
            #expect(throws: Never.self) {
                try EncryptedVaultStore.shared.saveRecord(makeRecord(label: newLabel))
            }
            let loadedNew = try EncryptedVaultStore.shared.loadRecord(label: newLabel)
            #expect(loadedNew?.label == newLabel)
            let loadedInitial = try EncryptedVaultStore.shared.loadRecord(label: initialLabel)
            #expect(loadedInitial?.label == initialLabel)
        }
    }

    @Test func testPinMismatchIsNotRepairedWithoutReplacePinFlag() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "vault-replace-test"))
            let wrongPin = Data(repeating: 0xee, count: 32)
            let pinStore = InMemoryMasterKeyPinStore(pin: wrongPin)
            EncryptedVaultStore.customPinStore = pinStore
            defer { EncryptedVaultStore.customPinStore = nil }

            // Without replacePin: true, repair must fail and not overwrite pin
            #expect(throws: (any Error).self) {
                try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: false)
            }
            #expect(try pinStore.loadPin() == wrongPin, "Mismatched pin must not be overwritten without replacePin: true")

            // With replacePin: true, repair succeeds and updates pin
            #expect(throws: Never.self) {
                _ = try EncryptedVaultStore.shared.repairMasterKeyPin(replacePin: true)
            }
            let pubData = try Data(contentsOf: EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub"))
            let expectedPin = Data(SHA256.hash(data: pubData))
            #expect(try pinStore.loadPin() == expectedPin)
        }
    }

    @Test func testSimulatedCrashLeavesNoPartialFilesAndSecondEnsureMasterKeySucceeds() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
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
            defer { EncryptedVaultStore.customPinStore = nil }

            let pubURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.pub")
            let keyURL = EncryptedVaultStore.shared.vaultDirectoryURL.appendingPathComponent("master.key")

            pinStore.onSavePin = {
                // When pin is saved, simulate crash/failure during file write by creating master.pub as a directory
                try? FileManager.default.createDirectory(at: pubURL, withIntermediateDirectories: false)
            }

            // First attempt must fail because writing files fails
            #expect(throws: (any Error).self) {
                try EncryptedVaultStore.shared.ensureMasterKey()
            }

            // Verify no stale partial files remain and pin was rolled back
            #expect(!FileManager.default.fileExists(atPath: keyURL.path), "master.key must not remain after failed write")
            #expect(!FileManager.default.fileExists(atPath: pubURL.path), "master.pub must not remain after failed write")
            let pinBefore = try pinStore.loadPin()
            #expect(pinBefore == nil, "Pin must be rolled back on file write failure")

            // Second ensureMasterKey succeeds
            pinStore.onSavePin = nil
            #expect(throws: Never.self) {
                _ = try EncryptedVaultStore.shared.ensureMasterKey()
            }
            #expect(FileManager.default.fileExists(atPath: pubURL.path))
            #expect(FileManager.default.fileExists(atPath: keyURL.path))
            let pinAfter = try pinStore.loadPin()
            #expect(pinAfter != nil)
        }
    }

    @Test func testNonTTYStdinRefusesRepairConfirmation() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "vault-tty-test"))
            EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: nil)
            defer { EncryptedVaultStore.customPinStore = nil }

            let result = CLIService.handle(
                args: ["clavis", "vault", "repair"],
                isTTY: false
            )
            #expect(result != nil)
            #expect(result?.exitCode == 1)
            #expect(
                result?.error?.contains("TTY") == true ||
                result?.error?.contains("terminal") == true ||
                result?.error?.contains("interactive") == true
            )
        }
    }

    @Test func testCLIVaultRepairInteractiveConfirmation() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cli-repair-test"))
            let pinStore = InMemoryMasterKeyPinStore(pin: nil)
            EncryptedVaultStore.customPinStore = pinStore
            defer { EncryptedVaultStore.customPinStore = nil }

            // User enters "no" -> cancelled
            let cancelled = CLIService.handle(
                args: ["clavis", "vault", "repair"],
                isTTY: true,
                confirmationPrompt: { "no" }
            )
            #expect(cancelled?.exitCode == 1)
            #expect(cancelled?.error?.contains("cancelled") == true)
            #expect(try pinStore.loadPin() == nil)

            // User enters "yes" -> succeeded
            let succeeded = CLIService.handle(
                args: ["clavis", "vault", "repair"],
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(succeeded?.exitCode == 0)
            #expect(succeeded?.output.contains("successfully repaired") == true)
            #expect(try pinStore.loadPin() != nil)
        }
    }

    @Test func testCLIVaultRepairPinMismatchRequiresReplacePinFlag() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cli-mismatch-test"))
            let wrongPin = Data(repeating: 0xee, count: 32)
            let pinStore = InMemoryMasterKeyPinStore(pin: wrongPin)
            EncryptedVaultStore.customPinStore = pinStore
            defer { EncryptedVaultStore.customPinStore = nil }

            // Mismatched pin without --replace-pin -> fails with warning
            let failed = CLIService.handle(
                args: ["clavis", "vault", "repair"],
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(failed?.exitCode == 1)
            #expect(failed?.error?.contains("--replace-pin") == true)
            #expect(try pinStore.loadPin() == wrongPin)

            // Mismatched pin with --replace-pin -> succeeds
            let succeeded = CLIService.handle(
                args: ["clavis", "vault", "repair", "--replace-pin"],
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(succeeded?.exitCode == 0)
            #expect(succeeded?.output.contains("WARNING: Replacing existing mismatched") == true)
            #expect(try pinStore.loadPin() != wrongPin)
        }
    }

    /// R17: without a TTY the command must fail before verifyMasterKey() (Touch ID). With no vault on
    /// disk verification would fail with a different message, so the TTY error proves the order.
    @Test func testVaultRepairWithoutTTYFailsBeforeVerification() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: nil)
            defer { EncryptedVaultStore.customPinStore = nil }
            let result = CLIService.handle(args: ["clavis", "vault", "repair"], isTTY: false)
            #expect(result?.exitCode == 1)
            #expect(result?.error?.contains("TTY") == true)
            #expect(result?.error?.contains("verify") != true)
        }
    }

    /// R17: the owner needs the pinned fingerprint as a baseline to tell a legitimate repair from a
    /// replaced master.key.
    @Test func testVaultRepairShowsPinnedFingerprintBaselineAndWarning() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "cli-baseline-test"))
            let wrongPin = Data(repeating: 0xee, count: 32)
            let oldFingerprint = EncryptedVaultStore.fingerprint(forPin: wrongPin)
            EncryptedVaultStore.customPinStore = InMemoryMasterKeyPinStore(pin: wrongPin)
            defer { EncryptedVaultStore.customPinStore = nil }

            // Even the refusal (no --replace-pin) prints the baseline.
            let refused = CLIService.handle(
                args: ["clavis", "vault", "repair"],
                isTTY: true,
                confirmationPrompt: { "yes" }
            )
            #expect(refused?.exitCode == 1)
            #expect(refused?.output.contains("Keychain pinned fingerprint: \(oldFingerprint)") == true)
            #expect(refused?.output.contains("master.key created:") == true)

            let replaced = CLIService.handle(
                args: ["clavis", "vault", "repair", "--replace-pin"],
                isTTY: true,
                confirmationPrompt: { "no" }
            )
            let output = replaced?.output ?? ""
            #expect(output.contains("Keychain pinned fingerprint: \(oldFingerprint)"))
            #expect(output.contains("Master key fingerprint: SHA256:"))
            #expect(output.contains("do not confirm"))
            #expect(oldFingerprint != (try EncryptedVaultStore.shared.verifyMasterKey().fingerprint))
        }
    }

    // MARK: - Finding N-4: Cross-Process Advisory File Lock Tests

    @Test func testExternalHolderBlocksMasterKeyCreation() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            EncryptedVaultStore.masterKeyLockPollInterval = 5_000
            defer { EncryptedVaultStore.masterKeyLockPollInterval = 50_000 }

            let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
            try SecureFS.createDirectory(at: vaultDir)
            let lockURL = vaultDir.appendingPathComponent(".master.lock")
            let lockFd = SecureFS.openLockFile(path: lockURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
            #expect(lockFd >= 0)
            #expect(flock(lockFd, LOCK_EX) == 0)

            let context = fixture.context
            let task = Task.detached {
                try await TestContextScope.$current.withValue(context) {
                    try EncryptedVaultStore.shared.ensureMasterKey()
                }
            }

            // Assert not finished while lock is held
            try await Task.sleep(nanoseconds: 30_000_000)

            // Release lock
            #expect(flock(lockFd, LOCK_UN) == 0)
            close(lockFd)

            // Assert it finishes and files exist
            let returnedPubKey = try await task.value
            #expect(returnedPubKey != nil)

            let pubURL = vaultDir.appendingPathComponent("master.pub")
            let keyURL = vaultDir.appendingPathComponent("master.key")
            #expect(FileManager.default.fileExists(atPath: pubURL.path))
            #expect(FileManager.default.fileExists(atPath: keyURL.path))
        }
    }

    @Test func testMasterKeyRecheckWorksWhenCreatedByAnotherProcess() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            EncryptedVaultStore.masterKeyLockPollInterval = 5_000
            defer {
                EncryptedVaultStore.masterKeyLockPollInterval = 50_000
                EncryptedVaultStore.customPinStore = nil
            }

            let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
            try SecureFS.createDirectory(at: vaultDir)
            let lockURL = vaultDir.appendingPathComponent(".master.lock")
            let lockFd = SecureFS.openLockFile(path: lockURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
            #expect(lockFd >= 0)
            #expect(flock(lockFd, LOCK_EX) == 0)

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

            let context = fixture.context
            let task = Task.detached {
                try await TestContextScope.$current.withValue(context) {
                    try EncryptedVaultStore.shared.ensureMasterKey()
                }
            }

            // Wait briefly to ensure background call has started and is polling lock
            try await Task.sleep(nanoseconds: 20_000_000)

            // Create valid key pair via file writes while holding lock
            let swKey = P256.KeyAgreement.PrivateKey()
            let pubData = swKey.publicKey.rawRepresentation
            let pin = Data(SHA256.hash(data: pubData))
            try EncryptedVaultStore.shared.activePinStore.savePin(pin)
            #expect(pinStore.saveCount == 1)

            let pubURL = vaultDir.appendingPathComponent("master.pub")
            let keyURL = vaultDir.appendingPathComponent("master.key")
            try SecureFS.withUmask(0o077) {
                var keyFileBytes = Data([0x01])
                keyFileBytes.append(swKey.rawRepresentation)
                try keyFileBytes.write(to: keyURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

                try pubData.write(to: pubURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubURL.path)
            }

            // Release lock
            #expect(flock(lockFd, LOCK_UN) == 0)
            close(lockFd)

            let returnedPubKey = try await task.value
            #expect(returnedPubKey.rawRepresentation == swKey.publicKey.rawRepresentation)

            // Verify pin was not overwritten
            let storedPin = try EncryptedVaultStore.shared.activePinStore.loadPin()
            #expect(storedPin == pin)
            #expect(pinStore.saveCount == 1)
        }
    }

    @Test func testMasterKeyLockTimeoutThrowsError() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            EncryptedVaultStore.masterKeyLockPollInterval = 5_000
            EncryptedVaultStore.masterKeyLockTimeout = 0.04
            defer {
                EncryptedVaultStore.masterKeyLockTimeout = 10.0
                EncryptedVaultStore.masterKeyLockPollInterval = 50_000
            }

            let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
            try SecureFS.createDirectory(at: vaultDir)
            let lockURL = vaultDir.appendingPathComponent(".master.lock")
            let lockFd = SecureFS.openLockFile(path: lockURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
            #expect(lockFd >= 0)
            #expect(flock(lockFd, LOCK_EX) == 0)
            defer {
                _ = flock(lockFd, LOCK_UN)
                close(lockFd)
            }

            let start = Date()
            #expect {
                try EncryptedVaultStore.shared.ensureMasterKey()
            } throws: { error in
                let nsError = error as NSError
                return nsError.domain == "Clavis" &&
                    nsError.code == -1 &&
                    nsError.localizedDescription == "Another Clavis process is creating the vault master key."
            }
            let elapsed = Date().timeIntervalSince(start)
            #expect(elapsed >= 0.04)
        }
    }

    @Test func testEnsureMasterKeyLockedThrowsWhenSecureEnclaveUnavailable() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            EncryptedVaultStore.isSecureEnclaveAvailableOverride = false
            defer {
                EncryptedVaultStore.isSecureEnclaveAvailableOverride = nil
            }

            #expect {
                try EncryptedVaultStore.shared.ensureMasterKeyLocked()
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .secureEnclaveRequired
            }
        }
    }

    @Test func testDeletingMasterFilesWhenPinExistsRefusesToOverwritePin() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "vault-existing-pin"))
            let originalPin = try #require(try EncryptedVaultStore.shared.activePinStore.loadPin())

            let vaultDir = EncryptedVaultStore.shared.vaultDirectoryURL
            let pubURL = vaultDir.appendingPathComponent("master.pub")
            let keyURL = vaultDir.appendingPathComponent("master.key")
            try FileManager.default.removeItem(at: pubURL)
            try FileManager.default.removeItem(at: keyURL)

            #expect {
                try EncryptedVaultStore.shared.ensureMasterKey()
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyTampered
            }
            #expect {
                try EncryptedVaultStore.shared.saveRecord(makeRecord(label: "attacker-key"))
            } throws: { error in
                error as? EncryptedVaultStore.VaultError == .masterKeyTampered
            }
            #expect(
                try EncryptedVaultStore.shared.activePinStore.loadPin() == originalPin,
                "Existing Keychain pin must never be overwritten when master files are deleted from disk"
            )
        }
    }
}
