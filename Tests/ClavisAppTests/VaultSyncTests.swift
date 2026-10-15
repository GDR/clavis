@testable import ClavisTestSupport
import Foundation
import Testing
import CryptoKit
import LocalAuthentication
@testable import ClavisCore
@testable import Clavis

final class TestSyncPrivateKeyStore: PrivateKeyStoring, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()

    func contains(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return values[label] != nil
    }

    func allLabels() throws -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return Array(values.keys).sorted()
    }

    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = []) throws {
        lock.lock()
        defer { lock.unlock() }
        values[label] = data
    }

    func load(label: String, context: LAContext, prompt: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[label]
    }

    func remove(label: String, context: LAContext?, prompt: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: label)
    }
}

@Suite(.serialized)
final class VaultSyncTests {
    private let fixture: ClavisTestFixture

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    private func makeKeyManager(
        privateKeyStore: PrivateKeyStoring = TestSyncPrivateKeyStore()
    ) -> KeychainManager {
        fixture.makeKeyManager(
            authenticator: AllowingAuthenticator(),
            privateKeyStore: privateKeyStore
        )
    }

    @Test func testDetectAndRepairOrphanedPublicCache() throws {
        try fixture.runSync {
            let keyManager = makeKeyManager()

            // Insert an orphaned public key (no corresponding private record)
            let orphanLabel = "ghost-orphan-\(UUID().uuidString)"
            let dummyKeyInfo = SSHKeyInfo(
                label: orphanLabel,
                publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhostKeyData dummy",
                publicKeyBlob: Data(repeating: 0x42, count: 32),
                fingerprint: "SHA256:dummyOrphanFingerprint",
                createdAt: Date(),
                algorithmName: "ECDSA P-256",
                storage: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .general
            )
            try PublicKeyStore.saveChecked(dummyKeyInfo)

            // Step 1: Detect without repair
            let dryRunReport = try keyManager.syncVault(repair: false)
            #expect(dryRunReport.isDesynchronized)
            #expect(dryRunReport.orphanedPublicCache.contains(orphanLabel))
            #expect(dryRunReport.detectedAnomalies.contains(.orphanedPublicCache(label: orphanLabel)))
            #expect(dryRunReport.repairedCount == 0)

            // Public key still exists in cache
            #expect(PublicKeyStore.loadAll().contains(where: { $0.label == orphanLabel }))

            // Step 2: Run repair
            let repairReport = try keyManager.syncVault(repair: true)
            #expect(repairReport.orphanedPublicCache.contains(orphanLabel))
            #expect(repairReport.repairedAnomalies.contains(.orphanedPublicCache(label: orphanLabel)))
            #expect(repairReport.repairedCount >= 1)

            // Ghost key is purged from cache
            #expect(!PublicKeyStore.loadAll().contains(where: { $0.label == orphanLabel }))

            // Subsequent sync is clean
            let cleanReport = try keyManager.syncVault(repair: false)
            #expect(!cleanReport.isDesynchronized)
            #expect(cleanReport.detectedAnomalies.isEmpty)
        }
    }

    @Test func testDetectAndRepairMissingPublicCache() throws {
        try fixture.runSync {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)

            // Step 1: Generate a legitimate key
            let keyLabel = "missing-cache-\(UUID().uuidString)"
            let originalInfo = try keyManager.generateKey(label: keyLabel)
            #expect(privateStore.contains(label: keyLabel))
            #expect(PublicKeyStore.loadAll().contains(where: { $0.label == keyLabel }))

            // Step 2: Evict public key from cache to create desynchronization
            try PublicKeyStore.removeChecked(label: keyLabel)
            PublicKeyStore.invalidateCache()
            #expect(!PublicKeyStore.loadAll().contains(where: { $0.label == keyLabel }))
            #expect(privateStore.contains(label: keyLabel))

            // Step 3: Detect without repair
            let dryRunReport = try keyManager.syncVault(repair: false)
            #expect(dryRunReport.isDesynchronized)
            #expect(dryRunReport.missingPublicCache.contains(keyLabel))
            #expect(dryRunReport.detectedAnomalies.contains(.missingPublicCache(label: keyLabel)))
            #expect(dryRunReport.repairedCount == 0)

            // Step 4: Run with repair: true
            let repairReport = try keyManager.syncVault(repair: true)
            #expect(repairReport.missingPublicCache.contains(keyLabel))
            #expect(repairReport.repairedAnomalies.contains(.missingPublicCache(label: keyLabel)))
            #expect(repairReport.repairedCount >= 1)

            // Public key has been regenerated and re-cached
            let restoredKey = PublicKeyStore.loadAll().first(where: { $0.label == keyLabel })
            #expect(restoredKey != nil)
            #expect(restoredKey?.publicKeyBlob == originalInfo.publicKeyBlob)
            #expect(restoredKey?.fingerprint == originalInfo.fingerprint)
            #expect(restoredKey?.publicKeyOpenSSH == originalInfo.publicKeyOpenSSH)

            // Subsequent sync is clean
            let cleanReport = try keyManager.syncVault(repair: false)
            #expect(!cleanReport.isDesynchronized)
            #expect(cleanReport.detectedAnomalies.isEmpty)
        }
    }

    @Test func testDetectAndRepairMultipleAnomaliesSimultaneously() throws {
        try fixture.runSync {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)

            // 1. Create a key with missing public cache
            let missingLabel = "both-missing-\(UUID().uuidString)"
            let missingInfo = try keyManager.generateKey(label: missingLabel)
            try PublicKeyStore.removeChecked(label: missingLabel)
            PublicKeyStore.invalidateCache()

            // 2. Create an orphaned public cache
            let orphanLabel = "both-orphan-\(UUID().uuidString)"
            let orphanInfo = SSHKeyInfo(
                label: orphanLabel,
                publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrphanKeyData dummy",
                publicKeyBlob: Data(repeating: 0x99, count: 32),
                fingerprint: "SHA256:bothOrphanFingerprint",
                createdAt: Date(),
                algorithmName: "ECDSA P-256",
                storage: .secureEnclave,
                biometricPolicy: .userPresence,
                keyPurpose: .general
            )
            try PublicKeyStore.saveChecked(orphanInfo)

            // Detection report
            let detectReport = try keyManager.syncVault(repair: false)
            #expect(detectReport.isDesynchronized)
            #expect(detectReport.missingPublicCache.contains(missingLabel))
            #expect(detectReport.orphanedPublicCache.contains(orphanLabel))
            #expect(detectReport.detectedAnomalies.count == 2)
            #expect(detectReport.repairedCount == 0)

            // Repair report
            let repairReport = try keyManager.syncVault(repair: true)
            #expect(repairReport.repairedCount == 2)
            #expect(repairReport.repairedAnomalies.contains(.missingPublicCache(label: missingLabel)))
            #expect(repairReport.repairedAnomalies.contains(.orphanedPublicCache(label: orphanLabel)))

            // Verify state
            let allPublic = PublicKeyStore.loadAll()
            #expect(allPublic.contains(where: { $0.label == missingLabel }))
            #expect(!allPublic.contains(where: { $0.label == orphanLabel }))
            #expect(allPublic.first(where: { $0.label == missingLabel })?.publicKeyBlob == missingInfo.publicKeyBlob)
        }
    }

    @Test func testFullySynchronizedVaultHasNoAnomalies() throws {
        try fixture.runSync {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)

            let label1 = "sync-ok-1-\(UUID().uuidString)"
            let label2 = "sync-ok-2-\(UUID().uuidString)"
            _ = try keyManager.generateKey(label: label1)
            _ = try keyManager.generateKey(label: label2)

            let report = try keyManager.syncVault(repair: false)
            #expect(!report.isDesynchronized)
            #expect(report.missingPublicCache.isEmpty)
            #expect(report.orphanedPublicCache.isEmpty)
            #expect(report.detectedAnomalies.isEmpty)
            #expect(report.repairedCount == 0)
        }
    }

    @Test @MainActor func testKeyManagementViewModelSyncVaultIntegration() async throws {
        try await fixture.run {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)
            let mockController = MockAgentController()
            let vm = KeyManagementViewModel(keyManager: keyManager, agentLifecycle: mockController)

            // Create orphan
            let orphanLabel = "vm-orphan-\(UUID().uuidString)"
            let orphanInfo = SSHKeyInfo(
                label: orphanLabel,
                publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrphanKeyData dummy",
                publicKeyBlob: Data(repeating: 0x77, count: 32),
                fingerprint: "SHA256:vmOrphanFingerprint"
            )
            try PublicKeyStore.saveChecked(orphanInfo)
            vm.refresh()

            #expect(vm.keys.contains(where: { $0.label == orphanLabel }))
            #expect(vm.vaultSyncReport == nil)

            // Dry run
            let dryReport = try vm.syncVault(repair: false)
            #expect(dryReport.isDesynchronized)
            #expect(vm.vaultSyncReport?.orphanedPublicCache.contains(orphanLabel) == true)

            // Repair run
            let repairReport = try vm.syncVault(repair: true)
            #expect(repairReport.repairedCount >= 1)
            #expect(vm.vaultSyncReport?.repairedAnomalies.contains(.orphanedPublicCache(label: orphanLabel)) == true)
            #expect(!vm.keys.contains(where: { $0.label == orphanLabel }))
        }
    }

    @Test @MainActor func testAppStateSyncVaultIntegration() async throws {
        try await fixture.run {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)
            let mockController = MockAgentController()
            let appState = AppState(
                keyManager: keyManager,
                agentLifecycle: mockController,
                isDaemonMode: true
            )

            // Generate key and evict public cache
            let missingLabel = "appstate-missing-\(UUID().uuidString)"
            _ = try appState.generateKey(label: missingLabel)
            try PublicKeyStore.removeChecked(label: missingLabel)
            PublicKeyStore.invalidateCache()
            appState.refresh()

            #expect(!appState.keys.contains(where: { $0.label == missingLabel }))

            // Run syncVault on AppState
            let report = try appState.syncVault(repair: true)
            #expect(report.missingPublicCache.contains(missingLabel))
            #expect(appState.vaultSyncReport?.repairedCount == 1)
            #expect(appState.keys.contains(where: { $0.label == missingLabel }))
        }
    }

    @Test func testAdversarialLargeScaleVaultDesyncAndIdempotentRepair() throws {
        try fixture.runSync {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)

            // Step 1: Create 30 legitimate keys
            var originalKeys: [String: SSHKeyInfo] = [:]
            for i in 1...30 {
                let label = "adv-legit-\(i)-\(UUID().uuidString)"
                let info = try keyManager.generateKey(label: label)
                originalKeys[label] = info
            }
            #expect(try privateStore.allLabels().count == 30)
            #expect(PublicKeyStore.loadAll().count == 30)

            // Step 2: Create 25 missing public cache anomalies by evicting 25 keys from public cache
            let missingLabels = Array(originalKeys.keys.prefix(25))
            for label in missingLabels {
                try PublicKeyStore.removeChecked(label: label)
            }
            PublicKeyStore.invalidateCache()
            #expect(PublicKeyStore.loadAll().count == 5)

            // Step 3: Create 25 orphaned public cache anomalies
            var orphanLabels: [String] = []
            for i in 1...25 {
                let orphanLabel = "adv-orphan-\(i)-\(UUID().uuidString)"
                orphanLabels.append(orphanLabel)
                let orphanInfo = SSHKeyInfo(
                    label: orphanLabel,
                    publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdversarialOrphan\(i) dummy",
                    publicKeyBlob: Data(repeating: UInt8(i % 256), count: 32),
                    fingerprint: "SHA256:advOrphanFingerprint\(i)",
                    createdAt: Date(),
                    algorithmName: "ECDSA P-256",
                    storage: .secureEnclave,
                    biometricPolicy: .userPresence,
                    keyPurpose: .general
                )
                try PublicKeyStore.saveChecked(orphanInfo)
            }
            #expect(PublicKeyStore.loadAll().count == 30) // 5 remaining legit + 25 orphans

            // Step 4: Dry-run syncVault(repair: false)
            let dryReport = try keyManager.syncVault(repair: false)
            #expect(dryReport.isDesynchronized)
            #expect(dryReport.missingPublicCache.count == 25)
            #expect(dryReport.orphanedPublicCache.count == 25)
            #expect(dryReport.detectedAnomalies.count == 50)
            #expect(dryReport.repairedCount == 0)
            #expect(dryReport.repairedAnomalies.isEmpty)

            // Verify no changes occurred during dry run
            #expect(try privateStore.allLabels().count == 30)
            #expect(PublicKeyStore.loadAll().count == 30)

            // Step 5: Repair run syncVault(repair: true)
            let repairReport = try keyManager.syncVault(repair: true)
            #expect(repairReport.repairedCount == 50)
            #expect(repairReport.repairedAnomalies.count == 50)
            #expect(repairReport.missingPublicCache.count == 25)
            #expect(repairReport.orphanedPublicCache.count == 25)

            // Step 6: Verify post-repair state
            let currentPublicKeys = PublicKeyStore.loadAll()
            #expect(currentPublicKeys.count == 30) // Exactly all 30 legitimate keys

            // Verify each missing key was properly restored with identical key data
            for label in missingLabels {
                guard let restored = currentPublicKeys.first(where: { $0.label == label }),
                      let original = originalKeys[label] else {
                    Issue.record("Missing restored key for \(label)")
                    continue
                }
                #expect(restored.publicKeyBlob == original.publicKeyBlob)
                #expect(restored.fingerprint == original.fingerprint)
                #expect(restored.publicKeyOpenSSH == original.publicKeyOpenSSH)
                #expect(restored.algorithmName == original.algorithmName)
                #expect(restored.keyPurpose == original.keyPurpose)
            }

            // Verify all orphans were purged
            for orphanLabel in orphanLabels {
                #expect(!currentPublicKeys.contains(where: { $0.label == orphanLabel }))
            }

            // Step 7: Verify subsequent dry run is clean
            let cleanDryReport = try keyManager.syncVault(repair: false)
            #expect(!cleanDryReport.isDesynchronized)
            #expect(cleanDryReport.detectedAnomalies.isEmpty)
            #expect(cleanDryReport.missingPublicCache.isEmpty)
            #expect(cleanDryReport.orphanedPublicCache.isEmpty)
            #expect(cleanDryReport.repairedCount == 0)

            // Step 8: Verify idempotency of repair
            let idempotentReport = try keyManager.syncVault(repair: true)
            #expect(!idempotentReport.isDesynchronized)
            #expect(idempotentReport.repairedCount == 0)
            #expect(idempotentReport.repairedAnomalies.isEmpty)
        }
    }

    @Test func testAdversarialCorruptPrivateRecordHandling() throws {
        try fixture.runSync {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)

            // Inject corrupt private record (unparseable random bytes)
            let corruptLabel = "corrupted-priv-key-\(UUID().uuidString)"
            try privateStore.save(label: corruptLabel, data: Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]))

            // Detection report should detect it as missing public cache
            let dryReport = try keyManager.syncVault(repair: false)
            #expect(dryReport.missingPublicCache.contains(corruptLabel))

            // Repair run should gracefully handle decoding failure without crashing
            let repairReport = try keyManager.syncVault(repair: true)
            #expect(repairReport.missingPublicCache.contains(corruptLabel))
            // Corrupt key cannot be derived, so it should not be in repairedAnomalies
            #expect(!repairReport.repairedAnomalies.contains(.missingPublicCache(label: corruptLabel)))
            #expect(repairReport.repairedCount == 0)

            // Private record still exists in private store (not wiped or corrupted)
            #expect(privateStore.contains(label: corruptLabel))
        }
    }

    @Test func testAdversarialSpecialCharactersInLabels() throws {
        try fixture.runSync {
            let privateStore = TestSyncPrivateKeyStore()
            let keyManager = makeKeyManager(privateKeyStore: privateStore)

            let specialLabels = [
                "ключ_для_сервера-2026",
                "deploy.key+prod@company_domain",
                "test-🔑-enclave"
            ]

            for label in specialLabels {
                let info = try keyManager.generateKey(label: label)
                #expect(PublicKeyStore.loadAll().contains(where: { $0.label == label }))

                // Evict
                try PublicKeyStore.removeChecked(label: label)
                PublicKeyStore.invalidateCache()

                // Detect
                let report = try keyManager.syncVault(repair: false)
                #expect(report.missingPublicCache.contains(label))

                // Repair
                let repairReport = try keyManager.syncVault(repair: true)
                #expect(repairReport.repairedAnomalies.contains(.missingPublicCache(label: label)))

                let restored = PublicKeyStore.loadAll().first(where: { $0.label == label })
                #expect(restored != nil)
                #expect(restored?.fingerprint == info.fingerprint)
            }
        }
    }
}

