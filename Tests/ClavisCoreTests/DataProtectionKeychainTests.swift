import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Testing
@testable import ClavisCore

@Suite(.serialized)
struct DataProtectionKeychainTests {
    private static let testGroup = "4G6X3KNZUS.com.clavis.shared"
    private static let dpScope = KeychainScope.dataProtection(accessGroup: testGroup)

    // MARK: - KeychainScope

    @Test func resolveSelectsValidTeamSharedAccessGroup() {
        let entitlements: [String: Any] = [
            "keychain-access-groups": [Self.testGroup]
        ]
        #expect(KeychainScope.resolve(fromEntitlements: entitlements) == Self.dpScope)
    }

    @Test func resolvePicksFirstValidSharedGroupFromMultipleEntries() {
        let entitlements: [String: Any] = [
            "keychain-access-groups": [
                "4G6X3KNZUS.com.example.other",
                "bad.com.clavis.shared",
                Self.testGroup,
                "9Z8Y7X6W5V.com.clavis.shared"
            ]
        ]
        #expect(KeychainScope.resolve(fromEntitlements: entitlements) == Self.dpScope)
    }

    @Test func resolveRejectsMalformedPrefixesAndMissingEntitlements() {
        #expect(KeychainScope.resolve(fromEntitlements: nil) == .legacyLogin)
        #expect(KeychainScope.resolve(fromEntitlements: [:]) == .legacyLogin)
        #expect(KeychainScope.resolve(fromEntitlements: ["keychain-access-groups": [String]()]) == .legacyLogin)
        #expect(KeychainScope.resolve(fromEntitlements: ["keychain-access-groups": 123]) == .legacyLogin)

        let malformedGroups = [
            "bad.com.clavis.shared",
            "4g6x3knzus.com.clavis.shared",
            "4G6X3KNZUS1.com.clavis.shared",
            ".com.clavis.shared",
            "$(AppIdentifierPrefix)com.clavis.shared",
            "4G6X3KNZUS.com.clavis.other",
            "4G6X3KNZUS.com.clavis.shared.extra"
        ]
        for group in malformedGroups {
            let scope = KeychainScope.resolve(fromEntitlements: ["keychain-access-groups": [group]])
            #expect(scope == .legacyLogin, "Expected malformed group '\(group)' to resolve to .legacyLogin")
        }
    }

    @Test func processDefaultIsLegacyLoginInTestEnvironment() {
        #expect(ClavisEnvironment.isTesting)
        #expect(KeychainScope.processDefault == .legacyLogin)
    }

    @Test func applyAndApplyingScopeMutateOnlyDataProtectionQueries() {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.clavis.test"
        ]

        var dpQuery = base
        Self.dpScope.apply(to: &dpQuery)
        assertScopedQuery(dpQuery, expectedGroup: Self.testGroup)

        let dpApplied = Self.dpScope.applying(to: base)
        assertScopedQuery(dpApplied, expectedGroup: Self.testGroup)

        var legacyQuery = base
        KeychainScope.legacyLogin.apply(to: &legacyQuery)
        assertLegacyQuery(legacyQuery)
        assertLegacyQuery(KeychainScope.legacyLogin.applying(to: base))
    }

    // MARK: - Store Scope Queries & Clean SecItemUpdate Attributes

    @Test func privateKeyStoreUsesDataProtectionQueriesAndCleanUpdateAttributes() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.private-keys"
        let store = makePrivateKeyStore(serviceName: service, scope: Self.dpScope, backend: backend)

        // Empty flags (Secure Enclave reference): insert then update
        try store.save(label: "se-ref", data: Data([0x01, 0x02]), accessControlFlags: [])
        try store.save(label: "se-ref", data: Data([0x03, 0x04]), accessControlFlags: [])

        // Non-empty flags: insert then update
        try store.save(label: "protected", data: Data([0x0A]), accessControlFlags: [.userPresence])
        try store.save(label: "protected", data: Data([0x0B]), accessControlFlags: [.userPresence])

        #expect(store.contains(label: "se-ref"))
        let labels = try store.allLabels()
        #expect(labels == ["se-ref", "protected"])

        let loaded = try store.load(label: "se-ref", context: LAContext(), prompt: "Load")
        #expect(loaded == Data([0x03, 0x04]))

        try store.remove(label: "se-ref")
        try store.remove(label: "protected")

        #expect(backend.addQueries.count == 2)
        for query in backend.addQueries {
            assertScopedQuery(query, expectedGroup: Self.testGroup)
        }

        // First two saves hit errSecItemNotFound -> add; second two saves succeed on update
        #expect(backend.updateCalls.count == 4)
        for call in backend.updateCalls {
            assertScopedQuery(call.query, expectedGroup: Self.testGroup)
            assertUpdateAttributesClean(call.attributes)
        }
    }

    @Test func privateKeyStoreProtectedDuplicateRetryUsesCleanUpdateAttributes() throws {
        var addAttempts = 0
        var updateCalls: [(query: [String: Any], attributes: [String: Any])] = []
        let store = KeychainPrivateKeyStore(
            serviceName: "com.clavis.test.dup-retry",
            scope: Self.dpScope,
            addItem: { _ in
                addAttempts += 1
                return errSecDuplicateItem
            },
            deleteItem: { _ in errSecItemNotFound },
            updateItem: { query, attributes in
                let q = query as! [String: Any]
                let a = attributes as! [String: Any]
                updateCalls.append((q, a))
                return updateCalls.count == 1 ? errSecItemNotFound : errSecSuccess
            }
        )

        try store.save(label: "race-key", data: Data([0x42]), accessControlFlags: [.userPresence])
        #expect(addAttempts == 1)
        #expect(updateCalls.count == 2)
        for call in updateCalls {
            assertScopedQuery(call.query, expectedGroup: Self.testGroup)
            assertUpdateAttributesClean(call.attributes)
        }
    }

    @Test func publicKeyStoreHelpersScopeQueriesAndOmitSecAccessInDataProtection() {
        let dpAccountQuery = PublicKeyStore.makeLookupQuery(account: "id_ed25519", scope: Self.dpScope)
        assertScopedQuery(dpAccountQuery, expectedGroup: Self.testGroup)
        #expect(dpAccountQuery[kSecAttrService as String] as? String == KeychainManager.publicServiceName)
        #expect(dpAccountQuery[kSecAttrAccount as String] as? String == "id_ed25519")

        let dpListQuery = PublicKeyStore.makeLookupQuery(account: nil, scope: Self.dpScope)
        assertScopedQuery(dpListQuery, expectedGroup: Self.testGroup)
        #expect(dpListQuery[kSecAttrAccount as String] == nil)

        let legacyQuery = PublicKeyStore.makeLookupQuery(account: "id_ed25519", scope: .legacyLogin)
        assertLegacyQuery(legacyQuery)
        #expect(legacyQuery[kSecAttrAccount as String] as? String == "id_ed25519")

        let payload = Data("{\"label\":\"k\"}".utf8)
        let dpSaveAttrs = PublicKeyStore.makeSaveAttributes(data: payload, scope: Self.dpScope)
        #expect(dpSaveAttrs[kSecAttrAccess as String] == nil)
        #expect(dpSaveAttrs[kSecValueData as String] as? Data == payload)
        assertUpdateAttributesClean(dpSaveAttrs)

        let legacySaveAttrs = PublicKeyStore.makeSaveAttributes(data: payload, scope: .legacyLogin)
        #expect(legacySaveAttrs[kSecAttrAccess as String] != nil)
        #expect(legacySaveAttrs[kSecValueData as String] as? Data == payload)
        assertUpdateAttributesClean(legacySaveAttrs)
    }

    @Test func applicationRegistryUsesDataProtectionQueriesAndNoLegacyFallback() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.app-registry"

        // Pre-seed legacy partition: DP registry must never fall back to it.
        let legacySnapshot = ApplicationRegistrySnapshot(applications: [try makeTestApplication()])
        backend.seed(
            service: service,
            account: "registry",
            scope: .legacyLogin,
            data: try JSONEncoder().encode(legacySnapshot)
        )

        let registry = KeychainApplicationRegistry(
            service: service,
            scope: Self.dpScope,
            copyItem: { backend.copy($0) },
            addItem: { backend.add($0) },
            updateItem: { backend.update($0, $1) }
        )

        let loaded = try registry.load()
        #expect(loaded.applications.isEmpty, "Data Protection registry must not read legacy items")

        let updated = ApplicationRegistrySnapshot(applications: [try makeTestApplication()])
        try registry.save(updated, replacing: loaded.revision)

        #expect(backend.copyQueries.count == 2)
        for query in backend.copyQueries {
            assertScopedQuery(query, expectedGroup: Self.testGroup)
        }
        #expect(backend.addQueries.count == 1)
        assertScopedQuery(backend.addQueries[0], expectedGroup: Self.testGroup)
        #expect(backend.updateCalls.count == 1)
        assertScopedQuery(backend.updateCalls[0].query, expectedGroup: Self.testGroup)
        assertUpdateAttributesClean(backend.updateCalls[0].attributes)
    }

    @Test func agentPolicyStoreUsesDataProtectionQueriesAndNoLegacyFallback() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.agent-policy"
        let fingerprint = "SHA256:testfingerprint"

        let legacyPolicy = AgentKeyPolicy(mode: .ask, leaseMinutes: 60)
        backend.seed(
            service: service,
            account: fingerprint,
            scope: .legacyLogin,
            data: try JSONEncoder().encode(legacyPolicy)
        )

        let store = KeychainAgentPolicyStore(
            service: service,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )

        // Legacy item must not be read under Data Protection scope.
        #expect(try store.policy(forFingerprint: fingerprint) == AgentKeyPolicy())

        let policy1 = AgentKeyPolicy(mode: .notify, leaseMinutes: 30)
        let policy2 = AgentKeyPolicy(mode: .ask, leaseMinutes: 45)
        try store.save(policy1, forFingerprint: fingerprint)
        try store.save(policy2, forFingerprint: fingerprint)
        #expect(try store.policy(forFingerprint: fingerprint) == policy2)

        try store.saveGlobal(AgentGlobalPolicy(version: 1, maxLeaseMinutes: 120))
        try store.saveGlobal(AgentGlobalPolicy(version: 1, maxLeaseMinutes: 240))
        #expect(try store.global().maxLeaseMinutes == 240)

        try store.deletePolicy(forFingerprint: fingerprint)

        for query in backend.copyQueries + backend.addQueries + backend.deleteQueries {
            assertScopedQuery(query, expectedGroup: Self.testGroup)
        }
        #expect(!backend.updateCalls.isEmpty)
        for call in backend.updateCalls {
            assertScopedQuery(call.query, expectedGroup: Self.testGroup)
            assertUpdateAttributesClean(call.attributes)
        }
    }

    @Test func auditKeyringUsesDataProtectionQueriesAndNoLegacyFallback() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.audit-keyring"

        let item1 = try makeAuditKeyItem(keyID: "key-1", mode: .passwordOrBiometry)
        let item2 = try makeAuditKeyItem(keyID: "key-2", mode: .biometryAndPIN)
        backend.seed(service: service, account: "legacy-only", scope: .legacyLogin, data: try JSONEncoder().encode(item2))
        backend.seed(service: service, account: "key-1", scope: Self.dpScope, data: try JSONEncoder().encode(item1))
        backend.seed(service: service, account: "key-2", scope: Self.dpScope, data: try JSONEncoder().encode(item2))

        let keyring = KeychainAuditKeyring(
            service: service,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )

        // First setCurrent adds "current" (errSecItemNotFound -> addItem), second updates "current".
        try keyring.setCurrent(keyID: "key-1")
        try keyring.setCurrent(keyID: "key-2")

        let current = try keyring.currentPublicKey()
        #expect(current.keyID == "key-2")
        #expect(try keyring.currentMode() == .biometryAndPIN)

        let ids = try keyring.knownKeyIDs()
        #expect(Set(ids) == ["key-1", "key-2"])
        #expect(!ids.contains("legacy-only"))

        try keyring.deleteKey(keyID: "key-1")
        #expect(Set(try keyring.knownKeyIDs()) == ["key-2"])

        for query in backend.copyQueries + backend.addQueries + backend.deleteQueries {
            assertScopedQuery(query, expectedGroup: Self.testGroup)
        }
        #expect(backend.updateCalls.count == 2)
        for call in backend.updateCalls {
            assertScopedQuery(call.query, expectedGroup: Self.testGroup)
            assertUpdateAttributesClean(call.attributes)
        }
    }

    @Test func pinAttemptStoreUsesDataProtectionQueriesAndNoLegacyFallback() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.pin-attempts"
        let account = "panel"

        let legacyState = PinAttemptState(attempts: 5, lastAttemptAt: 100)
        backend.seed(service: service, account: account, scope: .legacyLogin, data: try JSONEncoder().encode(legacyState))

        let store = KeychainPinAttemptStore(
            service: service,
            account: account,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )

        #expect(throws: PinAttemptError.missing) {
            try store.load()
        }

        let first = PinAttemptState(attempts: 1, lastAttemptAt: 200)
        let second = PinAttemptState(attempts: 2, lastAttemptAt: 300)
        try store.save(first)
        try store.save(second)
        #expect(try store.load() == second)
        try store.delete()

        for query in backend.copyQueries + backend.addQueries + backend.deleteQueries {
            assertScopedQuery(query, expectedGroup: Self.testGroup)
        }
        #expect(backend.updateCalls.count == 2)
        for call in backend.updateCalls {
            assertScopedQuery(call.query, expectedGroup: Self.testGroup)
            assertUpdateAttributesClean(call.attributes)
        }
    }

    @Test func masterKeyPinStoreUsesDataProtectionQueriesAndNoLegacyFallback() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.master-pin"
        let account = "master-key-pin"

        backend.seed(service: service, account: account, scope: .legacyLogin, data: Data([0xDE, 0xAD]))

        let store = KeychainMasterKeyPinStore(
            service: service,
            account: account,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )

        #expect(try store.loadPin() == nil)

        let pin1 = Data([0x01, 0x02, 0x03])
        let pin2 = Data([0x04, 0x05, 0x06])
        try store.savePin(pin1)
        try store.savePin(pin2)
        #expect(try store.loadPin() == pin2)
        try store.removePin()

        for query in backend.copyQueries + backend.addQueries + backend.deleteQueries {
            assertScopedQuery(query, expectedGroup: Self.testGroup)
        }
        #expect(backend.updateCalls.count == 2)
        for call in backend.updateCalls {
            assertScopedQuery(call.query, expectedGroup: Self.testGroup)
            assertUpdateAttributesClean(call.attributes)
        }
    }

    // MARK: - PrivateKeyStore Legacy Migration & Dual Cleanup

    @Test func privateKeyStoreMigratesLegacyItemOnAuthenticatedLoad() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.private-migration"
        let label = "legacy-ed25519"
        let secret = Data("migrated-key-record".utf8)
        backend.seed(service: service, account: label, scope: .legacyLogin, data: secret)

        let store = makePrivateKeyStore(serviceName: service, scope: Self.dpScope, backend: backend)

        #expect(store.contains(label: label))
        #expect(try store.allLabels() == [label])

        let context = LAContext()
        let loaded = try store.load(label: label, context: context, prompt: "Authenticate to migrate")
        #expect(loaded == secret)
        #expect(context.localizedReason == "Authenticate to migrate")

        // Migrated item exists in Data Protection partition and was deleted from legacy partition.
        #expect(backend.storedData(service: service, account: label, scope: Self.dpScope) == secret)
        #expect(backend.storedData(service: service, account: label, scope: .legacyLogin) == nil)
        #expect(backend.deleteQueries.count == 1)
        assertLegacyQuery(backend.deleteQueries[0])

        // Subsequent load reads directly from Data Protection partition.
        let copyCountBefore = backend.copyQueries.count
        let reloaded = try store.load(label: label, context: LAContext(), prompt: "Load")
        #expect(reloaded == secret)
        #expect(backend.copyQueries.count == copyCountBefore + 1)
        assertScopedQuery(backend.copyQueries.last!, expectedGroup: Self.testGroup)
    }

    @Test func privateKeyStoreMigrationPreservesLegacyItemWhenDataProtectionSaveFails() throws {
        let backend = MockKeychainBackend()
        backend.forcedAddStatus = errSecMissingEntitlement
        let service = "com.clavis.test.private-migration-fail"
        let label = "legacy-preserved"
        let secret = Data("must-not-lose".utf8)
        backend.seed(service: service, account: label, scope: .legacyLogin, data: secret)

        let store = makePrivateKeyStore(serviceName: service, scope: Self.dpScope, backend: backend)

        #expect {
            try store.load(label: label, context: LAContext(), prompt: "Authenticate")
        } throws: { error in
            guard case PrivateKeyStoreError.keychain(let status) = error else { return false }
            return status == errSecMissingEntitlement
        }

        #expect(backend.deleteQueries.isEmpty, "Legacy item must not be deleted when DP save fails")
        #expect(backend.storedData(service: service, account: label, scope: .legacyLogin) == secret)
        #expect(backend.storedData(service: service, account: label, scope: Self.dpScope) == nil)
    }

    @Test func privateKeyStoreAllLabelsUnionsBothPartitionsPreservingOrderAndUniqueness() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.all-labels-union"
        backend.seed(service: service, account: "dp-only", scope: Self.dpScope, data: Data([0x01]))
        backend.seed(service: service, account: "shared-label", scope: Self.dpScope, data: Data([0x02]))
        backend.seed(service: service, account: "shared-label", scope: .legacyLogin, data: Data([0x03]))
        backend.seed(service: service, account: "legacy-only", scope: .legacyLogin, data: Data([0x04]))

        let store = makePrivateKeyStore(serviceName: service, scope: Self.dpScope, backend: backend)
        let labels = try store.allLabels()

        #expect(labels == ["dp-only", "shared-label", "legacy-only"])
    }

    @Test func privateKeyStoreRemoveDeletesFromBothPartitions() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.dual-remove"
        backend.seed(service: service, account: "both", scope: Self.dpScope, data: Data([0x01]))
        backend.seed(service: service, account: "both", scope: .legacyLogin, data: Data([0x02]))
        backend.seed(service: service, account: "dp-only", scope: Self.dpScope, data: Data([0x03]))
        backend.seed(service: service, account: "legacy-only", scope: .legacyLogin, data: Data([0x04]))

        let store = makePrivateKeyStore(serviceName: service, scope: Self.dpScope, backend: backend)

        try store.remove(label: "both")
        try store.remove(label: "dp-only")
        try store.remove(label: "legacy-only")
        try store.remove(label: "missing")

        for label in ["both", "dp-only", "legacy-only"] {
            #expect(backend.storedData(service: service, account: label, scope: Self.dpScope) == nil)
            #expect(backend.storedData(service: service, account: label, scope: .legacyLogin) == nil)
        }
        #expect(backend.deleteQueries.count == 8)
    }

    // MARK: - In-Memory Hot-Read Caching

    @Test func applicationRegistryCachesRepeatedLoadsAndClearsOnFailedSave() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.registry-cache"
        let initial = ApplicationRegistrySnapshot()
        backend.seed(
            service: service,
            account: "registry",
            scope: Self.dpScope,
            data: try JSONEncoder().encode(initial)
        )

        let registry = KeychainApplicationRegistry(
            service: service,
            scope: Self.dpScope,
            copyItem: { backend.copy($0) },
            addItem: { backend.add($0) },
            updateItem: { backend.update($0, $1) }
        )

        #expect(try registry.load() == initial)
        #expect(backend.copyQueries.count == 1)

        // Repeated loads hit cache with 0 Keychain reads.
        #expect(try registry.load() == initial)
        #expect(try registry.load() == initial)
        #expect(backend.copyQueries.count == 1)

        // Successful save verifies revision against Keychain once and updates cache.
        let next = ApplicationRegistrySnapshot(applications: [try makeTestApplication()])
        try registry.save(next, replacing: initial.revision)
        #expect(backend.copyQueries.count == 2)
        #expect(backend.updateCalls.count == 1)

        #expect(try registry.load() == next)
        #expect(backend.copyQueries.count == 2)

        // Stale-revision save failure clears cache so the next load re-reads Keychain.
        #expect(throws: ApplicationRegistryError.staleRevision) {
            try registry.save(ApplicationRegistrySnapshot(), replacing: initial.revision)
        }
        #expect(backend.copyQueries.count == 3)

        _ = try registry.load()
        #expect(backend.copyQueries.count == 4)

        // Persistence failure on updateItem also clears cache.
        backend.forcedUpdateStatus = errSecAuthFailed
        #expect(throws: ApplicationRegistryError.persistence(errSecAuthFailed)) {
            try registry.save(ApplicationRegistrySnapshot(), replacing: next.revision)
        }
        backend.forcedUpdateStatus = nil
        let copyCountAfterFailedSave = backend.copyQueries.count
        _ = try registry.load()
        #expect(backend.copyQueries.count == copyCountAfterFailedSave + 1)
    }

    @Test func auditKeyringCachesCurrentModeAndUpdatesOnSetCurrent() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.audit-mode-cache"
        let item1 = try makeAuditKeyItem(keyID: "key-1", mode: .passwordOrBiometry)
        let item2 = try makeAuditKeyItem(keyID: "key-2", mode: .biometryAndPIN)
        backend.seed(service: service, account: "key-1", scope: Self.dpScope, data: try JSONEncoder().encode(item1))
        backend.seed(service: service, account: "key-2", scope: Self.dpScope, data: try JSONEncoder().encode(item2))
        backend.seed(service: service, account: "current", scope: Self.dpScope, data: Data("key-1".utf8))

        let keyring = KeychainAuditKeyring(
            service: service,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )

        #expect(try keyring.currentMode() == .passwordOrBiometry)
        #expect(backend.copyQueries.count == 2)

        // Repeated currentMode() calls make 0 additional copyItem calls.
        #expect(try keyring.currentMode() == .passwordOrBiometry)
        #expect(try keyring.currentMode() == .passwordOrBiometry)
        #expect(backend.copyQueries.count == 2)

        // setCurrent updates cachedMode immediately.
        try keyring.setCurrent(keyID: "key-2")
        let copyCountAfterSetCurrent = backend.copyQueries.count
        #expect(try keyring.currentMode() == .biometryAndPIN)
        #expect(backend.copyQueries.count == copyCountAfterSetCurrent)
    }

    @Test func auditKeyringCachesDefaultModeWhenCurrentIsMissing() throws {
        let backend = MockKeychainBackend()
        let keyring = KeychainAuditKeyring(
            service: "com.clavis.test.audit-mode-empty",
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )

        #expect(try keyring.currentMode() == .passwordOrBiometry)
        #expect(backend.copyQueries.count == 1)
        #expect(try keyring.currentMode() == .passwordOrBiometry)
        #expect(backend.copyQueries.count == 1)
    }

    @Test func auditKeyringSetCurrentSerializesCacheWithConcurrentWriter() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.audit-concurrent-setcurrent"
        let item1 = try makeAuditKeyItem(keyID: "key-1", mode: .passwordOrBiometry)
        let item2 = try makeAuditKeyItem(keyID: "key-2", mode: .biometryAndPIN)
        backend.seed(service: service, account: "key-1", scope: Self.dpScope, data: try JSONEncoder().encode(item1))
        backend.seed(service: service, account: "key-2", scope: Self.dpScope, data: try JSONEncoder().encode(item2))
        backend.seed(service: service, account: "current", scope: Self.dpScope, data: Data("key-1".utf8))

        let write1Entered = DispatchSemaphore(value: 0)
        let allowWrite1Continue = DispatchSemaphore(value: 0)
        let writer2Done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var ringRef: KeychainAuditKeyring?

        let keyring = KeychainAuditKeyring(
            service: service,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { query, attrs in
                let status = backend.update(query, attrs)
                if let attrDict = attrs as? [String: Any],
                   let val = attrDict[kSecValueData as String] as? Data,
                   String(data: val, encoding: .utf8) == "key-1" {
                    write1Entered.signal()
                    _ = allowWrite1Continue.wait(timeout: .now() + 2.0)
                }
                return status
            },
            copyItem: { backend.copy($0) }
        )
        ringRef = keyring

        let writer1Done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            try? ringRef?.setCurrent(keyID: "key-1")
            writer1Done.signal()
        }

        #expect(write1Entered.wait(timeout: .now() + 2.0) == .success)
        DispatchQueue.global().async {
            try? ringRef?.setCurrent(keyID: "key-2")
            writer2Done.signal()
        }
        // Release writer 1 after writer 2 has started waiting on `lock`.
        usleep(20_000)
        allowWrite1Continue.signal()

        #expect(writer1Done.wait(timeout: .now() + 2.0) == .success)
        #expect(writer2Done.wait(timeout: .now() + 2.0) == .success)

        let storedID = backend.storedData(service: service, account: "current", scope: Self.dpScope).flatMap {
            String(data: $0, encoding: .utf8)
        }
        #expect(storedID == "key-2")
        #expect(try keyring.currentPublicKey().keyID == "key-2")
        #expect(try keyring.currentMode() == .biometryAndPIN)
    }

    @Test func privateKeyStoreMigratesLargeNSDataPayloadCleanly() throws {
        let backend = MockKeychainBackend()
        let service = "com.clavis.test.private-migration-large"
        let label = "legacy-large"
        let secret = Data(repeating: 0x5A, count: 128)
        backend.seed(service: service, account: label, scope: .legacyLogin, data: secret)

        let store = KeychainPrivateKeyStore(
            serviceName: service,
            scope: Self.dpScope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { query in
                let (status, obj) = backend.copy(query)
                if status == errSecSuccess, let data = obj as? Data {
                    return (status, NSData(data: data))
                }
                return (status, obj)
            }
        )

        let loaded = try store.load(label: label, context: LAContext(), prompt: "Migrate")
        #expect(loaded == secret)
        #expect(backend.storedData(service: service, account: label, scope: Self.dpScope) == secret)
        #expect(backend.storedData(service: service, account: label, scope: .legacyLogin) == nil)
    }

    // MARK: - Helpers

    private func makePrivateKeyStore(
        serviceName: String,
        scope: KeychainScope,
        backend: MockKeychainBackend
    ) -> KeychainPrivateKeyStore {
        KeychainPrivateKeyStore(
            serviceName: serviceName,
            scope: scope,
            addItem: { backend.add($0) },
            deleteItem: { backend.delete($0) },
            updateItem: { backend.update($0, $1) },
            copyItem: { backend.copy($0) }
        )
    }

    private func makeTestApplication() throws -> RegisteredApplication {
        RegisteredApplication(
            identity: try ApplicationIdentity(kind: .executableSHA256, value: String(repeating: "a", count: 64)),
            name: "Test Bot",
            path: "/Applications/Test.app",
            classification: .bot
        )
    }

    private func makeAuditKeyItem(keyID: String, mode: AuditReadMode) throws -> AuditReadKeyItem {
        let key = P256.KeyAgreement.PrivateKey()
        return AuditReadKeyItem(
            keyID: keyID,
            publicKeyX963: key.publicKey.x963Representation.base64EncodedString(),
            seBlob: Data([0x01, 0x02, 0x03]).base64EncodedString(),
            mode: mode
        )
    }

    private func assertScopedQuery(_ query: [String: Any], expectedGroup: String) {
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrAccessGroup as String] as? String == expectedGroup)
    }

    private func assertLegacyQuery(_ query: [String: Any]) {
        #expect(query[kSecUseDataProtectionKeychain as String] == nil)
        #expect(query[kSecAttrAccessGroup as String] == nil)
    }

    private func assertUpdateAttributesClean(_ attributes: [String: Any]) {
        #expect(attributes[kSecClass as String] == nil)
        #expect(attributes[kSecAttrService as String] == nil)
        #expect(attributes[kSecAttrAccount as String] == nil)
        #expect(attributes[kSecUseDataProtectionKeychain as String] == nil)
        #expect(attributes[kSecAttrAccessGroup as String] == nil)
    }
}

private final class MockKeychainBackend: @unchecked Sendable {
    private struct PartitionKey: Hashable {
        let isDataProtection: Bool
        let accessGroup: String?
        let service: String
        let account: String
    }

    private static let forbiddenUpdateKeys: [String] = [
        kSecClass as String,
        kSecAttrService as String,
        kSecAttrAccount as String,
        kSecUseDataProtectionKeychain as String,
        kSecAttrAccessGroup as String
    ]

    private let lock = NSLock()
    private var storage: [PartitionKey: Data] = [:]
    private var insertionOrder: [PartitionKey] = []

    private var _addQueries: [[String: Any]] = []
    private var _copyQueries: [[String: Any]] = []
    private var _deleteQueries: [[String: Any]] = []
    private var _updateCalls: [(query: [String: Any], attributes: [String: Any])] = []

    var forcedAddStatus: OSStatus?
    var forcedUpdateStatus: OSStatus?

    var addQueries: [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return _addQueries
    }

    var copyQueries: [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return _copyQueries
    }

    var deleteQueries: [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return _deleteQueries
    }

    var updateCalls: [(query: [String: Any], attributes: [String: Any])] {
        lock.lock(); defer { lock.unlock() }
        return _updateCalls
    }

    func seed(service: String, account: String, scope: KeychainScope, data: Data) {
        lock.lock()
        defer { lock.unlock() }
        let key = partitionKey(service: service, account: account, scope: scope)
        if storage[key] == nil {
            insertionOrder.append(key)
        }
        storage[key] = data
    }

    func storedData(service: String, account: String, scope: KeychainScope) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[partitionKey(service: service, account: account, scope: scope)]
    }

    func add(_ item: CFDictionary) -> OSStatus {
        guard let dict = item as? [String: Any] else { return errSecParam }
        lock.lock()
        defer { lock.unlock() }
        _addQueries.append(dict)
        if let forcedAddStatus {
            return forcedAddStatus
        }
        guard let key = partitionKey(from: dict), let data = dict[kSecValueData as String] as? Data else {
            return errSecParam
        }
        if storage[key] != nil {
            return errSecDuplicateItem
        }
        storage[key] = data
        insertionOrder.append(key)
        return errSecSuccess
    }

    func delete(_ query: CFDictionary) -> OSStatus {
        guard let dict = query as? [String: Any] else { return errSecParam }
        lock.lock()
        defer { lock.unlock() }
        _deleteQueries.append(dict)
        guard let key = partitionKey(from: dict) else { return errSecParam }
        guard storage.removeValue(forKey: key) != nil else {
            return errSecItemNotFound
        }
        insertionOrder.removeAll { $0 == key }
        return errSecSuccess
    }

    func update(_ query: CFDictionary, _ attributes: CFDictionary) -> OSStatus {
        guard let queryDict = query as? [String: Any],
              let attrDict = attributes as? [String: Any] else {
            return errSecParam
        }
        lock.lock()
        defer { lock.unlock() }
        _updateCalls.append((queryDict, attrDict))
        if let forcedUpdateStatus {
            return forcedUpdateStatus
        }
        // Mirror macOS Data Protection Keychain rejecting search keys in attributesToUpdate.
        if Self.forbiddenUpdateKeys.contains(where: { attrDict[$0] != nil }) {
            return errSecParam
        }
        guard let key = partitionKey(from: queryDict) else { return errSecParam }
        guard storage[key] != nil else { return errSecItemNotFound }
        if let data = attrDict[kSecValueData as String] as? Data {
            storage[key] = data
        }
        return errSecSuccess
    }

    func copy(_ query: CFDictionary) -> (OSStatus, AnyObject?) {
        guard let dict = query as? [String: Any] else { return (errSecParam, nil) }
        lock.lock()
        defer { lock.unlock() }
        _copyQueries.append(dict)

        let isDP = (dict[kSecUseDataProtectionKeychain as String] as? Bool) == true
        let accessGroup = dict[kSecAttrAccessGroup as String] as? String
        guard let service = dict[kSecAttrService as String] as? String else {
            return (errSecParam, nil)
        }

        if let account = dict[kSecAttrAccount as String] as? String {
            let key = PartitionKey(
                isDataProtection: isDP,
                accessGroup: accessGroup,
                service: service,
                account: account
            )
            guard let data = storage[key] else {
                return (errSecItemNotFound, nil)
            }
            if (dict[kSecReturnAttributes as String] as? Bool) == true {
                let attrs: [String: Any] = [kSecAttrAccount as String: account]
                return (errSecSuccess, attrs as AnyObject)
            }
            return (errSecSuccess, data as AnyObject)
        }

        if (dict[kSecMatchLimit as String] as? String) == (kSecMatchLimitAll as String) {
            let matched = insertionOrder.filter {
                $0.isDataProtection == isDP && $0.accessGroup == accessGroup && $0.service == service && storage[$0] != nil
            }
            if matched.isEmpty {
                return (errSecItemNotFound, nil)
            }
            let dicts: [[String: Any]] = matched.map { [kSecAttrAccount as String: $0.account] }
            return (errSecSuccess, dicts as AnyObject)
        }

        return (errSecParam, nil)
    }

    private func partitionKey(service: String, account: String, scope: KeychainScope) -> PartitionKey {
        switch scope {
        case .dataProtection(let accessGroup):
            return PartitionKey(isDataProtection: true, accessGroup: accessGroup, service: service, account: account)
        case .legacyLogin:
            return PartitionKey(isDataProtection: false, accessGroup: nil, service: service, account: account)
        }
    }

    private func partitionKey(from dict: [String: Any]) -> PartitionKey? {
        guard let service = dict[kSecAttrService as String] as? String,
              let account = dict[kSecAttrAccount as String] as? String else {
            return nil
        }
        let isDP = (dict[kSecUseDataProtectionKeychain as String] as? Bool) == true
        let accessGroup = dict[kSecAttrAccessGroup as String] as? String
        return PartitionKey(isDataProtection: isDP, accessGroup: accessGroup, service: service, account: account)
    }
}
