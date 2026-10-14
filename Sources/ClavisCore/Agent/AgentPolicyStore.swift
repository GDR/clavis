import Foundation
import Security

public protocol AgentPolicyStoring: Sendable {
    func policy(forFingerprint fingerprint: String) throws -> AgentKeyPolicy
    func save(_ policy: AgentKeyPolicy, forFingerprint fingerprint: String) throws
    func deletePolicy(forFingerprint fingerprint: String) throws
    func global() throws -> AgentGlobalPolicy
    func saveGlobal(_ policy: AgentGlobalPolicy) throws
}

public final class KeychainAgentPolicyStore: AgentPolicyStoring, @unchecked Sendable {
    public static let serviceName = "com.clavis.agent-policy.v1"
    public static let globalAccount = "global"
    public static let configuredIndexAccount = "configured-index"

    private let service: String
    private let addItem: (CFDictionary) -> OSStatus
    private let deleteItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: (CFDictionary) -> (OSStatus, AnyObject?)
    private let lock = NSLock()
    private var knownConfiguredFingerprints: Set<String> = []

    public init(
        service: String = KeychainAgentPolicyStore.serviceName,
        addItem: @escaping (CFDictionary) -> OSStatus = { SecItemAdd($0, nil) },
        deleteItem: @escaping (CFDictionary) -> OSStatus = { SecItemDelete($0) },
        updateItem: @escaping (CFDictionary, CFDictionary) -> OSStatus = { SecItemUpdate($0, $1) },
        copyItem: @escaping (CFDictionary) -> (OSStatus, AnyObject?) = { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query, &result)
            return (status, result)
        }
    ) {
        self.service = service
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem
    }

    private func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    public func policy(forFingerprint fingerprint: String) throws -> AgentKeyPolicy {
        lock.lock()
        defer { lock.unlock() }

        var q = query(account: fingerprint)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = copyItem(q as CFDictionary)
        if status == errSecItemNotFound {
            if try isConfiguredLocked(fingerprint: fingerprint) {
                throw AgentPolicyError.policyUnavailable
            }
            return AgentKeyPolicy()
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AgentPolicyError.corrupt
        }
        do {
            let policy = try JSONDecoder().decode(AgentKeyPolicy.self, from: data)
            try policy.validate()
            knownConfiguredFingerprints.insert(fingerprint)
            return policy
        } catch {
            throw AgentPolicyError.corrupt
        }
    }

    public func save(_ policy: AgentKeyPolicy, forFingerprint fingerprint: String) throws {
        try policy.validate()
        let data: Data
        do {
            data = try JSONEncoder().encode(policy)
        } catch {
            throw AgentPolicyError.invalid("Failed to encode policy: \(error.localizedDescription)")
        }
        lock.lock()
        defer { lock.unlock() }
        try setItemData(data, account: fingerprint)
        try recordConfiguredLocked(fingerprint: fingerprint)
    }

    public func deletePolicy(forFingerprint fingerprint: String) throws {
        lock.lock()
        defer { lock.unlock() }
        let q = query(account: fingerprint)
        let status = deleteItem(q as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AgentPolicyError.corrupt
        }
        try removeConfiguredLocked(fingerprint: fingerprint)
    }

    public func global() throws -> AgentGlobalPolicy {
        lock.lock()
        defer { lock.unlock() }

        var q = query(account: Self.globalAccount)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = copyItem(q as CFDictionary)
        if status == errSecItemNotFound {
            return AgentGlobalPolicy()
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AgentPolicyError.corrupt
        }
        do {
            let policy = try JSONDecoder().decode(AgentGlobalPolicy.self, from: data)
            try policy.validate()
            return policy
        } catch {
            throw AgentPolicyError.corrupt
        }
    }

    public func saveGlobal(_ policy: AgentGlobalPolicy) throws {
        try policy.validate()
        let data: Data
        do {
            data = try JSONEncoder().encode(policy)
        } catch {
            throw AgentPolicyError.invalid("Failed to encode global policy: \(error.localizedDescription)")
        }
        lock.lock()
        defer { lock.unlock() }
        try setItemData(data, account: Self.globalAccount)
    }

    private func loadPersistedIndexLocked() throws -> Set<String> {
        var q = query(account: Self.configuredIndexAccount)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = copyItem(q as CFDictionary)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AgentPolicyError.corrupt
        }
        do {
            let list = try JSONDecoder().decode([String].self, from: data)
            return Set(list)
        } catch {
            throw AgentPolicyError.corrupt
        }
    }

    private func savePersistedIndexLocked(_ index: Set<String>) throws {
        let sorted = index.sorted()
        guard let data = try? JSONEncoder().encode(sorted) else {
            throw AgentPolicyError.corrupt
        }
        try setItemData(data, account: Self.configuredIndexAccount)
    }

    private func isConfiguredLocked(fingerprint: String) throws -> Bool {
        if knownConfiguredFingerprints.contains(fingerprint) {
            return true
        }
        let persisted = try loadPersistedIndexLocked()
        return persisted.contains(fingerprint)
    }

    private func recordConfiguredLocked(fingerprint: String) throws {
        knownConfiguredFingerprints.insert(fingerprint)
        var persisted = try loadPersistedIndexLocked()
        persisted.formUnion(knownConfiguredFingerprints)
        persisted.insert(fingerprint)
        try savePersistedIndexLocked(persisted)
        knownConfiguredFingerprints = persisted
    }

    private func removeConfiguredLocked(fingerprint: String) throws {
        var persisted = try loadPersistedIndexLocked()
        if persisted.remove(fingerprint) != nil {
            try savePersistedIndexLocked(persisted)
        }
        knownConfiguredFingerprints.remove(fingerprint)
    }

    private func setItemData(_ data: Data, account: String) throws {
        let q = query(account: account)
        let updates: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        var status = updateItem(q as CFDictionary, updates as CFDictionary)
        if status == errSecItemNotFound {
            var attributes = q
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = addItem(attributes as CFDictionary)
            if status == errSecDuplicateItem {
                status = updateItem(q as CFDictionary, updates as CFDictionary)
            }
        }
        guard status == errSecSuccess else {
            throw AgentPolicyError.corrupt
        }
    }
}
