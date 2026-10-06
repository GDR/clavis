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

    private let service: String
    private let addItem: (CFDictionary) -> OSStatus
    private let deleteItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: (CFDictionary) -> (OSStatus, AnyObject?)

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
        var q = query(account: fingerprint)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = copyItem(q as CFDictionary)
        if status == errSecItemNotFound {
            return AgentKeyPolicy()
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AgentPolicyError.corrupt
        }
        do {
            let policy = try JSONDecoder().decode(AgentKeyPolicy.self, from: data)
            try policy.validate()
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
        try setItemData(data, account: fingerprint)
    }

    public func deletePolicy(forFingerprint fingerprint: String) throws {
        let q = query(account: fingerprint)
        let status = deleteItem(q as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AgentPolicyError.corrupt
        }
    }

    public func global() throws -> AgentGlobalPolicy {
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
        try setItemData(data, account: Self.globalAccount)
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
