import Foundation
import Security

public enum PublicKeyStoreError: LocalizedError {
    case keychain(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown Keychain error"
            return "Public key index Keychain operation failed (\(status)): \(message)"
        }
    }
}

/// Index of public key metadata.
///
/// There is no on-disk index: the Keychain items (`KeychainManager.publicServiceName`) are the only
/// persistent copy, and every process (GUI, CLI, agent) keeps a short-lived in-memory copy.
/// The index is not a trust root — private records are authoritative and are cross-checked on
/// every use — so it needs neither a file nor its own integrity protection.
public struct PublicKeyStore {
    /// Test-only: keep the index purely in memory and never touch the real Keychain.
    static var disableKeychainMirrorForTesting = false

    /// How long a process trusts its in-memory copy. Other processes (e.g. the GUI creating a
    /// key while the agent runs) write straight to the Keychain, so the copy must expire.
    /// Local writes invalidate it immediately.
    private static let cacheTTL: TimeInterval = 2

    private static let stateLock = NSLock()
    private static var cachedKeys: [Ed25519KeyInfo]?
    private static var cachedAt = Date.distantPast
    /// Backing store when `disableKeychainMirrorForTesting` is set.
    private static var memoryOnlyKeys: [String: Ed25519KeyInfo] = [:]

    public static func loadAll() -> [Ed25519KeyInfo] {
        stateLock.lock()
        defer { stateLock.unlock() }

        if disableKeychainMirrorForTesting {
            return memoryOnlyKeys.values.sorted(by: { $0.label < $1.label })
        }
        if let cachedKeys, Date().timeIntervalSince(cachedAt) < cacheTTL {
            return cachedKeys
        }
        let keys = loadAllFromKeychain()
        cachedKeys = keys
        cachedAt = Date()
        return keys
    }

    public static func save(_ info: Ed25519KeyInfo) {
        try? saveChecked(info)
    }

    public static func saveChecked(_ info: Ed25519KeyInfo) throws {
        if disableKeychainMirrorForTesting {
            stateLock.lock(); defer { stateLock.unlock() }
            memoryOnlyKeys[info.label] = info
            return
        }
        try saveToKeychainChecked(info)
        invalidateCache()
    }

    public static func remove(label: String) {
        try? removeChecked(label: label)
    }

    public static func removeChecked(label: String) throws {
        if disableKeychainMirrorForTesting {
            stateLock.lock(); defer { stateLock.unlock() }
            memoryOnlyKeys[label] = nil
            return
        }
        try removeFromKeychainChecked(label: label)
        invalidateCache()
    }

    /// Drops the in-memory copy so the next `loadAll()` re-reads the Keychain.
    static func invalidateCache() {
        stateLock.lock(); defer { stateLock.unlock() }
        cachedKeys = nil
        cachedAt = .distantPast
    }

    /// Test-only: forget everything held in memory (both the cache and the memory-only store).
    static func resetForTesting() {
        stateLock.lock(); defer { stateLock.unlock() }
        cachedKeys = nil
        cachedAt = .distantPast
        memoryOnlyKeys = [:]
    }

    // MARK: - Keychain Public Record Mirroring & Recovery

    public static func saveToKeychain(_ info: Ed25519KeyInfo) {
        try? saveToKeychainChecked(info)
    }

    public static func saveToKeychainChecked(_ info: Ed25519KeyInfo) throws {
        let data = try JSONEncoder().encode(info)
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: info.label
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
            kSecAttrDescription as String: "Clavis public key metadata"
        ]
        var status = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = lookup
            for (key, value) in attributes { item[key] = value }
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw PublicKeyStoreError.keychain(status) }
    }

    public static func removeFromKeychain(label: String) {
        try? removeFromKeychainChecked(label: label)
    }

    public static func removeFromKeychainChecked(label: String) throws {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label
        ]
        let status = SecItemDelete(lookup as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PublicKeyStoreError.keychain(status)
        }
    }

    public static func loadAllFromKeychain() -> [Ed25519KeyInfo] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return [] }

        var keys: [Ed25519KeyInfo] = []
        let dicts = (result as? [[String: Any]]) ?? (result as? [String: Any]).map { [$0] } ?? []
        for dict in dicts {
            guard let account = dict[kSecAttrAccount as String] as? String else { continue }
            let itemQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: KeychainManager.publicServiceName,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]
            var itemResult: AnyObject?
            if SecItemCopyMatching(itemQuery as CFDictionary, &itemResult) == errSecSuccess,
               let data = itemResult as? Data,
               let info = try? JSONDecoder().decode(Ed25519KeyInfo.self, from: data) {
                keys.append(info)
            }
        }
        return keys.sorted(by: { $0.label < $1.label })
    }

}
