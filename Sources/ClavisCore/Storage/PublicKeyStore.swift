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
    private static var isRunningUnderXCTest: Bool {
        NSClassFromString("XCTestCase") != nil ||
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }

    private static var isKeychainAccessAllowed: Bool {
        if !isRunningUnderXCTest {
            return true
        }
        return ProcessInfo.processInfo.environment["CLAVIS_RUN_KEYCHAIN_INTEGRATION_TESTS"] == "1"
    }

    /// Test-only: keep the index purely in memory and never touch the real Keychain.
    static var disableKeychainMirrorForTesting: Bool = isRunningUnderXCTest

    #if DEBUG
    /// Test-only: force saveChecked to throw this error instead of completing.
    static var forcedSaveErrorForTesting: Error?
    #endif

    /// How long a process trusts its in-memory copy. Other processes (e.g. the GUI creating a
    /// key while the agent runs) write straight to the Keychain, so the copy must expire.
    /// Local writes invalidate it immediately.
    private static let cacheTTL: TimeInterval = 2

    private static let stateLock = NSLock()
    private static var cachedKeys: [Ed25519KeyInfo]?
    private static var cachedAt = Date.distantPast
    private static var generation: UInt64 = 0
    /// Backing store when `disableKeychainMirrorForTesting` is set.
    private static var memoryOnlyKeys: [String: Ed25519KeyInfo] = [:]

    #if DEBUG
    /// Test seam for loading keys without touching host Keychain.
    static var keychainLoader: () -> [Ed25519KeyInfo] = {
        guard isKeychainAccessAllowed else { return [] }
        return loadAllFromKeychain()
    }
    static var cachedKeysForTesting: [Ed25519KeyInfo]? {
        stateLock.lock(); defer { stateLock.unlock() }
        return cachedKeys
    }
    static var generationForTesting: UInt64 {
        stateLock.lock(); defer { stateLock.unlock() }
        return generation
    }
    #endif

    public static func loadAll() -> [Ed25519KeyInfo] {
        stateLock.lock()
        if disableKeychainMirrorForTesting {
            defer { stateLock.unlock() }
            return memoryOnlyKeys.values.sorted(by: { $0.label < $1.label })
        }
        if let cachedKeys, Date().timeIntervalSince(cachedAt) < cacheTTL {
            defer { stateLock.unlock() }
            return cachedKeys
        }
        let capturedGeneration = generation
        stateLock.unlock()

        #if DEBUG
        let keys = keychainLoader()
        #else
        let keys = loadAllFromKeychain()
        #endif

        stateLock.lock()
        defer { stateLock.unlock() }
        if generation == capturedGeneration {
            cachedKeys = keys
            cachedAt = Date()
        }
        return keys
    }

    public static func save(_ info: Ed25519KeyInfo) {
        try? saveChecked(info)
    }

    public static func saveChecked(_ info: Ed25519KeyInfo) throws {
        #if DEBUG
        if let forcedError = forcedSaveErrorForTesting {
            throw forcedError
        }
        #endif
        try saveToKeychainChecked(info)
    }

    public static func remove(label: String) {
        try? removeChecked(label: label)
    }

    public static func removeChecked(label: String) throws {
        try removeFromKeychainChecked(label: label)
    }

    /// Drops the in-memory copy so the next `loadAll()` re-reads the Keychain.
    static func invalidateCache() {
        stateLock.lock(); defer { stateLock.unlock() }
        generation &+= 1
        cachedKeys = nil
        cachedAt = .distantPast
    }

    /// Test-only: forget everything held in memory (both the cache and the memory-only store).
    static func resetForTesting() {
        stateLock.lock(); defer { stateLock.unlock() }
        generation &+= 1
        cachedKeys = nil
        cachedAt = .distantPast
        memoryOnlyKeys = [:]
        disableKeychainMirrorForTesting = isRunningUnderXCTest
        #if DEBUG
        forcedSaveErrorForTesting = nil
        keychainLoader = {
            guard isKeychainAccessAllowed else { return [] }
            return loadAllFromKeychain()
        }
        #endif
    }

    // MARK: - Keychain Public Record Mirroring & Recovery

    public static func saveToKeychain(_ info: Ed25519KeyInfo) {
        try? saveToKeychainChecked(info)
    }

    public static func saveToKeychainChecked(_ info: Ed25519KeyInfo) throws {
        if disableKeychainMirrorForTesting || !isKeychainAccessAllowed {
            stateLock.lock()
            memoryOnlyKeys[info.label] = info
            stateLock.unlock()
            invalidateCache()
            return
        }
        let data = try JSONEncoder().encode(info)
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: info.label
        ]
        var attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
            kSecAttrDescription as String: "Clavis public key metadata"
        ]
        #if os(macOS)
        var access: SecAccess?
        if SecAccessCreate("Clavis public key metadata" as CFString, nil, &access) == errSecSuccess, let access {
            attributes[kSecAttrAccess as String] = access
        }
        #endif
        var status = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = lookup
            for (key, value) in attributes { item[key] = value }
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw PublicKeyStoreError.keychain(status) }
        invalidateCache()
    }

    public static func removeFromKeychain(_ label: String) {
        try? removeFromKeychainChecked(label: label)
    }

    public static func removeFromKeychainChecked(label: String) throws {
        if disableKeychainMirrorForTesting || !isKeychainAccessAllowed {
            stateLock.lock()
            memoryOnlyKeys[label] = nil
            stateLock.unlock()
            invalidateCache()
            return
        }
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label
        ]
        let status = SecItemDelete(lookup as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PublicKeyStoreError.keychain(status)
        }
        invalidateCache()
    }

    public static func loadAllFromKeychain() -> [Ed25519KeyInfo] {
        guard isKeychainAccessAllowed else { return [] }
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
