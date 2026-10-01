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

public struct PublicKeyStore {
    public static var customStorageURL: URL? = nil
    static var disableKeychainMirrorForTesting = false

    private static var storageURL: URL {
        if let customStorageURL { return customStorageURL }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("keys.json")
    }

    public static func loadAll() -> [Ed25519KeyInfo] {
        if let data = try? Data(contentsOf: storageURL),
           let keys = try? JSONDecoder().decode([Ed25519KeyInfo].self, from: data) {
            return keys.sorted(by: { $0.label < $1.label })
        }
        if disableKeychainMirrorForTesting { return [] }
        // Rebuild from Keychain public store if keys.json is missing or corrupted
        return rebuildIndexFromKeychain()
    }

    public static func save(_ info: Ed25519KeyInfo) {
        try? saveChecked(info)
    }

    public static func saveChecked(_ info: Ed25519KeyInfo) throws {
        var current = loadAll().filter { $0.label != info.label }
        current.append(info)
        if !disableKeychainMirrorForTesting {
            try saveToKeychainChecked(info)
        }
        let data = try JSONEncoder().encode(current)
        try writeIndex(data)
    }

    /// Writes the index with owner-only permissions. The index is not a trust root (private
    /// records are authoritative), but there is no reason for it to be readable or writable
    /// by anyone else, and the parent directory also holds the log and vault.
    private static func writeIndex(_ data: Data) throws {
        let directory = storageURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // Best effort: a caller-supplied directory may not be ours to chmod.
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        try data.write(to: storageURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storageURL.path)
    }

    public static func remove(label: String) {
        try? removeChecked(label: label)
    }

    public static func removeChecked(label: String) throws {
        let current = loadAll().filter { $0.label != label }
        if !disableKeychainMirrorForTesting {
            try removeFromKeychainChecked(label: label)
        }
        let data = try JSONEncoder().encode(current)
        do {
            try writeIndex(data)
        } catch {
            // Avoid leaving a stale authoritative-looking file after the mirror
            // was successfully removed; a later load can rebuild an empty index.
            try? FileManager.default.removeItem(at: storageURL)
            throw error
        }
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

    @discardableResult
    public static func rebuildIndexFromKeychain() -> [Ed25519KeyInfo] {
        if disableKeychainMirrorForTesting { return [] }
        let keychainKeys = loadAllFromKeychain()
        if !keychainKeys.isEmpty {
            if let data = try? JSONEncoder().encode(keychainKeys) {
                try? writeIndex(data)
            }
        }
        return keychainKeys
    }
}
