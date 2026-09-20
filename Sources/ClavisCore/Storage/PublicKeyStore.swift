import Foundation
import Security

public struct PublicKeyStore {
    public static var customStorageURL: URL? = nil

    private static var storageURL: URL {
        if let customStorageURL { return customStorageURL }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("keys.json")
    }

    public static func loadAll() -> [Ed25519KeyInfo] {
        if let data = try? Data(contentsOf: storageURL),
           let keys = try? JSONDecoder().decode([Ed25519KeyInfo].self, from: data) {
            return keys.sorted(by: { $0.label < $1.label })
        }
        // Rebuild from Keychain public store if keys.json is missing or corrupted
        return rebuildIndexFromKeychain()
    }

    public static func save(_ info: Ed25519KeyInfo) {
        var current = loadAll().filter { $0.label != info.label }
        current.append(info)
        if let data = try? JSONEncoder().encode(current) {
            try? data.write(to: storageURL, options: .atomic)
        }
        saveToKeychain(info)
    }

    public static func remove(label: String) {
        let current = loadAll().filter { $0.label != label }
        if let data = try? JSONEncoder().encode(current) {
            try? data.write(to: storageURL, options: .atomic)
        }
        removeFromKeychain(label: label)
    }

    // MARK: - Keychain Public Record Mirroring & Recovery

    public static func saveToKeychain(_ info: Ed25519KeyInfo) {
        guard let data = try? JSONEncoder().encode(info) else { return }
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: info.label
        ]
        SecItemDelete(lookup as CFDictionary)

        var item = lookup
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecAttrSynchronizable as String] = false
        item[kSecAttrDescription as String] = "Clavis public key metadata"
        _ = SecItemAdd(item as CFDictionary, nil)
    }

    public static func removeFromKeychain(label: String) {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.publicServiceName,
            kSecAttrAccount as String: label
        ]
        SecItemDelete(lookup as CFDictionary)
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
        let keychainKeys = loadAllFromKeychain()
        if !keychainKeys.isEmpty {
            if let data = try? JSONEncoder().encode(keychainKeys) {
                try? data.write(to: storageURL, options: .atomic)
            }
        }
        return keychainKeys
    }
}
