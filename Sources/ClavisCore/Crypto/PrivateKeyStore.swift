import Foundation
import LocalAuthentication
import Security

public protocol PrivateKeyStoring {
    func contains(label: String) -> Bool
    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags) throws
    func load(label: String, context: LAContext, prompt: String) throws -> Data?
    func remove(label: String, context: LAContext?, prompt: String) throws
}

public extension PrivateKeyStoring {
    func save(label: String, data: Data) throws {
        try save(label: label, data: data, accessControlFlags: [.userPresence])
    }

    func remove(label: String) throws {
        try remove(label: label, context: nil, prompt: "")
    }
}

public enum PrivateKeyStoreError: LocalizedError {
    case accessControlCreation(String)
    case protectionUnavailable(OSStatus)
    case keychain(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .accessControlCreation(let message):
            return "Failed to create private-key access control: \(message)"
        case .protectionUnavailable(let status):
            return "The private key was not stored because the requested Keychain authentication protection is unavailable (\(status)). Check the application's Keychain entitlements; Clavis will not store the key with weaker protection."
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown Keychain error"
            return "Keychain operation failed (\(status)): \(message)"
        }
    }
}

enum PrivateKeyAccessControl {
    static func make(flags: SecAccessControlCreateFlags = [.userPresence]) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "Unknown access-control error"
            throw PrivateKeyStoreError.accessControlCreation(message)
        }
        return accessControl
    }
}

public final class KeychainPrivateKeyStore: PrivateKeyStoring {
    /// Team-scoped Keychain group shared by every signed Clavis executable
    /// that performs private-key operations.
    public static let sharedAccessGroup = "P7P693LH69.com.clavis.shared"

    private let serviceName: String
    private let accessGroup: String
    private let addItem: (CFDictionary) -> OSStatus
    private let deleteItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: (CFDictionary) -> (OSStatus, AnyObject?)

    public convenience init(serviceName: String = KeychainManager.privateServiceName) {
        self.init(
            serviceName: serviceName,
            accessGroup: Self.sharedAccessGroup,
            addItem: { SecItemAdd($0, nil) },
            deleteItem: { SecItemDelete($0) },
            updateItem: { SecItemUpdate($0, $1) },
            copyItem: { query in
                var result: CFTypeRef?
                let status = SecItemCopyMatching(query, &result)
                return (status, result)
            }
        )
    }

    init(
        serviceName: String,
        accessGroup: String = KeychainPrivateKeyStore.sharedAccessGroup,
        addItem: @escaping (CFDictionary) -> OSStatus,
        deleteItem: @escaping (CFDictionary) -> OSStatus,
        updateItem: @escaping (CFDictionary, CFDictionary) -> OSStatus = { SecItemUpdate($0, $1) },
        copyItem: @escaping (CFDictionary) -> (OSStatus, AnyObject?) = { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query, &result)
            return (status, result)
        }
    ) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem
    }

    public func contains(label: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        var query = sharedLookup(label: label)
        query.merge([
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        let (status, _) = copyItem(query as CFDictionary)
        if status == errSecSuccess || status == errSecInteractionNotAllowed {
            return true
        }

        // An existing legacy item still counts as a collision. This query does
        // not request secret data and suppresses authentication UI.
        var legacyQuery = legacyLookup(label: label)
        legacyQuery.merge([
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        let (legacyStatus, _) = copyItem(legacyQuery as CFDictionary)
        return legacyStatus == errSecSuccess || legacyStatus == errSecInteractionNotAllowed
    }

    public func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = [.userPresence]) throws {
        let lookup = sharedLookup(label: label)

        var baseItem = lookup
        baseItem[kSecValueData as String] = data
        baseItem[kSecAttrSynchronizable as String] = false
        baseItem[kSecAttrDescription as String] = "Clavis private key record"

        // Generic password records do not support .privateKeyUsage (reserved for SecKeyRef).
        let passwordFlags = accessControlFlags.subtracting([.privateKeyUsage])
        guard !passwordFlags.isEmpty else {
            throw PrivateKeyStoreError.accessControlCreation(
                "No authentication constraint remains after removing the SecKey-only privateKeyUsage flag."
            )
        }

        let accessControl = try PrivateKeyAccessControl.make(flags: passwordFlags)
        var protectedAttributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrSynchronizable as String: false,
            kSecAttrDescription as String: "Clavis private key record",
            kSecAttrAccessControl as String: accessControl
        ]
        var saveStatus = updateItem(lookup as CFDictionary, protectedAttributes as CFDictionary)
        if saveStatus == errSecItemNotFound {
            for (key, value) in baseItem where protectedAttributes[key] == nil {
                protectedAttributes[key] = value
            }
            saveStatus = addItem(protectedAttributes as CFDictionary)
        }

        // Never retry without SecAccessControl. A missing entitlement is a deployment
        // configuration failure, not permission to downgrade private-key protection.
        if saveStatus == errSecMissingEntitlement || saveStatus == -34018 {
            throw PrivateKeyStoreError.protectionUnavailable(saveStatus)
        }

        guard saveStatus == errSecSuccess else {
            throw PrivateKeyStoreError.keychain(saveStatus)
        }
    }

    public func load(label: String, context: LAContext, prompt: String) throws -> Data? {
        context.localizedReason = prompt
        var query = sharedLookup(label: label)
        query.merge([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }

        let (status, result) = copyItem(query as CFDictionary)
        if status == errSecSuccess, let data = result as? Data {
            return data
        }
        guard status == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(status)
        }

        return try migrateLegacyItem(label: label, context: context)
    }

    public func remove(label: String, context: LAContext?, prompt: String) throws {
        var sharedQuery = sharedLookup(label: label)
        if let context {
            context.localizedReason = prompt
            sharedQuery[kSecUseAuthenticationContext as String] = context
        }
        let sharedStatus = deleteItem(sharedQuery as CFDictionary)
        guard sharedStatus == errSecSuccess || sharedStatus == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(sharedStatus)
        }

        var legacyQuery = legacyLookup(label: label)
        if let context {
            legacyQuery[kSecUseAuthenticationContext as String] = context
        }
        let legacyStatus = deleteItem(legacyQuery as CFDictionary)
        guard legacyStatus == errSecSuccess || legacyStatus == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(legacyStatus)
        }
    }

    private func migrateLegacyItem(label: String, context: LAContext) throws -> Data? {
        var legacyQuery = legacyLookup(label: label)
        legacyQuery.merge([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }

        let (legacyStatus, legacyResult) = copyItem(legacyQuery as CFDictionary)
        if legacyStatus == errSecItemNotFound {
            return nil
        }
        guard legacyStatus == errSecSuccess, var legacyData = legacyResult as? Data else {
            throw PrivateKeyStoreError.keychain(legacyStatus)
        }
        defer {
            legacyData.withUnsafeMutableBytes { bytes in
                if let baseAddress = bytes.baseAddress {
                    SecureMemory.zero(baseAddress, byteCount: bytes.count)
                }
            }
            legacyData.removeAll(keepingCapacity: false)
        }

        let flags = migrationAccessControlFlags(for: legacyData)
        try save(label: label, data: legacyData, accessControlFlags: flags)

        // Delete only after the data-protection item has been stored. If this
        // fails, both copies remain and the caller sees the cleanup failure.
        var deletionQuery = legacyLookup(label: label)
        deletionQuery[kSecUseAuthenticationContext as String] = context
        let deletionStatus = deleteItem(deletionQuery as CFDictionary)
        guard deletionStatus == errSecSuccess || deletionStatus == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(deletionStatus)
        }

        return legacyData
    }

    private func migrationAccessControlFlags(for data: Data) -> SecAccessControlCreateFlags {
        guard var record = try? StoredPrivateKeyRecord.decode(from: data) else {
            return [.userPresence]
        }
        defer { record.wipe() }
        return record.biometricPolicy?.accessControlFlags ?? [.userPresence]
    }

    private func sharedLookup(label: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: accessGroup
        ]
    }

    private func legacyLookup(label: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]
    }
}
