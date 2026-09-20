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
    private let serviceName: String
    private let addItem: (CFDictionary) -> OSStatus
    private let deleteItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus

    public convenience init(serviceName: String = KeychainManager.privateServiceName) {
        self.init(
            serviceName: serviceName,
            addItem: { SecItemAdd($0, nil) },
            deleteItem: { SecItemDelete($0) },
            updateItem: { SecItemUpdate($0, $1) }
        )
    }

    init(
        serviceName: String,
        addItem: @escaping (CFDictionary) -> OSStatus,
        deleteItem: @escaping (CFDictionary) -> OSStatus,
        updateItem: @escaping (CFDictionary, CFDictionary) -> OSStatus = { SecItemUpdate($0, $1) }
    ) {
        self.serviceName = serviceName
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
    }

    public func contains(label: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    public func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = [.userPresence]) throws {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]

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
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw PrivateKeyStoreError.keychain(status)
        }
        return data
    }

    public func remove(label: String, context: LAContext?, prompt: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]
        if let context {
            context.localizedReason = prompt
            query[kSecUseAuthenticationContext as String] = context
        }
        let status = deleteItem(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(status)
        }
    }
}
