import Foundation
import LocalAuthentication
import Security

public protocol PrivateKeyStoring {
    func contains(label: String) -> Bool
    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags) throws
    func load(label: String, context: LAContext, prompt: String) throws -> Data?
    func remove(label: String) throws
}

public extension PrivateKeyStoring {
    func save(label: String, data: Data) throws {
        try save(label: label, data: data, accessControlFlags: [.userPresence])
    }
}

public enum PrivateKeyStoreError: LocalizedError {
    case accessControlCreation(String)
    case keychain(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .accessControlCreation(let message):
            return "Failed to create private-key access control: \(message)"
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

    public init(serviceName: String = KeychainManager.privateServiceName) {
        self.serviceName = serviceName
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
        let accessControl = try PrivateKeyAccessControl.make(flags: accessControlFlags)
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]

        let deleteStatus = SecItemDelete(lookup as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(deleteStatus)
        }

        var item = lookup
        item[kSecValueData as String] = data
        item[kSecAttrAccessControl as String] = accessControl
        item[kSecAttrSynchronizable as String] = false
        item[kSecAttrDescription as String] = "Clavis private key record"

        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw PrivateKeyStoreError.keychain(status)
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

    public func remove(label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(status)
        }
    }
}
