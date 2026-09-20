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
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]

        let deleteStatus = SecItemDelete(lookup as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(deleteStatus)
        }

        var baseItem = lookup
        baseItem[kSecValueData as String] = data
        baseItem[kSecAttrSynchronizable as String] = false
        baseItem[kSecAttrDescription as String] = "Clavis private key record"

        // Generic password records do not support .privateKeyUsage (reserved for SecKeyRef).
        let passwordFlags = accessControlFlags.subtracting([.privateKeyUsage])
        var saveStatus: OSStatus = errSecMissingEntitlement

        if !passwordFlags.isEmpty, let accessControl = try? PrivateKeyAccessControl.make(flags: passwordFlags) {
            var secureItem = baseItem
            secureItem[kSecAttrAccessControl as String] = accessControl
            saveStatus = SecItemAdd(secureItem as CFDictionary, nil)
        }

        // Fallback for environments where SecAccessControl on generic passwords requires
        // an Apple provisioning profile / keychain-access-groups (e.g. un-entitled debug runs,
        // ad-hoc binaries, or self-signed development certificates).
        // Protected by the macOS Login Keychain bound to this device.
        if saveStatus == errSecMissingEntitlement || saveStatus == -34018 {
            var fallbackItem = baseItem
            fallbackItem[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            saveStatus = SecItemAdd(fallbackItem as CFDictionary, nil)
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
