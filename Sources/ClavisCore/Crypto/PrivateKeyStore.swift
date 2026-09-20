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
    private let legacyServiceNames: [String]
    private let addItem: (CFDictionary) -> OSStatus
    private let deleteItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: (CFDictionary) -> (OSStatus, AnyObject?)

    public convenience init(serviceName: String = KeychainManager.privateServiceName) {
        let legacyServiceNames = serviceName == KeychainManager.privateServiceName
            ? [KeychainManager.legacyPrivateServiceName]
            : []
        self.init(
            serviceName: serviceName,
            legacyServiceNames: legacyServiceNames,
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
        legacyServiceNames: [String] = [],
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
        self.legacyServiceNames = legacyServiceNames
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem
    }

    public func contains(label: String) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        return ([serviceName] + legacyServiceNames).contains { candidateService in
            var query = lookup(label: label, serviceName: candidateService)
            query.merge([
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context
            ]) { _, new in new }
            let (status, _) = copyItem(query as CFDictionary)
            return status == errSecSuccess || status == errSecInteractionNotAllowed
        }
    }

    public func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = [.userPresence]) throws {
        let lookup = lookup(label: label, serviceName: serviceName)

        var baseItem = lookup
        baseItem[kSecValueData as String] = data
        baseItem[kSecAttrSynchronizable as String] = false
        baseItem[kSecAttrDescription as String] = "Clavis private key record"

        // An empty flag set is reserved for an opaque Secure Enclave reference.
        // The hardware key itself owns the authentication policy; the reference
        // is device-bound metadata and contains no exportable private scalar.
        if accessControlFlags.isEmpty {
            var referenceAttributes = baseItem
            referenceAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            var saveStatus = updateItem(lookup as CFDictionary, referenceAttributes as CFDictionary)
            if saveStatus == errSecItemNotFound {
                saveStatus = addItem(referenceAttributes as CFDictionary)
                if saveStatus == errSecDuplicateItem {
                    saveStatus = updateItem(lookup as CFDictionary, referenceAttributes as CFDictionary)
                }
            }
            guard saveStatus == errSecSuccess else {
                throw PrivateKeyStoreError.keychain(saveStatus)
            }
            return
        }

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
            if saveStatus == errSecDuplicateItem {
                saveStatus = updateItem(lookup as CFDictionary, protectedAttributes as CFDictionary)
            }
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
        let (status, result) = loadItem(label: label, serviceName: serviceName, context: context)
        if status == errSecSuccess, let data = result as? Data {
            return data
        }
        guard status == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(status)
        }

        for legacyServiceName in legacyServiceNames {
            let (legacyStatus, legacyResult) = loadItem(
                label: label,
                serviceName: legacyServiceName,
                context: context
            )
            if legacyStatus == errSecItemNotFound { continue }
            guard legacyStatus == errSecSuccess, let legacyData = legacyResult as? Data else {
                throw PrivateKeyStoreError.keychain(legacyStatus)
            }

            try save(
                label: label,
                data: legacyData,
                accessControlFlags: migrationAccessControlFlags(for: legacyData)
            )
            ClavisLogger.log(
                "KEYCHAIN_LOCATION_MIGRATE",
                "Copied '\(label)' to the current signed-client Keychain record; retained the legacy record as a recovery fallback."
            )
            return legacyData
        }
        return nil
    }

    public func remove(label: String, context: LAContext?, prompt: String) throws {
        for candidateService in [serviceName] + legacyServiceNames {
            var query = lookup(label: label, serviceName: candidateService)
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

    private func loadItem(
        label: String,
        serviceName: String,
        context: LAContext
    ) -> (OSStatus, AnyObject?) {
        var query = lookup(label: label, serviceName: serviceName)
        query.merge([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        return copyItem(query as CFDictionary)
    }

    private func migrationAccessControlFlags(for data: Data) -> SecAccessControlCreateFlags {
        guard var record = try? StoredPrivateKeyRecord.decode(from: data) else {
            return [.userPresence]
        }
        defer { record.wipe() }
        return record.biometricPolicy?.accessControlFlags ?? [.userPresence]
    }

    private func lookup(label: String, serviceName: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]
    }
}
