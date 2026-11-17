import Foundation
import LocalAuthentication
import Security

public protocol PrivateKeyStoring {
    func contains(label: String) -> Bool
    func allLabels() throws -> [String]
    func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags) throws
    func load(label: String, context: LAContext, prompt: String) throws -> Data?
    func remove(label: String, context: LAContext?, prompt: String) throws
}

public extension PrivateKeyStoring {
    func allLabels() throws -> [String] { [] }

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
    private let scope: KeychainScope
    private let addItem: (CFDictionary) -> OSStatus
    private let deleteItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: (CFDictionary) -> (OSStatus, AnyObject?)

    public convenience init(
        serviceName: String = KeychainManager.privateServiceName,
        scope: KeychainScope = .processDefault
    ) {
        self.init(
            serviceName: serviceName,
            scope: scope,
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
        scope: KeychainScope = .processDefault,
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
        self.scope = scope
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem
    }

    public func contains(label: String) -> Bool {
        if containsItem(baseLookup: lookup(label: label, serviceName: serviceName)) {
            return true
        }
        if case .dataProtection = scope {
            return containsItem(baseLookup: legacyLookup(label: label, serviceName: serviceName))
        }
        return false
    }

    private func containsItem(baseLookup: [String: Any]) -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        var query = baseLookup
        query.merge([
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        let (status, _) = copyItem(query as CFDictionary)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    public func allLabels() throws -> [String] {
        let context = LAContext()
        context.interactionNotAllowed = true
        let scopedLabels = try fetchLabels(query: allLabelsQuery(context: context))
        guard case .dataProtection = scope else {
            return scopedLabels
        }
        let legacyLabels = try fetchLabels(query: legacyAllLabelsQuery(context: context))
        var seen = Set<String>()
        var combined: [String] = []
        for label in scopedLabels + legacyLabels where seen.insert(label).inserted {
            combined.append(label)
        }
        return combined
    }

    private func allLabelsQuery(context: LAContext) -> [String: Any] {
        scope.applying(to: legacyAllLabelsQuery(context: context))
    }

    private func legacyAllLabelsQuery(context: LAContext) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationContext as String: context
        ]
    }

    private func fetchLabels(query: [String: Any]) throws -> [String] {
        let (status, result) = copyItem(query as CFDictionary)
        if status == errSecItemNotFound || status == errSecInteractionNotAllowed {
            return []
        }
        guard status == errSecSuccess else {
            throw PrivateKeyStoreError.keychain(status)
        }
        if let items = result as? [[String: Any]] {
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        }
        if let items = result as? [NSDictionary] {
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        }
        if let single = result as? [String: Any], let account = single[kSecAttrAccount as String] as? String {
            return [account]
        }
        if let single = result as? NSDictionary, let account = single[kSecAttrAccount as String] as? String {
            return [account]
        }
        return []
    }

    public func save(label: String, data: Data, accessControlFlags: SecAccessControlCreateFlags = [.userPresence]) throws {
        let lookup = lookup(label: label, serviceName: serviceName)

        // An empty flag set is reserved for an opaque Secure Enclave reference.
        // The hardware key itself owns the authentication policy; the reference
        // is device-bound metadata and contains no exportable private scalar.
        if accessControlFlags.isEmpty {
            let referenceUpdateAttributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrSynchronizable as String: false,
                kSecAttrDescription as String: "Clavis private key record",
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
            var referenceAddAttributes = lookup
            for (key, value) in referenceUpdateAttributes {
                referenceAddAttributes[key] = value
            }
            var saveStatus = updateItem(lookup as CFDictionary, referenceUpdateAttributes as CFDictionary)
            if saveStatus == errSecItemNotFound {
                saveStatus = addItem(referenceAddAttributes as CFDictionary)
                if saveStatus == errSecDuplicateItem {
                    saveStatus = updateItem(lookup as CFDictionary, referenceUpdateAttributes as CFDictionary)
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
        let protectedUpdateAttributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrSynchronizable as String: false,
            kSecAttrDescription as String: "Clavis private key record",
            kSecAttrAccessControl as String: accessControl
        ]
        var saveStatus = updateItem(lookup as CFDictionary, protectedUpdateAttributes as CFDictionary)
        if saveStatus == errSecItemNotFound {
            var protectedAddAttributes = lookup
            for (key, value) in protectedUpdateAttributes {
                protectedAddAttributes[key] = value
            }
            saveStatus = addItem(protectedAddAttributes as CFDictionary)
            if saveStatus == errSecDuplicateItem {
                saveStatus = updateItem(lookup as CFDictionary, protectedUpdateAttributes as CFDictionary)
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
        ClavisLogger.promptDebug("clavis-code", "PrivateKeyStore: loading private key '\(label)' with prompt \"\(prompt)\"")
        if !prompt.isEmpty {
            context.localizedReason = prompt
        }
        let (status, result) = loadItem(baseLookup: lookup(label: label, serviceName: serviceName), context: context)
        if status == errSecSuccess, let data = result as? Data {
            return data
        }
        if status == errSecItemNotFound {
            if case .dataProtection = scope {
                return try migrateLegacyItem(label: label, context: context, prompt: prompt)
            }
            return nil
        }
        throw PrivateKeyStoreError.keychain(status)
    }

    private func migrateLegacyItem(label: String, context: LAContext, prompt: String) throws -> Data? {
        let legacy = legacyLookup(label: label, serviceName: serviceName)
        guard var legacyData = try loadOwnedLegacyData(baseLookup: legacy, context: context) else {
            return nil
        }
        defer {
            legacyData.withUnsafeMutableBytes { ptr in
                if let baseAddress = ptr.baseAddress {
                    SecureMemory.zero(baseAddress, byteCount: ptr.count)
                }
            }
            legacyData.removeAll(keepingCapacity: false)
        }

        // Drain bridged NSData allocations from SecItemAdd/SecItemUpdate before defer wipes legacyData.
        try autoreleasepool {
            try save(label: label, data: legacyData, accessControlFlags: [])
        }

        var deleteQuery = legacy
        deleteQuery[kSecUseAuthenticationContext as String] = context
        _ = deleteItem(deleteQuery as CFDictionary)

        return legacyData.withUnsafeBytes { raw -> Data in
            guard let base = raw.baseAddress, !raw.isEmpty else { return Data() }
            return Data(bytes: base, count: raw.count)
        }
    }

    /// Reads the legacy Keychain item inside an autorelease pool and copies it into a
    /// uniquely owned Swift `Data` so the bridged `CFData`/`NSData` object is released
    /// immediately and `defer` zeroing operates on a dedicated buffer without CoW.
    private func loadOwnedLegacyData(baseLookup: [String: Any], context: LAContext) throws -> Data? {
        try autoreleasepool {
            let (status, result) = loadItem(baseLookup: baseLookup, context: context, suppressUI: true)
            if status == errSecItemNotFound || status == errSecInteractionNotAllowed || status == errSecAuthFailed {
                return nil
            }
            guard status == errSecSuccess, let bridged = result as? Data else {
                throw PrivateKeyStoreError.keychain(status)
            }
            return bridged.withUnsafeBytes { raw -> Data in
                guard let base = raw.baseAddress, !raw.isEmpty else { return Data() }
                return Data(bytes: base, count: raw.count)
            }
        }
    }

    public func remove(label: String, context: LAContext?, prompt: String) throws {
        ClavisLogger.promptDebug("clavis-code", "PrivateKeyStore: removing private key '\(label)' with prompt \"\(prompt)\"")
        if let context, !prompt.isEmpty {
            context.localizedReason = prompt
        }
        var query = lookup(label: label, serviceName: serviceName)
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        let status = deleteItem(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PrivateKeyStoreError.keychain(status)
        }
        if case .dataProtection = scope {
            var legacyQuery = legacyLookup(label: label, serviceName: serviceName)
            if let context {
                legacyQuery[kSecUseAuthenticationContext as String] = context
            }
            let legacyStatus = deleteItem(legacyQuery as CFDictionary)
            guard legacyStatus == errSecSuccess || legacyStatus == errSecItemNotFound else {
                throw PrivateKeyStoreError.keychain(legacyStatus)
            }
        }
    }

    private func loadItem(
        baseLookup: [String: Any],
        context: LAContext,
        suppressUI: Bool = false
    ) -> (OSStatus, AnyObject?) {
        var query = baseLookup
        query.merge([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        if suppressUI {
            // Suppress legacy SecurityAgent Keychain ACL prompts (`kSecUseAuthenticationUISkip`)
            // so inaccessible cross-team legacy items fall through to EncryptedVaultStore.
            query["u_AuthUI"] = "u_AuthUIS"
        }
        return copyItem(query as CFDictionary)
    }

    private func lookup(label: String, serviceName: String) -> [String: Any] {
        scope.applying(to: legacyLookup(label: label, serviceName: serviceName))
    }

    private func legacyLookup(label: String, serviceName: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: label
        ]
    }
}
