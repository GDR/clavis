import Foundation
import Security

/// One device-local Keychain item; no allow-by-default classification on read errors.
public final class KeychainApplicationRegistry: ApplicationRegistryStoring, @unchecked Sendable {
    public static let shared = KeychainApplicationRegistry()
    private let lock = NSLock()
    private let service: String
    private let copyItem: (CFDictionary) -> (OSStatus, AnyObject?)
    private let addItem: (CFDictionary) -> OSStatus
    private let updateItem: (CFDictionary, CFDictionary) -> OSStatus

    public init(
        service: String = "com.clavis.application-registry.v1",
        copyItem: @escaping (CFDictionary) -> (OSStatus, AnyObject?) = { query in
            var value: CFTypeRef?
            let status = SecItemCopyMatching(query, &value)
            return (status, value)
        },
        addItem: @escaping (CFDictionary) -> OSStatus = { SecItemAdd($0, nil) },
        updateItem: @escaping (CFDictionary, CFDictionary) -> OSStatus = { SecItemUpdate($0, $1) }
    ) {
        self.service = service
        self.copyItem = copyItem
        self.addItem = addItem
        self.updateItem = updateItem
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "registry"]
    }

    private func readLocked() throws -> ApplicationRegistrySnapshot? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = copyItem(request as CFDictionary)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ApplicationRegistryError.persistence(status) }
        guard let data = value as? Data, data.count <= 10_000_000 else {
            throw ApplicationRegistryError.corrupt
        }
        let snapshot = try JSONDecoder().decode(ApplicationRegistrySnapshot.self, from: data)
        try snapshot.validate()
        return snapshot
    }

    public func load() throws -> ApplicationRegistrySnapshot {
        lock.lock()
        defer { lock.unlock() }
        if let existing = try readLocked() { return existing }
        // Persist the empty revision so simultaneous first-use mutations cannot
        // silently overwrite one another. Duplicate creation is reread below.
        let initial = ApplicationRegistrySnapshot()
        let status = try insert(initial)
        if status == errSecDuplicateItem, let existing = try readLocked() { return existing }
        guard status == errSecSuccess else { throw ApplicationRegistryError.persistence(status) }
        return initial
    }

    private func insert(_ snapshot: ApplicationRegistrySnapshot) throws -> OSStatus {
        var item = query
        item[kSecValueData as String] = try JSONEncoder().encode(snapshot)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return addItem(item as CFDictionary)
    }

    public func save(_ snapshot: ApplicationRegistrySnapshot, replacing revision: UUID) throws {
        try snapshot.validate()
        lock.lock()
        defer { lock.unlock() }
        guard let current = try readLocked(), current.revision == revision,
              snapshot.revision != revision else { throw ApplicationRegistryError.staleRevision }
        let data = try JSONEncoder().encode(snapshot)
        let status = updateItem(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        guard status == errSecSuccess else { throw ApplicationRegistryError.persistence(status) }
    }
}
