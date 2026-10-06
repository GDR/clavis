import Foundation
import Security

public struct PinAttemptState: Codable, Equatable, Sendable {
    public var version: Int
    public var attempts: Int
    public var lastAttemptAt: Double

    public init(version: Int = 1, attempts: Int, lastAttemptAt: Double) {
        self.version = version
        self.attempts = attempts
        self.lastAttemptAt = lastAttemptAt
    }
}

public enum PinAttemptError: Error, Equatable, Sendable {
    case missing
    case corrupt
    case writeFailed
}

public protocol PinAttemptStoring: AnyObject, Sendable {
    func load() throws -> PinAttemptState
    func save(_ state: PinAttemptState) throws
    func delete() throws
}

public final class KeychainPinAttemptStore: PinAttemptStoring, @unchecked Sendable {
    public static let defaultService = "com.clavis.pin-attempts.v1"
    public static let defaultAccount = "panel"

    private let service: String
    private let account: String
    private let addItem: @Sendable (CFDictionary) -> OSStatus
    private let deleteItem: @Sendable (CFDictionary) -> OSStatus
    private let updateItem: @Sendable (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: @Sendable (CFDictionary) -> (OSStatus, AnyObject?)

    public convenience init(
        service: String = KeychainPinAttemptStore.defaultService,
        account: String = KeychainPinAttemptStore.defaultAccount
    ) {
        self.init(
            service: service,
            account: account,
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
        service: String = KeychainPinAttemptStore.defaultService,
        account: String = KeychainPinAttemptStore.defaultAccount,
        addItem: @escaping @Sendable (CFDictionary) -> OSStatus,
        deleteItem: @escaping @Sendable (CFDictionary) -> OSStatus,
        updateItem: @escaping @Sendable (CFDictionary, CFDictionary) -> OSStatus,
        copyItem: @escaping @Sendable (CFDictionary) -> (OSStatus, AnyObject?)
    ) {
        self.service = service
        self.account = account
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem
    }

    public func load() throws -> PinAttemptState {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        let (status, result) = copyItem(query as CFDictionary)
        if status == errSecItemNotFound {
            throw PinAttemptError.missing
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw PinAttemptError.corrupt
        }
        do {
            return try JSONDecoder().decode(PinAttemptState.self, from: data)
        } catch {
            throw PinAttemptError.corrupt
        }
    }

    public func save(_ state: PinAttemptState) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(state)
        } catch {
            throw PinAttemptError.writeFailed
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let updateAttributes: [String: Any] = [
            kSecValueData as String: data
        ]
        let updateStatus = updateItem(query as CFDictionary, updateAttributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            addQuery[kSecValueData as String] = data
            let addStatus = addItem(addQuery as CFDictionary)
            if addStatus != errSecSuccess {
                throw PinAttemptError.writeFailed
            }
        } else if updateStatus != errSecSuccess {
            throw PinAttemptError.writeFailed
        }
    }

    public func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = deleteItem(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw PinAttemptError.writeFailed
        }
    }
}

public enum PinAttemptPolicy {
    public static let backoffAfter = 3
    public static let disableAfter = 10

    public enum Decision: Equatable, Sendable {
        case allowed
        case wait(TimeInterval)
        case passwordRequired
    }

    public static func decide(_ state: PinAttemptState?, now: Date = Date()) -> Decision {
        guard let state = state else {
            return .passwordRequired
        }
        if state.attempts >= disableAfter {
            return .passwordRequired
        }
        if state.attempts >= backoffAfter {
            let exponent = Double(state.attempts - backoffAfter)
            let waitDuration = min(30.0 * pow(2.0, exponent), 3600.0)
            let elapsed = now.timeIntervalSince1970 - state.lastAttemptAt
            let remaining = waitDuration - elapsed
            if remaining > 0 {
                return .wait(remaining)
            }
        }
        return .allowed
    }
}
