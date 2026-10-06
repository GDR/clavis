import Foundation
import CryptoKit
import LocalAuthentication
import Security

public enum AuditReadMode: String, Codable, Sendable {
    case passwordOrBiometry
    case biometryOrPIN
    case biometryAndPIN

    public var requiresPIN: Bool {
        self == .biometryOrPIN || self == .biometryAndPIN
    }
}

public func flags(for mode: AuditReadMode) -> SecAccessControlCreateFlags {
    switch mode {
    case .passwordOrBiometry:
        return [.privateKeyUsage, .userPresence]
    case .biometryOrPIN:
        return [.privateKeyUsage, .biometryAny, .or, .applicationPassword]
    case .biometryAndPIN:
        return [.privateKeyUsage, .biometryAny, .and, .applicationPassword]
    }
}

public func accessControl(for mode: AuditReadMode) throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        flags(for: mode),
        &error
    ) else {
        throw AuditKeyringError.accessControlFailed
    }
    return accessControl
}

public struct AuditReadPublicKey: Equatable, Sendable {
    public let keyID: String
    public let publicKey: P256.KeyAgreement.PublicKey

    public init(keyID: String, publicKey: P256.KeyAgreement.PublicKey) {
        self.keyID = keyID
        self.publicKey = publicKey
    }

    public static func == (lhs: AuditReadPublicKey, rhs: AuditReadPublicKey) -> Bool {
        lhs.keyID == rhs.keyID && lhs.publicKey.x963Representation == rhs.publicKey.x963Representation
    }
}

public enum AuditKeyringValidation: Equatable, Sendable {
    case ok
    case missing
    case mismatch
    case unusable
}

public struct AuditReadKeyItem: Codable, Equatable, Sendable {
    public let version: Int
    public let keyID: String
    public let publicKeyX963: String
    public let seBlob: String
    public let mode: AuditReadMode
    public let created: Date

    public init(
        version: Int = 1,
        keyID: String,
        publicKeyX963: String,
        seBlob: String,
        mode: AuditReadMode,
        created: Date = Date()
    ) {
        self.version = version
        self.keyID = keyID
        self.publicKeyX963 = publicKeyX963
        self.seBlob = seBlob
        self.mode = mode
        self.created = created
    }
}

public enum AuditKeyringError: Error, Equatable {
    case secureEnclaveUnavailable
    case keyNotFound(String)
    case corruptedItem
    case accessControlFailed
    case keychainError(OSStatus)
    case cannotDeleteCurrentKey
}

public protocol AuditKeyring: AnyObject, Sendable {
    func currentPublicKey() throws -> AuditReadPublicKey
    func agree(keyID: String, with peer: P256.KeyAgreement.PublicKey, context: LAContext?) throws -> SharedSecret
    func validateCurrent(context: LAContext?) -> AuditKeyringValidation
    func rotate(mode: AuditReadMode) throws -> AuditReadPublicKey
    func knownKeyIDs() throws -> [String]
    func accessControl(for mode: AuditReadMode) throws -> SecAccessControl
    func createKey(mode: AuditReadMode, context: LAContext?) throws -> AuditReadPublicKey
    func setCurrent(keyID: String) throws
    func currentMode() throws -> AuditReadMode
    func deleteKey(keyID: String) throws
}

extension AuditKeyring {
    public func accessControl(for mode: AuditReadMode) throws -> SecAccessControl {
        try ClavisCore.accessControl(for: mode)
    }
}

public final class KeychainAuditKeyring: AuditKeyring, @unchecked Sendable {
    public static let defaultService = "com.clavis.audit-read.v1"
    public static let notificationName = NSNotification.Name("com.clavis.auditKeyringChanged")

    private let service: String
    private let addItem: @Sendable (CFDictionary) -> OSStatus
    private let deleteItem: @Sendable (CFDictionary) -> OSStatus
    private let updateItem: @Sendable (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: @Sendable (CFDictionary) -> (OSStatus, AnyObject?)

    private let lock = NSLock()
    private var cachedPublicKey: AuditReadPublicKey?
    private var observer: NSObjectProtocol?

    public convenience init(service: String = KeychainAuditKeyring.defaultService) {
        self.init(
            service: service,
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
        service: String,
        addItem: @escaping @Sendable (CFDictionary) -> OSStatus,
        deleteItem: @escaping @Sendable (CFDictionary) -> OSStatus,
        updateItem: @escaping @Sendable (CFDictionary, CFDictionary) -> OSStatus,
        copyItem: @escaping @Sendable (CFDictionary) -> (OSStatus, AnyObject?)
    ) {
        self.service = service
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem

        if NSClassFromString("XCTestCase") == nil {
            self.observer = DistributedNotificationCenter.default().addObserver(
                forName: Self.notificationName,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                self?.lock.lock()
                self?.cachedPublicKey = nil
                self?.lock.unlock()
            }
        }
    }

    deinit {
        if let observer = observer {
            DistributedNotificationCenter.default().removeObserver(observer)
        }
    }

    public func currentPublicKey() throws -> AuditReadPublicKey {
        lock.lock()
        if let cached = cachedPublicKey {
            lock.unlock()
            return cached
        }
        lock.unlock()

        guard let curData = readItemData(account: "current") else {
            return try createAndSetCurrentKey(mode: .passwordOrBiometry)
        }
        guard let keyID = String(data: curData, encoding: .utf8) else {
            throw AuditKeyringError.corruptedItem
        }

        let key = try loadKeyItem(keyID: keyID)
        lock.lock()
        cachedPublicKey = key
        lock.unlock()
        return key
    }

    private func readItemData(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        let (status, result) = copyItem(query as CFDictionary)
        return status == errSecSuccess ? result as? Data : nil
    }

    private func loadKeyItem(keyID: String) throws -> AuditReadPublicKey {
        guard let data = readItemData(account: keyID) else {
            throw AuditKeyringError.keyNotFound(keyID)
        }
        guard let item = try? JSONDecoder().decode(AuditReadKeyItem.self, from: data),
              let pubData = Data(base64Encoded: item.publicKeyX963),
              let pubKey = try? P256.KeyAgreement.PublicKey(x963Representation: pubData) else {
            throw AuditKeyringError.corruptedItem
        }
        return AuditReadPublicKey(keyID: item.keyID, publicKey: pubKey)
    }

    private func generateAndStoreSEKey(mode: AuditReadMode, context: LAContext? = nil) throws -> (AuditReadPublicKey, String) {
        guard PlatformSupport.hasSecureEnclave else {
            throw AuditKeyringError.secureEnclaveUnavailable
        }

        let accessControl = try accessControl(for: mode)

        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let context = context {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: false,
                accessControl: accessControl,
                authenticationContext: context
            )
        } else {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: false,
                accessControl: accessControl
            )
        }
        let pubX963 = seKey.publicKey.x963Representation
        let hash = SHA256.hash(data: pubX963)
        let keyID = String(hash.map { String(format: "%02x", $0) }.joined().prefix(16))

        let item = AuditReadKeyItem(
            version: 1,
            keyID: keyID,
            publicKeyX963: pubX963.base64EncodedString(),
            seBlob: seKey.dataRepresentation.base64EncodedString(),
            mode: mode,
            created: Date()
        )
        let itemData = try JSONEncoder().encode(item)

        let itemQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyID,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: itemData
        ]
        let addStatus = addItem(itemQuery as CFDictionary)
        if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
            throw AuditKeyringError.keychainError(addStatus)
        }

        return (AuditReadPublicKey(keyID: keyID, publicKey: seKey.publicKey), keyID)
    }

    public func createKey(mode: AuditReadMode, context: LAContext?) throws -> AuditReadPublicKey {
        let (pubKey, _) = try generateAndStoreSEKey(mode: mode, context: context)
        return pubKey
    }

    public func setCurrent(keyID: String) throws {
        let keyItem = try loadKeyItem(keyID: keyID)

        let currentQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "current"
        ]
        let updateAttributes: [String: Any] = [
            kSecValueData as String: Data(keyID.utf8)
        ]
        let updateStatus = updateItem(currentQuery as CFDictionary, updateAttributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addCurrent = currentQuery
            addCurrent[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            addCurrent[kSecValueData as String] = Data(keyID.utf8)
            let addCurStatus = addItem(addCurrent as CFDictionary)
            if addCurStatus != errSecSuccess {
                throw AuditKeyringError.keychainError(addCurStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw AuditKeyringError.keychainError(updateStatus)
        }

        notifyKeyringChanged()
        lock.lock()
        cachedPublicKey = keyItem
        lock.unlock()
    }

    public func currentMode() throws -> AuditReadMode {
        guard let curData = readItemData(account: "current"),
              let keyID = String(data: curData, encoding: .utf8) else {
            return .passwordOrBiometry
        }
        guard let data = readItemData(account: keyID),
              let item = try? JSONDecoder().decode(AuditReadKeyItem.self, from: data) else {
            throw AuditKeyringError.corruptedItem
        }
        return item.mode
    }

    public func deleteKey(keyID: String) throws {
        if let curData = readItemData(account: "current"),
           let curID = String(data: curData, encoding: .utf8),
           curID == keyID {
            throw AuditKeyringError.cannotDeleteCurrentKey
        }
        let delQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyID
        ]
        let status = deleteItem(delQuery as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw AuditKeyringError.keychainError(status)
        }
    }

    private func createAndSetCurrentKey(mode: AuditReadMode) throws -> AuditReadPublicKey {
        let (pubKey, keyID) = try generateAndStoreSEKey(mode: mode)

        let currentQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "current",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(keyID.utf8)
        ]
        let currentStatus = addItem(currentQuery as CFDictionary)
        if currentStatus == errSecDuplicateItem {
            let delQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: keyID
            ]
            _ = deleteItem(delQuery as CFDictionary)
            return try currentPublicKey()
        } else if currentStatus != errSecSuccess {
            throw AuditKeyringError.keychainError(currentStatus)
        }

        notifyKeyringChanged()
        lock.lock()
        cachedPublicKey = pubKey
        lock.unlock()
        return pubKey
    }

    public func rotate(mode: AuditReadMode) throws -> AuditReadPublicKey {
        let (pubKey, keyID) = try generateAndStoreSEKey(mode: mode)
        try setCurrent(keyID: keyID)
        return pubKey
    }

    public func agree(
        keyID: String,
        with peer: P256.KeyAgreement.PublicKey,
        context: LAContext?
    ) throws -> SharedSecret {
        guard let data = readItemData(account: keyID) else {
            throw AuditKeyringError.keyNotFound(keyID)
        }
        guard let item = try? JSONDecoder().decode(AuditReadKeyItem.self, from: data),
              let seBlobData = Data(base64Encoded: item.seBlob) else {
            throw AuditKeyringError.corruptedItem
        }

        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let context = context {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: seBlobData,
                authenticationContext: context
            )
        } else {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: seBlobData
            )
        }
        return try seKey.sharedSecretFromKeyAgreement(with: peer)
    }

    public func validateCurrent(context: LAContext?) -> AuditKeyringValidation {
        guard let curData = readItemData(account: "current"),
              let keyID = String(data: curData, encoding: .utf8) else {
            return .missing
        }
        guard let data = readItemData(account: keyID),
              let item = try? JSONDecoder().decode(AuditReadKeyItem.self, from: data),
              let expectedPubData = Data(base64Encoded: item.publicKeyX963),
              let seBlobData = Data(base64Encoded: item.seBlob) else {
            return .unusable
        }

        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            if let context = context {
                seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: seBlobData,
                    authenticationContext: context
                )
            } else {
                seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: seBlobData
                )
            }
        } catch {
            return .unusable
        }

        return seKey.publicKey.x963Representation == expectedPubData ? .ok : .mismatch
    }

    public func knownKeyIDs() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        let (status, result) = copyItem(query as CFDictionary)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            throw AuditKeyringError.keychainError(status)
        }
        return items.compactMap { dict in
            guard let account = dict[kSecAttrAccount as String] as? String, account != "current" else {
                return nil
            }
            return account
        }
    }

    private func notifyKeyringChanged() {
        guard NSClassFromString("XCTestCase") == nil else { return }
        DistributedNotificationCenter.default().postNotificationName(
            Self.notificationName,
            object: nil,
            userInfo: nil,
            deliverImmediately: false
        )
    }
}
