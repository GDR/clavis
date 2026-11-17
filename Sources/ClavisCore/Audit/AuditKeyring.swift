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
    private let scope: KeychainScope
    private let addItem: @Sendable (CFDictionary) -> OSStatus
    private let deleteItem: @Sendable (CFDictionary) -> OSStatus
    private let updateItem: @Sendable (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: @Sendable (CFDictionary) -> (OSStatus, AnyObject?)

    private let lock = NSLock()
    private var cachedPublicKey: AuditReadPublicKey?
    private var cachedMode: AuditReadMode?
    private var cacheGeneration: UInt64 = 0
    private var observer: NSObjectProtocol?

    public convenience init(
        service: String = KeychainAuditKeyring.defaultService,
        scope: KeychainScope = .processDefault
    ) {
        self.init(
            service: service,
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
        service: String,
        scope: KeychainScope = .processDefault,
        addItem: @escaping @Sendable (CFDictionary) -> OSStatus,
        deleteItem: @escaping @Sendable (CFDictionary) -> OSStatus,
        updateItem: @escaping @Sendable (CFDictionary, CFDictionary) -> OSStatus,
        copyItem: @escaping @Sendable (CFDictionary) -> (OSStatus, AnyObject?)
    ) {
        self.service = service
        self.scope = scope
        self.addItem = addItem
        self.deleteItem = deleteItem
        self.updateItem = updateItem
        self.copyItem = copyItem

        if !ClavisEnvironment.isTesting {
            self.observer = DistributedNotificationCenter.default().addObserver(
                forName: Self.notificationName,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                guard let self else { return }
                self.lock.lock()
                self.cachedPublicKey = nil
                self.cachedMode = nil
                self.cacheGeneration &+= 1
                self.lock.unlock()
            }
        }
    }

    deinit {
        if let observer = observer {
            DistributedNotificationCenter.default().removeObserver(observer)
        }
    }

    private func baseQuery(account: String? = nil) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if let account {
            query[kSecAttrAccount as String] = account
        }
        scope.apply(to: &query)
        return query
    }

    public func currentPublicKey() throws -> AuditReadPublicKey {
        lock.lock()
        if let cached = cachedPublicKey {
            lock.unlock()
            return cached
        }
        let capturedGeneration = cacheGeneration
        lock.unlock()

        guard let curData = readItemData(account: "current") else {
            return try createAndSetCurrentKey(mode: .passwordOrBiometry)
        }
        guard let keyID = String(data: curData, encoding: .utf8) else {
            throw AuditKeyringError.corruptedItem
        }

        let (key, mode) = try loadKeyItemWithMode(keyID: keyID)
        lock.lock()
        if cacheGeneration == capturedGeneration {
            cachedPublicKey = key
            cachedMode = mode
        }
        lock.unlock()
        return key
    }

    private func readItemData(account: String) -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = copyItem(query as CFDictionary)
        return status == errSecSuccess ? result as? Data : nil
    }

    private func loadKeyItemWithMode(keyID: String) throws -> (AuditReadPublicKey, AuditReadMode) {
        guard let data = readItemData(account: keyID) else {
            throw AuditKeyringError.keyNotFound(keyID)
        }
        guard let item = try? JSONDecoder().decode(AuditReadKeyItem.self, from: data),
              let pubData = Data(base64Encoded: item.publicKeyX963),
              let pubKey = try? P256.KeyAgreement.PublicKey(x963Representation: pubData) else {
            throw AuditKeyringError.corruptedItem
        }
        return (AuditReadPublicKey(keyID: item.keyID, publicKey: pubKey), item.mode)
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

        var itemQuery = baseQuery(account: keyID)
        itemQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        itemQuery[kSecValueData as String] = itemData
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
        lock.lock()
        do {
            let (keyItem, mode) = try loadKeyItemWithMode(keyID: keyID)

            let currentQuery = baseQuery(account: "current")
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

            cachedPublicKey = keyItem
            cachedMode = mode
            cacheGeneration &+= 1
        } catch {
            lock.unlock()
            throw error
        }
        lock.unlock()

        notifyKeyringChanged()
    }

    public func currentMode() throws -> AuditReadMode {
        lock.lock()
        if let cached = cachedMode {
            lock.unlock()
            return cached
        }
        let capturedGeneration = cacheGeneration
        lock.unlock()

        guard let curData = readItemData(account: "current"),
              let keyID = String(data: curData, encoding: .utf8) else {
            lock.lock()
            if cacheGeneration == capturedGeneration {
                cachedMode = .passwordOrBiometry
            }
            lock.unlock()
            return .passwordOrBiometry
        }
        guard let data = readItemData(account: keyID),
              let item = try? JSONDecoder().decode(AuditReadKeyItem.self, from: data) else {
            throw AuditKeyringError.corruptedItem
        }

        lock.lock()
        if cacheGeneration == capturedGeneration {
            cachedMode = item.mode
        }
        lock.unlock()
        return item.mode
    }

    public func deleteKey(keyID: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if let curData = readItemData(account: "current"),
           let curID = String(data: curData, encoding: .utf8),
           curID == keyID {
            throw AuditKeyringError.cannotDeleteCurrentKey
        }
        let delQuery = baseQuery(account: keyID)
        let status = deleteItem(delQuery as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw AuditKeyringError.keychainError(status)
        }
    }

    private func createAndSetCurrentKey(mode: AuditReadMode) throws -> AuditReadPublicKey {
        let (pubKey, keyID) = try generateAndStoreSEKey(mode: mode)

        lock.lock()
        var currentQuery = baseQuery(account: "current")
        currentQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        currentQuery[kSecValueData as String] = Data(keyID.utf8)
        let currentStatus = addItem(currentQuery as CFDictionary)
        if currentStatus == errSecDuplicateItem {
            let delQuery = baseQuery(account: keyID)
            _ = deleteItem(delQuery as CFDictionary)
            // Release lock before re-entering currentPublicKey() (NSLock is non-reentrant).
            lock.unlock()
            return try currentPublicKey()
        } else if currentStatus != errSecSuccess {
            lock.unlock()
            throw AuditKeyringError.keychainError(currentStatus)
        }

        cachedPublicKey = pubKey
        cachedMode = mode
        cacheGeneration &+= 1
        lock.unlock()

        notifyKeyringChanged()
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
        ClavisLogger.promptDebug("clavis-code", "AuditKeyring: performing ECDH key agreement for keyID '\(keyID)' (context: \(context != nil))")
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
        ClavisLogger.promptDebug("clavis-code", "AuditKeyring: validating current key (context: \(context != nil))")
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
        var query = baseQuery()
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        let (status, result) = copyItem(query as CFDictionary)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess,
              let items = (result as? [[String: Any]]) ?? (result as? [NSDictionary])?.compactMap({ $0 as? [String: Any] }) else {
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
        guard !ClavisEnvironment.isTesting else { return }
        DistributedNotificationCenter.default().postNotificationName(
            Self.notificationName,
            object: nil,
            userInfo: nil,
            deliverImmediately: false
        )
    }
}
