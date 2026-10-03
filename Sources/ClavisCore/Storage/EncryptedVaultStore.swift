import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Hardware-bound encrypted shadow vault for stored private key records.
///
/// Prevents permanent loss of keys when macOS Keychain items are erased by third-party
/// processes using unauthenticated `SecItemDelete`. Envelopes are encrypted with a device-bound
/// P256 master key (protected by the Secure Enclave when available), requiring user presence
/// to decrypt and recover keys.
public final class EncryptedVaultStore: @unchecked Sendable {
    public static let shared = EncryptedVaultStore()
    public static var customVaultDirectoryURL: URL? = nil {
        didSet {
            #if DEBUG
            inMemoryPinStoreForTesting = InMemoryMasterKeyPinStore()
            #endif
        }
    }
    public static var customPinStore: MasterKeyPinStoring? = nil
    private static var inMemoryPinStoreForTesting: MasterKeyPinStoring = InMemoryMasterKeyPinStore()
    static var forceSoftwareMasterKeyForTesting: Bool = false

    public static func resetForTesting() {
        customPinStore = nil
        #if DEBUG
        inMemoryPinStoreForTesting = InMemoryMasterKeyPinStore()
        #endif
    }

    private static var allowSoftwareMasterKeyForTesting: Bool {
        #if DEBUG
        return forceSoftwareMasterKeyForTesting
        #else
        return false
        #endif
    }

    private let lock = NSLock()
    private let defaultPinStore: MasterKeyPinStoring

    public init(pinStore: MasterKeyPinStoring = KeychainMasterKeyPinStore()) {
        self.defaultPinStore = pinStore
    }

    private var activePinStore: MasterKeyPinStoring {
        if let custom = Self.customPinStore {
            return custom
        }
        #if DEBUG
        if Self.allowSoftwareMasterKeyForTesting {
            return Self.inMemoryPinStoreForTesting
        }
        #endif
        return defaultPinStore
    }

    public enum VaultError: LocalizedError, Equatable {
        case secureEnclaveRequired
        case softwareMasterKeyUnsupported
        case incompleteMasterKey
        case masterKeyTampered

        public var errorDescription: String? {
            switch self {
            case .secureEnclaveRequired:
                return "Secure Enclave is required to protect the Clavis recovery vault."
            case .softwareMasterKeyUnsupported:
                return "This vault uses an old software master key. Its files were preserved; migrate the vault before creating more keys."
            case .incompleteMasterKey:
                return "The recovery vault master key is incomplete or invalid. Its files were preserved."
            case .masterKeyTampered:
                return "The recovery vault master key has been tampered with or its Keychain pin is invalid."
            }
        }
    }

    public var vaultDirectoryURL: URL {
        if let custom = Self.customVaultDirectoryURL { return custom }
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis/vault", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return dir
    }

    private func labelHash(_ label: String) -> String {
        SHA256.hash(data: Data(label.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public func containsRecord(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let hash = labelHash(label)
        let fileURL = vaultDirectoryURL.appendingPathComponent("\(hash).enc")
        return FileManager.default.fileExists(atPath: fileURL.path)
    }

    private enum MasterPrivateKey {
        case secureEnclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
        case software(P256.KeyAgreement.PrivateKey)
    }

    /// Authenticates the master key on disk against the Keychain pin and validates that
    /// the public key derived from `master.key` matches `master.pub`.
    private func authenticateExistingMasterKey(
        context: LAContext? = nil
    ) throws -> (publicKey: P256.KeyAgreement.PublicKey, privateKey: MasterPrivateKey) {
        let pubURL = vaultDirectoryURL.appendingPathComponent("master.pub")
        let keyURL = vaultDirectoryURL.appendingPathComponent("master.key")

        let hasPublicKey = FileManager.default.fileExists(atPath: pubURL.path)
        let hasPrivateKey = FileManager.default.fileExists(atPath: keyURL.path)

        guard hasPublicKey && hasPrivateKey else {
            throw VaultError.incompleteMasterKey
        }

        let pubData = try Data(contentsOf: pubURL)
        guard (try? P256.KeyAgreement.PublicKey(rawRepresentation: pubData)) != nil else {
            throw VaultError.masterKeyTampered
        }

        let privateData = try Data(contentsOf: keyURL)
        guard let keyType = privateData.first else {
            throw VaultError.incompleteMasterKey
        }
        guard keyType == 0x01 || (keyType == 0x02 && Self.allowSoftwareMasterKeyForTesting) else {
            throw keyType == 0x02 ? VaultError.softwareMasterKeyUnsupported : VaultError.incompleteMasterKey
        }

        let keyBytes = Data(privateData.dropFirst())
        let derivedPubKey: P256.KeyAgreement.PublicKey
        let masterPrivate: MasterPrivateKey

        if keyType == 0x01 {
            let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
            do {
                if let context {
                    seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                        dataRepresentation: keyBytes,
                        authenticationContext: context
                    )
                } else {
                    seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                        dataRepresentation: keyBytes
                    )
                }
            } catch {
                throw VaultError.masterKeyTampered
            }
            derivedPubKey = seKey.publicKey
            masterPrivate = .secureEnclave(seKey)
        } else {
            let swKey: P256.KeyAgreement.PrivateKey
            do {
                swKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: keyBytes)
            } catch {
                throw VaultError.masterKeyTampered
            }
            derivedPubKey = swKey.publicKey
            masterPrivate = .software(swKey)
        }

        guard derivedPubKey.rawRepresentation == pubData else {
            throw VaultError.masterKeyTampered
        }

        // Verify pin in Keychain / pinStore
        guard let storedPin = try activePinStore.loadPin() else {
            // Missing pin with existing master files fails closed; never silently re-pin.
            throw VaultError.masterKeyTampered
        }
        let expectedPin = Data(SHA256.hash(data: pubData))
        guard storedPin == expectedPin else {
            throw VaultError.masterKeyTampered
        }

        return (derivedPubKey, masterPrivate)
    }

    public func ensureMasterKey() throws -> P256.KeyAgreement.PublicKey {
        guard PlatformSupport.hasSecureEnclave || Self.allowSoftwareMasterKeyForTesting else {
            throw VaultError.secureEnclaveRequired
        }
        try FileManager.default.createDirectory(at: vaultDirectoryURL, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])

        let pubURL = vaultDirectoryURL.appendingPathComponent("master.pub")
        let keyURL = vaultDirectoryURL.appendingPathComponent("master.key")

        let hasPublicKey = FileManager.default.fileExists(atPath: pubURL.path)
        let hasPrivateKey = FileManager.default.fileExists(atPath: keyURL.path)
        guard hasPublicKey == hasPrivateKey else {
            throw VaultError.incompleteMasterKey
        }
        if hasPublicKey {
            let (pubKey, _) = try authenticateExistingMasterKey()
            return pubKey
        }

        let useSE = !Self.allowSoftwareMasterKeyForTesting

        if useSE {
            let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage, .userPresence])
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: false,
                accessControl: accessControl
            )
            var keyFileBytes = Data([0x01])
            keyFileBytes.append(seKey.dataRepresentation)
            try keyFileBytes.write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

            let pubData = seKey.publicKey.rawRepresentation
            try pubData.write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubURL.path)

            let pin = Data(SHA256.hash(data: pubData))
            do {
                try activePinStore.savePin(pin)
            } catch {
                try? FileManager.default.removeItem(at: keyURL)
                try? FileManager.default.removeItem(at: pubURL)
                throw error
            }
            return seKey.publicKey
        } else {
            let swKey = P256.KeyAgreement.PrivateKey()
            var keyFileBytes = Data([0x02])
            keyFileBytes.append(swKey.rawRepresentation)
            try keyFileBytes.write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

            let pubData = swKey.publicKey.rawRepresentation
            try pubData.write(to: pubURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubURL.path)

            let pin = Data(SHA256.hash(data: pubData))
            do {
                try activePinStore.savePin(pin)
            } catch {
                try? FileManager.default.removeItem(at: keyURL)
                try? FileManager.default.removeItem(at: pubURL)
                throw error
            }
            return swKey.publicKey
        }
    }

    /// Envelope formats. `CLVENV01` is rejected; `CLVENV02` authenticates the format
    /// and the record label, so a ciphertext file cannot be moved to another label's slot.
    private static let legacyMagic = Data("CLVENV01".utf8)
    private static let currentMagic = Data("CLVENV02".utf8)

    private static func associatedData(label: String) -> Data {
        var aad = Data("clavis-vault-record-v2".utf8)
        aad.append(0)
        aad.append(Data(label.utf8))
        return aad
    }

    public func saveRecord(_ record: StoredPrivateKeyRecord) throws {
        lock.lock()
        defer { lock.unlock() }
        try writeRecordLocked(record)
    }

    /// Caller must hold `lock`.
    private func writeRecordLocked(_ record: StoredPrivateKeyRecord) throws {
        let masterPubKey = try ensureMasterKey()
        let recordBytes = try record.encode()

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(with: masterPubKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.publicKey.rawRepresentation,
            sharedInfo: Data("clavis-vault-envelope-v1".utf8),
            outputByteCount: 32
        )

        let sealed = try ChaChaPoly.seal(
            recordBytes,
            using: symmetricKey,
            authenticating: Self.associatedData(label: record.label)
        )
        let epkRaw = ephemeral.publicKey.rawRepresentation
        guard epkRaw.count <= 255 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Ephemeral public key too large"])
        }

        var envelope = Self.currentMagic
        envelope.append(UInt8(epkRaw.count))
        envelope.append(epkRaw)
        envelope.append(sealed.combined)

        let hash = labelHash(record.label)
        let fileURL = vaultDirectoryURL.appendingPathComponent("\(hash).enc")
        try envelope.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    public func removeRecord(label: String) {
        lock.lock()
        defer { lock.unlock() }
        let hash = labelHash(label)
        let fileURL = vaultDirectoryURL.appendingPathComponent("\(hash).enc")
        try? FileManager.default.removeItem(at: fileURL)
    }

    public func loadRecord(label: String, context: LAContext? = nil) throws -> StoredPrivateKeyRecord? {
        guard PlatformSupport.hasSecureEnclave || Self.allowSoftwareMasterKeyForTesting else {
            throw VaultError.secureEnclaveRequired
        }
        lock.lock()
        defer { lock.unlock() }

        let hash = labelHash(label)
        let fileURL = vaultDirectoryURL.appendingPathComponent("\(hash).enc")
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)
        return try decryptEnvelope(data, label: label, context: context)
    }

    private func decryptEnvelope(
        _ data: Data,
        label: String,
        context: LAContext?
    ) throws -> StoredPrivateKeyRecord {
        guard !data.starts(with: Self.legacyMagic) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Legacy vault envelope format CLVENV01 is rejected"])
        }
        guard data.starts(with: Self.currentMagic), data.count > Self.currentMagic.count + 1 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid vault envelope format"])
        }

        var offset = Self.currentMagic.count
        let epkLen = Int(data[offset])
        offset += 1

        guard data.count >= offset + epkLen else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Truncated vault envelope"])
        }

        let epkData = data.subdata(in: offset..<offset + epkLen)
        offset += epkLen
        let ciphertext = data.subdata(in: offset..<data.count)

        let ephemeralPubKey = try P256.KeyAgreement.PublicKey(rawRepresentation: epkData)

        let (_, masterPrivateKey) = try authenticateExistingMasterKey(context: context)

        let sharedSecret: SharedSecret
        switch masterPrivateKey {
        case .secureEnclave(let seKey):
            sharedSecret = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        case .software(let swKey):
            sharedSecret = try swKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        }

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: epkData,
            sharedInfo: Data("clavis-vault-envelope-v1".utf8),
            outputByteCount: 32
        )

        let sealed = try ChaChaPoly.SealedBox(combined: ciphertext)
        let decrypted = try ChaChaPoly.open(
            sealed,
            using: symmetricKey,
            authenticating: Self.associatedData(label: label)
        )
        return try StoredPrivateKeyRecord.decode(from: decrypted)
    }
}

public protocol MasterKeyPinStoring: Sendable {
    func loadPin() throws -> Data?
    func savePin(_ pin: Data) throws
    func removePin() throws
}

public final class InMemoryMasterKeyPinStore: MasterKeyPinStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var pin: Data?

    public init(pin: Data? = nil) {
        self.pin = pin
    }

    public func loadPin() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return pin
    }

    public func savePin(_ pin: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        self.pin = pin
    }

    public func removePin() throws {
        lock.lock()
        defer { lock.unlock() }
        self.pin = nil
    }
}

public enum MasterKeyPinStoreError: LocalizedError, Equatable {
    case keychain(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown Keychain error"
            return "Master key pin Keychain operation failed (\(status)): \(message)"
        }
    }
}

public final class KeychainMasterKeyPinStore: MasterKeyPinStoring, @unchecked Sendable {
    public static let serviceName = "com.clavis.vault-master-pin.v1"
    public static let accountName = "master-key-pin"

    private let service: String
    private let account: String
    private let addItem: @Sendable (CFDictionary) -> OSStatus
    private let deleteItem: @Sendable (CFDictionary) -> OSStatus
    private let updateItem: @Sendable (CFDictionary, CFDictionary) -> OSStatus
    private let copyItem: @Sendable (CFDictionary) -> (OSStatus, AnyObject?)

    public convenience init(
        service: String = KeychainMasterKeyPinStore.serviceName,
        account: String = KeychainMasterKeyPinStore.accountName
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
        service: String,
        account: String,
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

    public func loadPin() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        let (status, result) = copyItem(query as CFDictionary)
        if status == errSecSuccess, let data = result as? Data {
            return data
        }
        if status == errSecItemNotFound {
            return nil
        }
        throw MasterKeyPinStoreError.keychain(status)
    }

    public func savePin(_ pin: Data) throws {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: pin,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
            kSecAttrDescription as String: "Clavis vault master key pin"
        ]
        var status = updateItem(lookup as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = lookup
            for (key, value) in attributes { item[key] = value }
            status = addItem(item as CFDictionary)
            if status == errSecDuplicateItem {
                status = updateItem(lookup as CFDictionary, attributes as CFDictionary)
            }
        }
        guard status == errSecSuccess else {
            throw MasterKeyPinStoreError.keychain(status)
        }
    }

    public func removePin() throws {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = deleteItem(lookup as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw MasterKeyPinStoreError.keychain(status)
        }
    }
}

