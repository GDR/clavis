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
    internal static var customVaultDirectoryURL: URL? = nil {
        didSet {
            #if DEBUG
            inMemoryPinStoreForTesting = InMemoryMasterKeyPinStore()
            #endif
        }
    }
    #if DEBUG
    private static var _staticCustomPinStore: (any MasterKeyPinStoring)? = nil
    private static let customPinStoreLock = NSLock()
    internal static var customPinStore: (any MasterKeyPinStoring)? {
        get {
            if let context = TestContextScope.current {
                if let override = context.pinStoreBox.override {
                    return override
                }
            }
            customPinStoreLock.lock()
            defer { customPinStoreLock.unlock() }
            return _staticCustomPinStore
        }
        set {
            if let context = TestContextScope.current {
                context.pinStoreBox.override = newValue
                return
            }
            customPinStoreLock.lock()
            defer { customPinStoreLock.unlock() }
            _staticCustomPinStore = newValue
        }
    }
    #else
    internal static var customPinStore: MasterKeyPinStoring? = nil
    #endif

    internal static var customKeyAgreementProvider: SecureEnclaveKeyAgreementProviding? = nil
    private static let lockSettingsLock = NSLock()
    private static var _staticMasterKeyLockTimeout: TimeInterval = 10.0
    private static var _staticMasterKeyLockPollInterval: useconds_t = 50_000

    internal static var masterKeyLockTimeout: TimeInterval {
        get {
            #if DEBUG
            if let context = TestContextScope.current {
                if let override = context.masterKeyLockTimeoutBox.override {
                    return override
                }
            }
            #endif
            lockSettingsLock.lock()
            defer { lockSettingsLock.unlock() }
            return _staticMasterKeyLockTimeout
        }
        set {
            #if DEBUG
            if let context = TestContextScope.current {
                context.masterKeyLockTimeoutBox.override = newValue
                return
            }
            #endif
            lockSettingsLock.lock()
            defer { lockSettingsLock.unlock() }
            _staticMasterKeyLockTimeout = newValue
        }
    }

    internal static var masterKeyLockPollInterval: useconds_t {
        get {
            #if DEBUG
            if let context = TestContextScope.current {
                if let override = context.masterKeyLockPollIntervalBox.override {
                    return override
                }
            }
            #endif
            lockSettingsLock.lock()
            defer { lockSettingsLock.unlock() }
            return _staticMasterKeyLockPollInterval
        }
        set {
            #if DEBUG
            if let context = TestContextScope.current {
                context.masterKeyLockPollIntervalBox.override = newValue
                return
            }
            #endif
            lockSettingsLock.lock()
            defer { lockSettingsLock.unlock() }
            _staticMasterKeyLockPollInterval = newValue
        }
    }
    private static var inMemoryPinStoreForTesting: MasterKeyPinStoring = InMemoryMasterKeyPinStore()
    #if DEBUG
    private static var _staticIsSecureEnclaveAvailableOverride: Bool? = nil
    private static let isSecureEnclaveLock = NSLock()
    internal static var isSecureEnclaveAvailableOverride: Bool? {
        get {
            if let context = TestContextScope.current {
                if let override = context.secureEnclaveOverrideBox.override {
                    return override
                }
            }
            isSecureEnclaveLock.lock()
            defer { isSecureEnclaveLock.unlock() }
            return _staticIsSecureEnclaveAvailableOverride
        }
        set {
            if let context = TestContextScope.current {
                context.secureEnclaveOverrideBox.override = newValue
                return
            }
            isSecureEnclaveLock.lock()
            defer { isSecureEnclaveLock.unlock() }
            _staticIsSecureEnclaveAvailableOverride = newValue
        }
    }
    #endif

    public static var isSecureEnclaveAvailable: Bool {
        #if DEBUG
        if let context = TestContextScope.current {
            if let override = context.secureEnclaveOverrideBox.override {
                return override
            }
            if context.keyAgreementProvider != nil {
                return true
            }
        }
        if let override = isSecureEnclaveAvailableOverride {
            return override
        }
        if customKeyAgreementProvider != nil {
            return true
        }
        #endif
        return SecureEnclave.isAvailable
    }

    public static func resetForTesting() {
        customPinStore = nil
        customKeyAgreementProvider = nil
        lockSettingsLock.lock()
        _staticMasterKeyLockTimeout = 10.0
        _staticMasterKeyLockPollInterval = 50_000
        lockSettingsLock.unlock()
        #if DEBUG
        inMemoryPinStoreForTesting = InMemoryMasterKeyPinStore()
        isSecureEnclaveAvailableOverride = nil
        customPinStoreLock.lock()
        _staticCustomPinStore = nil
        customPinStoreLock.unlock()
        isSecureEnclaveLock.lock()
        _staticIsSecureEnclaveAvailableOverride = nil
        isSecureEnclaveLock.unlock()
        #endif
    }

    /// Re-entrant lock for in-process thread serialization (allows methods like `saveRecord`
    /// that already hold `lock` to call `ensureMasterKey` without self-deadlock).
    private let lock = NSRecursiveLock()
    private let customInstanceVaultDirectoryURL: URL?
    private let injectedPinStore: MasterKeyPinStoring?
    private let injectedKeyAgreementProvider: SecureEnclaveKeyAgreementProviding?
    private let defaultPinStore: MasterKeyPinStoring
    private let defaultKeyAgreementProvider: SecureEnclaveKeyAgreementProviding
    private let defaultInstanceVaultDirectoryURL: URL

    public init(
        vaultDirectoryURL: URL? = nil,
        pinStore: MasterKeyPinStoring? = nil,
        keyAgreementProvider: SecureEnclaveKeyAgreementProviding? = nil
    ) {
        self.customInstanceVaultDirectoryURL = vaultDirectoryURL
        self.injectedPinStore = pinStore
        self.injectedKeyAgreementProvider = keyAgreementProvider
        if ClavisEnvironment.isTesting {
            self.defaultPinStore = InMemoryMasterKeyPinStore()
            self.defaultKeyAgreementProvider = InMemorySecureEnclaveKeyAgreementProvider()
            self.defaultInstanceVaultDirectoryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("clavis-vault-\(UUID().uuidString)", isDirectory: true)
        } else {
            self.defaultPinStore = KeychainMasterKeyPinStore()
            self.defaultKeyAgreementProvider = ProductionSecureEnclaveKeyAgreementProvider()
            let home = FileManager.default.homeDirectoryForCurrentUser
            self.defaultInstanceVaultDirectoryURL = home.appendingPathComponent(".config/clavis/vault", isDirectory: true)
        }
    }

    deinit {
        #if DEBUG
        if ClavisEnvironment.isTesting && customInstanceVaultDirectoryURL == nil {
            try? FileManager.default.removeItem(at: defaultInstanceVaultDirectoryURL)
        }
        #endif
    }

    var activePinStore: MasterKeyPinStoring {
        if let injected = injectedPinStore {
            return injected
        }
        #if DEBUG
        if let context = TestContextScope.current {
            if let override = context.pinStoreBox.override {
                return override
            }
            if let pinStore = context.pinStore {
                return pinStore
            }
            if context.keyAgreementProvider != nil {
                return context.inMemoryPinStore
            }
        }
        if let custom = Self.customPinStore {
            return custom
        }
        #endif
        return defaultPinStore
    }

    var activeKeyAgreementProvider: SecureEnclaveKeyAgreementProviding {
        if let injected = injectedKeyAgreementProvider {
            return injected
        }
        #if DEBUG
        if let context = TestContextScope.current, let provider = context.keyAgreementProvider {
            return provider
        }
        if let custom = Self.customKeyAgreementProvider {
            return custom
        }
        #endif
        return defaultKeyAgreementProvider
    }

    public enum VaultError: LocalizedError, Equatable {
        case secureEnclaveRequired
        case incompleteMasterKey
        case masterKeyTampered
        case masterKeyPinMissing
        case softwareKeyStorageProhibited

        public var errorDescription: String? {
            switch self {
            case .secureEnclaveRequired:
                return "Secure Enclave is required to protect the Clavis recovery vault."
            case .incompleteMasterKey:
                return "The recovery vault master key is incomplete or invalid. Its files were preserved. Run 'clavis vault repair' if files are intact."
            case .masterKeyTampered:
                return "The recovery vault master key has been tampered with or its Keychain pin is invalid. If this was intentional or the pin was modified, run 'clavis vault repair --replace-pin'."
            case .masterKeyPinMissing:
                return "The recovery vault master key pin is missing from Keychain. Run 'clavis vault repair' to restore it."
            case .softwareKeyStorageProhibited:
                return "Software private keys cannot be stored in the recovery vault."
            }
        }
    }

    public var vaultDirectoryURL: URL {
        if let custom = customInstanceVaultDirectoryURL {
            try? SecureFS.createDirectory(at: custom)
            return custom
        }
        #if DEBUG
        if let context = TestContextScope.current {
            let dir = context.vaultDirectoryURL
            try? SecureFS.createDirectory(at: dir)
            return dir
        }
        if let custom = Self.customVaultDirectoryURL { return custom }
        if ClavisEnvironment.isTesting {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("clavis-test-vault-\(getpid())", isDirectory: true)
            try? SecureFS.createDirectory(at: dir)
            return dir
        }
        #endif
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".config/clavis/vault", isDirectory: true)
        try? SecureFS.createDirectory(at: dir)
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

    /// Reads and verifies master key files on disk (both exist, format is 0x01, derived pub matches master.pub).
    /// Does not check pinStore so repair can inspect and fix missing/mismatched pins.
    private func readAndVerifyMasterKeyFiles(
        context: LAContext? = nil
    ) throws -> (publicKey: P256.KeyAgreement.PublicKey, keyBytes: Data) {
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
        guard keyType == 0x01 else {
            throw VaultError.incompleteMasterKey
        }

        let keyBytes = Data(privateData.dropFirst())
        let derivedPubKey: P256.KeyAgreement.PublicKey

        do {
            derivedPubKey = try activeKeyAgreementProvider.derivePublicKey(
                dataRepresentation: keyBytes,
                context: context
            )
        } catch {
            throw VaultError.masterKeyTampered
        }

        guard derivedPubKey.rawRepresentation == pubData else {
            throw VaultError.masterKeyTampered
        }

        return (derivedPubKey, keyBytes)
    }

    /// Authenticates the master key on disk against the Keychain pin and validates that
    /// the public key derived from `master.key` matches `master.pub`.
    private func authenticateExistingMasterKey(
        context: LAContext? = nil
    ) throws -> (publicKey: P256.KeyAgreement.PublicKey, keyBytes: Data) {
        let (derivedPubKey, keyBytes) = try readAndVerifyMasterKeyFiles(context: context)

        // Verify pin in Keychain / pinStore
        let pubURL = vaultDirectoryURL.appendingPathComponent("master.pub")
        let pubData = try Data(contentsOf: pubURL)
        guard let storedPin = try activePinStore.loadPin() else {
            // Missing pin with existing master files fails closed; never silently re-pin.
            throw VaultError.masterKeyPinMissing
        }
        let expectedPin = Data(SHA256.hash(data: pubData))
        guard storedPin == expectedPin else {
            throw VaultError.masterKeyTampered
        }

        return (derivedPubKey, keyBytes)
    }

    public func ensureMasterKey() throws -> P256.KeyAgreement.PublicKey {
        guard Self.isSecureEnclaveAvailable else {
            throw VaultError.secureEnclaveRequired
        }
        try SecureFS.createDirectory(at: vaultDirectoryURL)
        guard SecureFS.isDirectorySecure(at: vaultDirectoryURL) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Insecure vault directory permissions"])
        }

        let pubURL = vaultDirectoryURL.appendingPathComponent("master.pub")
        let keyURL = vaultDirectoryURL.appendingPathComponent("master.key")

        // Fast path: if both master.pub and master.key exist, authenticate and return
        // WITHOUT taking the file lock (do not hold flock across Touch ID).
        if FileManager.default.fileExists(atPath: pubURL.path) && FileManager.default.fileExists(atPath: keyURL.path) {
            let (pubKey, _) = try authenticateExistingMasterKey()
            return pubKey
        }

        return try ensureMasterKeyLocked()
    }

    @discardableResult
    public func ensureMasterKeyLocked() throws -> P256.KeyAgreement.PublicKey {
        // Lock order: in-process lock first, then advisory file lock.
        lock.lock()
        defer { lock.unlock() }

        guard Self.isSecureEnclaveAvailable else {
            throw VaultError.secureEnclaveRequired
        }
        try SecureFS.createDirectory(at: vaultDirectoryURL)
        guard SecureFS.isDirectorySecure(at: vaultDirectoryURL) else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Insecure vault directory permissions"])
        }

        let pubURL = vaultDirectoryURL.appendingPathComponent("master.pub")
        let keyURL = vaultDirectoryURL.appendingPathComponent("master.key")

        // Double-check after acquiring in-process lock.
        if FileManager.default.fileExists(atPath: pubURL.path) && FileManager.default.fileExists(atPath: keyURL.path) {
            let (pubKey, _) = try authenticateExistingMasterKey()
            return pubKey
        }

        let lockFileURL = vaultDirectoryURL.appendingPathComponent(".master.lock")
        let lockFd = SecureFS.openLockFile(path: lockFileURL.path, flags: O_CREAT | O_RDWR, mode: 0o600)
        guard lockFd >= 0 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to open master lock file: errno \(errno)"])
        }

        // Poll LOCK_EX | LOCK_NB every 50ms for at most masterKeyLockTimeout.
        let start = Date()
        var acquired = false
        while true {
            if flock(lockFd, LOCK_EX | LOCK_NB) == 0 {
                acquired = true
                break
            }
            if errno != EWOULDBLOCK && errno != EAGAIN {
                close(lockFd)
                throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to lock master lock file: errno \(errno)"])
            }
            if Date().timeIntervalSince(start) >= Self.masterKeyLockTimeout {
                break
            }
            usleep(Self.masterKeyLockPollInterval)
            if Date().timeIntervalSince(start) >= Self.masterKeyLockTimeout {
                if flock(lockFd, LOCK_EX | LOCK_NB) == 0 {
                    acquired = true
                }
                break
            }
        }

        guard acquired else {
            close(lockFd)
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Another Clavis process is creating the vault master key."])
        }

        // Re-check hasPublicKey/hasPrivateKey after acquiring lock.
        let hasPublicKey = FileManager.default.fileExists(atPath: pubURL.path)
        let hasPrivateKey = FileManager.default.fileExists(atPath: keyURL.path)

        // If another process created them in the meantime, release flock and take authenticate path.
        if hasPublicKey && hasPrivateKey {
            flock(lockFd, LOCK_UN)
            close(lockFd)
            let (pubKey, _) = try authenticateExistingMasterKey()
            return pubKey
        }

        guard hasPublicKey == hasPrivateKey else {
            flock(lockFd, LOCK_UN)
            close(lockFd)
            throw VaultError.incompleteMasterKey
        }

        // Otherwise create master key (pin-then-files with rollback), then unlock and close fd in defer.
        defer {
            flock(lockFd, LOCK_UN)
            close(lockFd)
        }

        // Refuse to silently generate a new master key and overwrite an existing valid pin
        // when master.pub / master.key were deleted from disk.
        if try activePinStore.loadPin() != nil {
            throw VaultError.masterKeyTampered
        }

        let accessControl = try PrivateKeyAccessControl.make(flags: [.privateKeyUsage, .userPresence])
        let (dataRepresentation, pubKey) = try activeKeyAgreementProvider.generateMasterKey(accessControl: accessControl)
        let pubData = pubKey.rawRepresentation
        let pin = Data(SHA256.hash(data: pubData))
        try activePinStore.savePin(pin)

        do {
            try SecureFS.withUmask(0o077) {
                var keyFileBytes = Data([0x01])
                keyFileBytes.append(dataRepresentation)
                try keyFileBytes.write(to: keyURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)

                try pubData.write(to: pubURL, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubURL.path)
            }
        } catch {
            try? activePinStore.removePin()
            try? FileManager.default.removeItem(at: keyURL)
            try? FileManager.default.removeItem(at: pubURL)
            throw error
        }
        return pubKey
    }

    /// Verifies that `master.key` and `master.pub` exist on disk, public key parses,
    /// and that the private key derives a public key matching `master.pub`.
    /// Performs an ECDH key agreement with a fresh ephemeral key under userPresence.
    public func verifyMasterKey(
        context: LAContext? = nil
    ) throws -> (publicKey: P256.KeyAgreement.PublicKey, fingerprint: String) {
        lock.lock()
        defer { lock.unlock() }

        let (derivedPubKey, keyBytes) = try readAndVerifyMasterKeyFiles(context: context)

        // Perform ECDH with a fresh ephemeral key under userPresence
        do {
            let ephemeral = P256.KeyAgreement.PrivateKey()
            _ = try activeKeyAgreementProvider.sharedSecret(
                dataRepresentation: keyBytes,
                with: ephemeral.publicKey,
                context: context
            )
        } catch {
            throw VaultError.masterKeyTampered
        }

        let fingerprint = Self.fingerprint(forPin: Data(SHA256.hash(data: derivedPubKey.rawRepresentation)))
        return (derivedPubKey, fingerprint)
    }

    /// Renders a master key pin (SHA-256 of `master.pub`) as `SHA256:<base64 without padding>`.
    public static func fingerprint(forPin pin: Data) -> String {
        "SHA256:" + pin.base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    /// Repairs the Keychain pin for an existing vault master key on disk.
    /// If an existing pin is found that does not match `master.pub`, `replacePin` must be true.
    /// Saves the pin to `activePinStore`. Never creates keys or deletes vault files.
    @discardableResult
    public func repairMasterKeyPin(
        replacePin: Bool = false,
        context: LAContext? = nil
    ) throws -> (publicKey: P256.KeyAgreement.PublicKey, fingerprint: String) {
        let (pubKey, fingerprint) = try verifyMasterKey(context: context)
        let pubData = pubKey.rawRepresentation
        let expectedPin = Data(SHA256.hash(data: pubData))

        if let existingPin = try activePinStore.loadPin() {
            if existingPin != expectedPin && !replacePin {
                throw VaultError.masterKeyTampered
            }
        }

        try activePinStore.savePin(expectedPin)
        return (pubKey, fingerprint)
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
        guard Self.isSecureEnclaveAvailable else {
            throw VaultError.secureEnclaveRequired
        }
        lock.lock()
        defer { lock.unlock() }
        guard record.storageType == .secureEnclave else {
            throw VaultError.softwareKeyStorageProhibited
        }
        try writeRecordLocked(record)
    }

    /// Caller must hold `lock`.
    private func writeRecordLocked(_ record: StoredPrivateKeyRecord) throws {
        guard record.storageType == .secureEnclave else {
            throw VaultError.softwareKeyStorageProhibited
        }
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
        try SecureFS.withUmask(0o077) {
            try envelope.write(to: fileURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        }
    }

    public func removeRecord(label: String) {
        lock.lock()
        defer { lock.unlock() }
        let hash = labelHash(label)
        let fileURL = vaultDirectoryURL.appendingPathComponent("\(hash).enc")
        try? FileManager.default.removeItem(at: fileURL)
    }

    public func hasRecord(label: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let hash = labelHash(label)
        let fileURL = vaultDirectoryURL.appendingPathComponent("\(hash).enc")
        return FileManager.default.fileExists(atPath: fileURL.path)
    }

    public func loadRecord(label: String, context: LAContext? = nil) throws -> StoredPrivateKeyRecord? {
        guard Self.isSecureEnclaveAvailable else {
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

        let (_, keyBytes) = try authenticateExistingMasterKey(context: context)

        let sharedSecret = try activeKeyAgreementProvider.sharedSecret(
            dataRepresentation: keyBytes,
            with: ephemeralPubKey,
            context: context
        )

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

