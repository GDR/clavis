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
    public static var customVaultDirectoryURL: URL? = nil
    static var forceSoftwareMasterKeyForTesting: Bool = false

    private static var allowSoftwareMasterKeyForTesting: Bool {
        #if DEBUG
        return forceSoftwareMasterKeyForTesting
        #else
        return false
        #endif
    }

    private let lock = NSLock()

    public enum VaultError: LocalizedError {
        case secureEnclaveRequired
        case softwareMasterKeyUnsupported
        case incompleteMasterKey

        public var errorDescription: String? {
            switch self {
            case .secureEnclaveRequired:
                return "Secure Enclave is required to protect the Clavis recovery vault."
            case .softwareMasterKeyUnsupported:
                return "This vault uses an old software master key. Its files were preserved; migrate the vault before creating more keys."
            case .incompleteMasterKey:
                return "The recovery vault master key is incomplete or invalid. Its files were preserved."
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
            let privateData = try Data(contentsOf: keyURL)
            guard let keyType = privateData.first else {
                throw VaultError.incompleteMasterKey
            }
            guard keyType == 0x01 || (keyType == 0x02 && Self.allowSoftwareMasterKeyForTesting) else {
                throw keyType == 0x02 ? VaultError.softwareMasterKeyUnsupported : VaultError.incompleteMasterKey
            }
            let pubData = try Data(contentsOf: pubURL)
            guard let pubKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: pubData) else {
                throw VaultError.incompleteMasterKey
            }
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
            return swKey.publicKey
        }
    }

    public func saveRecord(_ record: StoredPrivateKeyRecord) throws {
        lock.lock()
        defer { lock.unlock() }

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

        let sealed = try ChaChaPoly.seal(recordBytes, using: symmetricKey)
        let epkRaw = ephemeral.publicKey.rawRepresentation
        guard epkRaw.count <= 255 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Ephemeral public key too large"])
        }

        var envelope = Data("CLVENV01".utf8)
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
        return try decryptEnvelope(data, context: context)
    }

    private func decryptEnvelope(_ data: Data, context: LAContext?) throws -> StoredPrivateKeyRecord {
        let magic = Data("CLVENV01".utf8)
        guard data.starts(with: magic), data.count > magic.count + 1 else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid vault envelope format"])
        }

        var offset = magic.count
        let epkLen = Int(data[offset])
        offset += 1

        guard data.count >= offset + epkLen else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Truncated vault envelope"])
        }

        let epkData = data.subdata(in: offset..<offset + epkLen)
        offset += epkLen
        let ciphertext = data.subdata(in: offset..<data.count)

        let ephemeralPubKey = try P256.KeyAgreement.PublicKey(rawRepresentation: epkData)
        let keyURL = vaultDirectoryURL.appendingPathComponent("master.key")
        let fileData = try Data(contentsOf: keyURL)
        guard !fileData.isEmpty else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Empty master key in vault"])
        }

        let keyType = fileData[0]
        let keyData = fileData.dropFirst()

        let sharedSecret: SharedSecret
        if keyType == 0x01 {
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: Data(keyData),
                authenticationContext: context ?? LAContext()
            )
            sharedSecret = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        } else if keyType == 0x02 {
            guard Self.allowSoftwareMasterKeyForTesting else {
                throw VaultError.softwareMasterKeyUnsupported
            }
            let swKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(keyData))
            sharedSecret = try swKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        } else {
            throw NSError(domain: "Clavis", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unsupported master key format"])
        }

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: epkData,
            sharedInfo: Data("clavis-vault-envelope-v1".utf8),
            outputByteCount: 32
        )

        let sealed = try ChaChaPoly.SealedBox(combined: ciphertext)
        let decrypted = try ChaChaPoly.open(sealed, using: symmetricKey)
        return try StoredPrivateKeyRecord.decode(from: decrypted)
    }
}
