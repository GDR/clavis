import Foundation
import CryptoKit
import Security

/// Versioned, authenticated private-key record stored inside Keychain under `com.clavis.ed25519`.
///
/// This record is the single authoritative source of truth for key type, backing storage,
/// biometric policy, and private key payload. The public index (`~/.config/clavis/keys.json`)
/// is treated strictly as an unauthenticated display cache.
public struct StoredPrivateKeyRecord: Codable, Equatable {
    public static let currentVersion: Int = 1

    public let version: Int
    public let label: String
    public let algorithm: KeyAlgorithm
    public let storageType: KeyStorageType
    public let biometricPolicy: BiometricPolicy?
    public let keyPurpose: KeyPurpose?
    public var keyData: Data
    public let createdAt: Date

    public var purpose: KeyPurpose {
        keyPurpose ?? .general
    }

    public init(
        version: Int = StoredPrivateKeyRecord.currentVersion,
        label: String,
        algorithm: KeyAlgorithm,
        storageType: KeyStorageType,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose? = nil,
        keyData: Data,
        createdAt: Date = Date()
    ) {
        self.version = version
        self.label = label
        self.algorithm = algorithm
        self.storageType = storageType
        self.biometricPolicy = biometricPolicy
        self.keyPurpose = keyPurpose
        self.keyData = keyData
        self.createdAt = createdAt
    }

    /// Wipes sensitive key material in place.
    public mutating func wipe() {
        keyData.withUnsafeMutableBytes { ptr in
            if let baseAddress = ptr.baseAddress {
                SecureMemory.zero(baseAddress, byteCount: ptr.count)
            }
        }
        keyData.removeAll(keepingCapacity: false)
    }

    public func encode() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decode(from data: Data) throws -> StoredPrivateKeyRecord {
        let record = try JSONDecoder().decode(StoredPrivateKeyRecord.self, from: data)
        guard record.version <= currentVersion else {
            throw PrivateKeyRecordError.unsupportedVersion(record.version)
        }
        return record
    }
}

/// Errors raised when validating Keychain records or detecting tampering against `keys.json`.
public enum PrivateKeyRecordError: LocalizedError, Equatable {
    case unsupportedVersion(Int)
    case corruptedRecord(String)
    case labelMismatch(expected: String, actual: String)
    case metadataMismatch(field: String, expected: String, actual: String)
    case algorithmMismatch(expected: String, actual: String)
    case storageMismatch(expected: String, actual: String)
    case publicKeyMismatch
    case legacyRecordUnmigrated(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedVersion(let v):
            return "Unsupported private key record version (\(v))."
        case .corruptedRecord(let details):
            return "Corrupted private key record: \(details)"
        case .labelMismatch(let expected, let actual):
            return "Private key record label mismatch (expected '\(expected)', got '\(actual)')."
        case .metadataMismatch(let field, let expected, let actual):
            return "Security violation: metadata mismatch in \(field) (record has '\(actual)', requested '\(expected)'). Signing refused."
        case .algorithmMismatch(let expected, let actual):
            return "Security violation: algorithm mismatch (record has '\(actual)', requested '\(expected)'). Signing refused."
        case .storageMismatch(let expected, let actual):
            return "Security violation: storage type mismatch (record has '\(actual)', requested '\(expected)'). Signing refused."
        case .publicKeyMismatch:
            return "Security violation: derived public key does not match public key metadata blob. Signing refused."
        case .legacyRecordUnmigrated(let label):
            return "Legacy private key record for '\(label)' could not be migrated safely."
        }
    }
}
