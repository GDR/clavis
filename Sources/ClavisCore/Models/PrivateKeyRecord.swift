import Foundation
import CryptoKit
import Security

/// Versioned, authenticated private-key record stored inside Keychain under `com.clavis.ed25519`.
///
/// This record is the single authoritative source of truth for key type, backing storage,
/// biometric policy, and private key payload. The public index (`~/.config/clavis/keys.json`)
/// is treated strictly as an unauthenticated display cache.
public struct StoredPrivateKeyRecord: Codable, Equatable {
    public static let currentVersion: Int = 2
    private static let binaryMagic = Data("CLVPKR02".utf8)
    private static let maximumLabelBytes = 1_024
    private static let maximumKeyBytes = 65_536

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
        // JSON v1 remains available only for tests and explicit legacy fixtures.
        guard version == Self.currentVersion else {
            guard version == 1 else { throw PrivateKeyRecordError.unsupportedVersion(version) }
            return try JSONEncoder().encode(self)
        }
        guard let labelData = label.data(using: .utf8),
              !labelData.isEmpty,
              labelData.count <= Self.maximumLabelBytes,
              keyData.count <= Self.maximumKeyBytes else {
            throw PrivateKeyRecordError.corruptedRecord("Record field length exceeds the binary envelope limit")
        }

        var output = Self.binaryMagic
        output.append(UInt8(version))
        output.append(algorithm == .ed25519 ? 1 : 2)
        output.append(storageType == .keychain ? 1 : 2)
        output.append(purpose == .general ? 1 : 2)
        switch biometricPolicy {
        case nil: output.append(0)
        case .userPresence: output.append(1)
        case .biometryCurrentSet: output.append(2)
        }
        var timestamp = createdAt.timeIntervalSince1970.bitPattern.bigEndian
        Swift.withUnsafeBytes(of: &timestamp) { output.append(contentsOf: $0) }
        var labelLength = UInt16(labelData.count).bigEndian
        Swift.withUnsafeBytes(of: &labelLength) { output.append(contentsOf: $0) }
        output.append(labelData)
        var keyLength = UInt32(keyData.count).bigEndian
        Swift.withUnsafeBytes(of: &keyLength) { output.append(contentsOf: $0) }
        output.append(keyData)
        return output
    }

    public static func decode(from data: Data) throws -> StoredPrivateKeyRecord {
        if data.starts(with: binaryMagic) {
            return try decodeBinary(from: data)
        }

        // The only accepted non-binary representation is the deployed v1 JSON format.
        let record = try JSONDecoder().decode(StoredPrivateKeyRecord.self, from: data)
        guard record.version == 1 else {
            throw PrivateKeyRecordError.unsupportedVersion(record.version)
        }
        return record
    }

    private static func decodeBinary(from data: Data) throws -> StoredPrivateKeyRecord {
        var reader = PrivateRecordBinaryReader(data: data, offset: binaryMagic.count)
        guard let version = reader.readUInt8(), Int(version) == currentVersion,
              let algorithmByte = reader.readUInt8(),
              let storageByte = reader.readUInt8(),
              let purposeByte = reader.readUInt8(),
              let biometricByte = reader.readUInt8(),
              let timestampBits = reader.readUInt64(),
              let labelLength = reader.readUInt16(),
              Int(labelLength) <= maximumLabelBytes,
              let labelData = reader.readData(count: Int(labelLength)),
              let label = String(data: labelData, encoding: .utf8),
              !label.isEmpty,
              let keyLength = reader.readUInt32(),
              Int(keyLength) <= maximumKeyBytes,
              let keyData = reader.readData(count: Int(keyLength)),
              reader.isEOF else {
            throw PrivateKeyRecordError.corruptedRecord("Malformed binary private-key record")
        }

        let algorithm: KeyAlgorithm
        switch algorithmByte {
        case 1: algorithm = .ed25519
        case 2: algorithm = .ecdsaP256
        default: throw PrivateKeyRecordError.corruptedRecord("Unknown algorithm identifier")
        }
        let storage: KeyStorageType
        switch storageByte {
        case 1: storage = .keychain
        case 2: storage = .secureEnclave
        default: throw PrivateKeyRecordError.corruptedRecord("Unknown storage identifier")
        }
        let purpose: KeyPurpose
        switch purposeByte {
        case 1: purpose = .general
        case 2: purpose = .gitSigningOnly
        default: throw PrivateKeyRecordError.corruptedRecord("Unknown purpose identifier")
        }
        let biometric: BiometricPolicy?
        switch biometricByte {
        case 0: biometric = nil
        case 1: biometric = .userPresence
        case 2: biometric = .biometryCurrentSet
        default: throw PrivateKeyRecordError.corruptedRecord("Unknown biometric policy identifier")
        }

        return StoredPrivateKeyRecord(
            version: Int(version),
            label: label,
            algorithm: algorithm,
            storageType: storage,
            biometricPolicy: biometric,
            keyPurpose: purpose,
            keyData: keyData,
            createdAt: Date(timeIntervalSince1970: TimeInterval(bitPattern: timestampBits))
        )
    }
}

private struct PrivateRecordBinaryReader {
    let data: Data
    var offset: Int

    var isEOF: Bool { offset == data.endIndex }

    mutating func readUInt8() -> UInt8? {
        guard offset < data.endIndex else { return nil }
        defer { offset += 1 }
        return data[offset]
    }

    mutating func readUInt16() -> UInt16? { readInteger(UInt16.self) }
    mutating func readUInt32() -> UInt32? { readInteger(UInt32.self) }
    mutating func readUInt64() -> UInt64? { readInteger(UInt64.self) }

    mutating func readData(count: Int) -> Data? {
        guard count >= 0, offset <= data.endIndex - count else { return nil }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    private mutating func readInteger<T: FixedWidthInteger>(_ type: T.Type) -> T? {
        let size = MemoryLayout<T>.size
        guard let bytes = readData(count: size) else { return nil }
        var value: T = 0
        _ = Swift.withUnsafeMutableBytes(of: &value) { bytes.copyBytes(to: $0) }
        return T(bigEndian: value)
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
    case purposeMismatch(expected: String, actual: String)
    case purposeNotAllowed(purpose: String, operation: String)
    case publicKeyMismatch

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
        case .purposeMismatch(let expected, let actual):
            return "Security violation: key purpose mismatch (record has '\(actual)', requested '\(expected)'). Operation refused."
        case .purposeNotAllowed(let purpose, let operation):
            return "Security violation: key purpose '\(purpose)' does not permit \(operation)."
        case .publicKeyMismatch:
            return "Security violation: derived public key does not match public key metadata blob. Signing refused."
        }
    }
}
