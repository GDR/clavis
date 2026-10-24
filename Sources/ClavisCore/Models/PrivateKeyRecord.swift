import Foundation
import CryptoKit
import Security

/// Versioned, authenticated private-key record stored inside Keychain under `com.clavis.ed25519`.
///
/// This record is the single authoritative source of truth for key type, backing storage,
/// biometric policy, and private key payload. The public index (`PublicKeyStore`, an in-memory
/// copy of unauthenticated Keychain metadata items) is treated strictly as a display cache.
public struct StoredPrivateKeyRecord: Codable, Equatable {
    public static let currentVersion: Int = 3
    private static let binaryMagic = Data("CLVPKR02".utf8)
    private static let maximumLabelBytes = 1_024
    private static let maximumKeyBytes = 65_536

    public let version: Int
    public let label: String
    public let algorithm: KeyAlgorithm
    public let storageType: KeyStorageType
    public let biometricPolicy: BiometricPolicy?
    public let accessProfile: KeyAccessProfile
    public let keyPurpose: KeyPurpose
    public var keyData: Data
    public let createdAt: Date

    public var purpose: KeyPurpose {
        keyPurpose
    }

    private enum CodingKeys: String, CodingKey {
        case version, label, algorithm, storageType, biometricPolicy, keyPurpose, accessProfile, keyData, createdAt
    }

    public init(
        version: Int = StoredPrivateKeyRecord.currentVersion,
        label: String,
        algorithm: KeyAlgorithm,
        storageType: KeyStorageType,
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose,
        accessProfile: KeyAccessProfile? = nil,
        keyData: Data,
        createdAt: Date = Date()
    ) {
        self.version = version
        self.label = label
        self.algorithm = algorithm
        self.storageType = storageType
        self.biometricPolicy = biometricPolicy
        self.keyPurpose = keyPurpose
        self.accessProfile = accessProfile ?? KeyAccessProfile(legacyPurpose: keyPurpose)
        self.keyData = keyData
        self.createdAt = createdAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.version = try container.decode(Int.self, forKey: .version)
        self.label = try container.decode(String.self, forKey: .label)
        self.algorithm = try container.decode(KeyAlgorithm.self, forKey: .algorithm)
        self.storageType = try container.decode(KeyStorageType.self, forKey: .storageType)
        self.biometricPolicy = try container.decodeIfPresent(BiometricPolicy.self, forKey: .biometricPolicy)
        self.keyPurpose = try container.decodeIfPresent(KeyPurpose.self, forKey: .keyPurpose) ?? .general
        if version >= 3 {
            self.accessProfile = try container.decode(KeyAccessProfile.self, forKey: .accessProfile)
        } else {
            self.accessProfile = KeyAccessProfile(legacyPurpose: keyPurpose)
        }
        self.keyData = try container.decode(Data.self, forKey: .keyData)
        self.createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(label, forKey: .label)
        try container.encode(algorithm, forKey: .algorithm)
        try container.encode(storageType, forKey: .storageType)
        try container.encodeIfPresent(biometricPolicy, forKey: .biometricPolicy)
        try container.encode(keyPurpose, forKey: .keyPurpose)
        try container.encode(accessProfile, forKey: .accessProfile)
        try container.encode(keyData, forKey: .keyData)
        try container.encode(createdAt, forKey: .createdAt)
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
        guard version == 2 || version == Self.currentVersion else {
            throw PrivateKeyRecordError.unsupportedVersion(version)
        }
        if version == 2 && accessProfile != KeyAccessProfile(legacyPurpose: purpose) {
            throw KeyAccessError.legacyEncodingWouldLosePolicy
        }
        guard algorithm == .ecdsaP256 else {
            throw PrivateKeyRecordError.corruptedRecord("Unsupported algorithm: only ECDSA P-256 is supported")
        }
        guard storageType == .secureEnclave else {
            throw PrivateKeyRecordError.corruptedRecord("Unsupported storage: only Secure Enclave is supported")
        }
        guard let labelData = label.data(using: .utf8),
              !labelData.isEmpty,
              labelData.count <= Self.maximumLabelBytes,
              keyData.count <= Self.maximumKeyBytes else {
            throw PrivateKeyRecordError.corruptedRecord("Record field length exceeds the binary envelope limit")
        }

        var output = Self.binaryMagic
        output.append(UInt8(version))
        output.append(2) // .ecdsaP256
        output.append(2) // .secureEnclave
        switch purpose {
        case .general:
            output.append(1)
        case .gitSigningOnly:
            output.append(2)
        case .agent:
            output.append(3)
        }
        switch biometricPolicy {
        case nil: output.append(0)
        case .userPresence: output.append(1)
        case .biometryCurrentSet: output.append(2)
        }
        if version >= 3 {
            output.append(accessProfile.type == .personal ? 1 : 2)
            output.append((accessProfile.capabilities.ssh ? 1 : 0) | (accessProfile.capabilities.signature ? 2 : 0))
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
        guard data.starts(with: binaryMagic) else {
            throw PrivateKeyRecordError.corruptedRecord("Unrecognized private key record envelope")
        }
        return try decodeBinary(from: data)
    }

    private static func decodeBinary(from data: Data) throws -> StoredPrivateKeyRecord {
        var reader = PrivateRecordBinaryReader(data: data, offset: binaryMagic.count)
        guard let version = reader.readUInt8() else {
            throw PrivateKeyRecordError.corruptedRecord("Malformed binary private-key record")
        }
        guard version == 2 || Int(version) == currentVersion else {
            throw PrivateKeyRecordError.unsupportedVersion(Int(version))
        }
        guard let algorithmByte = reader.readUInt8(),
              let storageByte = reader.readUInt8(),
              let purposeByte = reader.readUInt8(),
              let biometricByte = reader.readUInt8() else {
            throw PrivateKeyRecordError.corruptedRecord("Malformed binary private-key record")
        }
        let profile: KeyAccessProfile?
        if version >= 3 {
            guard let typeByte = reader.readUInt8(), (1...2).contains(typeByte),
                  let bits = reader.readUInt8(), bits & ~3 == 0 else {
                throw PrivateKeyRecordError.corruptedRecord("Unknown key type or capability identifier")
            }
            profile = KeyAccessProfile(
                type: typeByte == 1 ? .personal : .bot,
                capabilities: KeyCapabilities(ssh: bits & 1 != 0, signature: bits & 2 != 0)
            )
        } else {
            profile = nil
        }
        guard let timestampBits = reader.readUInt64(),
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
        case 2: algorithm = .ecdsaP256
        default: throw PrivateKeyRecordError.corruptedRecord("Unsupported or unknown algorithm identifier: \(algorithmByte)")
        }
        let storage: KeyStorageType
        switch storageByte {
        case 2: storage = .secureEnclave
        default: throw PrivateKeyRecordError.corruptedRecord("Unsupported or unknown storage identifier: \(storageByte)")
        }
        let purpose: KeyPurpose
        switch purposeByte {
        case 1: purpose = .general
        case 2: purpose = .gitSigningOnly
        case 3: purpose = .agent
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
            accessProfile: profile,
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

/// Errors raised when validating Keychain records or detecting tampering against the public index.
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
