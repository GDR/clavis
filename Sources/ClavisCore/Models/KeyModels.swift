import Foundation
import Security

public struct Ed25519KeyInfo: Identifiable, Codable, Equatable {
    public var id: String { label }
    public let label: String
    public let publicKeyOpenSSH: String
    public let publicKeyBlob: Data
    public let fingerprint: String
    public let createdAt: Date
    public let algorithmName: String?
    public let storage: KeyStorageType?
    public let biometricPolicy: BiometricPolicy?

    public var isAgeCompatible: Bool {
        algorithm == "Ed25519" && storageType == .keychain
    }

    public var ageRecipient: String {
        guard isAgeCompatible, publicKeyBlob.count >= 32 else { return "" }
        let ed25519Pub = publicKeyBlob.suffix(32)
        guard let x25519Pub = Ed25519AgeConverter.ed25519PublicKeyToX25519PublicKey(ed25519PubKey: Data(ed25519Pub)) else {
            return ""
        }
        return Ed25519AgeConverter.ageRecipient(forPublicKey: x25519Pub)
    }

    public var displayIdentifier: String {
        if isAgeCompatible && !ageRecipient.isEmpty {
            return ageRecipient
        }
        return publicKeyOpenSSH
    }

    public var algorithm: String {
        if let name = algorithmName {
            return name
        }
        if publicKeyOpenSSH.hasPrefix("ecdsa-sha2-") {
            return "ECDSA P-256"
        } else if publicKeyOpenSSH.hasPrefix("ssh-rsa") {
            return "RSA 4096"
        }
        return "Ed25519"
    }

    public var storageType: KeyStorageType {
        storage ?? .keychain
    }

    public var isHardware: Bool {
        storageType == .secureEnclave
    }

    public var badgeTitle: String {
        isHardware ? "Hardware" : "Software"
    }

    public var effectiveBiometricPolicy: BiometricPolicy {
        biometricPolicy ?? .userPresence
    }

    public init(
        label: String,
        publicKeyOpenSSH: String,
        publicKeyBlob: Data,
        fingerprint: String,
        createdAt: Date = Date(),
        algorithmName: String? = nil,
        storage: KeyStorageType? = nil,
        biometricPolicy: BiometricPolicy? = nil
    ) {
        self.label = label
        self.publicKeyOpenSSH = publicKeyOpenSSH
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = fingerprint
        self.createdAt = createdAt
        self.algorithmName = algorithmName
        self.storage = storage
        self.biometricPolicy = biometricPolicy
    }
}

public enum BiometricPolicy: String, CaseIterable, Identifiable, Codable {
    case userPresence = "userPresence"
    case biometryCurrentSet = "biometryCurrentSet"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .userPresence:
            return "User Presence"
        case .biometryCurrentSet:
            return "Strict Biometrics"
        }
    }

    public var subtitle: String {
        switch self {
        case .userPresence:
            return "Touch ID, Apple Watch, or device password fallback"
        case .biometryCurrentSet:
            return "Touch ID only. Invalidated if system fingerprints change"
        }
    }

    public var accessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence:
            return [.privateKeyUsage, .userPresence]
        case .biometryCurrentSet:
            return [.privateKeyUsage, .biometryCurrentSet]
        }
    }
}

public enum KeyAlgorithm: String, CaseIterable, Identifiable, Codable {
    case ed25519 = "Ed25519"
    case ecdsaP256 = "ECDSA P-256"

    public var id: String { rawValue }

    public var description: String {
        switch self {
        case .ed25519:
            return "Deterministic Edwards-curve (Fast, approximately 128-bit security)"
        case .ecdsaP256:
            return "NIST P-256 curve (Hardware & Secure Enclave ready)"
        }
    }
}

public enum KeyStorageType: String, CaseIterable, Identifiable, Codable {
    case keychain = "Login Keychain"
    case secureEnclave = "Secure Enclave"

    public var id: String { rawValue }
}

public enum SessionTimeout: String, CaseIterable, Identifiable, Codable {
    case never = "Off (Always Prompt)"
    case fiveMinutes = "5 Minutes"
    case fifteenMinutes = "15 Minutes"
    case oneHour = "1 Hour"

    public var id: String { rawValue }

    public var timeInterval: TimeInterval? {
        switch self {
        case .never: return nil
        case .fiveMinutes: return 300
        case .fifteenMinutes: return 900
        case .oneHour: return 3600
        }
    }
}

public extension Data {
    init?(hexString: String) {
        let cleanHex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanHex.count % 2 == 0 else { return nil }
        var data = Data(capacity: cleanHex.count / 2)
        var i = cleanHex.startIndex
        while i < cleanHex.endIndex {
            let j = cleanHex.index(i, offsetBy: 2)
            let bytes = cleanHex[i..<j]
            guard let num = UInt8(bytes, radix: 16) else { return nil }
            data.append(num)
            i = j
        }
        self = data
    }
}
