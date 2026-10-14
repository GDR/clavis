import Foundation
import Security
import LocalAuthentication

public struct SSHKeyInfo: Identifiable, Codable, Equatable {
    public var id: String { label }
    public let label: String
    public let publicKeyOpenSSH: String
    public let publicKeyBlob: Data
    public let fingerprint: String
    public let createdAt: Date
    public let algorithmName: String?
    public let storage: KeyStorageType?
    public let biometricPolicy: BiometricPolicy?
    public let keyPurpose: KeyPurpose?

    public var purpose: KeyPurpose {
        keyPurpose ?? .general
    }

    public var displayIdentifier: String {
        publicKeyOpenSSH
    }

    public var cliSummary: String {
        """
        Purpose:     \(purpose.title)
        Fingerprint: \(fingerprint)
        Public Key:  \(publicKeyOpenSSH)
        """
    }

    public var algorithm: String {
        algorithmName ?? "ECDSA P-256"
    }

    public var storageType: KeyStorageType {
        storage ?? .secureEnclave
    }

    public var isHardware: Bool {
        true
    }

    public var badgeTitle: String {
        ClavisUIStrings.Badges.hardware
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
        biometricPolicy: BiometricPolicy? = nil,
        keyPurpose: KeyPurpose? = nil
    ) {
        self.label = label
        self.publicKeyOpenSSH = publicKeyOpenSSH
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = fingerprint
        self.createdAt = createdAt
        self.algorithmName = algorithmName
        self.storage = storage
        self.biometricPolicy = biometricPolicy
        self.keyPurpose = keyPurpose
    }
}

public typealias Ed25519KeyInfo = SSHKeyInfo

public enum KeyPurpose: String, CaseIterable, Identifiable, Codable {
    case general = "general"
    case gitSigningOnly = "gitSigningOnly"
    case agent = "agent"

    public var id: String { rawValue }

    public var isPersonal: Bool {
        self != .agent
    }

    public var title: String {
        switch self {
        case .general:
            return ClavisUIStrings.KeyPurposeStrings.generalTitle
        case .gitSigningOnly:
            return ClavisUIStrings.KeyPurposeStrings.gitSigningOnlyTitle
        case .agent:
            return ClavisUIStrings.KeyPurposeStrings.agentTitle
        }
    }

    public var subtitle: String {
        switch self {
        case .general:
            return ClavisUIStrings.KeyPurposeStrings.generalSubtitle
        case .gitSigningOnly:
            return ClavisUIStrings.KeyPurposeStrings.gitSigningOnlySubtitle
        case .agent:
            return ClavisUIStrings.KeyPurposeStrings.agentSubtitle
        }
    }
}

public enum KeyPurposeError: LocalizedError, Equatable {
    case notAllowedOnThisPath(KeyPurpose)
    case kindChangeNotAllowed

    public var errorDescription: String? {
        switch self {
        case .notAllowedOnThisPath(let purpose):
            return "Key with purpose '\(purpose.rawValue)' is not allowed on this path."
        case .kindChangeNotAllowed:
            return "Changing key kind is only allowed between general and agent."
        }
    }
}

public enum BiometricPolicy: String, CaseIterable, Identifiable, Codable {
    case userPresence = "userPresence"
    case biometryCurrentSet = "biometryCurrentSet"

    public var id: String { rawValue }

    public var laPolicy: LAPolicy {
        switch self {
        case .userPresence:
            return .deviceOwnerAuthentication
        case .biometryCurrentSet:
            return .deviceOwnerAuthenticationWithBiometrics
        }
    }

    public var title: String {
        switch self {
        case .userPresence:
            return ClavisUIStrings.BiometricPolicyStrings.userPresenceTitle
        case .biometryCurrentSet:
            return ClavisUIStrings.BiometricPolicyStrings.currentSetTitle
        }
    }

    public var subtitle: String {
        switch self {
        case .userPresence:
            return ClavisUIStrings.BiometricPolicyStrings.userPresenceSubtitle
        case .biometryCurrentSet:
            return ClavisUIStrings.BiometricPolicyStrings.currentSetSubtitle
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
    case ecdsaP256 = "ECDSA P-256"

    public var id: String { rawValue }

    public var description: String {
        switch self {
        case .ecdsaP256:
            return "NIST P-256 curve (Hardware & Secure Enclave ready)"
        }
    }
}

public enum KeyStorageType: String, CaseIterable, Identifiable, Codable {
    case secureEnclave = "Secure Enclave"

    public var id: String { rawValue }
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
