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
    public let accessProfile: KeyAccessProfile?
    public let unlockedTimeout: KeyGracePeriod?

    public var effectiveAccessProfile: KeyAccessProfile {
        accessProfile ?? KeyAccessProfile(legacyPurpose: purpose)
    }

    public var effectiveUnlockedTimeout: KeyGracePeriod {
        unlockedTimeout ?? KeyGracePeriod.defaultPeriod(for: purpose)
    }

    public var purpose: KeyPurpose {
        keyPurpose ?? .general
    }

    public var displayIdentifier: String {
        publicKeyOpenSSH
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
        keyPurpose: KeyPurpose? = nil,
        accessProfile: KeyAccessProfile? = nil,
        unlockedTimeout: KeyGracePeriod? = nil
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
        self.accessProfile = accessProfile
        self.unlockedTimeout = unlockedTimeout
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

    public var sidebarLabel: String {
        switch self {
        case .general:
            return "SSH & Git"
        case .gitSigningOnly:
            return "Git signing"
        case .agent:
            return "Agent"
        }
    }

    public var inspectorLabel: String {
        switch self {
        case .general:
            return "SSH & Git"
        case .gitSigningOnly:
            return "Git signing only"
        case .agent:
            return "Agent"
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
    case biometryCurrentSet = "biometryCurrentSet"
    case userPresence = "userPresence"
    /// D-40: Touch ID required, password fallback; invalidated on fingerprint change.
    case biometryOrPasscode = "biometryOrPasscode"
    /// D-40: Mac login password only (no biometrics).
    case devicePasscode = "devicePasscode"

    public var id: String { rawValue }

    public var laPolicy: LAPolicy {
        switch self {
        case .userPresence:
            return .deviceOwnerAuthentication
        case .biometryCurrentSet:
            return .deviceOwnerAuthenticationWithBiometrics
        case .biometryOrPasscode, .devicePasscode:
            return .deviceOwnerAuthentication
        }
    }

    public var title: String {
        switch self {
        case .userPresence:
            return ClavisUIStrings.BiometricPolicyStrings.userPresenceTitle
        case .biometryCurrentSet:
            return ClavisUIStrings.BiometricPolicyStrings.currentSetTitle
        case .biometryOrPasscode:
            return ClavisUIStrings.BiometricPolicyStrings.biometryOrPasscodeTitle
        case .devicePasscode:
            return ClavisUIStrings.BiometricPolicyStrings.devicePasscodeTitle
        }
    }

    public var subtitle: String {
        switch self {
        case .userPresence:
            return ClavisUIStrings.BiometricPolicyStrings.userPresenceSubtitle
        case .biometryCurrentSet:
            return ClavisUIStrings.BiometricPolicyStrings.currentSetSubtitle
        case .biometryOrPasscode:
            return ClavisUIStrings.BiometricPolicyStrings.biometryOrPasscodeSubtitle
        case .devicePasscode:
            return ClavisUIStrings.BiometricPolicyStrings.devicePasscodeSubtitle
        }
    }

    public var accessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence:
            return [.privateKeyUsage, .userPresence]
        case .biometryCurrentSet:
            return [.privateKeyUsage, .biometryCurrentSet]
        case .biometryOrPasscode:
            return [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]
        case .devicePasscode:
            return [.privateKeyUsage, .devicePasscode]
        }
    }
}

public enum KeyGracePeriod: String, CaseIterable, Identifiable, Codable, Equatable, Sendable {
    case always = "always"
    case session = "session"
    case oneMinute = "1"
    case twoMinutes = "2"
    case fiveMinutes = "5"
    case tenMinutes = "10"
    case fifteenMinutes = "15"
    case oneHour = "60"
    case twoHours = "120"
    /// D-40: session ends when the Mac locks or sleeps.
    case untilLock = "untilLock"
    /// D-40: one confirmation per day per requesting app.
    case oneDay = "1440"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .always: return "Once"
        case .session: return "8 hours"
        case .oneMinute: return "1 min"
        case .twoMinutes: return "2 min"
        case .fiveMinutes: return "5 min"
        case .tenMinutes: return "10 min"
        case .fifteenMinutes: return "15 min"
        case .oneHour: return "1 hour"
        case .twoHours: return "2 hours"
        case .untilLock: return "Until Lock"
        case .oneDay: return "1 Day"
        }
    }

    public var shortMenuTitle: String {
        switch self {
        case .always: return "Once"
        case .session: return "8h"
        case .oneMinute: return "1m"
        case .twoMinutes: return "2m"
        case .fiveMinutes: return "5m"
        case .tenMinutes: return "10m"
        case .fifteenMinutes: return "15m"
        case .oneHour: return "1h"
        case .twoHours: return "2h"
        case .untilLock: return "Until Lock"
        case .oneDay: return "1d"
        }
    }

    /// D-40 / INV-21: sessions with this flag survive lock until they expire.
    public var endsAtLock: Bool { self == .untilLock }

    public var durationSeconds: TimeInterval? {
        switch self {
        case .always: return nil
        case .session: return 8 * 3600
        case .oneMinute: return 60
        case .twoMinutes: return 120
        case .fiveMinutes: return 300
        case .tenMinutes: return 600
        case .fifteenMinutes: return 900
        case .oneHour: return 3600
        case .twoHours: return 7200
        case .untilLock: return nil
        case .oneDay: return 86400
        }
    }

    /// Grant TTL in seconds for active session caches (`nil` for single-shot `.always`;
    /// `.untilLock` uses a 24h upper bound alongside lock/sleep invalidation).
    public var grantDurationSeconds: TimeInterval? {
        switch self {
        case .always: return nil
        case .untilLock: return 24 * 3600
        default: return durationSeconds
        }
    }

    public var leaseMinutes: Int? {
        switch self {
        case .always: return nil
        case .session: return 480
        case .oneMinute: return 1
        case .twoMinutes: return 2
        case .fiveMinutes: return 5
        case .tenMinutes: return 10
        case .fifteenMinutes: return 15
        case .oneHour: return 60
        case .twoHours: return 120
        case .untilLock: return nil
        case .oneDay: return 1440
        }
    }

    /// D-40: every new key gets the same default unlocked timeout (15 min).
    public static func defaultPeriod(for purpose: KeyPurpose) -> KeyGracePeriod {
        .fifteenMinutes
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
