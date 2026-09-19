import Foundation

public struct Ed25519KeyInfo: Identifiable, Codable, Equatable {
    public var id: String { label }
    public let label: String
    public let publicKeyOpenSSH: String
    public let publicKeyBlob: Data
    public let fingerprint: String
    public let createdAt: Date
    public let algorithmName: String?
    public let storage: KeyStorageType?

    public var isAgeCompatible: Bool {
        algorithm == "Ed25519" && storageType == .keychain
    }

    public var ageRecipient: String {
        guard isAgeCompatible else { return "" }
        return Ed25519AgeConverter.ageRecipient(forPublicKey: publicKeyBlob)
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

    public init(
        label: String,
        publicKeyOpenSSH: String,
        publicKeyBlob: Data,
        fingerprint: String,
        createdAt: Date = Date(),
        algorithmName: String? = nil,
        storage: KeyStorageType? = nil
    ) {
        self.label = label
        self.publicKeyOpenSSH = publicKeyOpenSSH
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = fingerprint
        self.createdAt = createdAt
        self.algorithmName = algorithmName
        self.storage = storage
    }
}

public enum KeyAlgorithm: String, CaseIterable, Identifiable, Codable {
    case ed25519 = "Ed25519"
    case ecdsaP256 = "ECDSA P-256"
    case rsa4096 = "RSA 4096"

    public var id: String { rawValue }

    public var description: String {
        switch self {
        case .ed25519:
            return "Deterministic Edwards-curve (Fast, 256-bit security)"
        case .ecdsaP256:
            return "NIST P-256 curve (Hardware & Secure Enclave ready)"
        case .rsa4096:
            return "4096-bit RSA (Legacy server compatibility)"
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
