import Foundation

/// Key ownership is independent of the protocols the key may sign for.
public enum KeyType: String, Codable, CaseIterable, Sendable {
    case personal
    case bot

    public var title: String { self == .personal ? "Personal" : "Bot" }
}

public enum KeyOperation: String, Codable, CaseIterable, Sendable {
    case ssh
    case signature
}

public struct KeyCapabilities: Codable, Equatable, Sendable {
    public let ssh: Bool
    public let signature: Bool

    public init(ssh: Bool, signature: Bool) {
        self.ssh = ssh
        self.signature = signature
    }

    public func permits(_ operation: KeyOperation) -> Bool {
        switch operation {
        case .ssh: return ssh
        case .signature: return signature
        }
    }

    public var titles: [String] {
        (ssh ? ["SSH"] : []) + (signature ? ["SSHSIG"] : [])
    }
}

/// Persisted in the authenticated private record, mirrored in the display cache.
/// Legacy purpose checks remain an additional constraint during rollout.
public struct KeyAccessProfile: Codable, Equatable, Sendable {
    public let type: KeyType
    public let capabilities: KeyCapabilities

    public init(type: KeyType, capabilities: KeyCapabilities) {
        self.type = type
        self.capabilities = capabilities
    }

    public init(legacyPurpose: KeyPurpose) {
        type = legacyPurpose == .agent ? .bot : .personal
        capabilities = KeyCapabilities(ssh: legacyPurpose != .gitSigningOnly, signature: true)
    }

    public func changingType(to type: KeyType) -> KeyAccessProfile {
        KeyAccessProfile(type: type, capabilities: capabilities)
    }

    public func require(_ operation: KeyOperation) throws {
        guard capabilities.permits(operation) else {
            throw KeyAccessError.operationDisabled(operation)
        }
    }
}

public enum KeyAccessError: LocalizedError, Equatable {
    case operationDisabled(KeyOperation)
    case profileMismatch
    case legacyEncodingWouldLosePolicy

    public var errorDescription: String? {
        switch self {
        case .operationDisabled(let operation):
            return "This key does not permit \(operation == .ssh ? "SSH" : "Signature") requests."
        case .profileMismatch:
            return "Key policy differs from its authenticated record. Operation refused."
        case .legacyEncodingWouldLosePolicy:
            return "This key policy requires the current private-record format."
        }
    }
}
