import Foundation

public enum AgentSocketRole: String, Sendable {
    case personal
    case agent

    /// Legacy purpose is retained in records for migration restrictions. Socket
    /// eligibility is based on the independent profile, never on routing alone.
    public var allowedPurposes: Set<KeyPurpose> { Set(KeyPurpose.allCases) }

    public func permits(_ key: SSHKeyInfo) -> Bool {
        self == .personal || key.effectiveAccessProfile.type == .bot
    }

}

public enum KeyKindFilter: String, CaseIterable, Identifiable, Sendable {
    case all
    case personal
    case agent

    public var id: String { rawValue }

    public static func apply(_ filter: KeyKindFilter, to keys: [SSHKeyInfo]) -> [SSHKeyInfo] {
        switch filter {
        case .all:
            return keys
        case .personal:
            return keys.filter { $0.effectiveAccessProfile.type == .personal }
        case .agent:
            return keys.filter { $0.effectiveAccessProfile.type == .bot }
        }
    }
}
