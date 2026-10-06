import Foundation

public enum AgentSocketRole: String, Sendable {
    case personal
    case agent

    public var allowedPurposes: Set<KeyPurpose> {
        switch self {
        case .personal:
            return [.general, .gitSigningOnly]
        case .agent:
            return [.agent]
        }
    }

    public var listedPurposes: Set<KeyPurpose> {
        switch self {
        case .personal:
            return [.general]
        case .agent:
            return [.agent]
        }
    }
}

public enum KeyKindFilter: String, CaseIterable, Identifiable, Sendable {
    case all
    case personal
    case agent

    public var id: String { rawValue }

    public static func apply(_ filter: KeyKindFilter, to keys: [Ed25519KeyInfo]) -> [Ed25519KeyInfo] {
        switch filter {
        case .all:
            return keys
        case .personal:
            return keys.filter { $0.purpose.isPersonal }
        case .agent:
            return keys.filter { $0.purpose == .agent }
        }
    }
}
