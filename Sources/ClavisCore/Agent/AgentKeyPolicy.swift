import Foundation

public enum AgentPolicyError: LocalizedError, Equatable {
    case invalid(String)
    case corrupt
    case policyUnavailable

    public var errorDescription: String? {
        switch self {
        case .invalid(let reason):
            return "Invalid agent policy: \(reason)"
        case .corrupt:
            return "Agent policy data is corrupt or unreadable"
        case .policyUnavailable:
            return "Agent policy is unavailable"
        }
    }
}

public struct AgentAllowedHost: Codable, Equatable, Hashable, Sendable {
    public var name: String
    public var hostKeyBlob: Data

    public init(name: String, hostKeyBlob: Data) {
        self.name = name
        self.hostKeyBlob = hostKeyBlob
    }
}

public struct AgentKeyPolicy: Codable, Equatable, Sendable {
    public enum Mode: String, Codable, CaseIterable, Sendable {
        case none
        case notify
        case ask
    }

    public static let supportedHostKeyTypes: Set<String> = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521"
    ]

    public var mode: Mode
    public var leaseMinutes: Int
    public var allowedHosts: [AgentAllowedHost]
    public var burst: Int
    public var refillPerMinute: Int
    public var version: Int

    public init(
        mode: Mode = .none,
        leaseMinutes: Int = 480,
        allowedHosts: [AgentAllowedHost] = [],
        burst: Int = 30,
        refillPerMinute: Int = 6,
        version: Int = 1
    ) {
        self.mode = mode
        self.leaseMinutes = leaseMinutes
        self.allowedHosts = allowedHosts
        self.burst = burst
        self.refillPerMinute = refillPerMinute
        self.version = version
    }

    public func validate() throws {
        guard version == 1 else {
            throw AgentPolicyError.invalid("Unsupported policy version \(version)")
        }
        guard (1...10080).contains(leaseMinutes) else {
            throw AgentPolicyError.invalid("leaseMinutes must be between 1 and 10080, got \(leaseMinutes)")
        }
        guard (1...1000).contains(burst) else {
            throw AgentPolicyError.invalid("burst must be between 1 and 1000, got \(burst)")
        }
        guard (1...600).contains(refillPerMinute) else {
            throw AgentPolicyError.invalid("refillPerMinute must be between 1 and 600, got \(refillPerMinute)")
        }
        guard allowedHosts.count <= 64 else {
            throw AgentPolicyError.invalid("allowedHosts cannot exceed 64 entries, got \(allowedHosts.count)")
        }
        for host in allowedHosts {
            var reader = DataReader(data: host.hostKeyBlob)
            guard let keyType = reader.readWireString() else {
                throw AgentPolicyError.invalid("Invalid host key blob for '\(host.name)'")
            }
            guard Self.supportedHostKeyTypes.contains(keyType) else {
                throw AgentPolicyError.invalid("Unsupported host key type '\(keyType)' for '\(host.name)'")
            }
        }
    }
}

public struct AgentGlobalPolicy: Codable, Equatable, Sendable {
    public var version: Int
    public var maxLeaseMinutes: Int

    public init(version: Int = 1, maxLeaseMinutes: Int = 1440) {
        self.version = version
        self.maxLeaseMinutes = maxLeaseMinutes
    }

    public func validate() throws {
        guard version == 1 else {
            throw AgentPolicyError.invalid("Unsupported global policy version \(version)")
        }
        guard (1...10080).contains(maxLeaseMinutes) else {
            throw AgentPolicyError.invalid("maxLeaseMinutes must be between 1 and 10080, got \(maxLeaseMinutes)")
        }
    }
}
