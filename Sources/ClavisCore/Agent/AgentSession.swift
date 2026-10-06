import Foundation
import Security

public enum AgentSessionEndReason: String, Sendable {
    case rootExited, screenLocked, lockAll, revokedByUser, leaseExpired, keyChanged, signingError, daemonStopping
}

public struct AgentSessionRoot: Equatable, Sendable {
    public let pid: pid_t
    public let startTime: UInt64
    public init(pid: pid_t, startTime: UInt64) {
        self.pid = pid
        self.startTime = startTime
    }
}

public final class AgentSession: @unchecked Sendable, Equatable {
    public let id: String
    public let keyLabel: String
    public let keyFingerprint: String
    public let toolName: String
    public let root: AgentSessionRoot
    public let startedAt: Date
    public internal(set) var expiresAt: Date
    let grant: AgentSessionGrant

    public init(
        id: String? = nil,
        keyLabel: String,
        keyFingerprint: String,
        toolName: String,
        root: AgentSessionRoot,
        startedAt: Date = Date(),
        expiresAt: Date,
        grant: AgentSessionGrant
    ) {
        self.id = id ?? Self.generateSessionID()
        self.keyLabel = keyLabel
        self.keyFingerprint = keyFingerprint
        self.toolName = Self.sanitizeToolName(toolName)
        self.root = root
        self.startedAt = startedAt
        self.expiresAt = expiresAt
        self.grant = grant
    }

    public var summary: AgentSessionSummary {
        AgentSessionSummary(
            id: id, keyLabel: keyLabel, keyFingerprint: keyFingerprint,
            toolName: toolName, rootPid: root.pid, startedAt: startedAt, expiresAt: expiresAt
        )
    }

    public static func == (lhs: AgentSession, rhs: AgentSession) -> Bool {
        lhs.id == rhs.id
    }

    public static func generateSessionID() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func sanitizeToolName(_ raw: String) -> String {
        String(AuditEvent.sanitizedPath((raw as NSString).lastPathComponent).prefix(64))
    }
}

public struct AgentSessionSummary: Equatable, Sendable {
    public let id, keyLabel, keyFingerprint, toolName: String
    public let rootPid: pid_t
    public let startedAt, expiresAt: Date

    public init(
        id: String, keyLabel: String, keyFingerprint: String,
        toolName: String, rootPid: pid_t, startedAt: Date, expiresAt: Date
    ) {
        self.id = id
        self.keyLabel = keyLabel
        self.keyFingerprint = keyFingerprint
        self.toolName = toolName
        self.rootPid = rootPid
        self.startedAt = startedAt
        self.expiresAt = expiresAt
    }
}
