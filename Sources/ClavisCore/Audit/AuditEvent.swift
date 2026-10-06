import Foundation
import LocalAuthentication

public enum AuditEventType: String, Codable, CaseIterable, Sendable {
    case signature
    case sessionStart = "session_start"     // emitted by story 001
    case sessionExtend = "session_extend"   // story 006
    case sessionRevoke = "session_revoke"   // story 001/006
    case sessionEnd = "session_end"         // story 001
    case policyChange = "policy_change"     // story 006
    case keyCreate = "key_create"
    case keyImport = "key_import"
    case keyDelete = "key_delete"
    case keyKindChange = "key_kind_change"  // story 005
    case lock
    case securityAlert = "security_alert"
    case suppressed                          // flood aggregate row
}

public enum AuditResult: String, Codable, CaseIterable, Sendable {
    case allowed, denied, cancelled, failed, info
}

public enum AuditKeyKind: String, Codable, CaseIterable, Sendable {
    case personal, agent                     // always .personal until story 005
}

extension KeyPurpose {
    public var auditKind: AuditKeyKind {
        self == .agent ? .agent : .personal
    }
}

/// Machine-readable reason. Never free text (story 002 C1).
public enum AuditReason: String, Codable, CaseIterable, Sendable {
    case malformedRequest = "malformed_request"
    case unknownKey = "unknown_key"
    case noPeerAttribution = "no_peer_attribution"
    case gitOnlyKeyNonGitPayload = "git_only_key_non_git_payload"
    case gitAnchorUnavailable = "git_anchor_unavailable"
    case peerChanged = "peer_changed"
    case userCancelled = "user_cancelled"
    case authenticationFailed = "authentication_failed"
    case signingError = "signing_error"
    case viaPrompt = "via_prompt"
    case viaGitGrant = "via_git_grant"
    case lockNow = "lock_now"
    case screenLocked = "screen_locked"
    case partialDeletion = "partial_deletion"
    case noAgentSession = "no_agent_session"
    case wrongKeyKind = "wrong_key_kind"
    case auditKeyMismatch = "audit_key_mismatch"
    case viaAgentSession = "via_agent_session"
    case outsideSessionTree = "outside_session_tree"
    case rootExited = "root_exited"
    case lockAll = "lock_all"
    case revokedByUser = "revoked_by_user"
    case leaseExpired = "lease_expired"
    case keyChanged = "key_changed"
    case daemonStopping = "daemon_stopping"
    case sessionApproved = "session_approved"
    case policyUnavailable = "policy_unavailable"
    case rateLimited = "rate_limited"
    case forwardingRefused = "forwarding_refused"
    case hostNotAllowed = "host_not_allowed"
}

public struct AuditProcess: Codable, Equatable, Sendable {
    public let executablePath: String   // sanitized, max 512 chars
    public let pid: Int32

    public init(executablePath: String, pid: Int32) {
        self.executablePath = AuditEvent.sanitizedPath(executablePath)
        self.pid = pid
    }
}

/// Fields that story 008 will encrypt. Keep this the ONLY place for them.
public struct AuditSensitive: Codable, Equatable, Sendable {
    public var keyLabel: String?
    public var processChain: [AuditProcess]   // [0] = direct peer, then parents
    public var host: String?                  // filled by story 006

    public init(
        keyLabel: String? = nil,
        processChain: [AuditProcess] = [],
        host: String? = nil
    ) {
        self.keyLabel = keyLabel
        self.processChain = processChain
        self.host = host
    }
}

public struct AuditEvent: Equatable, Sendable {
    public let id: UUID
    public let time: Date
    public let type: AuditEventType
    public let result: AuditResult
    public let reason: AuditReason?
    public let keyFingerprint: String?
    public let keyKind: AuditKeyKind?
    public let sessionID: String?
    public let count: Int                     // 1, or N for .suppressed
    public let sensitive: AuditSensitive

    public init(
        id: UUID = UUID(),
        time: Date = Date(),
        type: AuditEventType,
        result: AuditResult,
        reason: AuditReason? = nil,
        keyFingerprint: String? = nil,
        keyKind: AuditKeyKind? = nil,
        sessionID: String? = nil,
        count: Int = 1,
        sensitive: AuditSensitive = AuditSensitive(keyLabel: nil, processChain: [], host: nil)
    ) {
        self.id = id
        self.time = time
        self.type = type
        self.result = result
        self.reason = reason
        self.keyFingerprint = keyFingerprint
        self.keyKind = keyKind
        self.sessionID = sessionID
        self.count = count
        self.sensitive = sensitive
    }

    public static func sanitizedPath(_ path: String) -> String {
        let cleaned = String(String.UnicodeScalarView(path.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0)
                && !CharacterSet.newlines.contains($0)
                && !Self.isBidiScalar($0)
                && $0.properties.generalCategory != .format
                && $0.properties.generalCategory != .control
                && $0.properties.generalCategory != .lineSeparator
                && $0.properties.generalCategory != .paragraphSeparator
        }))
        if cleaned.count > 512 {
            return String(cleaned.prefix(512))
        }
        return cleaned
    }

    private static func isBidiScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
            return true
        default:
            return false
        }
    }

    public static func isUserCancellation(_ error: Error) -> Bool {
        if let authError = error as? UserAuthenticationError {
            switch authError {
            case .timedOut:
                return true
            case .rejected(let underlying):
                if let underlying = underlying {
                    return isUserCancellation(underlying)
                }
                return false
            }
        }
        if let laError = error as? LAError {
            return laError.code == .userCancel || laError.code == .userFallback || laError.code == .appCancel || laError.code == .systemCancel
        }
        let nsError = error as NSError
        if nsError.domain == LAErrorDomain {
            let code = LAError.Code(rawValue: nsError.code)
            return code == .userCancel || code == .userFallback || code == .appCancel || code == .systemCancel
        }
        return false
    }
}

/// A stored row (event + store-assigned sequence number).
public struct AuditRecord: Equatable, Sendable {
    public let seq: Int64
    public let event: AuditEvent
    public let sensitiveFormat: Int
    public let sealedSensitive: Data?

    public init(
        seq: Int64,
        event: AuditEvent,
        sensitiveFormat: Int = 0,
        sealedSensitive: Data? = nil
    ) {
        self.seq = seq
        self.event = event
        self.sensitiveFormat = sensitiveFormat
        self.sealedSensitive = sealedSensitive
    }
}
