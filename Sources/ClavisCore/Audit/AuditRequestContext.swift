import Foundation

public extension AuditEvent {
    /// Request identity is sealed with other sensitive data. The original event
    /// identifier and timestamp remain stable for linked History records.
    func withRequestContext(operation: KeyOperation?, callerName: String?, uncertain: Bool?) -> AuditEvent {
        var details = sensitive
        details.requestOperation = operation
        details.callerName = callerName
        details.callerUncertain = uncertain
        return AuditEvent(id: id, time: time, type: type, result: result, reason: reason,
            keyFingerprint: keyFingerprint, keyKind: keyKind, sessionID: sessionID,
            count: count, sensitive: details)
    }
}
