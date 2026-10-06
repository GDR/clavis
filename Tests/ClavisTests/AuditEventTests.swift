import XCTest
import LocalAuthentication
@testable import ClavisCore

final class AuditEventTests: ClavisBaseTestCase {
    func test_002_C1_eventHasNoFreeTextFields() {
        let event = AuditEvent(
            type: .signature,
            result: .allowed
        )
        let eventMirror = Mirror(reflecting: event)
        let eventProperties = Set(eventMirror.children.compactMap { $0.label })
        let expectedEventProperties: Set<String> = [
            "id",
            "time",
            "type",
            "result",
            "reason",
            "keyFingerprint",
            "keyKind",
            "sessionID",
            "count",
            "sensitive"
        ]
        XCTAssertEqual(eventProperties, expectedEventProperties)

        let sensitive = AuditSensitive(keyLabel: nil, processChain: [], host: nil)
        let sensitiveMirror = Mirror(reflecting: sensitive)
        let sensitiveProperties = Set(sensitiveMirror.children.compactMap { $0.label })
        let expectedSensitiveProperties: Set<String> = [
            "keyLabel",
            "processChain",
            "host"
        ]
        XCTAssertEqual(sensitiveProperties, expectedSensitiveProperties)
    }

    func test_002_T1_reasonRawValuesAreStable() {
        XCTAssertEqual(AuditEventType.signature.rawValue, "signature")
        XCTAssertEqual(AuditEventType.sessionStart.rawValue, "session_start")
        XCTAssertEqual(AuditEventType.sessionExtend.rawValue, "session_extend")
        XCTAssertEqual(AuditEventType.sessionRevoke.rawValue, "session_revoke")
        XCTAssertEqual(AuditEventType.sessionEnd.rawValue, "session_end")
        XCTAssertEqual(AuditEventType.keyCreate.rawValue, "key_create")
        XCTAssertEqual(AuditEventType.keyImport.rawValue, "key_import")
        XCTAssertEqual(AuditEventType.keyDelete.rawValue, "key_delete")
        XCTAssertEqual(AuditEventType.keyKindChange.rawValue, "key_kind_change")
        XCTAssertEqual(AuditEventType.lock.rawValue, "lock")
        XCTAssertEqual(AuditEventType.securityAlert.rawValue, "security_alert")
        XCTAssertEqual(AuditEventType.suppressed.rawValue, "suppressed")

        XCTAssertEqual(AuditReason.malformedRequest.rawValue, "malformed_request")
        XCTAssertEqual(AuditReason.unknownKey.rawValue, "unknown_key")
        XCTAssertEqual(AuditReason.noPeerAttribution.rawValue, "no_peer_attribution")
        XCTAssertEqual(AuditReason.gitOnlyKeyNonGitPayload.rawValue, "git_only_key_non_git_payload")
        XCTAssertEqual(AuditReason.gitAnchorUnavailable.rawValue, "git_anchor_unavailable")
        XCTAssertEqual(AuditReason.peerChanged.rawValue, "peer_changed")
        XCTAssertEqual(AuditReason.userCancelled.rawValue, "user_cancelled")
        XCTAssertEqual(AuditReason.authenticationFailed.rawValue, "authentication_failed")
        XCTAssertEqual(AuditReason.signingError.rawValue, "signing_error")
        XCTAssertEqual(AuditReason.viaPrompt.rawValue, "via_prompt")
        XCTAssertEqual(AuditReason.viaGitGrant.rawValue, "via_git_grant")
        XCTAssertEqual(AuditReason.lockNow.rawValue, "lock_now")
        XCTAssertEqual(AuditReason.screenLocked.rawValue, "screen_locked")
        XCTAssertEqual(AuditReason.partialDeletion.rawValue, "partial_deletion")
        XCTAssertEqual(AuditReason.noAgentSession.rawValue, "no_agent_session")
        XCTAssertEqual(AuditReason.auditKeyMismatch.rawValue, "audit_key_mismatch")
        XCTAssertEqual(AuditReason.viaAgentSession.rawValue, "via_agent_session")
        XCTAssertEqual(AuditReason.outsideSessionTree.rawValue, "outside_session_tree")
        XCTAssertEqual(AuditReason.rootExited.rawValue, "root_exited")
        XCTAssertEqual(AuditReason.lockAll.rawValue, "lock_all")
        XCTAssertEqual(AuditReason.revokedByUser.rawValue, "revoked_by_user")
        XCTAssertEqual(AuditReason.leaseExpired.rawValue, "lease_expired")
        XCTAssertEqual(AuditReason.keyChanged.rawValue, "key_changed")
        XCTAssertEqual(AuditReason.daemonStopping.rawValue, "daemon_stopping")
        XCTAssertEqual(AuditReason.sessionApproved.rawValue, "session_approved")
    }

    func test_002_T1_sanitizedPathStripsControlAndBidi() {
        // Construct string with newline, control chars, bidi override (\u{202E}), and >512 length
        let bidiChar = "\u{202E}"
        let controlChar = "\u{0007}"
        let newlines = "\n\r"
        let padding = String(repeating: "a", count: 600)
        let rawPath = "/usr/bin/\(controlChar)test\(newlines)\(bidiChar)/\(padding)"

        let sanitized = AuditEvent.sanitizedPath(rawPath)

        XCTAssertLessThanOrEqual(sanitized.count, 512)
        XCTAssertFalse(sanitized.contains("\n"))
        XCTAssertFalse(sanitized.contains("\r"))
        XCTAssertFalse(sanitized.contains(bidiChar))
        XCTAssertFalse(sanitized.contains(controlChar))
    }

    func test_002_T1_isUserCancellation() {
        let cancelError = LAError(.userCancel)
        XCTAssertTrue(AuditEvent.isUserCancellation(cancelError))
        XCTAssertTrue(AuditEvent.isUserCancellation(UserAuthenticationError.rejected(cancelError)))
        XCTAssertTrue(AuditEvent.isUserCancellation(UserAuthenticationError.timedOut))

        let authFailedError = LAError(.authenticationFailed)
        XCTAssertFalse(AuditEvent.isUserCancellation(authFailedError))
        XCTAssertFalse(AuditEvent.isUserCancellation(UserAuthenticationError.rejected(authFailedError)))
    }
}
