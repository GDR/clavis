import Testing
import Foundation
import LocalAuthentication
@testable import ClavisCore

@Suite struct AuditEventTests {

    @Test func test_002_C1_eventHasNoFreeTextFields() {
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
        #expect(eventProperties == expectedEventProperties)

        let sensitive = AuditSensitive(keyLabel: nil, processChain: [], host: nil)
        let sensitiveMirror = Mirror(reflecting: sensitive)
        let sensitiveProperties = Set(sensitiveMirror.children.compactMap { $0.label })
        let expectedSensitiveProperties: Set<String> = [
            "keyLabel",
            "processChain",
            "host"
        ]
        #expect(sensitiveProperties == expectedSensitiveProperties)
    }

    @Test func test_002_T1_reasonRawValuesAreStable() {
        #expect(AuditEventType.signature.rawValue == "signature")
        #expect(AuditEventType.sessionStart.rawValue == "session_start")
        #expect(AuditEventType.sessionExtend.rawValue == "session_extend")
        #expect(AuditEventType.sessionRevoke.rawValue == "session_revoke")
        #expect(AuditEventType.sessionEnd.rawValue == "session_end")
        #expect(AuditEventType.keyCreate.rawValue == "key_create")
        #expect(AuditEventType.keyImport.rawValue == "key_import")
        #expect(AuditEventType.keyDelete.rawValue == "key_delete")
        #expect(AuditEventType.keyKindChange.rawValue == "key_kind_change")
        #expect(AuditEventType.lock.rawValue == "lock")
        #expect(AuditEventType.securityAlert.rawValue == "security_alert")
        #expect(AuditEventType.suppressed.rawValue == "suppressed")

        #expect(AuditReason.malformedRequest.rawValue == "malformed_request")
        #expect(AuditReason.unknownKey.rawValue == "unknown_key")
        #expect(AuditReason.noPeerAttribution.rawValue == "no_peer_attribution")
        #expect(AuditReason.gitOnlyKeyNonGitPayload.rawValue == "git_only_key_non_git_payload")
        #expect(AuditReason.gitAnchorUnavailable.rawValue == "git_anchor_unavailable")
        #expect(AuditReason.peerChanged.rawValue == "peer_changed")
        #expect(AuditReason.userCancelled.rawValue == "user_cancelled")
        #expect(AuditReason.authenticationFailed.rawValue == "authentication_failed")
        #expect(AuditReason.signingError.rawValue == "signing_error")
        #expect(AuditReason.viaPrompt.rawValue == "via_prompt")
        #expect(AuditReason.viaGitGrant.rawValue == "via_git_grant")
        #expect(AuditReason.lockNow.rawValue == "lock_now")
        #expect(AuditReason.screenLocked.rawValue == "screen_locked")
        #expect(AuditReason.partialDeletion.rawValue == "partial_deletion")
        #expect(AuditReason.noAgentSession.rawValue == "no_agent_session")
        #expect(AuditReason.auditKeyMismatch.rawValue == "audit_key_mismatch")
        #expect(AuditReason.viaAgentSession.rawValue == "via_agent_session")
        #expect(AuditReason.outsideSessionTree.rawValue == "outside_session_tree")
        #expect(AuditReason.rootExited.rawValue == "root_exited")
        #expect(AuditReason.lockAll.rawValue == "lock_all")
        #expect(AuditReason.revokedByUser.rawValue == "revoked_by_user")
        #expect(AuditReason.leaseExpired.rawValue == "lease_expired")
        #expect(AuditReason.keyChanged.rawValue == "key_changed")
        #expect(AuditReason.daemonStopping.rawValue == "daemon_stopping")
        #expect(AuditReason.sessionApproved.rawValue == "session_approved")
    }

    @Test func test_002_T1_sanitizedPathStripsControlAndBidi() {
        // Construct string with newline, control chars, bidi override (\u{202E}), and >512 length
        let bidiChar = "\u{202E}"
        let controlChar = "\u{0007}"
        let newlines = "\n\r"
        let padding = String(repeating: "a", count: 600)
        let rawPath = "/usr/bin/\(controlChar)test\(newlines)\(bidiChar)/\(padding)"

        let sanitized = AuditEvent.sanitizedPath(rawPath)

        #expect(sanitized.count <= 512)
        #expect(!sanitized.contains("\n"))
        #expect(!sanitized.contains("\r"))
        #expect(!sanitized.contains(bidiChar))
        #expect(!sanitized.contains(controlChar))
    }

    @Test func test_002_T1_isUserCancellation() {
        let cancelError = LAError(.userCancel)
        #expect(AuditEvent.isUserCancellation(cancelError))
        #expect(AuditEvent.isUserCancellation(UserAuthenticationError.rejected(cancelError)))
        #expect(AuditEvent.isUserCancellation(UserAuthenticationError.timedOut))

        let authFailedError = LAError(.authenticationFailed)
        #expect(!AuditEvent.isUserCancellation(authFailedError))
        #expect(!AuditEvent.isUserCancellation(UserAuthenticationError.rejected(authFailedError)))
    }
}
