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
        let expectedTypes: [(AuditEventType, String)] = [
            (.signature, "signature"),
            (.sessionStart, "session_start"),
            (.sessionExtend, "session_extend"),
            (.sessionRevoke, "session_revoke"),
            (.sessionEnd, "session_end"),
            (.keyCreate, "key_create"),
            (.keyImport, "key_import"),
            (.keyDelete, "key_delete"),
            (.keyKindChange, "key_kind_change"),
            (.lock, "lock"),
            (.securityAlert, "security_alert"),
            (.suppressed, "suppressed")
        ]
        for (eventType, expectedRaw) in expectedTypes {
            #expect(eventType.rawValue == expectedRaw)
        }

        let expectedReasons: [(AuditReason, String)] = [
            (.malformedRequest, "malformed_request"),
            (.unknownKey, "unknown_key"),
            (.noPeerAttribution, "no_peer_attribution"),
            (.gitOnlyKeyNonGitPayload, "git_only_key_non_git_payload"),
            (.gitAnchorUnavailable, "git_anchor_unavailable"),
            (.peerChanged, "peer_changed"),
            (.userCancelled, "user_cancelled"),
            (.authenticationFailed, "authentication_failed"),
            (.signingError, "signing_error"),
            (.viaPrompt, "via_prompt"),
            (.viaGitGrant, "via_git_grant"),
            (.lockNow, "lock_now"),
            (.screenLocked, "screen_locked"),
            (.partialDeletion, "partial_deletion"),
            (.noAgentSession, "no_agent_session"),
            (.auditKeyMismatch, "audit_key_mismatch"),
            (.viaAgentSession, "via_agent_session"),
            (.outsideSessionTree, "outside_session_tree"),
            (.rootExited, "root_exited"),
            (.lockAll, "lock_all"),
            (.revokedByUser, "revoked_by_user"),
            (.leaseExpired, "lease_expired"),
            (.keyChanged, "key_changed"),
            (.daemonStopping, "daemon_stopping"),
            (.sessionApproved, "session_approved")
        ]
        for (reason, expectedRaw) in expectedReasons {
            #expect(reason.rawValue == expectedRaw)
        }
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
