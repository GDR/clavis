import XCTest
import Foundation
@testable import ClavisCore
@testable import Clavis

final class AppStateAgentSessionTests: ClavisBaseTestCase {
    var manager: KeychainManager!
    var auditRecorder: InMemoryAuditRecorder!
    var registry: AgentSessionRegistry!
    var server: SSHAgentServer!
    var sockPath: String!
    var lifecycle: AgentLifecycleManager!

    override func setUpWithError() throws {
        try super.setUpWithError()
        auditRecorder = InMemoryAuditRecorder()
        manager = makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
        registry = AgentSessionRegistry(auditRecorder: auditRecorder)
        sockPath = testRootURL.appendingPathComponent("appstate-agent.sock").path

        server = SSHAgentServer(
            socketPath: sockPath,
            role: .personal,
            keyManager: manager,
            controlPeerValidator: { _ in true },
            peerProcessValidator: { _, _, _ in true },
            auditRecorder: auditRecorder,
            agentSessions: registry,
            authenticator: AllowingAuthenticator()
        )
        try server.start()

        lifecycle = AgentLifecycleManager(socketPath: sockPath)
    }

    override func tearDownWithError() throws {
        server?.stop()
        lifecycle = nil
        server = nil
        try super.tearDownWithError()
    }

    @MainActor
    func testRevokeAllAgentSessionsReturnsCount() throws {
        let appState = AppState(
            keyManager: manager,
            sessionCache: makeSessionCache(),
            sshAgentServer: server,
            agentLifecycle: lifecycle
        )

        let key = try manager.generateKey(label: "agent-revoke-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        _ = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-1", leaseMinutes: 10)
        _ = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-2", leaseMinutes: 10)
        XCTAssertEqual(lifecycle.listAgentSessions().count, 2)

        let revoked = appState.revokeAllAgentSessions()
        XCTAssertEqual(revoked, 2)
        XCTAssertEqual(lifecycle.listAgentSessions().count, 0)
    }

    @MainActor
    func testExtendAgentSessionReturnsNewExpiry() throws {
        let appState = AppState(
            keyManager: manager,
            sessionCache: makeSessionCache(),
            sshAgentServer: server,
            agentLifecycle: lifecycle
        )

        let key = try manager.generateKey(label: "agent-extend-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let session = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-extend", leaseMinutes: 10)

        let extended = appState.extendAgentSession(id: session.id, minutes: 30)
        XCTAssertNotNil(extended)
        if let extended {
            let diff = extended.timeIntervalSince(Date())
            // Should now be around 40 minutes (10 initial + 30 added)
            XCTAssertGreaterThan(diff, 38 * 60)
            XCTAssertLessThanOrEqual(diff, 41 * 60)
        }
    }

    @MainActor
    func testNotificationsAndCoalescing() throws {
        let appState = AppState(
            keyManager: manager,
            sessionCache: makeSessionCache(),
            sshAgentServer: server,
            agentLifecycle: lifecycle
        )

        var postedNotifications: [(title: String, body: String)] = []
        appState.onAgentNotificationPosted = { title, body in
            postedNotifications.append((title: title, body: body))
        }

        let key = try manager.generateKey(label: "notif-key", storageType: .keychain, biometricPolicy: .userPresence, keyPurpose: .agent)
        let session1 = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "agent-1", leaseMinutes: 10)
        let session2 = try lifecycle.registerAgentSession(keyLabel: key.label, toolName: "agent-2", leaseMinutes: 10)

        // Set agentSessions directly for deterministic testing in headless CI
        appState.agentSessions = lifecycle.listAgentSessions()
        XCTAssertEqual(appState.agentSessions.count, 2)

        // 1. Post agentSigned for session 1 directly to test notification formatting
        appState.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": session1.id, "fingerprint": key.fingerprint]
        ))

        XCTAssertEqual(postedNotifications.count, 1)
        XCTAssertEqual(postedNotifications.first?.title, ClavisUIStrings.AgentSession.notificationSignedTitle)
        XCTAssertEqual(postedNotifications.first?.body, "agent-1 · notif-key")

        // 2. Post agentSigned immediately again for session 1 -> must be COALESCED
        appState.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": session1.id, "fingerprint": key.fingerprint]
        ))

        XCTAssertEqual(postedNotifications.count, 1, "Immediate repeat notification for same session must be coalesced")

        // 3. Post agentSigned for session 2 -> NOT coalesced
        appState.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": session2.id, "fingerprint": key.fingerprint]
        ))

        XCTAssertEqual(postedNotifications.count, 2)
        XCTAssertEqual(postedNotifications.last?.body, "agent-2 · notif-key")

        // 4. Post agentRateLimited for session 1
        appState.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": session1.id, "fingerprint": key.fingerprint]
        ))

        XCTAssertEqual(postedNotifications.count, 3)
        XCTAssertEqual(postedNotifications.last?.title, ClavisUIStrings.AgentSession.notificationRateLimitedTitle)
        XCTAssertEqual(postedNotifications.last?.body, "agent-1 · notif-key")
    }
}
