import Testing
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport
@testable import Clavis

@Suite("AppStateAgentSessionTests")
struct AppStateAgentSessionTests {

    @MainActor
    private struct TestEnv {
        let fixture: ClavisTestFixture
        let manager: KeychainManager
        let auditRecorder: InMemoryAuditRecorder
        let registry: AgentSessionRegistry
        let server: SSHAgentServer
        let lifecycle: AgentLifecycleManager

        init() throws {
            let fixture = try ClavisTestFixture()
            let auditRecorder = InMemoryAuditRecorder()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let registry = AgentSessionRegistry(auditRecorder: auditRecorder)
            let sockPath = fixture.testRootURL.appendingPathComponent("appstate-agent.sock").path

            let server = SSHAgentServer(
                socketPath: sockPath,
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry,
                authenticator: AllowingAuthenticator(),
                testContext: fixture.context
            )
            try server.start()
            let lifecycle = AgentLifecycleManager(socketPath: sockPath, isTrustedServerPeer: { _ in true })

            self.fixture = fixture
            self.manager = manager
            self.auditRecorder = auditRecorder
            self.registry = registry
            self.server = server
            self.lifecycle = lifecycle
        }

        func cleanup() {
            server.stop()
            fixture.cleanup()
        }
    }

    @Test
    @MainActor
    func testRevokeAllAgentSessionsReturnsCount() async throws {
        let env = try TestEnv()
        defer { env.cleanup() }

        try await env.fixture.run {
            let appState = AppState(
                keyManager: env.manager,
                sshAgentServer: env.server,
                agentLifecycle: env.lifecycle
            )

            let key = try env.manager.generateKey(label: "agent-revoke-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            _ = try env.lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-1", leaseMinutes: 10)
            _ = try env.lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-2", leaseMinutes: 10)
            #expect(env.lifecycle.listAgentSessions().count == 2)

            let revoked = appState.revokeAllAgentSessions()
            #expect(revoked == 2)
            #expect(env.lifecycle.listAgentSessions().count == 0)
        }
    }

    @Test
    @MainActor
    func testExtendAgentSessionReturnsNewExpiry() async throws {
        let env = try TestEnv()
        defer { env.cleanup() }

        try await env.fixture.run {
            let appState = AppState(
                keyManager: env.manager,
                sshAgentServer: env.server,
                agentLifecycle: env.lifecycle
            )

            let key = try env.manager.generateKey(label: "agent-extend-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let session = try env.lifecycle.registerAgentSession(keyLabel: key.label, toolName: "tool-extend", leaseMinutes: 10)

            let extended = appState.extendAgentSession(id: session.id, minutes: 30)
            #expect(extended != nil)
            if let extended {
                let diff = extended.timeIntervalSince(Date())
                // Should now be around 40 minutes (10 initial + 30 added)
                #expect(diff > 38 * 60)
                #expect(diff <= 41 * 60)
            }
        }
    }

    @Test
    @MainActor
    func testNotificationsAndCoalescing() async throws {
        let env = try TestEnv()
        defer { env.cleanup() }

        try await env.fixture.run {
            let appState = AppState(
                keyManager: env.manager,
                sshAgentServer: env.server,
                agentLifecycle: env.lifecycle
            )

            var postedNotifications: [(title: String, body: String)] = []
            appState.onAgentNotificationPosted = { title, body in
                postedNotifications.append((title: title, body: body))
            }

            let key = try env.manager.generateKey(label: "notif-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let session1 = try env.lifecycle.registerAgentSession(keyLabel: key.label, toolName: "agent-1", leaseMinutes: 10)
            let session2 = try env.lifecycle.registerAgentSession(keyLabel: key.label, toolName: "agent-2", leaseMinutes: 10)

            // Set agentSessions directly for deterministic testing in headless CI
            appState.agentSessions = env.lifecycle.listAgentSessions()
            #expect(appState.agentSessions.count == 2)

            // 1. Post agentSigned for session 1 directly to test notification formatting
            appState.handleAgentSignedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentSigned"),
                object: nil,
                userInfo: ["sessionID": session1.id, "fingerprint": key.fingerprint]
            ))

            #expect(postedNotifications.count == 1)
            #expect(postedNotifications.first?.title == ClavisUIStrings.AgentSession.notificationSignedTitle)
            #expect(postedNotifications.first?.body == "agent-1 · notif-key")

            // 2. Post agentSigned immediately again for session 1 -> must be COALESCED
            appState.handleAgentSignedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentSigned"),
                object: nil,
                userInfo: ["sessionID": session1.id, "fingerprint": key.fingerprint]
            ))

            #expect(postedNotifications.count == 1, "Immediate repeat notification for same session must be coalesced")

            // 3. Post agentSigned for session 2 -> NOT coalesced
            appState.handleAgentSignedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentSigned"),
                object: nil,
                userInfo: ["sessionID": session2.id, "fingerprint": key.fingerprint]
            ))

            #expect(postedNotifications.count == 2)
            #expect(postedNotifications.last?.body == "agent-2 · notif-key")

            // 4. Post agentRateLimited for session 1
            appState.handleAgentRateLimitedNotification(Notification(
                name: NSNotification.Name("com.clavis.agentRateLimited"),
                object: nil,
                userInfo: ["sessionID": session1.id, "fingerprint": key.fingerprint]
            ))

            #expect(postedNotifications.count == 3)
            #expect(postedNotifications.last?.title == ClavisUIStrings.AgentSession.notificationRateLimitedTitle)
            #expect(postedNotifications.last?.body == "agent-1 · notif-key")
        }
    }
}
