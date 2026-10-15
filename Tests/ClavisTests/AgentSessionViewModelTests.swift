import Testing
import Foundation
@testable import ClavisCore
@testable import Clavis

@Suite
final class AgentSessionViewModelTests {
    private let fixture: ClavisTestFixture
    private let mockAgent: MockAgentController

    init() throws {
        self.fixture = try ClavisTestFixture()
        self.mockAgent = MockAgentController()
    }

    deinit {
        fixture.cleanup()
    }

    @Test @MainActor
    func testRefreshAgentSessionsPopulatesList() async throws {
        let initialSession = AgentSessionSummary(
            id: "sess-1",
            keyLabel: "test-key",
            keyFingerprint: "SHA256:111",
            toolName: "git-tool",
            rootPid: 1234,
            startedAt: Date(),
            expiresAt: Date().addingTimeInterval(3600)
        )
        mockAgent.stubbedSessions = [initialSession]

        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)

        // Wait for detached task to complete
        for _ in 0..<50 {
            if viewModel.agentSessions.count == 1 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(viewModel.agentSessions.count == 1)
        #expect(viewModel.agentSessions.first?.id == "sess-1")
        #expect(viewModel.agentSessions.first?.toolName == "git-tool")
    }

    @Test @MainActor
    func testEndAgentSessionRemovesSession() async throws {
        let session = AgentSessionSummary(
            id: "sess-to-end",
            keyLabel: "test-key",
            keyFingerprint: "SHA256:222",
            toolName: "builder",
            rootPid: 4321,
            startedAt: Date(),
            expiresAt: Date().addingTimeInterval(1800)
        )
        mockAgent.stubbedSessions = [session]

        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        for _ in 0..<50 {
            if viewModel.agentSessions.count == 1 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(viewModel.agentSessions.count == 1)

        viewModel.endAgentSession(id: "sess-to-end")

        for _ in 0..<50 {
            if viewModel.agentSessions.isEmpty { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        #expect(viewModel.agentSessions.count == 0)
        #expect(mockAgent.endAgentSessionCallCount == 1)
        #expect(mockAgent.recordedEndSessionIDs == ["sess-to-end"])
    }

    @Test @MainActor
    func testRevokeAllAgentSessionsReturnsCount() throws {
        let session1 = AgentSessionSummary(
            id: "s1", keyLabel: "k1", keyFingerprint: "fp1",
            toolName: "t1", rootPid: 101, startedAt: Date(), expiresAt: Date().addingTimeInterval(600)
        )
        let session2 = AgentSessionSummary(
            id: "s2", keyLabel: "k2", keyFingerprint: "fp2",
            toolName: "t2", rootPid: 102, startedAt: Date(), expiresAt: Date().addingTimeInterval(600)
        )
        mockAgent.stubbedSessions = [session1, session2]

        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        let revoked = viewModel.revokeAllAgentSessions()

        #expect(revoked == 2)
        #expect(mockAgent.revokeAllAgentSessionsCallCount == 1)
        #expect(mockAgent.stubbedSessions.count == 0)
    }

    @Test @MainActor
    func testExtendAgentSessionUpdatesExpiry() throws {
        let start = Date()
        let initialExpiry = start.addingTimeInterval(600)
        let session = AgentSessionSummary(
            id: "s-ext", keyLabel: "k-ext", keyFingerprint: "fp-ext",
            toolName: "t-ext", rootPid: 201, startedAt: start, expiresAt: initialExpiry
        )
        mockAgent.stubbedSessions = [session]

        let viewModel = AgentSessionViewModel(agentLifecycle: mockAgent)
        let newDate = viewModel.extendAgentSession(id: "s-ext", minutes: 30)

        #expect(newDate != nil)
        let diff = abs((newDate?.timeIntervalSince(initialExpiry) ?? 0) - 1800)
        #expect(diff < 1.0)
        #expect(mockAgent.extendAgentSessionCallCount == 1)
        #expect(mockAgent.recordedExtendCalls.first?.id == "s-ext")
        #expect(mockAgent.recordedExtendCalls.first?.minutes == 30)
    }

    @Test @MainActor
    func testNotificationsCoalescingAndFormatting() throws {
        let dummyKey = SSHKeyInfo(
            label: "key-from-provider",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:provider-fp"
        )
        let viewModel = AgentSessionViewModel(
            agentLifecycle: mockAgent,
            keysProvider: { [dummyKey] }
        )

        var notifications: [(title: String, body: String)] = []
        viewModel.onAgentNotificationPosted = { title, body in
            notifications.append((title: title, body: body))
        }

        let session = AgentSessionSummary(
            id: "sess-notif", keyLabel: "active-key", keyFingerprint: "fp-1",
            toolName: "curl", rootPid: 501, startedAt: Date(), expiresAt: Date().addingTimeInterval(600)
        )
        viewModel.agentSessions = [session]

        // 1. Post signed notification for existing session
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "sess-notif"]
        ))

        #expect(notifications.count == 1)
        #expect(notifications[0].title == ClavisUIStrings.AgentSession.notificationSignedTitle)
        #expect(notifications[0].body == "curl · active-key")

        // 2. Post immediate repeat notification -> must coalesce
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "sess-notif"]
        ))
        #expect(notifications.count == 1, "Immediate repeat notification for same sessionID must be coalesced")

        // 3. Post rate limited notification (not rate-coalesced by the 10s cooldown)
        viewModel.handleAgentRateLimitedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentRateLimited"),
            object: nil,
            userInfo: ["sessionID": "sess-notif"]
        ))
        #expect(notifications.count == 2)
        #expect(notifications[1].title == ClavisUIStrings.AgentSession.notificationRateLimitedTitle)
        #expect(notifications[1].body == "curl · active-key")

        // 4. Notification with unknown session but matching fingerprint via keysProvider
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "unknown-sess-1", "fingerprint": "SHA256:provider-fp"]
        ))
        #expect(notifications.count == 3)
        #expect(notifications[2].body == "key-from-provider")

        // 5. Notification with unknown session and unknown fingerprint
        viewModel.handleAgentSignedNotification(Notification(
            name: NSNotification.Name("com.clavis.agentSigned"),
            object: nil,
            userInfo: ["sessionID": "unknown-sess-2", "fingerprint": "SHA256:unmatched"]
        ))
        #expect(notifications.count == 4)
        #expect(notifications[3].body == "unknown-sess-2")
    }
}
