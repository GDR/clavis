import Testing
import Foundation
@testable import ClavisCore

@Suite("TokenBucketTests")
struct TokenBucketTests {

    private func makeRegisterPayload(keyLabel: String, toolName: String, leaseMinutes: UInt32) -> Data {
        var payload = Data([SSHAgentServer.registerAgentSessionRequest])
        payload.appendWireString(keyLabel)
        payload.appendWireString(toolName)
        payload.appendWireUInt32(leaseMinutes)
        return payload
    }

    private func makeSignPayload(publicKeyBlob: Data, dataToSign: Data) -> Data {
        var payload = Data([13]) // SSH2_AGENTC_SIGN_REQUEST
        payload.appendWireData(publicKeyBlob)
        payload.appendWireData(dataToSign)
        payload.appendWireUInt32(0) // flags = 0
        return payload
    }

    @Test
    func test_006_T4_burstThenRefill() {
        var now = Date()
        // 60 per minute = 1 per second
        var bucket = TokenBucket(burst: 5, refillPerMinute: 60, now: now)

        // Take burst count (5)
        for i in 1...5 {
            let granted = bucket.take(now: now)
            #expect(granted, "Token \(i) should be granted")
        }

        // Exhausted
        let deniedAtBurst = bucket.take(now: now)
        #expect(!deniedAtBurst, "Token 6 should be denied")

        // Advance 1 second -> 1 token refilled
        now = now.addingTimeInterval(1.0)
        let grantedAfter1s = bucket.take(now: now)
        #expect(grantedAfter1s, "Token after 1s refill should be granted")
        let deniedImmediate = bucket.take(now: now)
        #expect(!deniedImmediate, "Second token should be denied without time advancing")

        // Advance 0.5s -> 0.5 tokens (not enough for 1.0)
        now = now.addingTimeInterval(0.5)
        let deniedHalf = bucket.take(now: now)
        #expect(!deniedHalf, "Half token should not be enough")

        // Advance another 0.5s -> now 1.0 token total
        now = now.addingTimeInterval(0.5)
        let grantedAccumulated = bucket.take(now: now)
        #expect(grantedAccumulated, "Accumulated 1.0 token should be granted")
    }

    @Test
    func test_006_T4_noOverfill() {
        var now = Date()
        var bucket = TokenBucket(burst: 3, refillPerMinute: 60, now: now)

        // Advance time by 1000 seconds
        now = now.addingTimeInterval(1000.0)

        // Should only be able to take burst (3) tokens
        let t1 = bucket.take(now: now)
        let t2 = bucket.take(now: now)
        let t3 = bucket.take(now: now)
        let t4 = bucket.take(now: now)
        #expect(t1)
        #expect(t2)
        #expect(t3)
        #expect(!t4, "Cannot exceed burst capacity")
    }

    @Test
    func test_006_AC6_overflowDeniesAndAlerts() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let auditRecorder = InMemoryAuditRecorder()
        let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)

        try await fixture.run {
            let key = try manager.generateKey(label: "agent-ratelimit-key", biometricPolicy: .userPresence, keyPurpose: .agent)
            let policyStore = InMemoryAgentPolicyStore()
            let policy = AgentKeyPolicy(burst: 2, refillPerMinute: 6)
            try policyStore.save(policy, forFingerprint: key.fingerprint)

            var postedRateLimitNotifications: [(name: String, userInfo: [String: String])] = []
            let registry = AgentSessionRegistry(
                processInfo: { _ in (startTime: 1000, parentPid: 1) },
                auditRecorder: auditRecorder,
                watchRootExit: false
            )

            let regServer = SSHAgentServer(
                role: .personal,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry,
                agentPolicies: policyStore
            )

            let regPayload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
            let regResp = regServer.processAgentRequest(
                payload: regPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(regResp.first == 6)

            let server = SSHAgentServer(
                role: .agent,
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentSessions: registry,
                agentPolicies: policyStore,
                notificationPoster: { name, userInfo in
                    if name == "com.clavis.agentRateLimited" {
                        postedRateLimitNotifications.append((name, userInfo))
                    }
                }
            )

            let signPayload = makeSignPayload(publicKeyBlob: key.publicKeyBlob, dataToSign: Data("sign-data".utf8))

            // Request 1: Allowed (burst 2)
            let resp1 = server.processAgentRequest(payload: signPayload, clientPid: getpid(), clientStartTime: 1000)
            #expect(resp1.first == 14)

            // Request 2: Allowed
            let resp2 = server.processAgentRequest(payload: signPayload, clientPid: getpid(), clientStartTime: 1000)
            #expect(resp2.first == 14)

            // Request 3: Denied due to rate limit!
            let resp3 = server.processAgentRequest(payload: signPayload, clientPid: getpid(), clientStartTime: 1000)
            #expect(resp3 == Data([5]))

            // Verify denied signature audit
            let rateLimitedSignAudits = auditRecorder.events.filter { $0.type == .signature && $0.result == .denied && $0.reason == .rateLimited }
            #expect(rateLimitedSignAudits.count == 1)

            // Verify security alert audit
            let alerts = auditRecorder.events.filter { $0.type == .securityAlert && $0.reason == .rateLimited }
            #expect(alerts.count == 1)
            #expect(alerts.first?.result == .info)
            #expect(alerts.first?.keyFingerprint == key.fingerprint)

            // Verify notification
            #expect(postedRateLimitNotifications.count == 1)
            #expect(postedRateLimitNotifications.first?.userInfo["fingerprint"] == key.fingerprint)

            // Request 4: Denied again, but within 60s no duplicate securityAlert or notification
            let resp4 = server.processAgentRequest(payload: signPayload, clientPid: getpid(), clientStartTime: 1000)
            #expect(resp4 == Data([5]))

            let alertsAfterSecondDeny = auditRecorder.events.filter { $0.type == .securityAlert && $0.reason == .rateLimited }
            #expect(alertsAfterSecondDeny.count == 1, "Should coalesce alerts within 60 seconds")
            #expect(postedRateLimitNotifications.count == 1, "Should coalesce notifications within 60 seconds")
        }
    }
}
