import Testing
import LocalAuthentication
import Foundation
@testable import ClavisCore
@testable import ClavisTestSupport

@Suite("AgentKeyPolicyTests")
struct AgentKeyPolicyTests {

    private func makeHostKeyBlob(keyType: String) -> Data {
        var data = Data()
        data.appendWireString(keyType)
        data.appendWireData(Data(repeating: 0x42, count: 32))
        return data
    }

    private func makeSetPolicyPayload(fingerprint: String, policyJson: String) -> Data {
        var payload = Data([SSHAgentServer.setAgentPolicyRequest])
        payload.appendWireString(fingerprint)
        payload.appendWireString(policyJson)
        return payload
    }

    private func makeGetPolicyPayload(fingerprint: String) -> Data {
        var payload = Data([SSHAgentServer.getAgentPolicyRequest])
        payload.appendWireString(fingerprint)
        return payload
    }

    private func makeRegisterPayload(keyLabel: String, toolName: String, leaseMinutes: UInt32) -> Data {
        var payload = Data([SSHAgentServer.registerAgentSessionRequest])
        payload.appendWireString(keyLabel)
        payload.appendWireString(toolName)
        payload.appendWireUInt32(leaseMinutes)
        return payload
    }

    @Test
    func test_006_T1_defaultsMatchDecision() {
        let policy = AgentKeyPolicy()
        #expect(policy.mode == .none)
        #expect(policy.leaseMinutes == 480)
        #expect(policy.burst == 30)
        #expect(policy.refillPerMinute == 6)
        #expect(policy.allowedHosts == [])
        #expect(policy.version == 1)
        #expect(throws: Never.self) { try policy.validate() }

        let global = AgentGlobalPolicy()
        #expect(global.maxLeaseMinutes == 1440)
        #expect(global.version == 1)
        #expect(throws: Never.self) { try global.validate() }
    }

    @Test
    func test_006_T1_validateRejectsOutOfRange() {
        // Lease minutes range 1...10080
        var p = AgentKeyPolicy(leaseMinutes: 0)
        #expect(throws: (any Error).self) { try p.validate() }
        p = AgentKeyPolicy(leaseMinutes: 10081)
        #expect(throws: (any Error).self) { try p.validate() }
        p = AgentKeyPolicy(leaseMinutes: 1)
        #expect(throws: Never.self) { try p.validate() }
        p = AgentKeyPolicy(leaseMinutes: 10080)
        #expect(throws: Never.self) { try p.validate() }

        // Burst range 1...1000
        p = AgentKeyPolicy(burst: 0)
        #expect(throws: (any Error).self) { try p.validate() }
        p = AgentKeyPolicy(burst: 1001)
        #expect(throws: (any Error).self) { try p.validate() }
        p = AgentKeyPolicy(burst: 1)
        #expect(throws: Never.self) { try p.validate() }
        p = AgentKeyPolicy(burst: 1000)
        #expect(throws: Never.self) { try p.validate() }

        // Refill per minute range 1...600
        p = AgentKeyPolicy(refillPerMinute: 0)
        #expect(throws: (any Error).self) { try p.validate() }
        p = AgentKeyPolicy(refillPerMinute: 601)
        #expect(throws: (any Error).self) { try p.validate() }
        p = AgentKeyPolicy(refillPerMinute: 1)
        #expect(throws: Never.self) { try p.validate() }
        p = AgentKeyPolicy(refillPerMinute: 600)
        #expect(throws: Never.self) { try p.validate() }

        // Version must be 1
        p = AgentKeyPolicy(version: 2)
        #expect(throws: (any Error).self) { try p.validate() }

        // More than 64 allowed hosts rejected
        let ed25519Blob = makeHostKeyBlob(keyType: "ssh-ed25519")
        let hosts65 = (1...65).map { AgentAllowedHost(name: "host\($0)", hostKeyBlob: ed25519Blob) }
        p = AgentKeyPolicy(allowedHosts: hosts65)
        #expect(throws: (any Error).self) { try p.validate() }

        let hosts64 = (1...64).map { AgentAllowedHost(name: "host\($0)", hostKeyBlob: ed25519Blob) }
        p = AgentKeyPolicy(allowedHosts: hosts64)
        #expect(throws: Never.self) { try p.validate() }

        // Host key types
        for supported in ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
            let host = AgentAllowedHost(name: "test.example.com", hostKeyBlob: makeHostKeyBlob(keyType: supported))
            p = AgentKeyPolicy(allowedHosts: [host])
            #expect(throws: Never.self, "Expected \(supported) to be supported") { try p.validate() }
        }

        let dsaHost = AgentAllowedHost(name: "dsa.example.com", hostKeyBlob: makeHostKeyBlob(keyType: "ssh-dss"))
        p = AgentKeyPolicy(allowedHosts: [dsaHost])
        #expect(throws: (any Error).self) { try p.validate() }

        let malformedHost = AgentAllowedHost(name: "bad.example.com", hostKeyBlob: Data([0x00, 0x01]))
        p = AgentKeyPolicy(allowedHosts: [malformedHost])
        #expect(throws: (any Error).self) { try p.validate() }

        // Global policy validation
        var g = AgentGlobalPolicy(maxLeaseMinutes: 0)
        #expect(throws: (any Error).self) { try g.validate() }
        g = AgentGlobalPolicy(maxLeaseMinutes: 10081)
        #expect(throws: (any Error).self) { try g.validate() }
        g = AgentGlobalPolicy(maxLeaseMinutes: 1)
        #expect(throws: Never.self) { try g.validate() }
        g = AgentGlobalPolicy(maxLeaseMinutes: 10080)
        #expect(throws: Never.self) { try g.validate() }
        g = AgentGlobalPolicy(version: 0)
        #expect(throws: (any Error).self) { try g.validate() }
    }

    @Test
    func test_006_T1_jsonRoundTrip() throws {
        let host1 = AgentAllowedHost(name: "server1.example.com", hostKeyBlob: makeHostKeyBlob(keyType: "ssh-ed25519"))
        let host2 = AgentAllowedHost(name: "server2.example.com", hostKeyBlob: makeHostKeyBlob(keyType: "ecdsa-sha2-nistp256"))
        let original = AgentKeyPolicy(
            mode: .ask,
            leaseMinutes: 120,
            allowedHosts: [host1, host2],
            burst: 50,
            refillPerMinute: 10,
            version: 1
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(original)
        let decoded = try JSONDecoder().decode(AgentKeyPolicy.self, from: data)
        #expect(decoded == original)

        let originalGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 720)
        let globalData = try encoder.encode(originalGlobal)
        let decodedGlobal = try JSONDecoder().decode(AgentGlobalPolicy.self, from: globalData)
        #expect(decodedGlobal == originalGlobal)
    }

    @Test
    func test_006_T1_keychainAgentPolicyStoreOperations() throws {
        var storage: [String: Data] = [:]
        let store = KeychainAgentPolicyStore(
            service: "com.clavis.test-agent-policy",
            addItem: { dict in
                let d = dict as! [String: Any]
                let account = d[kSecAttrAccount as String] as! String
                let data = d[kSecValueData as String] as! Data
                if storage[account] != nil { return errSecDuplicateItem }
                storage[account] = data
                return errSecSuccess
            },
            deleteItem: { dict in
                let d = dict as! [String: Any]
                let account = d[kSecAttrAccount as String] as! String
                storage.removeValue(forKey: account)
                return errSecSuccess
            },
            updateItem: { query, dict in
                let q = query as! [String: Any]
                let d = dict as! [String: Any]
                let account = q[kSecAttrAccount as String] as! String
                guard storage[account] != nil else { return errSecItemNotFound }
                let data = d[kSecValueData as String] as! Data
                storage[account] = data
                return errSecSuccess
            },
            copyItem: { query in
                let q = query as! [String: Any]
                let account = q[kSecAttrAccount as String] as! String
                guard let data = storage[account] else { return (errSecItemNotFound, nil) }
                return (errSecSuccess, data as AnyObject)
            }
        )

        // Missing item returns default policy
        let missing = try store.policy(forFingerprint: "SHA256:nonexistent")
        #expect(missing == AgentKeyPolicy())

        // Save and load policy
        let custom = AgentKeyPolicy(mode: .notify, leaseMinutes: 60, burst: 15, refillPerMinute: 3)
        try store.save(custom, forFingerprint: "SHA256:test1")
        let loaded = try store.policy(forFingerprint: "SHA256:test1")
        #expect(loaded == custom)

        // Delete policy
        try store.deletePolicy(forFingerprint: "SHA256:test1")
        let afterDelete = try store.policy(forFingerprint: "SHA256:test1")
        #expect(afterDelete == AgentKeyPolicy())

        // Corrupt item throws AgentPolicyError.corrupt
        storage["SHA256:corrupt"] = Data("not json".utf8)
        #expect {
            try store.policy(forFingerprint: "SHA256:corrupt")
        } throws: { error in
            (error as? AgentPolicyError) == .corrupt
        }

        // Global policy missing returns default
        let missingGlobal = try store.global()
        #expect(missingGlobal == AgentGlobalPolicy())

        // Save and load global policy
        let customGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 300)
        try store.saveGlobal(customGlobal)
        let loadedGlobal = try store.global()
        #expect(loadedGlobal == customGlobal)

        // Corrupt global policy throws corrupt
        storage[KeychainAgentPolicyStore.globalAccount] = Data("garbage".utf8)
        #expect {
            try store.global()
        } throws: { error in
            (error as? AgentPolicyError) == .corrupt
        }
    }

    @Test
    func test_006_T1_setPolicyRequiresUserPresence() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let key = try manager.generateKey(label: "agent-presence-key", biometricPolicy: .userPresence, keyPurpose: .agent)

            let policyStore = InMemoryAgentPolicyStore()
            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore,
                authenticator: authenticator
            )

            let policy = AgentKeyPolicy(mode: .notify, leaseMinutes: 120, burst: 10, refillPerMinute: 2)
            let policyData = try JSONEncoder().encode(policy)
            let policyJson = String(data: policyData, encoding: .utf8)!

            let payload = makeSetPolicyPayload(fingerprint: key.fingerprint, policyJson: policyJson)
            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )

            #expect(response == Data([6]))
            #expect(authenticator.authenticationCount == 1)

            let saved = try policyStore.policy(forFingerprint: key.fingerprint)
            #expect(saved == policy)

            let policyEvents = auditRecorder.events.filter { $0.type == .policyChange }
            #expect(policyEvents.count == 1)
            #expect(policyEvents.first?.result == .allowed)
            #expect(policyEvents.first?.keyFingerprint == key.fingerprint)
        }
    }

    @Test
    func test_006_T1_setPolicyRejectsInvalidBeforePrompt() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let key = try manager.generateKey(label: "agent-invalid-key", biometricPolicy: .userPresence, keyPurpose: .agent)

            let policyStore = InMemoryAgentPolicyStore()
            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore,
                authenticator: authenticator
            )

            // Invalid JSON
            let badJsonPayload = makeSetPolicyPayload(fingerprint: key.fingerprint, policyJson: "not json")
            let badJsonResponse = server.processAgentRequest(
                payload: badJsonPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(badJsonResponse == Data([5]))
            #expect(authenticator.authenticationCount == 0)

            // Valid JSON but out-of-range policy (burst = 99999)
            let outOfRangePolicy = AgentKeyPolicy(burst: 99999)
            let outOfRangeData = try JSONEncoder().encode(outOfRangePolicy)
            let outOfRangeJson = String(data: outOfRangeData, encoding: .utf8)!

            let outOfRangePayload = makeSetPolicyPayload(fingerprint: key.fingerprint, policyJson: outOfRangeJson)
            let outOfRangeResponse = server.processAgentRequest(
                payload: outOfRangePayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(outOfRangeResponse == Data([5]))
            #expect(authenticator.authenticationCount == 0)
        }
    }

    @Test
    func test_006_T1_setPolicyRejectsPersonalKeyFingerprint() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let personalKey = try manager.generateKey(label: "personal-key-for-policy", biometricPolicy: .userPresence, keyPurpose: .general)

            let policyStore = InMemoryAgentPolicyStore()
            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore,
                authenticator: authenticator
            )

            let policy = AgentKeyPolicy(mode: .notify)
            let policyData = try JSONEncoder().encode(policy)
            let policyJson = String(data: policyData, encoding: .utf8)!

            let payload = makeSetPolicyPayload(fingerprint: personalKey.fingerprint, policyJson: policyJson)
            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(response == Data([5]))
            #expect(authenticator.authenticationCount == 0)
        }
    }

    @Test
    func test_006_T1_corruptPolicyRefusesSessionStart() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let key = try manager.generateKey(label: "agent-corrupt-policy-key", biometricPolicy: .userPresence, keyPurpose: .agent)

            let policyStore = InMemoryAgentPolicyStore()
            policyStore.corruptFingerprints.insert(key.fingerprint)

            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore
            )

            let payload = makeRegisterPayload(keyLabel: key.label, toolName: "agent-tool", leaseMinutes: 60)
            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )

            #expect(response == Data([5]))

            let deniedEvent = auditRecorder.events.first { $0.type == .sessionStart && $0.result == .denied }
            #expect(deniedEvent != nil)
            #expect(deniedEvent?.reason == .policyUnavailable)
        }
    }

    @Test
    func test_006_T1_getAgentPolicyRoundTrip() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let key = try manager.generateKey(label: "agent-get-policy-key", biometricPolicy: .userPresence, keyPurpose: .agent)

            let policyStore = InMemoryAgentPolicyStore()
            let customPolicy = AgentKeyPolicy(mode: .ask, leaseMinutes: 240, burst: 50, refillPerMinute: 10)
            try policyStore.save(customPolicy, forFingerprint: key.fingerprint)

            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore
            )

            let payload = makeGetPolicyPayload(fingerprint: key.fingerprint)
            let response = server.processAgentRequest(
                payload: payload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )

            #expect(response.first == 6)
            var reader = DataReader(data: Data(response.dropFirst()))
            let rawJsonString = reader.readWireString()
            let jsonString = try #require(rawJsonString, "Failed to read JSON string from response")
            let decoded = try JSONDecoder().decode(AgentKeyPolicy.self, from: Data(jsonString.utf8))
            #expect(decoded == customPolicy)
        }
    }

    @Test
    func test_006_T1_globalPolicyGetAndSetRoundTrip() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let policyStore = InMemoryAgentPolicyStore()

            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore,
                authenticator: authenticator
            )

            // Default global policy via getAgentPolicyRequest("global")
            let initialGetPayload = makeGetPolicyPayload(fingerprint: KeychainAgentPolicyStore.globalAccount)
            let initialGetResponse = server.processAgentRequest(
                payload: initialGetPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(initialGetResponse.first == 6)
            var initialReader = DataReader(data: Data(initialGetResponse.dropFirst()))
            let rawInitialJson = initialReader.readWireString()
            let initialJson = try #require(rawInitialJson, "Failed to read initial global policy JSON")
            let initialDecoded = try JSONDecoder().decode(AgentGlobalPolicy.self, from: Data(initialJson.utf8))
            #expect(initialDecoded == AgentGlobalPolicy())

            // Set custom global policy via setAgentPolicyRequest("global")
            let updatedGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 360)
            let updatedData = try JSONEncoder().encode(updatedGlobal)
            let updatedJson = String(data: updatedData, encoding: .utf8)!
            let setPayload = makeSetPolicyPayload(
                fingerprint: KeychainAgentPolicyStore.globalAccount,
                policyJson: updatedJson
            )
            let setResponse = server.processAgentRequest(
                payload: setPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(setResponse == Data([6]))
            #expect(authenticator.authenticationCount == 1)
            #expect(try policyStore.global() == updatedGlobal)

            // Verify round-trip via getAgentPolicyRequest("global")
            let getResponse = server.processAgentRequest(
                payload: initialGetPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(getResponse.first == 6)
            var reader = DataReader(data: Data(getResponse.dropFirst()))
            let rawJsonString = reader.readWireString()
            let jsonString = try #require(rawJsonString, "Failed to read updated global policy JSON")
            let decoded = try JSONDecoder().decode(AgentGlobalPolicy.self, from: Data(jsonString.utf8))
            #expect(decoded == updatedGlobal)

            let policyEvents = auditRecorder.events.filter { $0.type == .policyChange }
            #expect(policyEvents.count == 1)
            #expect(policyEvents.first?.result == .allowed)
            #expect(policyEvents.first?.sensitive.keyLabel == KeychainAgentPolicyStore.globalAccount)
        }
    }

    @Test
    func test_006_T1_setGlobalPolicyRejectsInvalidBeforePrompt() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            let policyStore = InMemoryAgentPolicyStore()

            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore,
                authenticator: authenticator
            )

            // Malformed JSON
            let badJsonPayload = makeSetPolicyPayload(
                fingerprint: KeychainAgentPolicyStore.globalAccount,
                policyJson: "not json"
            )
            let badJsonResponse = server.processAgentRequest(
                payload: badJsonPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(badJsonResponse == Data([5]))
            #expect(authenticator.authenticationCount == 0)

            // Out-of-range maxLeaseMinutes
            let invalidGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 0)
            let invalidData = try JSONEncoder().encode(invalidGlobal)
            let invalidJson = String(data: invalidData, encoding: .utf8)!
            let invalidPayload = makeSetPolicyPayload(
                fingerprint: KeychainAgentPolicyStore.globalAccount,
                policyJson: invalidJson
            )
            let invalidResponse = server.processAgentRequest(
                payload: invalidPayload,
                clientPid: getpid(),
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )
            #expect(invalidResponse == Data([5]))
            #expect(authenticator.authenticationCount == 0)
        }
    }

    @Test
    func test_F03_externalDeletionOfConfiguredPolicyFailsClosed() throws {
        var storage: [String: Data] = [:]
        let makeStore = {
            KeychainAgentPolicyStore(
                service: "com.clavis.test-agent-policy-f03",
                addItem: { dict in
                    let d = dict as! [String: Any]
                    let account = d[kSecAttrAccount as String] as! String
                    let data = d[kSecValueData as String] as! Data
                    if storage[account] != nil { return errSecDuplicateItem }
                    storage[account] = data
                    return errSecSuccess
                },
                deleteItem: { dict in
                    let d = dict as! [String: Any]
                    let account = d[kSecAttrAccount as String] as! String
                    storage.removeValue(forKey: account)
                    return errSecSuccess
                },
                updateItem: { query, dict in
                    let q = query as! [String: Any]
                    let d = dict as! [String: Any]
                    let account = q[kSecAttrAccount as String] as! String
                    guard storage[account] != nil else { return errSecItemNotFound }
                    let data = d[kSecValueData as String] as! Data
                    storage[account] = data
                    return errSecSuccess
                },
                copyItem: { query in
                    let q = query as! [String: Any]
                    let account = q[kSecAttrAccount as String] as! String
                    guard let data = storage[account] else { return (errSecItemNotFound, nil) }
                    return (errSecSuccess, data as AnyObject)
                }
            )
        }

        let store = makeStore()
        let strictPolicy = AgentKeyPolicy(mode: .ask, leaseMinutes: 30, burst: 5, refillPerMinute: 1)
        try store.save(strictPolicy, forFingerprint: "SHA256:configured")
        #expect(try store.policy(forFingerprint: "SHA256:configured") == strictPolicy)

        // Simulate external SecItemDelete of the per-key policy item (bypassing deletePolicy)
        storage.removeValue(forKey: "SHA256:configured")

        // Same store instance must fail closed rather than reverting to permissive default
        #expect {
            try store.policy(forFingerprint: "SHA256:configured")
        } throws: { error in
            (error as? AgentPolicyError) == .policyUnavailable
        }

        // Fresh store instance reading persisted index must also fail closed
        let reloadedStore = makeStore()
        #expect {
            try reloadedStore.policy(forFingerprint: "SHA256:configured")
        } throws: { error in
            (error as? AgentPolicyError) == .policyUnavailable
        }

        // Explicit deletePolicy removes it from the configured index and restores default
        try reloadedStore.deletePolicy(forFingerprint: "SHA256:configured")
        #expect(try reloadedStore.policy(forFingerprint: "SHA256:configured") == AgentKeyPolicy())
    }

    @Test
    func test_F03_globalPolicyUpdateEnforcesStrictBiometricsWhenStrictAgentKeyExists() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        try await fixture.run {
            let auditRecorder = InMemoryAuditRecorder()
            let authenticator = CountingAuthenticator()
            let manager = fixture.makeKeyManager(authenticator: AllowingAuthenticator(), auditRecorder: auditRecorder)
            _ = try manager.generateKey(
                label: "strict-agent-key-f03",
                biometricPolicy: .biometryCurrentSet,
                keyPurpose: .agent
            )

            let policyStore = InMemoryAgentPolicyStore()
            let server = SSHAgentServer(
                keyManager: manager,
                controlPeerValidator: { _ in true },
                peerProcessValidator: { _, _, _ in true },
                auditRecorder: auditRecorder,
                agentPolicies: policyStore,
                authenticator: authenticator
            )

            let updatedGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 240)
            let updatedData = try JSONEncoder().encode(updatedGlobal)
            let updatedJson = String(data: updatedData, encoding: .utf8)!
            let setPayload = makeSetPolicyPayload(
                fingerprint: KeychainAgentPolicyStore.globalAccount,
                policyJson: updatedJson
            )
            let setResponse = server.processAgentRequest(
                payload: setPayload,
                clientPid: 4321,
                clientExecutablePath: "/usr/bin/clavis",
                clientStartTime: 1000,
                isTrustedControlPeer: { true }
            )

            #expect(setResponse == Data([6]))
            #expect(authenticator.authenticationCount == 1)
            #expect(authenticator.lastPolicy == .deviceOwnerAuthenticationWithBiometrics)
            #expect(authenticator.lastReason?.contains("240m") ?? false)
            #expect(authenticator.lastReason?.contains("4321") ?? false)
        }
    }

    @Test
    func test_F01_F03_promptsIncludeRequesterModeHostsAndPolicyDetails() {
        let legacyPrompt = ClavisUIStrings.AgentSession.approvePrompt(
            tool: "/usr/bin/claude",
            keyLabel: "my-key",
            minutes: 30
        )
        #expect(legacyPrompt == "Start agent session for “claude” with key “my-key” for 30 minutes")

        let host = AgentAllowedHost(name: "github.com", hostKeyBlob: makeHostKeyBlob(keyType: "ssh-ed25519"))
        let detailedPrompt = ClavisUIStrings.AgentSession.approvePrompt(
            tool: "/tmp/custom/claude",
            keyLabel: "my-key",
            minutes: 60,
            requester: "/usr/local/bin/clavis (PID 999)",
            mode: .ask,
            allowedHosts: [host]
        )
        #expect(detailedPrompt.contains("claude (/tmp/custom/claude)"))
        #expect(detailedPrompt.contains("mode: ask"))
        #expect(detailedPrompt.contains("hosts: github.com"))
        #expect(detailedPrompt.contains("requested by /usr/local/bin/clavis (PID 999)"))

        let policyReason = ClavisUIStrings.AgentPolicy.authReason(
            keyLabel: "my-key",
            requester: "/usr/local/bin/clavis (PID 999)",
            mode: .notify,
            leaseMinutes: 120
        )
        #expect(policyReason.contains("mode=notify"))
        #expect(policyReason.contains("lease=120m"))
        #expect(policyReason.contains("PID 999"))

        // Resolve executable path helper preserves full paths and resolves bare commands in PATH
        let resolvedEcho = AgentRunner.resolveExecutablePath("sh", environment: ["PATH": "/bin:/usr/bin"])
        #expect(resolvedEcho.hasSuffix("/sh") && resolvedEcho.contains("/"))
        let resolvedRelative = AgentRunner.resolveExecutablePath("/tmp/../usr/bin/git")
        #expect(resolvedRelative.hasSuffix("/usr/bin/git"))
    }

    @Test
    func test_F03_defect2_keychainAgentPolicyStoreGlobalConcurrency() throws {
        var storage: [String: Data] = [:]
        let lock = NSLock()
        let store = KeychainAgentPolicyStore(
            service: "com.clavis.test-agent-policy-concurrency",
            addItem: { dict in
                lock.lock()
                defer { lock.unlock() }
                let d = dict as! [String: Any]
                let account = d[kSecAttrAccount as String] as! String
                let data = d[kSecValueData as String] as! Data
                if storage[account] != nil { return errSecDuplicateItem }
                storage[account] = data
                return errSecSuccess
            },
            deleteItem: { dict in
                lock.lock()
                defer { lock.unlock() }
                let d = dict as! [String: Any]
                let account = d[kSecAttrAccount as String] as! String
                storage.removeValue(forKey: account)
                return errSecSuccess
            },
            updateItem: { query, dict in
                lock.lock()
                defer { lock.unlock() }
                let q = query as! [String: Any]
                let d = dict as! [String: Any]
                let account = q[kSecAttrAccount as String] as! String
                guard storage[account] != nil else { return errSecItemNotFound }
                let data = d[kSecValueData as String] as! Data
                storage[account] = data
                return errSecSuccess
            },
            copyItem: { query in
                lock.lock()
                defer { lock.unlock() }
                let q = query as! [String: Any]
                let account = q[kSecAttrAccount as String] as! String
                guard let data = storage[account] else { return (errSecItemNotFound, nil) }
                return (errSecSuccess, data as AnyObject)
            }
        )

        let iterations = 50
        DispatchQueue.concurrentPerform(iterations: iterations) { i in
            if i % 2 == 0 {
                let policy = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 60 + i)
                try? store.saveGlobal(policy)
            } else {
                _ = try? store.global()
            }
        }

        let finalGlobal = try store.global()
        #expect(finalGlobal.maxLeaseMinutes >= 60)
    }

    @Test
    func test_F03_defect3_transientKeychainErrorPreservesConfiguredIndex() throws {
        final class StorageBox: @unchecked Sendable {
            var storage: [String: Data] = [:]
            var simulateTransientIndexError = false
        }
        let box = StorageBox()

        let store = KeychainAgentPolicyStore(
            service: "com.clavis.test-agent-policy-transient-error",
            addItem: { dict in
                let d = dict as! [String: Any]
                let account = d[kSecAttrAccount as String] as! String
                let data = d[kSecValueData as String] as! Data
                if box.storage[account] != nil { return errSecDuplicateItem }
                box.storage[account] = data
                return errSecSuccess
            },
            deleteItem: { dict in
                let d = dict as! [String: Any]
                let account = d[kSecAttrAccount as String] as! String
                box.storage.removeValue(forKey: account)
                return errSecSuccess
            },
            updateItem: { query, dict in
                let q = query as! [String: Any]
                let d = dict as! [String: Any]
                let account = q[kSecAttrAccount as String] as! String
                guard box.storage[account] != nil else { return errSecItemNotFound }
                let data = d[kSecValueData as String] as! Data
                box.storage[account] = data
                return errSecSuccess
            },
            copyItem: { query in
                let q = query as! [String: Any]
                let account = q[kSecAttrAccount as String] as! String
                if account == KeychainAgentPolicyStore.configuredIndexAccount && box.simulateTransientIndexError {
                    return (errSecIO, nil)
                }
                guard let data = box.storage[account] else { return (errSecItemNotFound, nil) }
                return (errSecSuccess, data as AnyObject)
            }
        )

        // Step 1: Successfully save Key A
        let policyA = AgentKeyPolicy(mode: .ask, leaseMinutes: 30, burst: 5, refillPerMinute: 1)
        try store.save(policyA, forFingerprint: "SHA256:keyA")

        // Step 2: Inject transient Keychain read failure for configured-index account
        box.simulateTransientIndexError = true

        // Step 3: Attempt to save Key B - MUST fail and throw error rather than silently overwriting index
        let policyB = AgentKeyPolicy(mode: .notify, leaseMinutes: 60, burst: 10, refillPerMinute: 2)
        #expect {
            try store.save(policyB, forFingerprint: "SHA256:keyB")
        } throws: { error in
            (error as? AgentPolicyError) == .corrupt
        }

        // Step 4: Resolve transient read error
        box.simulateTransientIndexError = false

        // Step 5: Verify Key A's index was NOT wiped out in Keychain storage
        let indexData = box.storage[KeychainAgentPolicyStore.configuredIndexAccount]
        let rawIndex = try #require(indexData)
        let persistedList = try JSONDecoder().decode([String].self, from: rawIndex)
        #expect(persistedList.contains("SHA256:keyA"), "Key A must remain in the persisted index")

        // Step 6: Verify fail-closed behavior: external deletion of Key A must throw policyUnavailable
        box.storage.removeValue(forKey: "SHA256:keyA")
        #expect {
            try store.policy(forFingerprint: "SHA256:keyA")
        } throws: { error in
            (error as? AgentPolicyError) == .policyUnavailable
        }
    }
}
