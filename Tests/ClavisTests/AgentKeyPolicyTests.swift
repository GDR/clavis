import XCTest
@testable import ClavisCore

final class AgentKeyPolicyTests: ClavisBaseTestCase {

    private func makeHostKeyBlob(keyType: String) -> Data {
        var data = Data()
        data.appendWireString(keyType)
        data.appendWireData(Data(repeating: 0x42, count: 32))
        return data
    }

    func test_006_T1_defaultsMatchDecision() {
        let policy = AgentKeyPolicy()
        XCTAssertEqual(policy.mode, .none)
        XCTAssertEqual(policy.leaseMinutes, 480)
        XCTAssertEqual(policy.burst, 30)
        XCTAssertEqual(policy.refillPerMinute, 6)
        XCTAssertEqual(policy.allowedHosts, [])
        XCTAssertEqual(policy.version, 1)
        XCTAssertNoThrow(try policy.validate())

        let global = AgentGlobalPolicy()
        XCTAssertEqual(global.maxLeaseMinutes, 1440)
        XCTAssertEqual(global.version, 1)
        XCTAssertNoThrow(try global.validate())
    }

    func test_006_T1_validateRejectsOutOfRange() {
        // Lease minutes range 1...10080
        var p = AgentKeyPolicy(leaseMinutes: 0)
        XCTAssertThrowsError(try p.validate())
        p = AgentKeyPolicy(leaseMinutes: 10081)
        XCTAssertThrowsError(try p.validate())
        p = AgentKeyPolicy(leaseMinutes: 1)
        XCTAssertNoThrow(try p.validate())
        p = AgentKeyPolicy(leaseMinutes: 10080)
        XCTAssertNoThrow(try p.validate())

        // Burst range 1...1000
        p = AgentKeyPolicy(burst: 0)
        XCTAssertThrowsError(try p.validate())
        p = AgentKeyPolicy(burst: 1001)
        XCTAssertThrowsError(try p.validate())
        p = AgentKeyPolicy(burst: 1)
        XCTAssertNoThrow(try p.validate())
        p = AgentKeyPolicy(burst: 1000)
        XCTAssertNoThrow(try p.validate())

        // Refill per minute range 1...600
        p = AgentKeyPolicy(refillPerMinute: 0)
        XCTAssertThrowsError(try p.validate())
        p = AgentKeyPolicy(refillPerMinute: 601)
        XCTAssertThrowsError(try p.validate())
        p = AgentKeyPolicy(refillPerMinute: 1)
        XCTAssertNoThrow(try p.validate())
        p = AgentKeyPolicy(refillPerMinute: 600)
        XCTAssertNoThrow(try p.validate())

        // Version must be 1
        p = AgentKeyPolicy(version: 2)
        XCTAssertThrowsError(try p.validate())

        // More than 64 allowed hosts rejected
        let ed25519Blob = makeHostKeyBlob(keyType: "ssh-ed25519")
        let hosts65 = (1...65).map { AgentAllowedHost(name: "host\($0)", hostKeyBlob: ed25519Blob) }
        p = AgentKeyPolicy(allowedHosts: hosts65)
        XCTAssertThrowsError(try p.validate())

        let hosts64 = (1...64).map { AgentAllowedHost(name: "host\($0)", hostKeyBlob: ed25519Blob) }
        p = AgentKeyPolicy(allowedHosts: hosts64)
        XCTAssertNoThrow(try p.validate())

        // Host key types
        for supported in ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"] {
            let host = AgentAllowedHost(name: "test.example.com", hostKeyBlob: makeHostKeyBlob(keyType: supported))
            p = AgentKeyPolicy(allowedHosts: [host])
            XCTAssertNoThrow(try p.validate(), "Expected \(supported) to be supported")
        }

        let rsaHost = AgentAllowedHost(name: "rsa.example.com", hostKeyBlob: makeHostKeyBlob(keyType: "ssh-rsa"))
        p = AgentKeyPolicy(allowedHosts: [rsaHost])
        XCTAssertThrowsError(try p.validate())

        let malformedHost = AgentAllowedHost(name: "bad.example.com", hostKeyBlob: Data([0x00, 0x01]))
        p = AgentKeyPolicy(allowedHosts: [malformedHost])
        XCTAssertThrowsError(try p.validate())

        // Global policy validation
        var g = AgentGlobalPolicy(maxLeaseMinutes: 0)
        XCTAssertThrowsError(try g.validate())
        g = AgentGlobalPolicy(maxLeaseMinutes: 10081)
        XCTAssertThrowsError(try g.validate())
        g = AgentGlobalPolicy(maxLeaseMinutes: 1)
        XCTAssertNoThrow(try g.validate())
        g = AgentGlobalPolicy(maxLeaseMinutes: 10080)
        XCTAssertNoThrow(try g.validate())
        g = AgentGlobalPolicy(version: 0)
        XCTAssertThrowsError(try g.validate())
    }

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
        XCTAssertEqual(decoded, original)

        let originalGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 720)
        let globalData = try encoder.encode(originalGlobal)
        let decodedGlobal = try JSONDecoder().decode(AgentGlobalPolicy.self, from: globalData)
        XCTAssertEqual(decodedGlobal, originalGlobal)
    }

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
        XCTAssertEqual(missing, AgentKeyPolicy())

        // Save and load policy
        let custom = AgentKeyPolicy(mode: .notify, leaseMinutes: 60, burst: 15, refillPerMinute: 3)
        try store.save(custom, forFingerprint: "SHA256:test1")
        let loaded = try store.policy(forFingerprint: "SHA256:test1")
        XCTAssertEqual(loaded, custom)

        // Delete policy
        try store.deletePolicy(forFingerprint: "SHA256:test1")
        let afterDelete = try store.policy(forFingerprint: "SHA256:test1")
        XCTAssertEqual(afterDelete, AgentKeyPolicy())

        // Corrupt item throws AgentPolicyError.corrupt
        storage["SHA256:corrupt"] = Data("not json".utf8)
        XCTAssertThrowsError(try store.policy(forFingerprint: "SHA256:corrupt")) { error in
            XCTAssertEqual(error as? AgentPolicyError, .corrupt)
        }

        // Global policy missing returns default
        let missingGlobal = try store.global()
        XCTAssertEqual(missingGlobal, AgentGlobalPolicy())

        // Save and load global policy
        let customGlobal = AgentGlobalPolicy(version: 1, maxLeaseMinutes: 300)
        try store.saveGlobal(customGlobal)
        let loadedGlobal = try store.global()
        XCTAssertEqual(loadedGlobal, customGlobal)

        // Corrupt global policy throws corrupt
        storage[KeychainAgentPolicyStore.globalAccount] = Data("garbage".utf8)
        XCTAssertThrowsError(try store.global()) { error in
            XCTAssertEqual(error as? AgentPolicyError, .corrupt)
        }
    }
}
