import Testing
import Foundation
@testable import ClavisCore

@Suite struct AuditExporterTests {

    @Test func test_002_AC7_exportRedactsLabelsAndPaths() throws {
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            reason: .viaPrompt,
            keyFingerprint: "SHA256:abc123fingerprint",
            keyKind: .personal,
            count: 1,
            sensitive: AuditSensitive(
                keyLabel: "super-secret-key-label",
                processChain: [
                    AuditProcess(executablePath: "/Users/alice/bin/custom-ssh-client", pid: 1234)
                ],
                host: "bastion.example.com"
            )
        )
        let record = AuditRecord(seq: 42, event: event)

        let exportedData = AuditExporter.export([record])
        let jsonString = try #require(String(data: exportedData, encoding: .utf8))

        // Must not contain secret key label or raw process path
        #expect(!jsonString.contains("super-secret-key-label"))
        #expect(!jsonString.contains("/Users/alice/bin/custom-ssh-client"))

        // Must contain host in clear text
        #expect(jsonString.contains("bastion.example.com"))

        // Must contain pid, fingerprint, and pseudo-hashes starting with "h:"
        #expect(jsonString.contains("1234"))
        #expect(jsonString.contains("SHA256:abc123fingerprint"))
        #expect(jsonString.contains("\"keyLabel\":\"h:"))
        #expect(jsonString.contains("\"executablePath\":\"h:"))
    }

    @Test func test_002_AC7_sameLabelSameHashWithinOneExport() throws {
        let event1 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(
                keyLabel: "shared-key-label",
                processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 100)]
            )
        )
        let event2 = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(
                keyLabel: "shared-key-label",
                processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 200)]
            )
        )
        let records = [AuditRecord(seq: 1, event: event1), AuditRecord(seq: 2, event: event2)]

        let data = AuditExporter.export(records)
        let output = try #require(String(data: data, encoding: .utf8))

        let lines = output.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: "\n")
        #expect(lines.count == 2)

        // Parse JSON objects from both lines
        let json1 = try #require(try JSONSerialization.jsonObject(with: Data(lines[0].utf8)) as? [String: Any])
        let json2 = try #require(try JSONSerialization.jsonObject(with: Data(lines[1].utf8)) as? [String: Any])

        #expect((json1["keyLabel"] as? String) == (json2["keyLabel"] as? String))

        let chain1 = try #require(json1["processChain"] as? [[String: Any]])
        let chain2 = try #require(json2["processChain"] as? [[String: Any]])
        #expect((chain1.first?["executablePath"] as? String) == (chain2.first?["executablePath"] as? String))
    }

    @Test func test_002_AC7_differentExportsUseDifferentSalts() throws {
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: AuditSensitive(
                keyLabel: "test-salt-key",
                processChain: [AuditProcess(executablePath: "/usr/bin/ssh", pid: 100)]
            )
        )
        let record = AuditRecord(seq: 1, event: event)

        let data1 = AuditExporter.export([record])
        let data2 = AuditExporter.export([record])

        let str1 = try #require(String(data: data1, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines))
        let str2 = try #require(String(data: data2, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines))

        let json1 = try #require(try JSONSerialization.jsonObject(with: Data(str1.utf8)) as? [String: Any])
        let json2 = try #require(try JSONSerialization.jsonObject(with: Data(str2.utf8)) as? [String: Any])

        let label1 = try #require(json1["keyLabel"] as? String)
        let label2 = try #require(json2["keyLabel"] as? String)

        #expect(label1 != label2, "Successive exports without explicit salt must produce distinct pseudonyms")
    }
}
