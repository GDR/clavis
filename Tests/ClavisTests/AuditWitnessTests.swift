import Foundation
import Testing
import CryptoKit
@testable import ClavisCore

@Suite struct AuditWitnessTests {
    private final class MockWitnessWriter: AuditWitnessWriting, @unchecked Sendable {
        private let lock = NSLock()
        private var _entries: [AuditWitnessEntry] = []
        var entries: [AuditWitnessEntry] {
            lock.lock(); defer { lock.unlock() }
            return _entries
        }
        func write(_ e: AuditWitnessEntry) {
            lock.lock(); defer { lock.unlock() }
            _entries.append(e)
        }
    }

    @Test func test_007_T1_digestIsStable() {
        let fixedEventID = UUID(uuidString: "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1")!
        let fixedTime = Date(timeIntervalSinceReferenceDate: 123456789.0)
        let blob = Data([0x01, 0x02, 0x03, 0x04])

        let digest = AuditWitness.digest(
            seq: 1,
            eventID: fixedEventID,
            time: fixedTime,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc123def456",
            kind: "personal",
            session: "sess-999",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        )

        // Verify digest length is 32 hex chars
        #expect(digest.count == 32)

        // Run again to ensure determinism
        let digest2 = AuditWitness.digest(
            seq: 1,
            eventID: fixedEventID,
            time: fixedTime,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc123def456",
            kind: "personal",
            session: "sess-999",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        )
        #expect(digest == digest2)

        // Golden check: verify matches expected SHA-256 prefix
        let bitPatternStr = String(fixedTime.timeIntervalSinceReferenceDate.bitPattern)
        let expectedPayload = "w1|1|e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1|\(bitPatternStr)|signature|allowed|via_prompt|SHA256:abc123def456|personal|sess-999|1|1|\(blob.base64EncodedString())"
        let expectedHash = CryptoKitDigestHelper.sha256Hex16(expectedPayload)
        #expect(digest == expectedHash)
    }

    @Test func test_007_T1_digestChangesWithEveryField() {
        let eventID = UUID(uuidString: "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1")!
        let time = Date(timeIntervalSinceReferenceDate: 123456789.0)
        let blob = Data([0x01, 0x02, 0x03, 0x04])

        let base = AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        )

        // Change seq
        #expect(base != AuditWitness.digest(
            seq: 2,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change eventID
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: UUID(),
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change time
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time.addingTimeInterval(1.0),
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change type
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "session_start",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change result
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "denied",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change reason
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "lock_now",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: nil,
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change fingerprint
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:xyz",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: nil,
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change kind
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "agent",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: nil,
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change session
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-2",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: nil,
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change count
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 2,
            sensitiveFormat: 1,
            sensitiveBlob: blob
        ))

        // Change sensitiveFormat
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 2,
            sensitiveBlob: blob
        ))

        // Change sensitiveBlob (when format == 1)
        #expect(base != AuditWitness.digest(
            seq: 1,
            eventID: eventID,
            time: time,
            type: "signature",
            result: "allowed",
            reason: "via_prompt",
            fingerprint: "SHA256:abc",
            kind: "personal",
            session: "sess-1",
            count: 1,
            sensitiveFormat: 1,
            sensitiveBlob: Data([0x09, 0x08])
        ))
    }

    @Test func test_007_C2_lineHasNoSensitiveFields() {
        let sensitive = AuditSensitive(
            keyLabel: "super-secret-key-label",
            processChain: [
                AuditProcess(executablePath: "/Users/alice/bin/secret-deploy", pid: 9999)
            ],
            host: "production.cluster.internal"
        )
        let event = AuditEvent(
            type: .signature,
            result: .allowed,
            sensitive: sensitive
        )
        let entry = AuditWitnessEntry(
            seq: 42,
            eventID: event.id,
            type: event.type.rawValue,
            result: event.result.rawValue,
            fingerprint: "SHA256:abcdef",
            digest: "0123456789abcdef0123456789abcdef"
        )

        let line = AuditWitness.line(entry)

        #expect(!line.contains("super-secret-key-label"))
        #expect(!line.contains("/Users/alice/bin/secret-deploy"))
        #expect(!line.contains("secret-deploy"))
        #expect(!line.contains("9999"))
        #expect(!line.contains("production.cluster.internal"))
    }

    @Test func test_007_T1_lineParseRoundTrip() {
        let entryWithFP = AuditWitnessEntry(
            seq: 123,
            eventID: UUID(uuidString: "a1b2c3d4-e5f6-7890-abcd-ef1234567890")!,
            type: "signature",
            result: "allowed",
            fingerprint: "SHA256:myfingerprint",
            digest: "abcdef0123456789abcdef0123456789"
        )
        let lineWithFP = AuditWitness.line(entryWithFP)
        let parsedWithFP = AuditWitness.parse(line: lineWithFP)
        #expect(parsedWithFP == entryWithFP)

        let entryWithoutFP = AuditWitnessEntry(
            seq: 124,
            eventID: UUID(uuidString: "b2c3d4e5-f6a7-8901-bcde-f12345678901")!,
            type: "lock",
            result: "info",
            fingerprint: nil,
            digest: "123456789abcdef0123456789abcdef0"
        )
        let lineWithoutFP = AuditWitness.line(entryWithoutFP)
        #expect(lineWithoutFP.contains("fp=-"))
        let parsedWithoutFP = AuditWitness.parse(line: lineWithoutFP)
        #expect(parsedWithoutFP == entryWithoutFP)
    }

    @Test func test_007_T1_parseRejectsGarbage() {
        // Empty
        #expect(AuditWitness.parse(line: "") == nil)
        // Unsupported version
        #expect(AuditWitness.parse(line: "w2 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef") == nil)
        // Free text
        #expect(AuditWitness.parse(line: "hello world") == nil)
        // Invalid seq
        #expect(AuditWitness.parse(line: "w1 seq=abc eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef") == nil)
        // Invalid UUID
        #expect(AuditWitness.parse(line: "w1 seq=1 eid=not-a-uuid type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef") == nil)
        // Missing field
        #expect(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=-") == nil)
        // Extra field
        #expect(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef extra=foo") == nil)
        // Double equals in token
        #expect(AuditWitness.parse(line: "w1 seq==1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef") == nil)
        // Short digest
        #expect(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=012345") == nil)
        // Non-hex digest
        #expect(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") == nil)
    }

    @Test func test_007_T1_recorderWritesOneWitnessPerInsert() throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }
        let testDirURL = fixture.testRootURL.appendingPathComponent("witness-rec-test-\(UUID().uuidString)", isDirectory: true)
        try SecureFS.createDirectory(at: testDirURL)
        defer { try? FileManager.default.removeItem(at: testDirURL) }
        let dbURL = testDirURL.appendingPathComponent("audit.db")

        let mockWriter = MockWitnessWriter()
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)

        let recorder = AuditRecorder(
            storeFactory: { try AuditStore(url: dbURL) },
            now: { currentTime },
            sealer: nil,
            witness: mockWriter,
            floodThreshold: 5,
            floodWindow: 60
        )

        // 5 distinct non-flooded events
        for i in 0..<5 {
            currentTime = currentTime.addingTimeInterval(1.0)
            recorder.record(AuditEvent(
                time: currentTime,
                type: .keyCreate,
                result: .allowed,
                keyFingerprint: "SHA256:key\(i)"
            ))
        }

        // Trigger flood suppression: 10 events of same key, threshold 5
        for _ in 0..<10 {
            currentTime = currentTime.addingTimeInterval(0.1)
            recorder.record(AuditEvent(
                time: currentTime,
                type: .signature,
                result: .denied,
                reason: .unknownKey,
                keyFingerprint: "SHA256:floodedKey"
            ))
        }

        // Advance clock and flush to write the aggregated suppressed row
        currentTime = currentTime.addingTimeInterval(61.0)
        recorder.flush()

        let store = try AuditStore(url: dbURL)
        defer { store.close() }
        let dbCount = try store.count()

        // 5 keyCreate + 5 signature (in threshold) + 1 suppressed = 11 rows
        #expect(dbCount == 11)
        #expect(mockWriter.entries.count == 11)

        // Seqs must match 1...11
        let witnessedSeqs = mockWriter.entries.map(\.seq)
        #expect(witnessedSeqs == Array(Int64(1)...Int64(11)))
    }
}

private enum CryptoKitDigestHelper {
    static func sha256Hex16(_ string: String) -> String {
        let hash = SHA256.hash(data: Data(string.utf8))
        return hash.prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
