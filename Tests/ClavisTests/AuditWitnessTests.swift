import CryptoKit
import XCTest
@testable import ClavisCore

final class AuditWitnessTests: ClavisBaseTestCase {
    private final class MockWitnessWriter: AuditWitnessWriting {
        var entries: [AuditWitnessEntry] = []
        func write(_ e: AuditWitnessEntry) {
            entries.append(e)
        }
    }

    func test_007_T1_digestIsStable() {
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
        XCTAssertEqual(digest.count, 32)

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
        XCTAssertEqual(digest, digest2)

        // Golden check: verify matches expected SHA-256 prefix
        let bitPatternStr = String(fixedTime.timeIntervalSinceReferenceDate.bitPattern)
        let expectedPayload = "w1|1|e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1|\(bitPatternStr)|signature|allowed|via_prompt|SHA256:abc123def456|personal|sess-999|1|1|\(blob.base64EncodedString())"
        let expectedHash = CryptoKitDigestHelper.sha256Hex16(expectedPayload)
        XCTAssertEqual(digest, expectedHash)
    }

    func test_007_T1_digestChangesWithEveryField() {
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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
        XCTAssertNotEqual(base, AuditWitness.digest(
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

    func test_007_C2_lineHasNoSensitiveFields() {
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

        XCTAssertFalse(line.contains("super-secret-key-label"))
        XCTAssertFalse(line.contains("/Users/alice/bin/secret-deploy"))
        XCTAssertFalse(line.contains("secret-deploy"))
        XCTAssertFalse(line.contains("9999"))
        XCTAssertFalse(line.contains("production.cluster.internal"))
    }

    func test_007_T1_lineParseRoundTrip() {
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
        XCTAssertEqual(parsedWithFP, entryWithFP)

        let entryWithoutFP = AuditWitnessEntry(
            seq: 124,
            eventID: UUID(uuidString: "b2c3d4e5-f6a7-8901-bcde-f12345678901")!,
            type: "lock",
            result: "info",
            fingerprint: nil,
            digest: "123456789abcdef0123456789abcdef0"
        )
        let lineWithoutFP = AuditWitness.line(entryWithoutFP)
        XCTAssertTrue(lineWithoutFP.contains("fp=-"))
        let parsedWithoutFP = AuditWitness.parse(line: lineWithoutFP)
        XCTAssertEqual(parsedWithoutFP, entryWithoutFP)
    }

    func test_007_T1_parseRejectsGarbage() {
        // Empty
        XCTAssertNil(AuditWitness.parse(line: ""))
        // Unsupported version
        XCTAssertNil(AuditWitness.parse(line: "w2 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef"))
        // Free text
        XCTAssertNil(AuditWitness.parse(line: "hello world"))
        // Invalid seq
        XCTAssertNil(AuditWitness.parse(line: "w1 seq=abc eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef"))
        // Invalid UUID
        XCTAssertNil(AuditWitness.parse(line: "w1 seq=1 eid=not-a-uuid type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef"))
        // Missing field
        XCTAssertNil(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=-"))
        // Extra field
        XCTAssertNil(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef extra=foo"))
        // Double equals in token
        XCTAssertNil(AuditWitness.parse(line: "w1 seq==1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef"))
        // Short digest
        XCTAssertNil(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=012345"))
        // Non-hex digest
        XCTAssertNil(AuditWitness.parse(line: "w1 seq=1 eid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 type=signature result=allowed fp=- h=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
    }

    func test_007_T1_recorderWritesOneWitnessPerInsert() throws {
        let testDirURL = testRootURL.appendingPathComponent("witness-rec-test-\(UUID().uuidString)", isDirectory: true)
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
        XCTAssertEqual(dbCount, 11)
        XCTAssertEqual(mockWriter.entries.count, 11)

        // Seqs must match 1...11
        let witnessedSeqs = mockWriter.entries.map(\.seq)
        XCTAssertEqual(witnessedSeqs, Array(Int64(1)...Int64(11)))
    }
}

private enum CryptoKitDigestHelper {
    static func sha256Hex16(_ string: String) -> String {
        let hash = SHA256.hash(data: Data(string.utf8))
        return hash.prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
