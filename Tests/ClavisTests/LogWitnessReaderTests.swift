import XCTest
@testable import ClavisCore

final class LogWitnessReaderTests: ClavisBaseTestCase {
    func test_007_T2_parsesFixture() {
        let fixture = """
        Filtering the log data using "subsystem == com.clavis.audit AND category == witness"
        {"processImagePath":"/Applications/Clavis.app/Contents/MacOS/Clavis","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=SHA256:abc h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/usr/local/bin/clavis-agent","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:42.123456Z"}
        Log stream finished
        """

        let reader = LogWitnessReader(run: { args in
            XCTAssertTrue(args.contains("--last"))
            XCTAssertTrue(args.contains("7d"))
            return (0, Data(fixture.utf8))
        })

        let result = reader.read(days: 7)
        guard case .entries(let entries) = result else {
            XCTFail("Expected .entries, got \(result)")
            return
        }

        XCTAssertEqual(entries.count, 2)

        let first = entries[0]
        XCTAssertEqual(first.seq, 1)
        XCTAssertEqual(first.eventID, UUID(uuidString: "11111111-1111-1111-1111-111111111111"))
        XCTAssertEqual(first.type, "signature")
        XCTAssertEqual(first.result, "allowed")
        XCTAssertEqual(first.fingerprint, "SHA256:abc")
        XCTAssertEqual(first.digest, "0123456789abcdef0123456789abcdef")
        XCTAssertNotNil(first.loggedAt)

        let second = entries[1]
        XCTAssertEqual(second.seq, 2)
        XCTAssertEqual(second.eventID, UUID(uuidString: "22222222-2222-2222-2222-222222222222"))
        XCTAssertEqual(second.type, "key_create")
        XCTAssertEqual(second.result, "allowed")
        XCTAssertNil(second.fingerprint)
        XCTAssertEqual(second.digest, "fedcba9876543210fedcba9876543210")
        XCTAssertNotNil(second.loggedAt)
    }

    func test_007_T2_ignoresForeignProcesses() {
        let fixture = """
        {"processImagePath":"/usr/bin/python3","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/usr/local/bin/clavis-cli","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:42.123456+0000"}
        """

        let reader = LogWitnessReader(run: { _ in
            return (0, Data(fixture.utf8))
        })

        let result = reader.read(days: 1)
        guard case .entries(let entries) = result else {
            XCTFail("Expected .entries, got \(result)")
            return
        }

        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].seq, 2)

        // Only foreign process: should return .unavailable("log show failed") because 0 accepted entries
        let foreignOnlyFixture = """
        {"processImagePath":"/bin/zsh","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        """
        let foreignReader = LogWitnessReader(run: { _ in (0, Data(foreignOnlyFixture.utf8)) })
        XCTAssertEqual(foreignReader.read(days: 1), .unavailable("log show failed"))
    }

    func test_007_T2_nonZeroStatusIsUnavailable() {
        let nonZeroReader = LogWitnessReader(run: { _ in
            return (1, Data("Permission denied".utf8))
        })
        XCTAssertEqual(nonZeroReader.read(days: 7), .unavailable("log show failed"))

        let timeoutReader = LogWitnessReader(run: { _ in
            throw LogWitnessReaderError.timeout
        })
        XCTAssertEqual(timeoutReader.read(days: 7), .unavailable("timeout"))

        let emptyReader = LogWitnessReader(run: { _ in
            return (0, Data())
        })
        XCTAssertEqual(emptyReader.read(days: 7), .unavailable("log show failed"))
    }
}
