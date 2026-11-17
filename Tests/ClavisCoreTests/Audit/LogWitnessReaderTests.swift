import Foundation
import Testing
@testable import ClavisCore

@Suite struct LogWitnessReaderTests {
    @Test func test_007_T2_parsesFixture() {
        let fixture = """
        Filtering the log data using "subsystem == com.clavis.audit AND category == witness"
        {"processImagePath":"/Applications/Clavis.app/Contents/MacOS/Clavis","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=SHA256:abc h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/usr/local/bin/clavis-agent","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:42.123456Z"}
        Log stream finished
        """

        let reader = LogWitnessReader(run: { args in
            #expect(args.contains("--last"))
            #expect(args.contains("7d"))
            return (0, Data(fixture.utf8))
        })

        let result = reader.read(days: 7)
        guard case .entries(let entries) = result else {
            Issue.record("Expected .entries, got \(result)")
            return
        }

        #expect(entries.count == 2)

        let first = entries[0]
        #expect(first.seq == 1)
        #expect(first.eventID == UUID(uuidString: "11111111-1111-1111-1111-111111111111"))
        #expect(first.type == "signature")
        #expect(first.result == "allowed")
        #expect(first.fingerprint == "SHA256:abc")
        #expect(first.digest == "0123456789abcdef0123456789abcdef")
        #expect(first.loggedAt != nil)

        let second = entries[1]
        #expect(second.seq == 2)
        #expect(second.eventID == UUID(uuidString: "22222222-2222-2222-2222-222222222222"))
        #expect(second.type == "key_create")
        #expect(second.result == "allowed")
        #expect(second.fingerprint == nil)
        #expect(second.digest == "fedcba9876543210fedcba9876543210")
        #expect(second.loggedAt != nil)
    }

    @Test func test_007_T2_ignoresForeignProcesses() {
        let fixture = """
        {"processImagePath":"/usr/bin/python3","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/usr/local/bin/clavis-cli","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:42.123456+0000"}
        """

        let reader = LogWitnessReader(run: { _ in
            return (0, Data(fixture.utf8))
        })

        let result = reader.read(days: 1)
        guard case .entries(let entries) = result else {
            Issue.record("Expected .entries, got \(result)")
            return
        }

        #expect(entries.count == 1)
        #expect(entries[0].seq == 2)

        // Only foreign process: should return .unavailable("log show failed") because 0 accepted entries
        let foreignOnlyFixture = """
        {"processImagePath":"/bin/zsh","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        """
        let foreignReader = LogWitnessReader(run: { _ in (0, Data(foreignOnlyFixture.utf8)) })
        #expect(foreignReader.read(days: 1) == .unavailable("log show failed"))
    }

    @Test func test_007_T2_nonZeroStatusIsUnavailable() {
        let nonZeroReader = LogWitnessReader(run: { _ in
            return (1, Data("Permission denied".utf8))
        })
        #expect(nonZeroReader.read(days: 7) == .unavailable("log show failed"))

        let timeoutReader = LogWitnessReader(run: { _ in
            throw LogWitnessReaderError.timeout
        })
        #expect(timeoutReader.read(days: 7) == .unavailable("timeout"))

        let emptyReader = LogWitnessReader(run: { _ in
            return (0, Data())
        })
        #expect(emptyReader.read(days: 7) == .unavailable("log show failed"))
    }

    @Test func test_F08_rejectsUntrustedProcessPaths() {
        let fixture = """
        {"processImagePath":"/tmp/clavis-cli","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/private/tmp/clavis-agent","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:42.123456+0000"}
        {"processImagePath":"/var/tmp/Clavis","eventMessage":"w1 seq=3 eid=33333333-3333-3333-3333-333333333333 type=signature result=allowed fp=- h=11223344556677881122334455667788","timestamp":"2026-10-06 03:55:43.000000+0000"}
        """

        let reader = LogWitnessReader(run: { _ in
            return (0, Data(fixture.utf8))
        })

        // All entries come from untrusted temporary paths; none should be accepted.
        let result = reader.read(days: 7)
        #expect(result == .unavailable("log show failed"))
    }

    @Test func test_F08_acceptsCanonicalInstallPaths() {
        let fixture = """
        {"processImagePath":"/opt/homebrew/bin/clavis-cli","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/run/current-system/sw/bin/clavis-agent","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:42.123456+0000"}
        {"processImagePath":"/nix/store/1234567890abcdef-clavis-0.1.1/bin/clavis-cli","eventMessage":"w1 seq=3 eid=33333333-3333-3333-3333-333333333333 type=signature result=allowed fp=- h=11223344556677881122334455667788","timestamp":"2026-10-06 03:55:43.000000+0000"}
        """

        let reader = LogWitnessReader(run: { _ in
            return (0, Data(fixture.utf8))
        })

        let result = reader.read(days: 7)
        guard case .entries(let entries) = result else {
            Issue.record("Expected .entries, got \(result)")
            return
        }
        #expect(entries.count == 3)
        #expect(entries.map(\.seq) == [1, 2, 3])
    }

    @Test func test_F08_customPathValidator() {
        let fixture = """
        {"processImagePath":"/custom/path/clavis-cli","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        """

        let reader = LogWitnessReader(
            run: { _ in (0, Data(fixture.utf8)) },
            pathValidator: { $0.hasPrefix("/custom/path/") }
        )

        let result = reader.read(days: 7)
        guard case .entries(let entries) = result else {
            Issue.record("Expected .entries, got \(result)")
            return
        }
        #expect(entries.count == 1)
        #expect(entries[0].seq == 1)
    }

    @Test func test_F08_isCanonicalPathRejectsRelativeAndTempTraversal() {
        #expect(!LogWitnessReader.isCanonicalPath("/tmp/../Applications/Clavis.app/Contents/MacOS/Clavis"))
        #expect(!LogWitnessReader.isCanonicalPath("/private/tmp/../Applications/Clavis.app/Contents/MacOS/Clavis"))
        #expect(!LogWitnessReader.isCanonicalPath("/var/tmp/../Applications/Clavis.app/Contents/MacOS/Clavis"))
        #expect(!LogWitnessReader.isCanonicalPath("/private/var/tmp/../Applications/Clavis.app/Contents/MacOS/Clavis"))
        #expect(!LogWitnessReader.isCanonicalPath("../Applications/Clavis.app/Contents/MacOS/Clavis"))
        #expect(!LogWitnessReader.isCanonicalPath("/Applications/Clavis.app/../Applications/Clavis.app/Contents/MacOS/Clavis"))
        #expect(!LogWitnessReader.isCanonicalPath("Applications/Clavis.app/Contents/MacOS/Clavis"))
    }

    @Test func test_F08_isCanonicalPathCaseInsensitiveOnMacOS() {
        #expect(LogWitnessReader.isCanonicalPath("/applications/clavis.app/Contents/MacOS/Clavis"))
        #expect(LogWitnessReader.isCanonicalPath("/APPLICATIONS/CLAVIS.APP/Contents/MacOS/Clavis"))
        #expect(LogWitnessReader.isCanonicalPath("/opt/Homebrew/bin/clavis-cli"))
        #expect(LogWitnessReader.isCanonicalPath("/OPT/HOMEBREW/BIN/clavis-cli"))
        #expect(LogWitnessReader.isCanonicalPath("/usr/local/BIN/clavis-agent"))
    }

    @Test func test_F08_isCanonicalPathRequiresResolvedMatchesAllowedPrefix() {
        #expect(!LogWitnessReader.isCanonicalPath("/Users/Shared/evil/clavis-cli"))
        #expect(!LogWitnessReader.isCanonicalPath("/usr/bin/clavis-cli"))
        #expect(!LogWitnessReader.isCanonicalPath("/tmp/clavis-cli"))
        #expect(!LogWitnessReader.isCanonicalPath("/private/tmp/clavis-cli"))
        #expect(!LogWitnessReader.isCanonicalPath("/etc/clavis-cli"))
    }

    @Test func test_F08_readerFiltersTraversalAndAcceptsCaseInsensitiveFixture() {
        let fixture = """
        {"processImagePath":"/tmp/../Applications/Clavis.app/Contents/MacOS/Clavis","eventMessage":"w1 seq=1 eid=11111111-1111-1111-1111-111111111111 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:41.787123+0000"}
        {"processImagePath":"/applications/clavis.app/Contents/MacOS/Clavis","eventMessage":"w1 seq=2 eid=22222222-2222-2222-2222-222222222222 type=signature result=allowed fp=- h=0123456789abcdef0123456789abcdef","timestamp":"2026-10-06 03:55:42.000000+0000"}
        {"processImagePath":"/opt/Homebrew/bin/clavis-cli","eventMessage":"w1 seq=3 eid=33333333-3333-3333-3333-333333333333 type=key_create result=allowed fp=- h=fedcba9876543210fedcba9876543210","timestamp":"2026-10-06 03:55:43.000000+0000"}
        """

        let reader = LogWitnessReader(run: { _ in
            return (0, Data(fixture.utf8))
        })

        let result = reader.read(days: 7)
        guard case .entries(let entries) = result else {
            Issue.record("Expected .entries, got \(result)")
            return
        }

        #expect(entries.count == 2)
        #expect(entries.map(\.seq) == [2, 3])
    }
}
