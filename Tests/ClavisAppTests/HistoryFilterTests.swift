import Testing
import Foundation
@testable import ClavisCore
@testable import Clavis

@Suite struct HistoryFilterTests {

    private func calendar(_ tz: String) -> Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: tz)!
        return c
    }

    private func record(
        seq: Int64 = 1, time: Date = Date(timeIntervalSince1970: 1_800_000_000),
        result: AuditResult = .allowed, key: String? = "SHA256:aaa"
    ) -> AuditRecord {
        AuditRecord(seq: seq, event: AuditEvent(
            time: time, type: .signature, result: result, reason: .viaPrompt, keyFingerprint: key))
    }

    private func sens(host: String? = nil, procs: [String] = []) -> AuditSensitive {
        AuditSensitive(keyLabel: "Personal Mac",
                       processChain: procs.enumerated().map { AuditProcess(executablePath: $1, pid: Int32(100 + $0)) },
                       host: host)
    }

    // MARK: Algebra

    @Test func test_009_twoHostsAreOrAcrossTypesAnd() {
        var f = HistoryFilter()
        f.add(.host("github.com")); f.add(.host("gitlab.com"))
        f.add(.process(.name("ssh")))
        f.add(.result(.rejected))
        let cal = calendar("UTC")

        let ok = record(result: .denied)
        #expect(f.matches(ok, sensitive: sens(host: "gitlab.com", procs: ["/usr/bin/ssh"]), calendar: cal))
        #expect(f.matches(ok, sensitive: sens(host: "GitHub.com.", procs: ["/usr/bin/ssh"]), calendar: cal))
        // Wrong host → out (host OR group fails)
        #expect(!f.matches(ok, sensitive: sens(host: "example.org", procs: ["/usr/bin/ssh"]), calendar: cal))
        // Right host, wrong process → out (AND across types)
        #expect(!f.matches(ok, sensitive: sens(host: "gitlab.com", procs: ["/usr/bin/git"]), calendar: cal))
        // Right host+process, wrong result → out
        #expect(!f.matches(record(result: .allowed), sensitive: sens(host: "gitlab.com", procs: ["/usr/bin/ssh"]), calendar: cal))
    }

    @Test func test_009_emptyFilterMatchesEverythingIncludingUnreadable() {
        #expect(HistoryFilter().matches(record(), sensitive: nil, calendar: calendar("UTC")))
    }

    @Test func test_009_unreadableSensitiveCannotMatchHostOrProcess() {
        var f = HistoryFilter()
        f.add(.host("github.com"))
        #expect(!f.matches(record(), sensitive: nil, calendar: calendar("UTC")))
    }

    @Test func test_009_processPathCriterionDoesNotCollapseSameBasename() {
        var f = HistoryFilter()
        f.add(.process(.path("/usr/bin/ssh")))
        let cal = calendar("UTC")
        #expect(f.matches(record(), sensitive: sens(procs: ["/usr/bin/ssh"]), calendar: cal))
        #expect(!f.matches(record(), sensitive: sens(procs: ["/opt/homebrew/bin/ssh"]), calendar: cal))
    }

    @Test func test_009_processMatchesDirectPeerNotParents() {
        var f = HistoryFilter()
        f.add(.process(.name("zsh")))
        // chain[0] = direct peer (ssh), parent = zsh → must NOT match.
        #expect(!f.matches(record(), sensitive: sens(procs: ["/usr/bin/ssh", "/bin/zsh"]), calendar: calendar("UTC")))
    }

    @Test func test_009_textTermsAreAnded() {
        var f = HistoryFilter()
        f.add(.text("personal")); f.add(.text("github"))
        let cal = calendar("UTC")
        #expect(f.matches(record(), sensitive: sens(host: "github.com"), calendar: cal))
        #expect(!f.matches(record(), sensitive: sens(host: "gitlab.com"), calendar: cal))
    }

    @Test func test_009_duplicatesIgnoredAndRemovalKeepsOthers() {
        var f = HistoryFilter()
        let first = f.add(.host("a.com"))
        let dup = f.add(.host("a.com"))
        #expect(first && !dup)
        f.add(.host("b.com")); f.add(.result(.approved))
        let removed = f.remove(id: HistoryCriterion.host("a.com").id)
        #expect(removed)
        #expect(f.criteria == [.host("b.com"), .result(.approved)])
    }

    @Test func test_009_sqlQueryCarriesKeysResultsAndDatesButNotSensitive() {
        var f = HistoryFilter()
        f.add(.key("A")); f.add(.key("B")); f.add(.result(.rejected)); f.add(.host("x.com"))
        f.sortOrder = .oldestFirst
        f.dateBounds.setFrom(CalendarDay(year: 2026, month: 3, day: 1))
        let q = f.auditQuery(limit: 50, calendar: calendar("UTC"), sessionID: "S1")
        #expect(q.keyFingerprints == ["A", "B"])
        #expect(q.results == [.denied, .cancelled, .failed])
        #expect(q.sortOrder == .oldestFirst && q.orderByTime && q.sessionID == "S1")
        #expect(q.from != nil && q.toExclusive == nil)
        #expect(f.needsSensitiveScan)
    }

    // MARK: Sidebar / key badge synchronisation (§8)

    @Test func test_009_sync_openFromKeyCreatesExactlyOneBadge() {
        var f = HistoryFilter(criteria: [.host("old.com")])
        f.open(forKey: "K")
        #expect(f.criteria == [.key("K")])
        #expect(f.soleKey == "K")
    }

    @Test func test_009_sync_sidebarClickReplacesKeysKeepsOtherFilters() {
        var f = HistoryFilter()
        f.open(forKey: "K")
        f.add(.host("github.com")); f.add(.result(.rejected))
        f.dateBounds.setTo(CalendarDay(year: 2026, month: 5, day: 5))
        f.selectSidebarKey("B")
        #expect(f.keyFingerprints == ["B"])
        #expect(f.hosts == ["github.com"] && f.results == [.rejected] && f.dateBounds.to != nil)
    }

    @Test func test_009_sync_secondKeyClearsSelectionAndQueriesBothWithOr() {
        var f = HistoryFilter()
        f.open(forKey: "K")
        f.add(.key("B"))
        #expect(f.soleKey == nil)
        #expect(Set(f.keyFingerprints) == ["K", "B"])
        let q = f.auditQuery(limit: 10, calendar: calendar("UTC"), sessionID: nil)
        #expect(q.keyFingerprints == ["K", "B"])
    }

    @Test func test_009_sync_removingOneOfTwoSelectsTheOtherThenRemovingLastClears() {
        var f = HistoryFilter(criteria: [.key("K"), .key("B")])
        f.remove(id: HistoryCriterion.key("K").id)
        #expect(f.soleKey == "B")
        f.remove(id: HistoryCriterion.key("B").id)
        #expect(f.soleKey == nil && f.keyFingerprints.isEmpty)
    }

    @Test func test_009_sync_repeatedSelectionNeverDuplicates() {
        var f = HistoryFilter()
        f.selectSidebarKey("K"); f.selectSidebarKey("K")
        f.add(.key("K"))
        #expect(f.keyFingerprints == ["K"])
    }

    @Test func test_009_sync_renameDoesNotChangePredicate() {
        // Badges store the fingerprint; a label change cannot alter the committed state.
        let f = HistoryFilter(criteria: [.key("SHA256:aaa")])
        let before = f.auditQuery(limit: 10, calendar: calendar("UTC"), sessionID: nil)
        let renamed = [HistoryKeyChoice(fingerprint: "SHA256:aaa", label: "Renamed")]
        #expect(renamed.first { $0.fingerprint == f.soleKey }?.label == "Renamed")
        #expect(f.auditQuery(limit: 10, calendar: calendar("UTC"), sessionID: nil) == before)
    }

    @Test func test_009_clearFiltersKeepsSoleKeyAndSortOnly() {
        var f = HistoryFilter(criteria: [.key("K"), .host("a.com"), .result(.approved)], sortOrder: .oldestFirst)
        f.dateBounds.setFrom(CalendarDay(year: 2026, month: 1, day: 1))
        f.clearFilters()
        #expect(f.criteria == [.key("K")])
        #expect(f.dateBounds.isEmpty)
        #expect(f.sortOrder == .oldestFirst)

        var two = HistoryFilter(criteria: [.key("K"), .key("B"), .host("a.com")])
        two.clearFilters()
        #expect(two.criteria.isEmpty)   // no single sidebar scope to preserve
    }

    // MARK: Dates (§9)

    @Test func test_009_dateBoundsAllFourCombinations() {
        let cal = calendar("UTC")
        func d(_ day: Int) -> Date { Date(timeIntervalSince1970: TimeInterval(day * 86_400 + 3_600)) }
        let from = CalendarDay(Date(timeIntervalSince1970: 86_400 * 2), calendar: cal)   // Jan 3
        let to = CalendarDay(Date(timeIntervalSince1970: 86_400 * 4), calendar: cal)     // Jan 5

        #expect(HistoryDateBounds().contains(d(0), in: cal))
        let fromOnly = HistoryDateBounds(from: from)
        #expect(!fromOnly.contains(d(1), in: cal) && fromOnly.contains(d(2), in: cal) && fromOnly.contains(d(40), in: cal))
        let toOnly = HistoryDateBounds(to: to)
        #expect(toOnly.contains(d(0), in: cal) && toOnly.contains(d(4), in: cal) && !toOnly.contains(d(5), in: cal))
        let both = HistoryDateBounds(from: from, to: to)
        #expect(!both.contains(d(1), in: cal) && both.contains(d(3), in: cal) && !both.contains(d(5), in: cal))
    }

    @Test func test_009_endDayIsInclusiveThroughLastSecond() {
        let cal = calendar("UTC")
        let to = CalendarDay(year: 2026, month: 3, day: 5)
        let b = HistoryDateBounds(to: to)
        let lastSecond = to.startOfNextDay(in: cal).addingTimeInterval(-1)
        #expect(b.contains(lastSecond, in: cal))
        #expect(!b.contains(to.startOfNextDay(in: cal), in: cal))
    }

    @Test func test_009_invalidIntervalIsRejectedNotSwapped() {
        var b = HistoryDateBounds(from: CalendarDay(year: 2026, month: 3, day: 10), to: CalendarDay(year: 2026, month: 3, day: 12))
        let badFrom = b.setFrom(CalendarDay(year: 2026, month: 3, day: 13))
        let badTo = b.setTo(CalendarDay(year: 2026, month: 3, day: 9))
        #expect(!badFrom && !badTo)
        #expect(b.from == CalendarDay(year: 2026, month: 3, day: 10))
        #expect(b.to == CalendarDay(year: 2026, month: 3, day: 12))
        // Clearing one side is always allowed and independent.
        let cleared = b.setFrom(nil)
        #expect(cleared && b.to != nil)
    }

    @Test func test_009_dstDaysAreNot24Hours() {
        let cal = calendar("America/New_York")
        // 2026-03-08: spring forward (23h day). 2026-11-01: fall back (25h day).
        let spring = CalendarDay(year: 2026, month: 3, day: 8)
        #expect(spring.startOfNextDay(in: cal).timeIntervalSince(spring.startOfDay(in: cal)) == 23 * 3600)
        let fall = CalendarDay(year: 2026, month: 11, day: 1)
        #expect(fall.startOfNextDay(in: cal).timeIntervalSince(fall.startOfDay(in: cal)) == 25 * 3600)

        // Last second of the DST day is inside; first second of the next day is outside.
        let b = HistoryDateBounds(to: spring)
        #expect(b.contains(spring.startOfNextDay(in: cal).addingTimeInterval(-1), in: cal))
        #expect(!b.contains(spring.startOfNextDay(in: cal), in: cal))
    }

    @Test func test_009_sameInstantFallsOnDifferentDaysInDifferentZones() {
        // 23:30 UTC on some day → already the next day in Tokyo (UTC+9).
        let midnightUTC: TimeInterval = 1_800_000_000 - TimeInterval(1_800_000_000 % 86_400)
        let instant = Date(timeIntervalSince1970: midnightUTC + 23.5 * 3600)
        let utc = CalendarDay(instant, calendar: calendar("UTC"))
        let tokyo = CalendarDay(instant, calendar: calendar("Asia/Tokyo"))
        #expect(utc != tokyo)
        #expect(HistoryDateBounds(from: tokyo, to: tokyo).contains(instant, in: calendar("Asia/Tokyo")))
        #expect(!HistoryDateBounds(from: tokyo, to: tokyo).contains(instant, in: calendar("UTC")))
    }
}
