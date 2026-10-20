import Testing
import Foundation
import SwiftUI
import AppKit
@testable import ClavisCore
@testable import Clavis

@Suite(.serialized) struct HistoryFilterTests {

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

    @MainActor
    @Test func test_009_searchTextFieldRetainsNativeCellAndAppearance() throws {
        let searchField = HistorySearchTextField(
            text: "Host:github.com",
            caret: 15,
            focusToken: 0,
            placeholder: "Search history",
            accessibilityLabel: "Search history",
            onEdit: { _, _ in },
            onFocusChange: { _ in },
            onMove: { _ in false },
            onReturn: { false },
            onEscape: { false }
        )

        let hosting = NSHostingView(rootView: searchField.controlSize(.large).frame(width: 320))
        hosting.frame = NSRect(x: 0, y: 0, width: 320, height: 60)
        hosting.layoutSubtreeIfNeeded()

        func findTextField(in view: NSView) -> NSTextField? {
            if let tf = view as? NSTextField { return tf }
            for sub in view.subviews {
                if let found = findTextField(in: sub) { return found }
            }
            return nil
        }

        let field = try #require(findTextField(in: hosting))
        #expect(HistorySearchTextField.height == 34)
        #expect(field is NSSearchField)
        let standard = NSSearchField()
        standard.controlSize = .large
        #expect(type(of: try #require(field.cell)) == type(of: try #require(standard.cell)))
        if #available(macOS 26.0, *) {
            #expect(field.isBezeled)
            #expect(!field.drawsBackground)
            #expect(field.backgroundColor == .clear)
            var ancestor = field.superview
            while ancestor != nil, !(ancestor is NSGlassEffectView) { ancestor = ancestor?.superview }
            #expect(ancestor is NSGlassEffectView)
        } else {
            #expect(field.isBezeled == standard.isBezeled)
        }
        #expect(field.bezelStyle == standard.bezelStyle)
        let search = try #require(field as? NSSearchField)
        search.frame.size.width = 320
        standard.frame = search.frame
        #expect(search.searchTextBounds.width < standard.searchTextBounds.width)
        #expect(search.cancelButtonBounds.minX < standard.cancelButtonBounds.minX)
        #expect(field.focusRingType != .none)
        #expect(field.controlSize == .large)
        #expect(field.font == .systemFont(ofSize: NSFont.systemFontSize(for: .large)))
    }

    @MainActor
    @Test func searchSurfaceFallbackKeepsStandardSearchBezel() {
        let field = HistorySearchTextField.FieldView()
        let standard = NSSearchField()
        let surface = HistorySearchTextField.SearchSurface(field: field, usesGlass: false)
        #expect(field.superview === surface)
        #expect(field.isBezeled == standard.isBezeled)
        #expect(field.drawsBackground == standard.drawsBackground)
    }

    @MainActor
    @Test func test_009_nativeSearchFocusAndTableActionShowValueSuggestions() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("audit-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = try AuditStore(url: url)
        try store.insert(AuditEvent(
            time: Date(timeIntervalSince1970: 1_800_000_000),
            type: .signature,
            result: .allowed,
            reason: .viaPrompt,
            keyFingerprint: "SHA256:k0",
            sensitive: AuditSensitive(keyLabel: "Personal Mac", host: "github.com")
        ))

        let vm = HistoryViewModel(
            store: { store },
            keyring: nil,
            contextProvider: { nil },
            notificationCenter: NotificationCenter(),
            calendar: calendar("UTC")
        )
        vm.keyChoicesForTesting([HistoryKeyChoice(fingerprint: "SHA256:k0", label: "Test")])
        vm.openForKey("SHA256:k0")
        await vm.waitForLoad()
        await vm.ensureSuggestionIndex().value
        let ui = HistoryUIState()

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 500),
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        defer { window.orderOut(nil); window.close() }
        window.isReleasedWhenClosed = false
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true

        let root = HStack(spacing: 0) {
            Color.clear.frame(width: 222)
            ZStack(alignment: .top) {
                DesignTokens.inspectorBackground.ignoresSafeArea()
                HistoryView(viewModel: vm, ui: ui, keys: [])
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .topLiquidGlassBar {
                        VStack(spacing: 0) {
                            Color.clear.frame(height: 58)
                            HistoryFilterHeader(viewModel: vm, ui: ui)
                        }
                    }
            }
        }
        .ignoresSafeArea()
        let hosting = NSHostingView(rootView: root)
        window.contentView = hosting
        window.appearance = NSAppearance(named: .darkAqua)
        window.makeKeyAndOrderFront(nil)
        hosting.layoutSubtreeIfNeeded()
        try await Task.sleep(nanoseconds: 100_000_000)

        func findTextField(in view: NSView) -> NSTextField? {
            if let tf = view as? NSTextField, tf.isEditable { return tf }
            for sub in view.subviews {
                if let found = findTextField(in: sub) { return found }
            }
            return nil
        }

        let field = try #require(findTextField(in: hosting))
        // Exercise AppKit's real first-responder transition (no replacement field editor).
        window.makeFirstResponder(field)
        try await Task.sleep(nanoseconds: 100_000_000)
        hosting.layoutSubtreeIfNeeded()

        #expect(ui.isSearchFocused)
        #expect(ui.surface == .suggestions)
        #expect(vm.suggestions.map(\.title) == ["Host:", "Process:", "Key:", "Result:"])

        // Step 2: The native table action inserts Host: and offers its values, retaining editor focus.
        let panel = try #require(window.childWindows?.first { $0.identifier?.rawValue == "ClavisHistoryCompletions" })
        func findTable(in view: NSView) -> NSTableView? {
            if let table = view as? NSTableView { return table }
            return view.subviews.compactMap { findTable(in: $0) }.first
        }
        let table = try #require(panel.contentView.flatMap { findTable(in: $0) })
        if let bitmap = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) {
            hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
            if let data = bitmap.representation(using: .png, properties: [:]) {
                try data.write(to: FileManager.default.temporaryDirectory.appendingPathComponent("clavis-history-native-header.png"))
            }
        }
        table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        #expect(table.sendAction(table.action, to: table.target))
        try await Task.sleep(nanoseconds: 150_000_000)
        hosting.layoutSubtreeIfNeeded()

        #expect(vm.draftText == "Host:")
        #expect(vm.draftCaret == 5)
        #expect(field.currentEditor()?.string == "Host:")
        #expect(ui.isSearchFocused)
        #expect(ui.surface == .suggestions)
        #expect(vm.suggestions.map(\.title) == ["github.com"])

        // Step 3: Dismiss, then deliberately refocus an already focused search control.
        ui.dismiss()
        vm.updateDraft(text: "", caret: 0)
        hosting.layoutSubtreeIfNeeded()
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(ui.isSearchFocused)
        #expect(ui.surface == .none)

        ui.requestSearchFocus(opensSuggestions: true)
        try await Task.sleep(nanoseconds: 100_000_000)
        hosting.layoutSubtreeIfNeeded()

        #expect(ui.isSearchFocused)
        #expect(ui.surface == .suggestions)
        #expect(vm.suggestions.map(\.title) == ["Host:", "Process:", "Key:", "Result:"])
    }
}


extension HistoryFilterTests {
    @MainActor
    @Test func suggestionBlurDismissesSynchronouslyWithoutTimer() {
        let ui = HistoryUIState()
        ui.searchFocusChanged(true)
        #expect(ui.surface == .suggestions)
        ui.searchFocusChanged(false)
        #expect(ui.surface == .none)
    }

    @MainActor
    @Test func committedValueRefocusDoesNotReopenSuggestions() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("history-\(UUID()).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = try AuditStore(url: url)
        let vm = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil }, notificationCenter: NotificationCenter())
        let ui = HistoryUIState()
        vm.updateDraft(text: "Result:", caret: 7)
        ui.surface = .suggestions
        let rejected = try #require(vm.suggestions.first { $0.title == "Rejected" })
        HistorySuggestionActions.accept(rejected, viewModel: vm, ui: ui)
        #expect(vm.filter.criteria == [.result(.rejected)])
        #expect(vm.draftText.isEmpty)
        #expect(ui.surface == .none)
        ui.searchFocusChanged(true)
        ui.focusRequestHandled()
        #expect(ui.surface == .none)
        // A subsequent deliberate focus is a new interaction, not permanently suppressed.
        ui.searchFocusChanged(false)
        ui.searchFocusChanged(true)
        #expect(ui.surface == .suggestions)
    }

    @MainActor
    @Test func staleSuggestionCannotCommitAfterContextChanged() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("history-\(UUID()).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = try AuditStore(url: url)
        let vm = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil }, notificationCenter: NotificationCenter())
        vm.updateDraft(text: "Result:", caret: 7)
        let old = try #require(vm.suggestions.first)
        vm.updateDraft(text: "Host:", caret: 5)
        HistorySuggestionActions.accept(old, viewModel: vm, ui: HistoryUIState())
        #expect(vm.filter.criteria.isEmpty)
        #expect(vm.draftText == "Host:")
    }
}

extension HistoryFilterTests {
    @MainActor
    @Test(arguments: [false, true])
    func nativeCompletionPanelAnchoringMaterialsAndOutsideClick(preferLegacy: Bool) async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("history-panel-\(UUID()).db")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = try AuditStore(url: url)
        let vm = HistoryViewModel(store: { store }, keyring: nil, contextProvider: { nil }, notificationCenter: NotificationCenter())
        vm.beginSuggesting()
        let ui = HistoryUIState()
        let window = NSWindow(contentRect: NSRect(x: 150, y: 150, width: 620, height: 420),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Clavis History — completion verification"
        window.isReleasedWhenClosed = false
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 620, height: 420))
        let search = NSSearchField(frame: NSRect(x: 20, y: 340, width: 580, height: 34))
        search.placeholderString = "Host:github.com Process:ssh"
        root.addSubview(search)
        window.contentView = root
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(search)
        ui.surface = .suggestions
        let controller = HistoryCompletionPanelController(viewModel: vm, ui: ui, preferLegacyMaterial: preferLegacy)
        defer { controller.invalidate(); window.orderOut(nil); window.close() }
        controller.scheduleUpdate(anchor: search)
        controller.update()
        #expect(controller.panel.parent === window)
        #expect(!controller.panel.canBecomeKey)
        #expect(controller.table.numberOfRows == 4)
        let fieldRect = window.convertToScreen(search.convert(search.bounds, to: nil))
        #expect(abs(controller.panel.frame.width - fieldRect.width) < 1)
        #expect(abs(controller.panel.frame.maxY + HistoryUIState.dropdownGap - fieldRect.minY) < 1)
        if NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency {
            #expect(controller.panel.contentView is NSBox)
        } else if preferLegacy {
            #expect(controller.panel.contentView is NSVisualEffectView)
        } else if #available(macOS 26.0, *) {
            #expect(controller.panel.contentView is NSGlassEffectView)
        }
        // Keyboard highlight tracks identity even if a refreshed catalog changes row order.
        ui.highlightedSuggestionID = vm.suggestions[2].id
        controller.update()
        #expect(controller.table.selectedRow == 2)
        #expect(controller.table.effectiveStyle == .inset)
        let selectedRow = try #require(controller.table.rowView(atRow: 2, makeIfNecessary: true))
        #expect(selectedRow.isEmphasized == window.isKeyWindow)
        // Pointer tracking selects through the native table and updates the shared
        // highlighted identity without taking focus from the search field editor.
        let hoveredRect = controller.table.rect(ofRow: 1)
        let pointerPoint = controller.table.convert(NSPoint(x: hoveredRect.midX, y: hoveredRect.midY), to: nil)
        let move = try #require(NSEvent.mouseEvent(with: .mouseMoved,
            location: pointerPoint, modifierFlags: [], timestamp: 0,
            windowNumber: controller.panel.windowNumber, context: nil, eventNumber: 1, clickCount: 0, pressure: 0))
        controller.table.mouseMoved(with: move)
        #expect(controller.table.selectedRow == 1)
        #expect(ui.highlightedSuggestionID == vm.suggestions[1].id)
        #expect(search.currentEditor() != nil)
        let hoverRow = try #require(controller.table.rowView(atRow: 1, makeIfNecessary: true))
        #expect(hoverRow.isEmphasized == window.isKeyWindow)

        // All rows fit, including a single-result list. Native inset padding must
        // not consume the first/last row's visible area or create a gap under title.
        ui.highlightedSuggestionID = nil
        vm.updateDraft(text: "Ke", caret: 2)
        controller.update()
        #expect(controller.table.numberOfRows == 1)
        let firstRowRect = controller.table.rect(ofRow: 0)
        #expect(controller.table.enclosingScrollView == nil)
        #expect(controller.table.bounds.contains(firstRowRect))

        func heading(in view: NSView) -> NSTextField? {
            if let label = view as? NSTextField, label.stringValue == HistoryText.filterBy { return label }
            return view.subviews.lazy.compactMap { heading(in: $0) }.first
        }
        func assertHeadingAlignment() throws {
            controller.panel.contentView?.layoutSubtreeIfNeeded()
            let header = try #require(heading(in: controller.panel.contentView!))
            let cell = try #require(controller.table.view(atColumn: 0, row: 0, makeIfNecessary: true) as? NSTableCellView)
            cell.layoutSubtreeIfNeeded()
            let label = try #require(cell.textField)
            let headerX = header.convert(header.bounds, to: nil).minX
            let labelX = label.convert(label.bounds, to: nil).minX
            #expect(abs(headerX - labelX) < 1)
        }
        try assertHeadingAlignment()
        vm.updateDraft(text: "", caret: 0)
        controller.update()
        #expect(controller.table.bounds.contains(controller.table.rect(ofRow: 3)))
        try assertHeadingAlignment()
        // Values have no icons; their text and heading must share the same edge too.
        vm.updateDraft(text: "Result:", caret: 7)
        controller.update()
        let valueCell = try #require(controller.table.view(atColumn: 0, row: 0, makeIfNecessary: true) as? NSTableCellView)
        let valueLabel = try #require(valueCell.textField)
        func valueHeading(in view: NSView) -> NSTextField? {
            if let label = view as? NSTextField, label.stringValue == HistoryText.matchAny("Result") { return label }
            return view.subviews.lazy.compactMap { valueHeading(in: $0) }.first
        }
        controller.panel.contentView?.layoutSubtreeIfNeeded()
        let valueHeader = try #require(valueHeading(in: controller.panel.contentView!))
        #expect(abs(valueHeader.convert(valueHeader.bounds, to: nil).minX - valueLabel.convert(valueLabel.bounds, to: nil).minX) < 1)
        vm.keyChoicesForTesting((0..<12).map { HistoryKeyChoice(fingerprint: "SHA256:\($0)", label: "Key \($0)") })
        vm.updateDraft(text: "Key:", caret: 4)
        controller.update()
        #expect(controller.table.numberOfRows == 7)
        #expect(controller.table.bounds.contains(controller.table.rect(ofRow: 6)))
        #expect(controller.table.enclosingScrollView == nil)
        vm.updateDraft(text: "", caret: 0)
        controller.update()

        // Resize is positioned from real AppKit bounds, not a cached global SwiftUI rectangle.
        search.frame.size.width = 460
        controller.update()
        #expect(abs(controller.panel.frame.width - 460) < 1)

        controller.panel.contentView?.layoutSubtreeIfNeeded()
        controller.panel.displayIfNeeded()
        if let view = controller.panel.contentView,
           let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
            view.cacheDisplay(in: view.bounds, to: bitmap)
            let name = preferLegacy ? "clavis-history-legacy-panel.png" : "clavis-history-glass-panel.png"
            if let data = bitmap.representation(using: .png, properties: [:]) {
                try data.write(to: FileManager.default.temporaryDirectory.appendingPathComponent(name))
            }
        }

        let event = try #require(NSEvent.mouseEvent(with: .leftMouseDown,
            location: NSPoint(x: 10, y: 10), modifierFlags: [], timestamp: 0,
            windowNumber: window.windowNumber, context: nil, eventNumber: 42, clickCount: 1, pressure: 1))
        #expect(controller.handleEvent(event) === event) // same event continues to its target
        #expect(ui.surface == .none)
        #expect(!controller.panel.isVisible)
        #expect(window.childWindows?.contains(controller.panel) != true)
    }

    @MainActor
    @Test func nativeSearchFocusKeepsZeroCaretAndUserSelection() async throws {
        let window = NSWindow(contentRect: NSRect(x: 100, y: 100, width: 500, height: 120),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.orderOut(nil); window.close() }
        var view = HistorySearchTextField(text: "Host:github.com", caret: 0, focusToken: 0,
            placeholder: "History", accessibilityLabel: "History", onEdit: { _, _ in },
            onFocusChange: { _ in }, onMove: { _ in false }, onReturn: { false }, onEscape: { false })
        let host = NSHostingView(rootView: view.frame(width: 460, height: 34))
        window.contentView = host
        window.makeKeyAndOrderFront(nil)
        host.layoutSubtreeIfNeeded()
        view.focusToken = 1
        host.rootView = view.frame(width: 460, height: 34)
        // Wait for the public first-responder transition, rather than a fixed click delay.
        var foundEditor: NSTextView?
        for _ in 0..<100 {
            if let current = window.firstResponder as? NSTextView { foundEditor = current; break }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        let editor = try #require(foundEditor)
        #expect(editor.selectedRange() == NSRange(location: 0, length: 0))
        let selected = NSRange(location: 5, length: 6)
        editor.setSelectedRange(selected)
        view.isExpanded = true
        host.rootView = view.frame(width: 460, height: 34)
        host.layoutSubtreeIfNeeded()
        await Task.yield()
        #expect(editor.selectedRange() == selected)
    }
}
