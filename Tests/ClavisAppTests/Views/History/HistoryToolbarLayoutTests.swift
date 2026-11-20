import Testing
import Foundation
import SwiftUI
import AppKit
@testable import ClavisCore
@testable import Clavis

/// S-09: the filter controls live INSIDE the unified 52pt sticky toolbar row beside the
/// "History" title — one line, never a separate filter row below the band.
@Suite @MainActor
struct HistoryToolbarLayoutTests {

    private func makeViewModel() throws -> HistoryViewModel {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("audit-\(UUID().uuidString).db")
        let store = try AuditStore(url: url)
        return HistoryViewModel(
            store: { store },
            keyring: nil,
            contextProvider: { nil },
            notificationCenter: NotificationCenter()
        )
    }

    @Test
    func filterControlsFitOnOneLineInsideTheToolbarBand() throws {
        let vm = try makeViewModel()
        let ui = HistoryUIState()
        let header = HistoryFilterHeader(viewModel: vm, ui: ui)
        let hosting = NSHostingView(rootView: header.frame(width: 620))
        hosting.layoutSubtreeIfNeeded()
        // Search field (34pt) + calendar/sort controls share a single row that fits the band.
        #expect(hosting.fittingSize.height <= KeyListView.toolbarHeight)
        #expect(hosting.fittingSize.height >= HistorySearchTextField.height)
    }

    @Test
    func appliedBadgesGrowTheSummaryNotTheToolbarRow() throws {
        let vm = try makeViewModel()
        let ui = HistoryUIState()
        let rowHosting = NSHostingView(rootView: HistoryFilterHeader(viewModel: vm, ui: ui).frame(width: 620))
        let summaryHosting = NSHostingView(rootView: HistoryFilterSummary(viewModel: vm).frame(width: 620))
        rowHosting.layoutSubtreeIfNeeded()
        summaryHosting.layoutSubtreeIfNeeded()
        let rowHeightBefore = rowHosting.fittingSize.height
        let summaryHeightBefore = summaryHosting.fittingSize.height

        // Committing a filter adds a badge: it must land in the pinned summary, never inflate
        // the one-line toolbar row.
        vm.add(.host("github.com"))
        rowHosting.layoutSubtreeIfNeeded()
        summaryHosting.layoutSubtreeIfNeeded()
        #expect(rowHosting.fittingSize.height == rowHeightBefore)
        #expect(summaryHosting.fittingSize.height > summaryHeightBefore)
    }
}