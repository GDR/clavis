import SwiftUI
import AppKit

/// One native search field and one shared completion session for both entry points.
struct HistorySearchBar: View {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    var body: some View {
        HistorySearchTextField(
            text: viewModel.draftText,
            caret: viewModel.draftCaret,
            focusToken: ui.focusToken,
            placeholder: HistoryText.searchPlaceholder,
            accessibilityLabel: HistoryText.searchAccessibilityLabel,
            onEdit: { text, caret in
                let textChanged = text != viewModel.draftText
                viewModel.updateDraft(text: text, selection: ui.searchSelection)
                if textChanged {
                    ui.highlightedSuggestionID = nil
                    ui.surface = .suggestions
                }
            },
            onFocusChange: { focused in
                ui.searchFocusChanged(focused)
                if focused { viewModel.beginSuggesting() }
            },
            onMove: move,
            onReturn: commitOrAccept,
            onEscape: escape,
            onCaretGesture: {
                ui.highlightedSuggestionID = nil
                ui.surface = .suggestions
                viewModel.beginSuggesting()
            },
            onFocusRequestHandled: { ui.focusRequestHandled() },
            isExpanded: ui.surface == .suggestions && viewModel.showsDropdown,
            onAddFilter: addFilter,
            onSelectionChange: { ui.searchSelection = $0 },
            onNativeField: { ui.searchField = $0 }
        )
        .controlSize(.large)
        .frame(height: HistorySearchTextField.height)
        .background(HistoryCompletionPresenter(viewModel: viewModel, ui: ui))
        .onChange(of: viewModel.filter) { _ in
            if ui.surface == .suggestions { ui.dismiss() }
        }
        .onChange(of: viewModel.suggestions.map(\.id)) { ids in
            if let selected = ui.highlightedSuggestionID, !ids.contains(selected) {
                ui.highlightedSuggestionID = nil
            }
        }
    }

    private var visibleSuggestions: [HistorySuggestion] {
        ui.surface == .suggestions && viewModel.showsDropdown ? viewModel.suggestions : []
    }

    private func addFilter() {
        viewModel.prepareForNewFilter()
        ui.highlightedSuggestionID = nil
        ui.surface = .suggestions
        ui.requestSearchFocus(opensSuggestions: false)
        viewModel.beginSuggesting()
    }

    private func move(_ delta: Int) -> Bool {
        if ui.surface != .suggestions {
            viewModel.beginSuggesting()
            guard viewModel.showsDropdown, !viewModel.suggestions.isEmpty else { return false }
            ui.surface = .suggestions
        }
        let list = visibleSuggestions
        guard !list.isEmpty else { return false }
        let current = list.firstIndex { $0.id == ui.highlightedSuggestionID }
        let next = current.map { ($0 + delta + list.count) % list.count } ?? (delta > 0 ? 0 : list.count - 1)
        ui.highlightedSuggestionID = list[next].id
        return true
    }

    private func commitOrAccept() -> Bool {
        if let selected = visibleSuggestions.first(where: { $0.id == ui.highlightedSuggestionID }) {
            HistorySuggestionActions.accept(selected, viewModel: viewModel, ui: ui)
        } else if viewModel.commitDraft() {
            ui.dismiss()
            ui.requestSearchFocus(opensSuggestions: false)
        }
        return true
    }

    private func escape() -> Bool {
        if ui.surface != .none { ui.dismiss(); return true }
        return !viewModel.draftText.isEmpty
    }
}

enum HistorySuggestionActions {
    @MainActor
    static func accept(_ suggestion: HistorySuggestion, viewModel: HistoryViewModel, ui: HistoryUIState) {
        // Ignore a stale row if the catalog or caret changed before its action arrived.
        guard viewModel.suggestions.contains(where: { $0.id == suggestion.id }) else { return }
        viewModel.accept(suggestion)
        ui.highlightedSuggestionID = nil
        switch suggestion.kind {
        case .prefix:
            ui.surface = .suggestions
            viewModel.ensureSuggestionIndex()
        case .value:
            ui.dismiss()
        }
        ui.requestSearchFocus(opensSuggestions: false)
    }
}
