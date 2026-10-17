import SwiftUI
import AppKit
import ClavisCore

// MARK: - Search bar (capsule with embedded `+ Filter`)

struct HistorySearchBar: View {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 13))
                .foregroundColor(DesignTokens.textSecondary)
                .accessibilityHidden(true)

            HistorySearchTextField(
                text: viewModel.draftText,
                caret: viewModel.draftCaret,
                focusToken: ui.focusToken,
                placeholder: HistoryText.searchPlaceholder,
                accessibilityLabel: HistoryText.searchAccessibilityLabel,
                onEdit: { text, caret in
                    let textChanged = text != viewModel.draftText
                    viewModel.updateDraft(text: text, caret: caret)
                    if textChanged {
                        // Typing (re)opens the dropdown; pure caret moves keep whatever is open.
                        ui.highlightedIndex = -1
                        ui.surface = .suggestions
                    }
                },
                onFocusChange: { focused in
                    ui.searchFocusChanged(focused, draftIsEmpty: viewModel.draftText.isEmpty)
                    if focused { viewModel.ensureSuggestionIndex() }
                },
                onMove: move,
                onReturn: commitOrAccept,
                onEscape: escape
            )
            .frame(height: 20)

            Button(action: addFilter) {
                HStack(spacing: 4) {
                    Image(systemName: "plus")
                        .font(.system(size: 11, weight: .semibold))
                    Text(HistoryText.addFilter)
                        .font(.system(size: 12))
                }
                .foregroundColor(DesignTokens.textSecondary)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(HistoryText.addFilterAccessibility)
            .help(HistoryText.addFilterAccessibility)
        }
        .padding(.horizontal, 11)
        .frame(height: 34)
        .liquidGlassCapsuleControl(isFocused: ui.isSearchFocused)
        .reportGlobalFrame { ui.searchFieldFrame = $0 }
    }

    // MARK: Actions

    private var visibleSuggestions: [HistorySuggestion] {
        ui.surface == .suggestions ? viewModel.suggestions : []
    }

    /// `+ Filter` opens the same dropdown as focusing an empty field.
    private func addFilter() {
        viewModel.prepareForNewFilter()
        ui.highlightedIndex = -1
        ui.surface = .suggestions
        ui.requestSearchFocus(opensSuggestions: false)
        viewModel.ensureSuggestionIndex()
    }

    private func move(_ delta: Int) -> Bool {
        let list = visibleSuggestions
        guard !list.isEmpty else { return false }
        let next = ui.highlightedIndex + delta
        ui.highlightedIndex = min(max(next, -1), list.count - 1)
        if ui.highlightedIndex < 0, delta < 0 { ui.highlightedIndex = list.count - 1 }
        return true
    }

    private func commitOrAccept() -> Bool {
        let list = visibleSuggestions
        if list.indices.contains(ui.highlightedIndex) {
            accept(list[ui.highlightedIndex])
            return true
        }
        if viewModel.commitDraft() {
            ui.dismiss()
            ui.requestSearchFocus(opensSuggestions: false)
        }
        return true
    }

    private func escape() -> Bool {
        guard ui.surface != .none else { return false }
        ui.dismiss()   // the draft stays
        return true
    }

    private func accept(_ suggestion: HistorySuggestion) {
        HistorySuggestionActions.accept(suggestion, viewModel: viewModel, ui: ui)
    }
}

enum HistorySuggestionActions {
    @MainActor
    static func accept(_ suggestion: HistorySuggestion, viewModel: HistoryViewModel, ui: HistoryUIState) {
        viewModel.accept(suggestion)
        ui.highlightedIndex = -1
        switch suggestion.kind {
        case .prefix:
            ui.surface = .suggestions            // now offering values for that prefix
            viewModel.ensureSuggestionIndex()
        case .value:
            ui.dismiss()                          // committed: close, keep focus
        }
        ui.requestSearchFocus(opensSuggestions: false)
    }
}

// MARK: - Shared dropdown

struct HistorySuggestionList: View {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    private var title: String {
        switch viewModel.completionContext?.mode {
        case .value(let field, _): return HistoryText.matchAny(field.prefix)
        default: return HistoryText.filterBy
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(DesignTokens.textSecondary)
                .padding(.horizontal, 10)
                .padding(.top, 4)
                .accessibilityAddTraits(.isHeader)

            if viewModel.suggestions.isEmpty {
                Text(HistoryText.noMatchingValues)
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
            }

            ForEach(Array(viewModel.suggestions.enumerated()), id: \.element.id) { index, suggestion in
                HistorySuggestionRow(
                    suggestion: suggestion,
                    isHighlighted: index == ui.highlightedIndex
                ) {
                    HistorySuggestionActions.accept(suggestion, viewModel: viewModel, ui: ui)
                }
                .onHover { hovering in
                    if hovering { ui.highlightedIndex = index }
                }
            }
        }
        .padding(6)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.regularMaterial)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(DesignTokens.cardBorder, lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.18), radius: 14, x: 0, y: 6)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(HistoryText.suggestionsAccessibility)
    }
}

private struct HistorySuggestionRow: View {
    let suggestion: HistorySuggestion
    let isHighlighted: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                if let symbol = suggestion.symbol {
                    Image(systemName: symbol)
                        .font(.system(size: 12))
                        .frame(width: 16)
                        .foregroundColor(DesignTokens.textSecondary)
                        .accessibilityHidden(true)
                }
                Text(suggestion.title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                Spacer(minLength: 12)
                if let caption = suggestion.caption {
                    Text(caption)
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .padding(.horizontal, 10)
            .frame(height: 30)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(isHighlighted ? Color.accentColor.opacity(0.18) : .clear)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel([suggestion.title, suggestion.caption].compactMap { $0 }.joined(separator: ", "))
        .accessibilityAddTraits(isHighlighted ? .isSelected : [])
    }
}

/// Positions the one dropdown under the search field, full width, and supplies the
/// click-outside catcher below the header. Placed above the whole main pane.
struct HistorySuggestionOverlay: View {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    private var isShown: Bool { ui.surface == .suggestions && ui.searchFieldFrame.width > 0 }

    var body: some View {
        GeometryReader { pane in
            if isShown {
                let origin = pane.frame(in: .global).origin
                let field = ui.searchFieldFrame
                ZStack(alignment: .topLeading) {
                    // Outside clicks below the header dismiss without undoing committed changes.
                    Color.clear
                        .contentShape(Rectangle())
                        .padding(.top, max(0, field.maxY - origin.y))
                        .onTapGesture { ui.dismiss() }

                    HistorySuggestionList(viewModel: viewModel, ui: ui)
                        .frame(width: field.width)
                        .offset(x: field.minX - origin.x,
                                y: field.maxY - origin.y + HistoryUIState.dropdownGap)
                }
            }
        }
        .allowsHitTesting(isShown)
    }
}
