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
                    ui.searchFocusChanged(focused)
                    if focused { viewModel.beginSuggesting() }
                },
                onMove: move,
                onReturn: commitOrAccept,
                onEscape: escape,
                onCaretGesture: {
                    // Click / ← → Home End re-show the dropdown for the new caret position.
                    ui.highlightedIndex = -1
                    ui.surface = .suggestions
                    viewModel.beginSuggesting()
                },
                onFocusRequestHandled: { ui.focusRequestHandled() },
                isExpanded: ui.surface == .suggestions && viewModel.showsDropdown
            )

            if !viewModel.draftText.isEmpty {
                Button(action: clearDraft) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(DesignTokens.textTertiary)
                        .font(.system(size: 12))
                }
                .buttonStyle(.plain)
                .accessibilityLabel(ClavisUIStrings.Common.cancel)
            }

            Button(action: addFilter) {
                HStack(spacing: 4) {
                    Image(systemName: "plus")
                        .font(.system(size: 11, weight: .semibold))
                    Text(HistoryText.addFilter)
                        .font(.system(size: 12))
                }
                .foregroundColor(DesignTokens.textSecondary)
                .padding(.horizontal, 6)
                .frame(height: 24)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(HistoryText.addFilterAccessibility)
            .help(HistoryText.addFilterAccessibility)
        }
        .padding(.leading, 11)
        .padding(.trailing, 8)
        .frame(height: HistorySearchTextField.height)
        .contentShape(Capsule())
        .onTapGesture {
            if !ui.isSearchFocused {
                ui.requestSearchFocus(opensSuggestions: true)
            }
        }
        .liquidGlassCapsuleControl(isFocused: ui.isSearchFocused)
        .reportGlobalFrame { ui.searchFieldFrame = $0 }
        // Any committed change (badge added/removed, sidebar key picked) closes the dropdown.
        .onChange(of: viewModel.filter) { _ in
            if ui.surface == .suggestions { ui.dismiss() }
        }
        // VoiceOver: announce the highlighted row (the field keeps keyboard focus).
        .onChange(of: ui.highlightedIndex) { index in
            let list = visibleSuggestions
            guard list.indices.contains(index) else { return }
            let row = list[index]
            let text = [row.title, row.caption].compactMap { $0 }.joined(separator: ", ")
            HistoryAccessibility.announce("\(text). \(index + 1) / \(list.count)")
        }
    }

    // MARK: Actions

    private var visibleSuggestions: [HistorySuggestion] {
        ui.surface == .suggestions && viewModel.showsDropdown ? viewModel.suggestions : []
    }

    private func clearDraft() {
        viewModel.updateDraft(text: "", caret: 0)
        ui.highlightedIndex = -1
        ui.requestSearchFocus(opensSuggestions: false)
    }

    /// `+ Filter` opens the same dropdown as focusing an empty field.
    private func addFilter() {
        viewModel.prepareForNewFilter()
        ui.highlightedIndex = -1
        ui.surface = .suggestions
        ui.requestSearchFocus(opensSuggestions: false)
        viewModel.beginSuggesting()
    }

    /// ↑/↓ wrap around; from "nothing highlighted" ↓ goes to the first row and ↑ to the last.
    /// When the dropdown is closed they open it first (prototype), and only then navigate.
    private func move(_ delta: Int) -> Bool {
        if ui.surface != .suggestions {
            viewModel.beginSuggesting()
            guard viewModel.showsDropdown, !viewModel.suggestions.isEmpty else { return false }
            ui.surface = .suggestions
        }
        let count = visibleSuggestions.count
        guard count > 0 else { return false }
        let current = ui.highlightedIndex
        if current < 0 {
            ui.highlightedIndex = delta > 0 ? 0 : count - 1
        } else {
            ui.highlightedIndex = (current + delta + count) % count
        }
        return true
    }

    /// Return: highlighted row → accept it; otherwise commit the typed condition. Never guesses a
    /// value from a partial one (`Host:git` is committed as typed, or rejected if incomplete).
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

    /// Escape closes the dropdown and keeps the draft. It is consumed even when nothing is open:
    /// NSSearchField's default would clear the text (use the native ✕ for that).
    private func escape() -> Bool {
        if ui.surface != .none { ui.dismiss(); return true }
        return !viewModel.draftText.isEmpty
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

    private static let rowHeight: CGFloat = 30
    private static let visibleRows = 8

    /// Rows are keyboard-highlighted only; pointer hover is a separate visual state, so a resting
    /// mouse can never change what Return accepts.
    @ViewBuilder private var rows: some View {
        let list = viewModel.suggestions
        let content = VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(list.enumerated()), id: \.element.id) { index, suggestion in
                HistorySuggestionRow(
                    suggestion: suggestion,
                    isHighlighted: index == ui.highlightedIndex
                ) {
                    HistorySuggestionActions.accept(suggestion, viewModel: viewModel, ui: ui)
                }
                .id(suggestion.id)
            }
        }
        if list.count > Self.visibleRows {
            ScrollViewReader { proxy in
                ScrollView {
                    content
                }
                .frame(height: CGFloat(Self.visibleRows) * (Self.rowHeight + 2))
                .onChange(of: ui.highlightedIndex) { index in
                    guard list.indices.contains(index) else { return }
                    proxy.scrollTo(list[index].id)
                }
            }
        } else {
            content
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

            rows
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
    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                if let symbol = suggestion.symbol {
                    Image(systemName: symbol)
                        .font(.system(size: 12))
                        .frame(width: 16)
                        .foregroundColor(isHighlighted
                                         ? Color(nsColor: .alternateSelectedControlTextColor)
                                         : DesignTokens.textSecondary)
                        .accessibilityHidden(true)
                }
                Text(suggestion.title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(isHighlighted ? Color(nsColor: .alternateSelectedControlTextColor) : .primary)
                    .lineLimit(1)
                Spacer(minLength: 12)
                if let caption = suggestion.caption {
                    Text(caption)
                        .font(.system(size: 11))
                        .foregroundColor(isHighlighted
                                         ? Color(nsColor: .alternateSelectedControlTextColor).opacity(0.8)
                                         : DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .padding(.horizontal, 10)
            .frame(height: 30)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(isHighlighted ? Color(nsColor: .selectedContentBackgroundColor)   // system selection
                          : isHovering ? Color.primary.opacity(0.07) : .clear)
            )
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
        .accessibilityLabel([suggestion.title, suggestion.caption].compactMap { $0 }.joined(separator: ", "))
        .accessibilityAddTraits(isHighlighted ? .isSelected : [])
    }
}

/// Positions the one dropdown under the search field, full width, and supplies the
/// click-outside catcher below the header. Placed above the whole main pane.
struct HistorySuggestionOverlay: View {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    private var isShown: Bool {
        ui.surface == .suggestions && viewModel.showsDropdown && ui.searchFieldFrame.width > 0
    }

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

enum HistoryAccessibility {
    /// Posts a VoiceOver announcement without moving focus.
    @MainActor
    static func announce(_ message: String) {
        guard let window = NSApp.keyWindow else { return }
        NSAccessibility.post(
            element: window,
            notification: .announcementRequested,
            userInfo: [.announcement: message, .priority: NSAccessibilityPriorityLevel.high.rawValue])
    }
}
