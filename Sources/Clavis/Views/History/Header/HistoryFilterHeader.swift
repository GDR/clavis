import SwiftUI
import AppKit
import ClavisCore

/// Thin facade over `ClavisUIStrings.History` so views keep short call sites.
enum HistoryText {
    static var searchPlaceholder: String { ClavisUIStrings.History.searchField }
    static var searchAccessibilityLabel: String { ClavisUIStrings.History.searchFieldAccessibility }
    static var addFilter: String { ClavisUIStrings.History.addFilter }
    static var addFilterAccessibility: String { ClavisUIStrings.History.addFilterAccessibility }
    static var filterBy: String { ClavisUIStrings.History.filterBy }
    static func matchAny(_ field: String) -> String { ClavisUIStrings.History.matchAny(field.lowercased()) }
    static var noMatchingValues: String { ClavisUIStrings.History.noMatchingValues }
    static var suggestionsAccessibility: String { ClavisUIStrings.History.suggestionsAccessibility }
    static var clearFilters: String { ClavisUIStrings.History.clearFilters }
    static var back: String { ClavisUIStrings.History.back }
    static var calendar: String { ClavisUIStrings.History.dateRange }
    static var sort: String { ClavisUIStrings.History.sortOrder }
    static var from: String { ClavisUIStrings.History.dateFrom }
    static var to: String { ClavisUIStrings.History.dateTo }
    static var newestFirst: String { ClavisUIStrings.History.newestFirst }
    static var oldestFirst: String { ClavisUIStrings.History.oldestFirst }

    static func removeBadge(_ label: String) -> String { ClavisUIStrings.History.removeBadge(label) }
    static func clearDate(_ name: String) -> String { ClavisUIStrings.History.clearDate(name.lowercased()) }

    static func matchingCount(_ n: Int) -> String {
        n == 1 ? ClavisUIStrings.History.matchingCountOne : ClavisUIStrings.History.matchingCount(n.formatted())
    }
    static func matchingSoFar(_ n: Int) -> String {
        n == 1 ? ClavisUIStrings.History.matchingSoFarOne : ClavisUIStrings.History.matchingSoFar(n.formatted())
    }
    static func unreadable(_ n: Int) -> String { ClavisUIStrings.History.unreadableCount(n.formatted()) }
    static var unreadableHelp: String { ClavisUIStrings.History.unreadableHelp }
    static var loadingEvents: String { ClavisUIStrings.History.loadingEvents }
}

/// Fixed header region of History: search row, applied badges and the matching count.
/// Everything here sits in the safe-area bar; only the results scroll beneath it.
struct HistoryFilterHeader: View {
    @ObservedObject var viewModel: HistoryViewModel
    @ObservedObject var ui: HistoryUIState

    static let horizontalInset: CGFloat = 20

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                HistorySearchBar(viewModel: viewModel, ui: ui)

                AdaptiveGlassEffectContainer(spacing: 8) {
                    calendarButton
                    sortButton
                }
            }
            .padding(.top, 4)

            if let error = viewModel.draftError {
                Text(error.message)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
                    .padding(.top, 6)
                    .padding(.leading, 11)
                    .accessibilityLabel(error.message)
            }

            HistoryBadgeRow(viewModel: viewModel)

            Text(countText)
                .font(.system(size: 12).monospacedDigit())
                .foregroundColor(DesignTokens.textSecondary)
                .help(viewModel.filter.needsSensitiveScan && viewModel.unreadableScanned > 0 ? HistoryText.unreadableHelp : "")
                .padding(.top, 10)
                .padding(.bottom, 10)
                .accessibilityLabel(countText)
        }
        .padding(.horizontal, Self.horizontalInset)
        .background(DesignTokens.inspectorBackground)
        .overlay(alignment: .bottom) {
            Rectangle().fill(DesignTokens.cardBorder).frame(height: 1)
        }
    }

    private var countText: String {
        if viewModel.isLoading && viewModel.records.isEmpty { return HistoryText.loadingEvents }
        var text: String
        if let total = viewModel.totalMatching {
            text = HistoryText.matchingCount(total)
        } else {
            text = HistoryText.matchingSoFar(viewModel.records.count)
        }
        if viewModel.filter.needsSensitiveScan, viewModel.unreadableScanned > 0 {
            text += " · " + HistoryText.unreadable(viewModel.unreadableScanned)
        }
        return text
    }

    // MARK: Calendar & Sort — same native control size as History/Settings above

    private func binding(for surface: HistorySurface) -> Binding<Bool> {
        Binding(
            get: { ui.surface == surface },
            set: { presented in
                if presented { ui.surface = surface }
                else if ui.surface == surface { ui.dismiss() }
            }
        )
    }

    private var calendarButton: some View {
        CircularGlassIconButton(
            icon: "calendar",
            size: 34,
            iconSize: 15,
            isActive: !viewModel.filter.dateBounds.isEmpty,   // tint only while a bound is set
            helpText: HistoryText.calendar,
            accessibilityLabel: HistoryText.calendar
        ) {
            ui.toggle(.calendar)
        }
        .popover(isPresented: binding(for: .calendar), arrowEdge: .bottom) {
            HistoryDatePopover(viewModel: viewModel)
        }
    }

    private var sortButton: some View {
        CircularGlassIconButton(
            icon: "arrow.up.arrow.down",
            size: 34,
            iconSize: 15,
            helpText: HistoryText.sort,
            accessibilityLabel: HistoryText.sort
        ) {
            ui.toggle(.sort)
        }
        .accessibilityValue(viewModel.filter.sortOrder == .newestFirst ? HistoryText.newestFirst : HistoryText.oldestFirst)
        .popover(isPresented: binding(for: .sort), arrowEdge: .bottom) {
            HistorySortPopover(viewModel: viewModel, onChosen: { ui.dismiss() })
        }
    }
}

// MARK: - Badges

struct HistoryBadgeRow: View {
    @ObservedObject var viewModel: HistoryViewModel

    private var timeLabel: String? {
        let b = viewModel.filter.dateBounds
        let cal = viewModel.calendar
        func fmt(_ d: CalendarDay) -> String {
            d.startOfDay(in: cal).formatted(Date.FormatStyle(date: .abbreviated, time: .omitted, timeZone: cal.timeZone))
        }
        switch (b.from, b.to) {
        case (nil, nil): return nil
        case (let f?, nil): return "Time: From \(fmt(f))"
        case (nil, let t?): return "Time: Until \(fmt(t))"
        case (let f?, let t?): return "Time: \(fmt(f)) – \(fmt(t))"
        }
    }

    var body: some View {
        let filter = viewModel.filter
        if !filter.criteria.isEmpty || timeLabel != nil {
            HistoryFlowLayout(spacing: 6, lineSpacing: 6) {
                ForEach(filter.criteria) { criterion in
                    let text = HistoryBadgeText.label(for: criterion, viewModel: viewModel)
                    HistoryBadge(label: text.label, help: text.help) {
                        viewModel.removeCriterion(id: criterion.id)
                    }
                }
                if let timeLabel {
                    HistoryBadge(label: timeLabel, help: timeLabel) {
                        // One Time badge covers both bounds.
                        viewModel.setDateFrom(nil)
                        viewModel.setDateTo(nil)
                    }
                }
                if filter.canClear {
                    Button(HistoryText.clearFilters) { viewModel.clearFilters() }
                        .buttonStyle(.plain)
                        .font(.system(size: 12))
                        .foregroundColor(.accentColor)
                        .padding(.horizontal, 4)
                }
            }
            .padding(.top, 10)
        }
    }
}

enum HistoryBadgeText {
    /// `label` is what the badge shows; `help` carries the full value (paths, long names).
    @MainActor
    static func label(for criterion: HistoryCriterion, viewModel: HistoryViewModel) -> (label: String, help: String) {
        switch criterion {
        case .host(let h):
            return ("Host: \(h)", "Host: \(h)")
        case .process(.name(let n)):
            return ("Process: \(n)", "Process: \(n)")
        case .process(.path(let p)):
            // Show the basename; the full path keeps same-named binaries distinguishable.
            return ("Process: \((p as NSString).lastPathComponent)", p)
        case .key(let fp):
            let name = viewModel.label(forKeyFingerprint: fp)
            return ("Key: \(name)", "Key: \(name)")
        case .result(let r):
            return ("Result: \(r.title)", "Result: \(r.title)")
        case .text(let t):
            return ("Search: \(t)", "Search: \(t)")
        }
    }
}

struct HistoryBadge: View {
    let label: String
    let help: String
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 12))
                .foregroundColor(.primary)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 260, alignment: .leading)
            Button(action: onRemove) {
                Image(systemName: "xmark")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(DesignTokens.textSecondary)
                    .frame(width: 16, height: 16)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(HistoryText.removeBadge(label))
            .help(HistoryText.removeBadge(label))
        }
        .padding(.leading, 10)
        .padding(.trailing, 5)
        .padding(.vertical, 4)
        .background(Capsule().fill(Color.accentColor.opacity(0.12)))
        .overlay(Capsule().strokeBorder(Color.accentColor.opacity(0.25), lineWidth: 0.5))
        .help(help)
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Sort popover (highlight-only selection, no checkmark)

struct HistorySortPopover: View {
    @ObservedObject var viewModel: HistoryViewModel
    let onChosen: () -> Void

    var body: some View {
        VStack(spacing: 2) {
            row(.newestFirst, symbol: "arrow.down", title: HistoryText.newestFirst)
            row(.oldestFirst, symbol: "arrow.up", title: HistoryText.oldestFirst)
        }
        .padding(6)
        .frame(width: 180)
    }

    private func row(_ order: AuditSortOrder, symbol: String, title: String) -> some View {
        let selected = viewModel.filter.sortOrder == order
        return Button {
            viewModel.setSortOrder(order)
            onChosen()
        } label: {
            HStack(spacing: 8) {
                Image(systemName: symbol).font(.system(size: 12)).frame(width: 16)
                Text(title).font(.system(size: 13))
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .frame(height: 30)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(selected ? Color.accentColor.opacity(0.18) : .clear)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: - Date popover: two optional, independent bounds

struct HistoryDatePopover: View {
    @ObservedObject var viewModel: HistoryViewModel
    private enum Bound { case from, to }
    @State private var editing: Bound?

    private var calendar: Calendar { viewModel.calendar }
    private var bounds: HistoryDateBounds { viewModel.filter.dateBounds }

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 8) {
                field(.from, day: bounds.from, name: HistoryText.from)
                field(.to, day: bounds.to, name: HistoryText.to)
            }
            if let editing {
                DatePicker("", selection: pickerBinding(editing), in: pickerRange(editing), displayedComponents: .date)
                    .datePickerStyle(.graphical)
                    .labelsHidden()
                    .environment(\.calendar, calendar)
                    .environment(\.timeZone, calendar.timeZone)
                    .accessibilityLabel(editing == .from ? HistoryText.from : HistoryText.to)
            }
        }
        .padding(12)
        .frame(width: 292)
    }

    private func formatted(_ day: CalendarDay) -> String {
        day.startOfDay(in: calendar)
            .formatted(Date.FormatStyle(date: .abbreviated, time: .omitted, timeZone: calendar.timeZone))
    }

    private func field(_ bound: Bound, day: CalendarDay?, name: String) -> some View {
        ZStack(alignment: .trailing) {
            Button {
                editing = (editing == bound) ? nil : bound
            } label: {
                HStack(spacing: 6) {
                    Text(day.map(formatted) ?? name)
                        .font(.system(size: 13))
                        .foregroundColor(day == nil ? DesignTokens.textSecondary : .primary)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                    if day == nil {
                        Image(systemName: "calendar")
                            .font(.system(size: 12))
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                }
                .padding(.horizontal, 10)
                .frame(maxWidth: .infinity, minHeight: 30, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(day.map { "\(name), \(formatted($0))" } ?? "\(name), not set, no date limit")

            if day != nil {
                // Clears only this bound; the inline X lives inside the field.
                Button {
                    switch bound {
                    case .from: viewModel.setDateFrom(nil)
                    case .to: viewModel.setDateTo(nil)
                    }
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 13))
                        .foregroundColor(DesignTokens.textSecondary)
                        .frame(width: 24, height: 30)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(HistoryText.clearDate(name))
                .help(HistoryText.clearDate(name))
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(editing == bound ? Color.accentColor : DesignTokens.cardBorder,
                              lineWidth: editing == bound ? 1.5 : 1)
        )
    }

    /// A calendar needs *some* date to show; an unset bound anchors on the other bound or today.
    /// The anchor is presentation only and never becomes a committed bound by itself.
    private func anchor(for bound: Bound) -> Date {
        switch bound {
        case .from: return (bounds.from ?? bounds.to).map { $0.startOfDay(in: calendar) } ?? Date()
        case .to: return (bounds.to ?? bounds.from).map { $0.startOfDay(in: calendar) } ?? Date()
        }
    }

    private func pickerBinding(_ bound: Bound) -> Binding<Date> {
        Binding(
            get: {
                switch bound {
                case .from: return bounds.from.map { $0.startOfDay(in: calendar) } ?? anchor(for: .from)
                case .to: return bounds.to.map { $0.startOfDay(in: calendar) } ?? anchor(for: .to)
                }
            },
            set: { date in
                let day = CalendarDay(date, calendar: calendar)
                let ok: Bool
                switch bound {
                case .from: ok = viewModel.setDateFrom(day)
                case .to: ok = viewModel.setDateTo(day)
                }
                if ok { editing = nil }
            }
        )
    }

    /// From can't pass To and vice versa; no fixture-based maximum.
    private func pickerRange(_ bound: Bound) -> ClosedRange<Date> {
        switch bound {
        case .from: return Date.distantPast...(bounds.to.map { $0.startOfDay(in: calendar) } ?? Date.distantFuture)
        case .to: return (bounds.from.map { $0.startOfDay(in: calendar) } ?? Date.distantPast)...Date.distantFuture
        }
    }
}
