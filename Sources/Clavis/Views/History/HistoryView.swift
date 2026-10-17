import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ClavisCore

public struct HistoryView: View {
    @ObservedObject public var viewModel: HistoryViewModel
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @State private var availableKeys: [SSHKeyInfo] = []
    @State private var selectedKeyFingerprint: String = ""
    @State private var hostInputText: String = ""
    @State private var isHostSuggestionsVisible: Bool = false
    @State private var highlightedHostIndex: Int = -1
    @State private var pickerDate: Date = Date()
    @State private var isDatePopoverPresented: Bool = false
    @State private var expandedSeqs: Set<Int64> = []
    @State private var showingIntegritySheet: Bool = false
    @FocusState private var isHostFieldFocused: Bool
    @FocusState private var isSearchFieldFocused: Bool

    public enum TimeRange: String, CaseIterable, Identifiable {
        case hour, day, week, all

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .hour: return ClavisUIStrings.History.filterRangeHour
            case .day: return ClavisUIStrings.History.filterRangeDay
            case .week: return ClavisUIStrings.History.filterRangeWeek
            case .all: return ClavisUIStrings.History.filterRangeAll
            }
        }

        public var startDate: Date? {
            switch self {
            case .hour: return Date().addingTimeInterval(-3600)
            case .day: return Date().addingTimeInterval(-86400)
            case .week: return Date().addingTimeInterval(-7 * 86400)
            case .all: return nil
            }
        }
    }

    private static let shortDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "MMM d, yyyy"
        return formatter
    }()

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    private static let isoFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    public init(viewModel: HistoryViewModel) {
        self.viewModel = viewModel
    }

    private var currentHostSuggestions: [HistoryHostSuggestion] {
        viewModel.hostSuggestions(matching: hostInputText)
    }

    private var groupedSections: [HistoryDaySection] {
        viewModel.groupedSections()
    }

    public var body: some View {
        // Single scroll surface containing both filters and date-grouped event sections
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                if let activeSessionID = viewModel.query.sessionID {
                    activeSessionBanner(sessionID: activeSessionID)
                    Divider()
                }

                if viewModel.needsKeyContext {
                    PinEntryView(isInlineBanner: true) { _ in
                        viewModel.reload()
                    }
                    .padding(.horizontal, 30)
                    .padding(.vertical, 8)
                    .background(Color(nsColor: .controlBackgroundColor))

                    Divider()
                }

                VStack(alignment: .leading, spacing: 0) {
                    historyFilterControls
                        .zIndex(20)

                    historyResultSummaryBar

                    if let error = viewModel.errorMessage {
                        errorStateView(message: error)
                    } else if viewModel.items.isEmpty && !viewModel.isLoading {
                        emptyHistoryStateView
                    } else {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(groupedSections) { section in
                                Section(header: historyDayHeader(for: section)) {
                                    ForEach(section.items) { item in
                                        switch item {
                                        case .record(let record):
                                            recordRow(for: record)
                                                .onAppear {
                                                    if record.seq == viewModel.records.last?.seq && viewModel.hasMore {
                                                        viewModel.loadMore()
                                                    }
                                                }
                                        case .gap(let fromSeq, let toSeq, let count):
                                            gapRow(fromSeq: fromSeq, toSeq: toSeq, count: count)
                                        }
                                    }
                                }
                            }
                        }

                        historyLoadStateFooter
                    }
                }
                .padding(.top, 20)
                .padding(.horizontal, 35)
                .padding(.bottom, 18)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background {
            Button("") {
                viewModel.reload()
            }
            .keyboardShortcut("r", modifiers: .command)
            .opacity(0)
            .allowsHitTesting(false)
        }
        .onAppear {
            loadKeys()
            syncFiltersFromQuery()
            viewModel.reload()
        }
        .onChange(of: viewModel.query.keyFingerprint) { newFingerprint in
            let normalized = newFingerprint ?? ""
            if selectedKeyFingerprint != normalized {
                selectedKeyFingerprint = normalized
            }
        }
        .onChange(of: isHostFieldFocused) { focused in
            if focused {
                isHostSuggestionsVisible = true
                highlightedHostIndex = -1
            } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                    if !isHostFieldFocused {
                        isHostSuggestionsVisible = false
                        highlightedHostIndex = -1
                    }
                }
            }
        }
        .sheet(isPresented: $showingIntegritySheet) {
            HistoryIntegritySheet(viewModel: viewModel, isPresented: $showingIntegritySheet)
                .dismissOnOutsideClick {
                    showingIntegritySheet = false
                }
        }
    }

    // MARK: - Filter Controls (Inside Scroll Surface)

    /// Native grouped-form look (System Settings): one rounded card, rows separated by dividers.
    private var historyFilterControls: some View {
        VStack(spacing: 0) {
            LabeledContent("Key") {
                Picker("Key", selection: $selectedKeyFingerprint) {
                    Text("All keys").tag("")
                    ForEach(availableKeys, id: \.fingerprint) { key in
                        Text(key.label).tag(key.fingerprint)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .fixedSize()
                .onChange(of: selectedKeyFingerprint) { newValue in
                    let fp = newValue.isEmpty ? nil : newValue
                    if viewModel.query.keyFingerprint != fp {
                        viewModel.query.keyFingerprint = fp
                        AppState.shared.historyFilterKeyFingerprint = fp
                        viewModel.reload()
                    }
                }
                .accessibilityLabel("Key")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider().padding(.leading, 12)

            LabeledContent("Date range") {
                Toggle("Date range", isOn: dateRangeEnabled)
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .controlSize(.small)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            if dateRangeEnabled.wrappedValue {
                Divider().padding(.leading, 12)

                LabeledContent("From") {
                    DatePicker("From", selection: dateRangeStartBinding, in: ...dateRangeEndBinding.wrappedValue, displayedComponents: [.date])
                        .labelsHidden()
                        .datePickerStyle(.compact)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)

                Divider().padding(.leading, 12)

                LabeledContent("To") {
                    DatePicker("To", selection: dateRangeEndBinding, in: dateRangeStartBinding.wrappedValue...Date(), displayedComponents: [.date])
                        .labelsHidden()
                        .datePickerStyle(.compact)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.6))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.6), lineWidth: 0.5)
        )
        .padding(.bottom, 12)
    }

    private var dateRangeEnabled: Binding<Bool> {
        Binding(
            get: { viewModel.dateRangeStart != nil || viewModel.dateRangeEnd != nil },
            set: { on in
                if on {
                    let today = Date()
                    viewModel.dateRangeEnd = today
                    viewModel.dateRangeStart = Calendar.current.date(byAdding: .day, value: -7, to: today) ?? today
                } else {
                    viewModel.clearDateFilter()
                }
            }
        )
    }

    private var dateRangeStartBinding: Binding<Date> {
        Binding(
            get: { viewModel.dateRangeStart ?? Date() },
            set: { viewModel.dateRangeStart = $0 }
        )
    }

    private var dateRangeEndBinding: Binding<Date> {
        Binding(
            get: { viewModel.dateRangeEnd ?? Date() },
            set: { viewModel.dateRangeEnd = $0 }
        )
    }

    private var historyResultSummaryBar: some View {
        HStack(spacing: 10) {
            Text("\(viewModel.records.count.formatted()) matching events")
                .font(.system(size: 11).monospacedDigit())
                .foregroundColor(DesignTokens.textSecondary)

            Spacer()

            Text("Newest first")
                .font(.system(size: 11))
                .foregroundColor(DesignTokens.textSecondary)
        }
        .padding(.vertical, 9)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(DesignTokens.cardBorder)
                .frame(height: 1)
        }
    }

    // MARK: - Sticky Date Section Header

    private func historyDayHeader(for section: HistoryDaySection) -> some View {
        HStack(spacing: 10) {
            Text(section.title)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.primary)

            Spacer()

            Text(section.totalCount == 1 ? "1 event" : "\(section.totalCount.formatted()) events")
                .font(.system(size: 11).monospacedDigit())
                .foregroundColor(DesignTokens.textSecondary)
        }
        .padding(.top, 16)
        .padding(.bottom, 6)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(DesignTokens.cardBorder)
                .frame(height: 1)
        }
    }

    // MARK: - Event Row & Expandable Audit Details

    private func recordRow(for record: AuditRecord) -> some View {
        let event = record.event
        let isExpanded = expandedSeqs.contains(record.seq)
        let unsealResult = resolveUnsealResult(for: record)
        let sens = viewModel.resolvedSensitive(for: record)
        let operation = HistoryViewModel.operationTitle(for: record, sensitive: sens)
        let status = HistoryViewModel.statusLabel(for: event.result)
        let isRejected = event.result == .denied || event.result == .cancelled || event.result == .failed

        let keyDisplay: String = {
            switch unsealResult {
            case .plaintext(let s):
                return s.keyLabel ?? event.keyFingerprint?.prefix(16).description ?? "Unknown key"
            case .omitted:
                return event.keyFingerprint?.prefix(16).description ?? ClavisUIStrings.History.omitted
            case .unreadable:
                return event.keyFingerprint?.prefix(16).description ?? ClavisUIStrings.History.unreadable
            }
        }()

        let hostDisplay: String = {
            if case .plaintext(let s) = unsealResult, let h = s.host, !h.isEmpty {
                return h
            }
            if let h = sens.host, !h.isEmpty {
                return h
            }
            return "local"
        }()

        let subtitleText = "\(keyDisplay) · \(hostDisplay) · \(status)"

        return VStack(alignment: .leading, spacing: 0) {
            Button(action: {
                if isExpanded {
                    expandedSeqs.remove(record.seq)
                } else {
                    expandedSeqs.insert(record.seq)
                }
            }) {
                HStack(alignment: .center, spacing: 9) {
                    Image(systemName: isRejected ? "xmark" : "checkmark")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(isRejected ? Color.red : DesignTokens.accentGreen)
                        .frame(width: 14, height: 14)

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(operation)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundColor(.primary)
                                .lineLimit(1)

                            if event.count > 1 || event.type == .suppressed {
                                Text(ClavisUIStrings.History.suppressedCount(event.count))
                                    .font(.system(size: 10, weight: .medium))
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Capsule().fill(DesignTokens.accentOrange.opacity(0.15)))
                                    .foregroundColor(DesignTokens.accentOrange)
                            }
                        }

                        Text(subtitleText)
                            .font(.system(size: 11))
                            .foregroundColor(DesignTokens.textSecondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }

                    Spacer(minLength: 12)

                    VStack(alignment: .trailing, spacing: 2) {
                        Text(Self.shortDateFormatter.string(from: event.time))
                            .font(.system(size: 10).monospacedDigit())
                            .foregroundColor(DesignTokens.textSecondary)

                        Text(Self.timeFormatter.string(from: event.time))
                            .font(.system(size: 11).monospacedDigit())
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                    .help(Self.isoFormatter.string(from: event.time))
                }
                .frame(minHeight: 32)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(operation), \(subtitleText)")
            .accessibilityValue(
                isExpanded
                    ? ClavisUIStrings.Accessibility.expanded
                    : ClavisUIStrings.Accessibility.collapsed
            )

            if isExpanded {
                expandedEventDataView(
                    record: record,
                    unsealResult: unsealResult,
                    keyDisplay: keyDisplay,
                    hostDisplay: hostDisplay,
                    status: status
                )
            }
        }
        .padding(.vertical, 10)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(DesignTokens.cardBorder)
                .frame(height: 1)
        }
        .contextMenu {
            eventContextMenu(for: record, unsealResult: unsealResult)
        }
    }

    private func expandedEventDataView(
        record: AuditRecord,
        unsealResult: AuditUnsealResult,
        keyDisplay: String,
        hostDisplay: String,
        status: String
    ) -> some View {
        let event = record.event
        let digest = AuditWitness.digest(for: record)
        let timestampISO = Self.isoFormatter.string(from: event.time)
        let sens = viewModel.resolvedSensitive(for: record)

        let resultLine: String = {
            if let reason = event.reason {
                return "\(status) · \(reason.rawValue.replacingOccurrences(of: "_", with: " "))"
            }
            return status
        }()

        let processLine: String = {
            guard !sens.processChain.isEmpty else { return "—" }
            let names = sens.processChain.reversed().map {
                ($0.executablePath as NSString).lastPathComponent
            }.joined(separator: " → ")
            let pids = sens.processChain.reversed().map { String($0.pid) }.joined(separator: " → ")
            return "\(names) (PID \(pids))"
        }()

        let sessionLine = event.sessionID ?? "—"

        let detailLines = [
            "Key: \(keyDisplay)",
            "Host: \(hostDisplay)",
            "Result: \(resultLine)",
            "Process: \(processLine)",
            "Timestamp: \(timestampISO)",
            "Session: \(sessionLine)",
            "Record hash: SHA256:\(digest)"
        ].joined(separator: "\n")

        return Text(detailLines)
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(DesignTokens.textSecondary)
            .lineSpacing(4)
            .textSelection(.enabled)
            .padding(.leading, 23)
            .padding(.top, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private func eventContextMenu(for record: AuditRecord, unsealResult: AuditUnsealResult) -> some View {
        let event = record.event
        let recordDigest = AuditWitness.digest(for: record)

        Button(action: { copyToClipboard(recordDigest) }) {
            Label("Copy SHA-256 Hash", systemImage: "doc.on.doc")
        }

        if let sid = event.sessionID {
            Button(action: { copyToClipboard(sid) }) {
                Label("Copy Session ID", systemImage: "cpu")
            }
            Button(ClavisUIStrings.AgentSession.historyShowSession) {
                viewModel.query.sessionID = sid
                viewModel.reload()
            }
        }

        if let fp = event.keyFingerprint {
            Button(action: { copyToClipboard(fp) }) {
                Label("Copy Fingerprint", systemImage: "key")
            }
            Button(action: {
                selectedKeyFingerprint = fp
                viewModel.query.keyFingerprint = fp
                AppState.shared.historyFilterKeyFingerprint = fp
                viewModel.reload()
            }) {
                Label("Filter by this Key", systemImage: "line.3.horizontal.decrease.circle")
            }
        }

        if case .plaintext(let sens) = unsealResult {
            if let host = sens.host, !host.isEmpty {
                Button(action: { copyToClipboard(host) }) {
                    Label("Copy Host", systemImage: "network")
                }
            }
            if let firstProc = sens.processChain.first {
                Button(action: { copyToClipboard(firstProc.executablePath) }) {
                    Label("Copy Process Path", systemImage: "terminal")
                }
            }
        }

        Button(action: {
            let summary = formatFullRecordSummary(record, unsealResult: unsealResult)
            copyToClipboard(summary)
        }) {
            Label("Copy Full Row Details", systemImage: "doc.text")
        }

        Divider()

        Button(action: {
            showingIntegritySheet = true
            viewModel.checkIntegrity()
        }) {
            Label(ClavisUIStrings.History.checkIntegrity, systemImage: "checkmark.shield")
        }

        Button(action: exportHistory) {
            Label(ClavisUIStrings.History.export, systemImage: "square.and.arrow.up")
        }
    }

    // MARK: - Supporting Views & Helpers

    private func activeSessionBanner(sessionID: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "cpu")
                .foregroundColor(.purple)
                .font(.system(size: 11))
            Text("Session: \(sessionID)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.primary)
            Button(action: {
                viewModel.query.sessionID = nil
                viewModel.reload()
            }) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.secondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ClavisUIStrings.Common.cancel)

            Spacer()

            if AppState.shared.agentSessions.contains(where: { $0.id == sessionID }) {
                Button(action: {
                    AppState.shared.endAgentSession(id: sessionID)
                }) {
                    Text(ClavisUIStrings.AgentSession.historyEndSession)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.red)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 35)
        .padding(.vertical, 6)
        .background(Color.purple.opacity(0.1))
    }

    private var emptyHistoryStateView: some View {
        VStack(spacing: 7) {
            Text("No matching signatures")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.primary)
            Text("Try another host, date, or search term.")
                .font(.system(size: 12))
                .foregroundColor(DesignTokens.textSecondary)
        }
        .multilineTextAlignment(.center)
        .padding(.vertical, 35)
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity)
    }

    private func errorStateView(message: String) -> some View {
        VStack(spacing: 8) {
            Text(ClavisUIStrings.Common.error)
                .font(.headline)
                .foregroundColor(Color.red)
            Text(message)
                .font(.subheadline)
                .foregroundColor(DesignTokens.textSecondary)
            Button("Retry") {
                viewModel.reload()
            }
            .liquidGlassButton()
        }
        .padding(.vertical, 35)
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private var historyLoadStateFooter: some View {
        if !viewModel.records.isEmpty {
            HStack(spacing: 6) {
                Spacer()
                if viewModel.isLoadingMore {
                    ProgressView()
                        .controlSize(.small)
                    Text("Loading more events…")
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                } else if viewModel.hasMore {
                    Button(action: {
                        viewModel.loadMore()
                    }) {
                        Text("\(viewModel.records.count.formatted()) loaded · scroll for more")
                            .font(.system(size: 11).monospacedDigit())
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                    .buttonStyle(.plain)
                } else {
                    Text("End of history")
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                }
                Spacer()
            }
            .padding(.top, 20)
            .padding(.bottom, 12)
        }
    }

    private func gapRow(fromSeq: Int64, toSeq: Int64, count: Int64) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.orange)
                .font(.system(size: 13))

            Text(ClavisUIStrings.History.gapBanner(count: count))
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.orange)

            Spacer()

            Text(fromSeq == toSeq ? "seq \(fromSeq)" : "seq \(fromSeq)..\(toSeq)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color.orange.opacity(0.12))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color.orange.opacity(0.3), lineWidth: 1)
        )
        .padding(.vertical, 4)
    }

    private func resolveUnsealResult(for record: AuditRecord) -> AuditUnsealResult {
        if let res = viewModel.sensitive[record.seq] {
            return res
        } else if record.sensitiveFormat == 0 {
            return .plaintext(record.event.sensitive)
        } else if record.sensitiveFormat == 2 {
            return .omitted
        } else {
            return .unreadable
        }
    }

    private func loadKeys() {
        if AppState.shared.keys.isEmpty {
            AppState.shared.refresh()
        }
        availableKeys = AppState.shared.keys
    }

    private func syncFiltersFromQuery() {
        selectedKeyFingerprint = viewModel.query.keyFingerprint ?? ""
        hostInputText = viewModel.filterRemoteHost ?? ""
    }

    private func resetAllFilters() {
        hostInputText = ""
        selectedKeyFingerprint = ""
        isHostSuggestionsVisible = false
        highlightedHostIndex = -1
        AppState.shared.historyFilterKeyFingerprint = nil
        viewModel.resetFilters()
        viewModel.reload()
    }

    private func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func formatFullRecordSummary(_ record: AuditRecord, unsealResult: AuditUnsealResult) -> String {
        let event = record.event
        let digest = AuditWitness.digest(for: record)
        var lines: [String] = []
        lines.append("Sequence: \(record.seq)")
        lines.append("Event ID: \(event.id.uuidString.lowercased())")
        lines.append("Timestamp: \(Self.isoFormatter.string(from: event.time))")
        lines.append("Type: \(event.type.rawValue)")
        lines.append("Result: \(event.result.rawValue)")
        if let reason = event.reason {
            lines.append("Reason: \(reason.rawValue)")
        }
        if let fp = event.keyFingerprint {
            lines.append("Key Fingerprint: \(fp)")
        }
        if case .plaintext(let sens) = unsealResult {
            if let label = sens.keyLabel {
                lines.append("Key Label: \(label)")
            }
            if let host = sens.host {
                lines.append("Host: \(host)")
            }
            if !sens.processChain.isEmpty {
                lines.append("Processes:")
                for proc in sens.processChain {
                    lines.append("  - \(proc.executablePath) (PID \(proc.pid))")
                }
            }
        }
        if let sid = event.sessionID {
            lines.append("Session ID: \(sid)")
        }
        lines.append("SHA-256 Digest: \(digest)")
        return lines.joined(separator: "\n")
    }

    private func exportHistory() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clavis-history.jsonl"
        panel.allowedContentTypes = [UTType(filenameExtension: "jsonl") ?? .data]
        panel.canCreateDirectories = true
        panel.begin { response in
            if response == .OK, let url = panel.url {
                do {
                    try viewModel.export(to: url)
                } catch {
                    viewModel.errorMessage = error.localizedDescription
                }
            }
        }
    }
}

public struct HistoryIntegritySheet: View {
    @ObservedObject public var viewModel: HistoryViewModel
    @Binding public var isPresented: Bool
    @State private var showLearnMore: Bool = false

    private let dateFormatter: DateFormatter = {
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .medium
        return df
    }()

    public init(viewModel: HistoryViewModel, isPresented: Binding<Bool>) {
        self.viewModel = viewModel
        self._isPresented = isPresented
    }

    public var body: some View {
        VStack(spacing: 16) {
            // Header
            HStack {
                Text(ClavisUIStrings.History.checkIntegrityTitle)
                    .font(.headline)
                Spacer()
                Button(ClavisUIStrings.Common.ok) {
                    isPresented = false
                }
                .liquidGlassButton(prominent: true)
                .keyboardShortcut(.defaultAction)
            }

            Divider()

            if viewModel.isCheckingIntegrity {
                VStack(spacing: 12) {
                    ProgressView()
                    Text(ClavisUIStrings.History.checkingIntegrity)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = viewModel.integrityCheckError {
                VStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 32))
                    Text(error)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let report = viewModel.integrityReport {
                VStack(alignment: .leading, spacing: 14) {
                    // Status banner
                    statusBanner(for: report)

                    // Summary counts
                    HStack(spacing: 16) {
                        Text(ClavisUIStrings.History.checkCheckedRows(report.checkedRows))
                            .font(.subheadline)
                        if !report.missingRows.isEmpty {
                            Text(ClavisUIStrings.History.checkMissingRows(report.missingRows.count))
                                .font(.subheadline)
                                .foregroundColor(.red)
                        }
                        if !report.inconsistentRows.isEmpty {
                            Text(ClavisUIStrings.History.checkInconsistentRows(report.inconsistentRows.count))
                                .font(.subheadline)
                                .foregroundColor(.red)
                        }
                        if report.truncatedTail {
                            Text(ClavisUIStrings.History.checkTruncatedTail)
                                .font(.subheadline)
                                .foregroundColor(.red)
                        }
                    }

                    // Problem list if any
                    if !report.missingRows.isEmpty || !report.inconsistentRows.isEmpty || report.truncatedTail {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(ClavisUIStrings.History.checkProblemsHeader)
                                .font(.subheadline)
                                .fontWeight(.semibold)

                            ScrollView {
                                VStack(alignment: .leading, spacing: 4) {
                                    ForEach(report.missingRows, id: \.seq) { missing in
                                        let timeStr = missing.loggedAt.map { dateFormatter.string(from: $0) } ?? "—"
                                        Text(ClavisUIStrings.History.checkMissingRowFormat(seq: missing.seq, witnessedAt: timeStr))
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                    ForEach(report.inconsistentRows, id: \.self) { seq in
                                        Text(ClavisUIStrings.History.checkInconsistentRowFormat(seq: seq))
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                    if report.truncatedTail {
                                        Text(ClavisUIStrings.History.checkTruncatedTail)
                                            .font(.caption)
                                            .foregroundColor(.red)
                                    }
                                }
                                .padding(8)
                            }
                            .frame(maxHeight: 140)
                            .background(Color(nsColor: .controlBackgroundColor))
                            .cornerRadius(6)
                        }
                    }

                    // Retention explanation
                    DisclosureGroup(ClavisUIStrings.History.checkLearnMore, isExpanded: $showLearnMore) {
                        Text(ClavisUIStrings.History.checkRetentionExplanation)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding(.top, 4)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Spacer()
        }
        .padding(20)
        .frame(width: 520, height: 380)
    }

    @ViewBuilder
    private func statusBanner(for report: AuditIntegrityReport) -> some View {
        HStack(spacing: 12) {
            switch report.status {
            case .ok:
                Image(systemName: "checkmark.shield.fill")
                    .foregroundColor(.green)
                    .font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.History.checkStatusOk)
                        .font(.headline)
                    Text(ClavisUIStrings.History.checkStatusOkDesc)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            case .problems:
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundColor(.red)
                    .font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.History.checkStatusProblems)
                        .font(.headline)
                    Text(ClavisUIStrings.History.checkStatusProblemsDesc)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            case .unavailable(let reason):
                Image(systemName: "questionmark.diamond.fill")
                    .foregroundColor(.orange)
                    .font(.system(size: 32))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ClavisUIStrings.History.checkStatusUnavailable)
                        .font(.headline)
                    Text(reason)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .cornerRadius(8)
    }
}
