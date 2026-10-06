import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ClavisCore

public struct HistoryView: View {
    @ObservedObject public var viewModel: HistoryViewModel

    @State private var availableKeys: [Ed25519KeyInfo] = []
    @State private var selectedKeyFingerprint: String = ""
    @State private var selectedKind: String = "all"
    @State private var selectedResult: String = "all"
    @State private var selectedTimeRange: TimeRange = .all
    @State private var expandedSeqs: Set<Int64> = []
    @State private var showingIntegritySheet: Bool = false

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

    public init(viewModel: HistoryViewModel) {
        self.viewModel = viewModel
    }

    private let relativeDateFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()

    private let absoluteDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    public var body: some View {
        VStack(spacing: 0) {
            // Filter Toolbar
            filterToolbar
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Color(nsColor: .windowBackgroundColor))

            Divider()

            // Active Session Filter Banner
            if let activeSessionID = viewModel.query.sessionID {
                HStack(spacing: 8) {
                    Image(systemName: "cpu")
                        .foregroundColor(.purple)
                        .font(.system(size: 11))
                    Text("Session: \(activeSessionID)")
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

                    Spacer()

                    if AppState.shared.agentSessions.contains(where: { $0.id == activeSessionID }) {
                        Button(action: {
                            AppState.shared.endAgentSession(id: activeSessionID)
                        }) {
                            Text(ClavisUIStrings.AgentSession.historyEndSession)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.red)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
                .background(Color.purple.opacity(0.1))

                Divider()
            }

            // Key Context Required Banner (PIN mode unlocked with device password)
            if viewModel.needsKeyContext {
                PinEntryView(isInlineBanner: true) { _ in
                    viewModel.reload()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(Color(nsColor: .controlBackgroundColor))

                Divider()
            }

            // Content
            if let error = viewModel.errorMessage {
                VStack(spacing: 8) {
                    Text(ClavisUIStrings.Common.error)
                        .font(.headline)
                        .foregroundColor(.red)
                    Text(error)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Button(action: { viewModel.reload() }) {
                        Text(ClavisUIStrings.Common.appName)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if viewModel.items.isEmpty && !viewModel.isLoading {
                VStack(spacing: 12) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary.opacity(0.6))
                    Text(ClavisUIStrings.History.empty)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(viewModel.items) { item in
                        switch item {
                        case .record(let record):
                            recordRow(for: record)
                                .onAppear {
                                    if record.seq == viewModel.records.last?.seq {
                                        viewModel.loadMore()
                                    }
                                }
                        case .gap(let fromSeq, let toSeq, let count):
                            gapRow(fromSeq: fromSeq, toSeq: toSeq, count: count)
                        }
                    }
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .frame(minWidth: 750, minHeight: 500)
        .onAppear {
            loadKeys()
            syncFiltersFromQuery()
            viewModel.reload()
        }
        .sheet(isPresented: $showingIntegritySheet) {
            HistoryIntegritySheet(viewModel: viewModel, isPresented: $showingIntegritySheet)
        }
    }

    private var filterToolbar: some View {
        HStack(spacing: 10) {
            // Key Picker
            Picker("", selection: $selectedKeyFingerprint) {
                Text(ClavisUIStrings.History.filterAllKeys).tag("")
                ForEach(availableKeys, id: \.fingerprint) { key in
                    Text(key.label).tag(key.fingerprint)
                }
            }
            .labelsHidden()
            .frame(width: 130)
            .onChange(of: selectedKeyFingerprint) { newValue in
                viewModel.query.keyFingerprint = newValue.isEmpty ? nil : newValue
                viewModel.reload()
            }

            // Kind Picker
            Picker("", selection: $selectedKind) {
                Text(ClavisUIStrings.History.filterAllKinds).tag("all")
                Text(ClavisUIStrings.History.filterKindPersonal).tag("personal")
                Text(ClavisUIStrings.History.filterKindAgent).tag("agent")
            }
            .labelsHidden()
            .frame(width: 100)
            .onChange(of: selectedKind) { newValue in
                switch newValue {
                case "personal": viewModel.query.keyKind = .personal
                case "agent": viewModel.query.keyKind = .agent
                default: viewModel.query.keyKind = nil
                }
                viewModel.reload()
            }

            // Result Picker
            Picker("", selection: $selectedResult) {
                Text(ClavisUIStrings.History.filterAllResult).tag("all")
                Text(ClavisUIStrings.History.resultAllowed).tag("allowed")
                Text(ClavisUIStrings.History.resultDenied).tag("denied")
                Text(ClavisUIStrings.History.resultCancelled).tag("cancelled")
                Text(ClavisUIStrings.History.resultFailed).tag("failed")
            }
            .labelsHidden()
            .frame(width: 110)
            .onChange(of: selectedResult) { newValue in
                switch newValue {
                case "allowed": viewModel.query.results = [.allowed]
                case "denied": viewModel.query.results = [.denied]
                case "cancelled": viewModel.query.results = [.cancelled]
                case "failed": viewModel.query.results = [.failed]
                default: viewModel.query.results = []
                }
                viewModel.reload()
            }

            // Date Range Picker
            Picker("", selection: $selectedTimeRange) {
                ForEach(TimeRange.allCases) { range in
                    Text(range.title).tag(range)
                }
            }
            .labelsHidden()
            .frame(width: 120)
            .onChange(of: selectedTimeRange) { newRange in
                viewModel.query.from = newRange.startDate
                viewModel.reload()
            }

            Spacer()

            // Check Integrity Button
            Button(action: {
                showingIntegritySheet = true
                viewModel.checkIntegrity()
            }) {
                HStack(spacing: 4) {
                    Image(systemName: "checkmark.shield")
                    Text(ClavisUIStrings.History.checkIntegrity)
                }
            }

            // Export Button
            Button(action: exportHistory) {
                HStack(spacing: 4) {
                    Image(systemName: "square.and.arrow.up")
                    Text(ClavisUIStrings.History.export)
                }
            }
        }
    }

    private func recordRow(for record: AuditRecord) -> some View {
        let event = record.event
        let isExpanded = expandedSeqs.contains(record.seq)

        let unsealResult: AuditUnsealResult
        if let res = viewModel.sensitive[record.seq] {
            unsealResult = res
        } else if record.sensitiveFormat == 0 {
            unsealResult = .plaintext(event.sensitive)
        } else if record.sensitiveFormat == 2 {
            unsealResult = .omitted
        } else {
            unsealResult = .unreadable
        }

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                // Timestamp
                Text(relativeDateFormatter.localizedString(for: event.time, relativeTo: Date()))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(width: 80, alignment: .leading)
                    .help(absoluteDateFormatter.string(from: event.time))

                switch unsealResult {
                case .plaintext(let sensitive):
                    // Key Label & Badge
                    HStack(spacing: 6) {
                        Text(sensitive.keyLabel ?? event.keyFingerprint?.prefix(12).description ?? "—")
                            .font(.system(size: 13, weight: .medium))
                            .lineLimit(1)

                        if let kind = event.keyKind {
                            Text(kind == .personal ? ClavisUIStrings.History.filterKindPersonal : ClavisUIStrings.History.filterKindAgent)
                                .font(.system(size: 9, weight: .semibold))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(Color.secondary.opacity(0.15)))
                                .foregroundColor(.secondary)
                        }
                    }
                    .frame(width: 140, alignment: .leading)

                    // Process Info with Chain Disclosure
                    HStack(spacing: 4) {
                        if let firstProc = sensitive.processChain.first {
                            let procName = (firstProc.executablePath as NSString).lastPathComponent
                            Text(procName)
                                .font(.system(size: 12, design: .monospaced))

                            if sensitive.processChain.count > 1 {
                                Button(action: {
                                    if isExpanded {
                                        expandedSeqs.remove(record.seq)
                                    } else {
                                        expandedSeqs.insert(record.seq)
                                    }
                                }) {
                                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                                        .font(.system(size: 9))
                                        .foregroundColor(.secondary)
                                }
                                .buttonStyle(.plain)
                            }
                        } else {
                            Text("—")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .frame(width: 150, alignment: .leading)

                    // Host
                    Text(sensitive.host ?? "—")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 90, alignment: .leading)

                case .unreadable:
                    Text(ClavisUIStrings.History.unreadable)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 380, alignment: .leading)

                case .omitted:
                    HStack(spacing: 6) {
                        Text(ClavisUIStrings.History.omitted)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .help(ClavisUIStrings.History.omittedTooltip)

                        if let kind = event.keyKind {
                            Text(kind == .personal ? ClavisUIStrings.History.filterKindPersonal : ClavisUIStrings.History.filterKindAgent)
                                .font(.system(size: 9, weight: .semibold))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(Color.secondary.opacity(0.15)))
                                .foregroundColor(.secondary)
                        }
                    }
                    .frame(width: 380, alignment: .leading)
                }

                Spacer()

                // Suppressed badge if count > 1
                if event.count > 1 || event.type == .suppressed {
                    Text(ClavisUIStrings.History.suppressedCount(event.count))
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.orange.opacity(0.15)))
                        .foregroundColor(.orange)
                }

                // Result Status
                resultBadge(for: event.result)
                    .frame(width: 80, alignment: .trailing)
            }

            // Expanded Process Chain
            if isExpanded, case .plaintext(let sensitive) = unsealResult, sensitive.processChain.count > 1 {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(sensitive.processChain.enumerated()), id: \.offset) { idx, proc in
                        HStack(spacing: 6) {
                            Text(idx == 0 ? "├─" : "└─")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Text("\(proc.executablePath) (PID \(proc.pid))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        .padding(.leading, 120)
                    }
                }
                .padding(.vertical, 2)
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            if let sid = event.sessionID {
                Button(ClavisUIStrings.AgentSession.historyShowSession) {
                    viewModel.query.sessionID = sid
                    viewModel.reload()
                }
            }
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
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color.orange.opacity(0.12))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color.orange.opacity(0.3), lineWidth: 1)
        )
        .padding(.vertical, 2)
    }

    private func resultBadge(for result: AuditResult) -> some View {
        let (title, color): (String, Color) = {
            switch result {
            case .allowed: return (ClavisUIStrings.History.resultAllowed, DesignTokens.accentGreen)
            case .denied: return (ClavisUIStrings.History.resultDenied, .red)
            case .cancelled: return (ClavisUIStrings.History.resultCancelled, DesignTokens.accentOrange)
            case .failed: return (ClavisUIStrings.History.resultFailed, .red)
            case .info: return (ClavisUIStrings.History.resultInfo, DesignTokens.accentBlue)
            }
        }()

        return Text(title)
            .font(.system(size: 11, weight: .semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 2.5)
            .background(Capsule().fill(color.opacity(0.15)))
            .foregroundColor(color)
    }

    private func loadKeys() {
        if let keys = try? KeychainManager.shared.listKeys() {
            availableKeys = keys
        }
    }

    private func syncFiltersFromQuery() {
        if let fp = viewModel.query.keyFingerprint {
            selectedKeyFingerprint = fp
        }
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
