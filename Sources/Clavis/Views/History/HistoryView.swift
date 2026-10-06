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
            } else if viewModel.records.isEmpty && !viewModel.isLoading {
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
                    ForEach(viewModel.records, id: \.seq) { record in
                        recordRow(for: record)
                            .onAppear {
                                if record.seq == viewModel.records.last?.seq {
                                    viewModel.loadMore()
                                }
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

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                // Timestamp
                Text(relativeDateFormatter.localizedString(for: event.time, relativeTo: Date()))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(width: 80, alignment: .leading)
                    .help(absoluteDateFormatter.string(from: event.time))

                // Key Label & Badge
                HStack(spacing: 6) {
                    Text(event.sensitive.keyLabel ?? event.keyFingerprint?.prefix(12).description ?? "—")
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
                    if let firstProc = event.sensitive.processChain.first {
                        let procName = (firstProc.executablePath as NSString).lastPathComponent
                        Text(procName)
                            .font(.system(size: 12, design: .monospaced))

                        if event.sensitive.processChain.count > 1 {
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
                Text(event.sensitive.host ?? "—")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(width: 90, alignment: .leading)

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
            if isExpanded && event.sensitive.processChain.count > 1 {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(event.sensitive.processChain.enumerated()), id: \.offset) { idx, proc in
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
