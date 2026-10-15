import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ClavisCore

public struct HistoryView: View {
    @ObservedObject public var viewModel: HistoryViewModel

    @State private var availableKeys: [SSHKeyInfo] = []
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
                    .accessibilityLabel(ClavisUIStrings.Common.cancel)

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
                        Text(retryButtonLabel)
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
                                    if record.seq == viewModel.records.last?.seq && viewModel.hasMore {
                                        viewModel.loadMore()
                                    }
                                }
                        case .gap(let fromSeq, let toSeq, let count):
                            gapRow(fromSeq: fromSeq, toSeq: toSeq, count: count)
                        }
                    }

                    if viewModel.hasMore {
                        HStack {
                            Spacer()
                            if viewModel.isLoadingMore {
                                ProgressView()
                                    .scaleEffect(0.8)
                                    .padding(.vertical, 8)
                            } else {
                                Button(action: {
                                    viewModel.loadMore()
                                }) {
                                    HStack(spacing: 6) {
                                        Image(systemName: "arrow.down.circle")
                                        Text(loadMoreButtonLabel)
                                    }
                                    .font(.system(size: 12, weight: .medium))
                                }
                                .buttonStyle(.plain)
                                .foregroundColor(.accentColor)
                                .padding(.vertical, 8)
                            }
                            Spacer()
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

    private var isRussian: Bool {
        Locale.preferredLanguages.first?.hasPrefix("ru") == true
            || Locale.current.language.languageCode?.identifier == "ru"
    }

    private var retryButtonLabel: String {
        isRussian ? "Повторить" : "Retry"
    }

    private var refreshButtonLabel: String {
        isRussian ? "Обновить" : "Refresh"
    }

    private var loadMoreButtonLabel: String {
        isRussian ? "Загрузить ещё" : "Load More"
    }

    private var searchPlaceholder: String {
        isRussian ? "Поиск (ключ, отпечаток, узел, процесс, PID)..." : "Search (key, fingerprint, host, process, PID)..."
    }

    private func eventCountLabel(count: Int) -> String {
        isRussian ? "Событий: \(count)" : "\(count) events"
    }

    private var filterToolbar: some View {
        VStack(spacing: 8) {
            // Row 1: Search field & Actions
            HStack(spacing: 10) {
                // Search Input Field
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.secondary)
                        .font(.system(size: 12))
                    TextField(searchPlaceholder, text: $viewModel.searchText)
                        .textFieldStyle(.plain)
                        .font(.system(size: 12))
                    if !viewModel.searchText.isEmpty {
                        Button(action: { viewModel.searchText = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.secondary)
                                .font(.system(size: 11))
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(ClavisUIStrings.Common.cancel)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(Color(nsColor: .controlBackgroundColor))
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
                )

                Spacer()

                // Refresh Button (⌘R)
                Button(action: {
                    viewModel.reload()
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.clockwise")
                        Text(refreshButtonLabel)
                    }
                }
                .keyboardShortcut("r", modifiers: .command)
                .help("Refresh (⌘R)")

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

            // Row 2: Specific Filter Pickers & Counter
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

                Text(eventCountLabel(count: viewModel.records.count))
                    .font(.caption)
                    .foregroundColor(.secondary)
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
            HStack(spacing: 8) {
                // Disclosure chevron button
                Button(action: {
                    if isExpanded {
                        expandedSeqs.remove(record.seq)
                    } else {
                        expandedSeqs.insert(record.seq)
                    }
                }) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.secondary)
                        .frame(width: 14, height: 14)
                }
                .buttonStyle(.plain)
                .help(isExpanded ? (isRussian ? "Свернуть" : "Collapse") : (isRussian ? "Развернуть детали" : "Expand details"))
                .accessibilityLabel(isExpanded ? ClavisUIStrings.Accessibility.collapseDetails : ClavisUIStrings.Accessibility.expandDetails)
                .accessibilityValue(isExpanded ? ClavisUIStrings.Accessibility.expanded : ClavisUIStrings.Accessibility.collapsed)

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

                    // Process Info
                    HStack(spacing: 4) {
                        if let firstProc = sensitive.processChain.first {
                            let procName = (firstProc.executablePath as NSString).lastPathComponent
                            Text(procName)
                                .font(.system(size: 12, design: .monospaced))
                        } else {
                            Text("—")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .frame(width: 140, alignment: .leading)

                    // Host
                    Text(sensitive.host ?? "—")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 90, alignment: .leading)

                case .unreadable:
                    Text(ClavisUIStrings.History.unreadable)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 370, alignment: .leading)

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
                    .frame(width: 370, alignment: .leading)
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

            // Expanded Detail Inspection View (#124)
            if isExpanded {
                eventDetailInspectionView(for: record, unsealResult: unsealResult)
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            let recordDigest = AuditWitness.digest(for: record)
            Button(action: { copyToClipboard(recordDigest) }) {
                Label(isRussian ? "Копировать хэш SHA-256" : "Copy SHA-256 Hash", systemImage: "doc.on.doc")
            }

            if let sid = event.sessionID {
                Button(action: { copyToClipboard(sid) }) {
                    Label(isRussian ? "Копировать ID сессии" : "Copy Session ID", systemImage: "cpu")
                }
                Button(ClavisUIStrings.AgentSession.historyShowSession) {
                    viewModel.query.sessionID = sid
                    viewModel.reload()
                }
            }

            if let fp = event.keyFingerprint {
                Button(action: { copyToClipboard(fp) }) {
                    Label(isRussian ? "Копировать отпечаток" : "Copy Fingerprint", systemImage: "key")
                }
                Button(action: {
                    viewModel.query.keyFingerprint = fp
                    viewModel.reload()
                }) {
                    Label(isRussian ? "Фильтровать по этому ключу" : "Filter by this Key", systemImage: "line.3.horizontal.decrease.circle")
                }
            }

            if case .plaintext(let sens) = unsealResult {
                if let host = sens.host, !host.isEmpty {
                    Button(action: { copyToClipboard(host) }) {
                        Label(isRussian ? "Копировать узел" : "Copy Host", systemImage: "network")
                    }
                }
                if let firstProc = sens.processChain.first {
                    Button(action: { copyToClipboard(firstProc.executablePath) }) {
                        Label(isRussian ? "Копировать путь процесса" : "Copy Process Path", systemImage: "terminal")
                    }
                }
            }

            Button(action: {
                let summary = formatFullRecordSummary(record, unsealResult: unsealResult)
                copyToClipboard(summary)
            }) {
                Label(isRussian ? "Копировать все данные строки" : "Copy Full Row Details", systemImage: "doc.text")
            }
        }
    }

    private func eventDetailInspectionView(for record: AuditRecord, unsealResult: AuditUnsealResult) -> some View {
        let event = record.event
        let recordDigest = AuditWitness.digest(for: record)
        let isoFormatter = ISO8601DateFormatter()
        let timestampStr = isoFormatter.string(from: event.time)

        return VStack(alignment: .leading, spacing: 8) {
            Divider()
                .padding(.vertical, 2)

            VStack(alignment: .leading, spacing: 6) {
                // Timestamp
                detailItem(
                    label: isRussian ? "Время" : "Timestamp",
                    value: "\(absoluteDateFormatter.string(from: event.time)) (\(timestampStr))",
                    copyValue: timestampStr
                )

                // SHA-256 Record Hash
                detailItem(
                    label: isRussian ? "Хэш SHA-256" : "SHA-256 Hash",
                    value: recordDigest,
                    copyValue: recordDigest,
                    isMonospace: true
                )

                // Sequence & Event ID
                HStack(spacing: 20) {
                    detailItem(
                        label: isRussian ? "Номер" : "Sequence",
                        value: "\(record.seq)",
                        copyValue: "\(record.seq)",
                        isMonospace: true
                    )
                    detailItem(
                        label: isRussian ? "ID события" : "Event ID",
                        value: event.id.uuidString.lowercased(),
                        copyValue: event.id.uuidString.lowercased(),
                        isMonospace: true
                    )
                }

                // Session ID (if present)
                if let sessionID = event.sessionID {
                    HStack(spacing: 8) {
                        detailItem(
                            label: isRussian ? "Сессия" : "Session ID",
                            value: sessionID,
                            copyValue: sessionID,
                            isMonospace: true
                        )
                        Button(action: {
                            viewModel.query.sessionID = sessionID
                            viewModel.reload()
                        }) {
                            Text(ClavisUIStrings.AgentSession.historyShowSession)
                                .font(.system(size: 10, weight: .medium))
                                .foregroundColor(.purple)
                        }
                        .buttonStyle(.plain)
                    }
                }

                // Key Label & Fingerprint
                let keyLabelText: String? = {
                    if case .plaintext(let sens) = unsealResult {
                        return sens.keyLabel
                    }
                    return event.sensitive.keyLabel
                }()
                if let keyLabelText {
                    detailItem(
                        label: isRussian ? "Ключ" : "Key Label",
                        value: keyLabelText,
                        copyValue: keyLabelText
                    )
                }

                if let fp = event.keyFingerprint {
                    detailItem(
                        label: isRussian ? "Отпечаток" : "Fingerprint",
                        value: fp,
                        copyValue: fp,
                        isMonospace: true
                    )
                }

                // Remote host (if present)
                let hostText: String? = {
                    if case .plaintext(let sens) = unsealResult {
                        return sens.host
                    }
                    return event.sensitive.host
                }()
                if let hostText, !hostText.isEmpty {
                    detailItem(
                        label: isRussian ? "Узел" : "Remote Host",
                        value: hostText,
                        copyValue: hostText
                    )
                }

                // Process chain & PIDs
                let processChain: [AuditProcess] = {
                    if case .plaintext(let sens) = unsealResult {
                        return sens.processChain
                    }
                    return event.sensitive.processChain
                }()

                if !processChain.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(isRussian ? "Цепочка процессов:" : "Process Hierarchy:")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(.secondary)
                            Spacer()
                            Button(action: {
                                let text = processChain.map { "\($0.executablePath) (PID \($0.pid))" }.joined(separator: "\n")
                                copyToClipboard(text)
                            }) {
                                HStack(spacing: 3) {
                                    Image(systemName: "doc.on.doc")
                                    Text(isRussian ? "Копировать цепочку" : "Copy Chain")
                                }
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                            }
                            .buttonStyle(.plain)
                        }

                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(processChain.enumerated()), id: \.offset) { idx, proc in
                                HStack(spacing: 6) {
                                    Text(idx == 0 ? "├─" : (idx == processChain.count - 1 ? "└─" : "├─"))
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                    Text(proc.executablePath)
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(.primary)
                                        .textSelection(.enabled)
                                    Text("(PID \(proc.pid))")
                                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                        .foregroundColor(.secondary)
                                    Button(action: {
                                        copyToClipboard("\(proc.executablePath) (PID \(proc.pid))")
                                    }) {
                                        Image(systemName: "doc.on.doc")
                                            .font(.system(size: 9))
                                            .foregroundColor(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                    .help("Copy process path and PID")
                                    .accessibilityLabel(ClavisUIStrings.Accessibility.copyProcessInfo)
                                }
                                .padding(.leading, 8)
                            }
                        }
                        .padding(6)
                        .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
                        .cornerRadius(6)
                    }
                }
            }
            .padding(.leading, 24)
            .padding(.vertical, 4)
        }
    }

    private func detailItem(label: String, value: String, copyValue: String? = nil, isMonospace: Bool = false) -> some View {
        HStack(spacing: 6) {
            Text("\(label):")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
                .frame(minWidth: 90, alignment: .leading)
            Text(value)
                .font(isMonospace ? .system(size: 11, design: .monospaced) : .system(size: 11))
                .foregroundColor(.primary)
                .textSelection(.enabled)
            if let toCopy = copyValue ?? (value.isEmpty ? nil : value) {
                Button(action: {
                    copyToClipboard(toCopy)
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("Copy \(label)")
                .accessibilityLabel(ClavisUIStrings.Accessibility.copyItem(label: label))
            }
        }
    }

    private func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func formatFullRecordSummary(_ record: AuditRecord, unsealResult: AuditUnsealResult) -> String {
        let event = record.event
        let digest = AuditWitness.digest(for: record)
        let isoFormatter = ISO8601DateFormatter()
        var lines: [String] = []
        lines.append("Sequence: \(record.seq)")
        lines.append("Event ID: \(event.id.uuidString.lowercased())")
        lines.append("Timestamp: \(isoFormatter.string(from: event.time))")
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
        if AppState.shared.keys.isEmpty {
            AppState.shared.refresh()
        }
        availableKeys = AppState.shared.keys
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
