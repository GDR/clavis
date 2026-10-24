import SwiftUI
import AppKit
import ClavisCore

/// One event: **key → destination** on top, "operation · result" below, time on the right.
struct HistoryEventRow: View {
    let record: AuditRecord
    @ObservedObject var viewModel: HistoryViewModel
    let isExpanded: Bool
    let toggle: () -> Void
    let onFilterHost: (String) -> Void
    let showIntegrity: () -> Void
    let export: () -> Void

    private static let isoFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    // MARK: Derived display values (from typed event data, never parsed back from strings)

    private var event: AuditEvent { record.event }
    private var unseal: AuditUnsealResult {
        if let res = viewModel.sensitive[record.seq] { return res }
        if record.sensitiveFormat == 0 { return .plaintext(event.sensitive) }
        return record.sensitiveFormat == 2 ? .omitted : .unreadable
    }
    private var sens: AuditSensitive { viewModel.resolvedSensitive(for: record) }
    private var operation: String { HistoryViewModel.operationTitle(for: record, sensitive: sens) }
    private var result: HistoryResult { HistoryResult(event.result) }

    /// Current key name wins (so renames show), then the name sealed in the event, then a fingerprint prefix.
    private var keyName: String? {
        if let fp = event.keyFingerprint,
           let current = viewModel.keyChoices.first(where: { $0.fingerprint == fp }) {
            return current.label
        }
        if case .plaintext(let s) = unseal, let label = s.keyLabel, !label.isEmpty { return label }
        if let fp = event.keyFingerprint { return String(fp.prefix(16)) }
        return nil
    }

    /// Local security events (lock, policy…) have no destination; none is invented for them.
    private var host: String? {
        guard case .plaintext(let s) = unseal, let h = s.host, !h.isEmpty else { return nil }
        return h
    }

    private var statusSymbol: (name: String, color: Color) {
        switch result {
        case .approved: return ("checkmark", DesignTokens.accentGreen)
        case .rejected: return ("xmark", .red)
        case .recorded: return ("circle.dashed", DesignTokens.textSecondary)   // recorded ≠ approved
        }
    }

    private var secondaryText: String {
        [operation, HistoryViewModel.callerTitle(sens), result.title].compactMap { $0 }.joined(separator: " · ")
    }
    private var primaryTitle: String { keyName ?? operation }

    private var dateText: String {
        event.time.formatted(Date.FormatStyle(date: .abbreviated, time: .omitted, timeZone: viewModel.calendar.timeZone))
    }
    private var timeText: String {
        event.time.formatted(Date.FormatStyle(date: .omitted, time: .standard, timeZone: viewModel.calendar.timeZone))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: statusSymbol.name)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(statusSymbol.color)
                    .frame(width: 14, height: 14)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(primaryTitle)
                            .font(.system(size: 13, weight: .medium))
                            .lineLimit(1)
                        if let host {
                            Image(systemName: "arrow.right")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(DesignTokens.textSecondary)
                                .accessibilityHidden(true)
                            HistoryHostLink(host: host) { onFilterHost(host) }
                        }
                        if event.count > 1 || event.type == .suppressed {
                            Text(ClavisUIStrings.History.suppressedCount(event.count))
                                .font(.system(size: 10, weight: .medium))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Capsule().fill(DesignTokens.accentOrange.opacity(0.15)))
                                .foregroundColor(DesignTokens.accentOrange)
                        }
                    }
                    Text(secondaryText)
                        .font(.system(size: 12))
                        .foregroundColor(DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                Spacer(minLength: 12)

                VStack(alignment: .trailing, spacing: 2) {
                    Text(dateText).font(.system(size: 11).monospacedDigit())
                    Text(timeText).font(.system(size: 11).monospacedDigit())
                }
                .foregroundColor(DesignTokens.textSecondary)
                .help(Self.isoFormatter.string(from: event.time))
            }
            .frame(minHeight: 34)
            .padding(.vertical, 9)
            .background {
                ZStack {
                    VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
                    DesignTokens.inspectorBackground
                }
            }
            .zIndex(1)
            .contentShape(Rectangle())
            // Whole row discloses details; the host link above is its own control and wins its clicks.
            .onTapGesture(perform: toggle)
            .modifier(HistoryRowKeyboardDisclosure(toggle: toggle))
            .accessibilityElement(children: .contain)
            .accessibilityLabel("\(primaryTitle)\(host.map { " to \($0)" } ?? ""), \(secondaryText)")
            .accessibilityValue(isExpanded ? ClavisUIStrings.Accessibility.expanded : ClavisUIStrings.Accessibility.collapsed)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction(.default, toggle)

            if isExpanded {
                details
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .clipped()
        .overlay(alignment: .bottom) {
            Rectangle().fill(DesignTokens.cardBorder).frame(height: 1)
        }
        .contextMenu { contextMenu }
    }

    // MARK: Details

    private var details: some View {
        let digest = AuditWitness.digest(for: record)
        let status = result.title
        let reasonLine = event.reason.map { "\(status) · \($0.rawValue.replacingOccurrences(of: "_", with: " "))" } ?? status
        let chain = sens.processChain

        // The requesting executable is distinct from the processes that launched it.
        let processLine: String = chain.first.map { "\($0.executablePath) (PID \($0.pid))" } ?? "—"
        let parentsLine: String = chain.dropFirst().isEmpty
            ? "—"
            : chain.dropFirst().map { ($0.executablePath as NSString).lastPathComponent }.joined(separator: " → ")

        let lines = [
            "Key: \(keyName ?? "—")",
            "Host: \(host ?? "—")",
            "Result: \(reasonLine)",
            "Caller: \(HistoryViewModel.callerTitle(sens) ?? "Not recorded")",
            "Process: \(processLine)",
            "Launched by: \(parentsLine)",
            "Timestamp: \(Self.isoFormatter.string(from: event.time))",
            "Session: \(event.sessionID ?? "—")",
            "Record hash: SHA256:\(digest)"
        ].joined(separator: "\n")

        return Text(lines)
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(DesignTokens.textSecondary)
            .lineSpacing(4)
            .textSelection(.enabled)
            .padding(.leading, 24)
            .padding(.top, 1)
            .padding(.bottom, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Context menu

    @ViewBuilder
    private var contextMenu: some View {
        let digest = AuditWitness.digest(for: record)

        Button { copy(digest) } label: { Label(ClavisUIStrings.History.copyHash, systemImage: "doc.on.doc") }

        if let sid = event.sessionID {
            Button { copy(sid) } label: { Label(ClavisUIStrings.History.copySessionID, systemImage: "cpu") }
            Button(ClavisUIStrings.AgentSession.historyShowSession) { viewModel.setSessionScope(sid) }
        }

        if let fp = event.keyFingerprint {
            Button { copy(fp) } label: { Label(ClavisUIStrings.History.copyFingerprint, systemImage: "key") }
            Button { viewModel.selectSidebarKey(fp) } label: {
                Label(ClavisUIStrings.History.filterByKey, systemImage: "line.3.horizontal.decrease.circle")
            }
        }

        if let host {
            Button { copy(host) } label: { Label(ClavisUIStrings.History.copyHost, systemImage: "network") }
            Button { onFilterHost(host) } label: { Label(ClavisUIStrings.History.filterByHost, systemImage: "line.3.horizontal.decrease.circle") }
        }
        if let peer = sens.processChain.first {
            Button { copy(peer.executablePath) } label: { Label(ClavisUIStrings.History.copyProcessPath, systemImage: "terminal") }
            Button { viewModel.add(.process(.path(peer.executablePath))) } label: {
                Label(ClavisUIStrings.History.filterByProcess, systemImage: "line.3.horizontal.decrease.circle")
            }
        }

        Button { copy(fullSummary(digest: digest)) } label: { Label(ClavisUIStrings.History.copyFullRow, systemImage: "doc.text") }

        Divider()

        Button(action: showIntegrity) { Label(ClavisUIStrings.History.checkIntegrity, systemImage: "checkmark.shield") }
        Button(action: export) { Label(ClavisUIStrings.History.export, systemImage: "square.and.arrow.up") }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func fullSummary(digest: String) -> String {
        var lines: [String] = []
        lines.append("Sequence: \(record.seq)")
        lines.append("Event ID: \(event.id.uuidString.lowercased())")
        lines.append("Timestamp: \(Self.isoFormatter.string(from: event.time))")
        lines.append("Type: \(event.type.rawValue)")
        lines.append("Result: \(event.result.rawValue)")
        if let reason = event.reason { lines.append("Reason: \(reason.rawValue)") }
        if let fp = event.keyFingerprint { lines.append("Key Fingerprint: \(fp)") }
        if case .plaintext(let s) = unseal {
            if let label = s.keyLabel { lines.append("Key Label: \(label)") }
            if let operation = s.requestOperation { lines.append("Operation: \(operation.rawValue)") }
            if let caller = HistoryViewModel.callerTitle(s) { lines.append("Caller: \(caller)") }
            if let host = s.host { lines.append("Host: \(host)") }
            if !s.processChain.isEmpty {
                lines.append("Processes:")
                for proc in s.processChain { lines.append("  - \(proc.executablePath) (PID \(proc.pid))") }
            }
        }
        if let sid = event.sessionID { lines.append("Session ID: \(sid)") }
        lines.append("SHA-256 Digest: \(digest)")
        return lines.joined(separator: "\n")
    }
}

/// Host text that adds a Host badge; restrained link-like hover/focus treatment.
struct HistoryHostLink: View {
    let host: String
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Text(host)
                .font(.system(size: 13, weight: .medium))
                .underline(isHovered)
                .foregroundColor(isHovered ? .accentColor : .primary)
                .lineLimit(1)
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .help(ClavisUIStrings.History.filterByHostNamed(host))
        .accessibilityLabel(ClavisUIStrings.History.filterByHostNamed(host))
    }
}

/// Space/Return disclose the focused row (macOS 14+ key handling; mouse and VoiceOver work everywhere).
private struct HistoryRowKeyboardDisclosure: ViewModifier {
    let toggle: () -> Void

    func body(content: Content) -> some View {
        if #available(macOS 14.0, *) {
            content
                .focusable()
                .focusEffectDisabled()
                .onKeyPress(.space) { toggle(); return .handled }
                .onKeyPress(.return) { toggle(); return .handled }
        } else {
            content
        }
    }
}
