import SwiftUI
import AppKit
import ClavisCore

/// S01.menu: status, recent signing events, Copy public key, Lock Now, New Key…, Open Clavis.
/// The pause/resume (kill switch) controls are gone (D-38); the request-pause state model stays
/// and is still reflected in the passive status line.
@MainActor
public struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @ObservedObject var lock: PanelLockController
    @StateObject private var history = HistoryViewModel(keyring: nil, contextProvider: { nil })
    @State private var pendingApprovals = NotchPromptWindowController.shared.pendingApprovalCount

    /// Recent signing decisions shown in the menu (prototype: the five latest non-config events).
    static let recentEventLimit = 5
    static let lockNowTitle = "Lock Now"
    static let copyPublicKeyTitle = "Copy public key"
    static let showAllHistoryTitle = "Show All History"
    static let noEventsTitle = "No signing events yet"

    public init(lock: PanelLockController? = nil) {
        self.lock = lock ?? .shared
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            header
            separator

            if let message = appState.errorMessage {
                errorBanner(message)
            }

            if pendingApprovals > 0 {
                Button {
                    NotchPromptWindowController.shared.presentNextApprovalIfIdle()
                    NotchPromptWindowController.shared.focusPromptWindow()
                    WindowManager.shared.dismissMenuBarExtra()
                } label: {
                    Text("Answer pending (\(pendingApprovals))")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.accentColor)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 4)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }

            recentEvents

            Button(action: openAllHistory) {
                Text(Self.showAllHistoryTitle)
                    .font(.system(size: 12))
                    .foregroundColor(.accentColor)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 4)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            separator

            copyPublicKeyMenu

            MenuBarActionItem(
                title: Self.lockNowTitle,
                icon: "lock",
                shortcut: "⌘L"
            ) {
                WindowManager.shared.dismissMenuBarExtra()
                PanelLockController.shared.lock(reason: .lockNow)
            }

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.newKey,
                icon: "plus",
                shortcut: "⌘N"
            ) {
                WindowManager.shared.dismissMenuBarExtra()
                WindowManager.shared.openKeyManager(sheet: .create)
            }

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.openClavis,
                icon: "macwindow",
                shortcut: "⌘O"
            ) {
                WindowManager.shared.dismissMenuBarExtra()
                WindowManager.shared.openKeyManager()
            }
        }
        .padding(6)
        .frame(width: 306)
        .modifier(MenuBarBackgroundModifier())
        .onReceive(NotchPromptWindowController.shared.queueChanges) { pendingApprovals = $0 }
        .background(
            WindowAccessor { window in
                window.isOpaque = false
                window.backgroundColor = .clear
                window.hasShadow = false
                WindowManager.shared.menuBarWindow = window
            }
        )
        .onAppear {
            appState.refresh()
            history.query.limit = Self.recentEventLimit
            history.updateKeys(appState.keys)
            if history.records.isEmpty && !history.isLoading { history.reload() }
        }
        .onChange(of: appState.keys) { _, newKeys in history.updateKeys(newKeys) }
        .task { await appState.requestPolicy.refresh() }
    }

    // MARK: - Status

    private var header: some View {
        HStack(alignment: .center) {
            Text(ClavisUIStrings.Common.appName)
                .font(.system(size: 13, weight: .semibold))
            Spacer(minLength: 12)
            if pendingApprovals > 0 {
                Text("\(pendingApprovals)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(DesignTokens.accentOrange))
            }
            HStack(spacing: 6) {
                Circle()
                    .fill(appState.isSocketActive ? DesignTokens.accentGreen : Color.secondary)
                    .frame(width: 6, height: 6)
                    .accessibilityHidden(true)
                Text(appState.isSocketActive
                     ? appState.requestPolicy.status
                     : ClavisUIStrings.MenuBar.agentOffline)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
    }

    private var separator: some View {
        Divider().padding(.horizontal, 9)
    }

    // MARK: - Recent events

    /// Signing decisions only (config/lifecycle records are not signing events).
    private var recentSigningRecords: [AuditRecord] {
        Self.recentSigningRecords(from: history.records, limit: Self.recentEventLimit)
    }

    static func recentSigningRecords(from records: [AuditRecord], limit: Int) -> [AuditRecord] {
        records
            .filter { $0.event.type == .signature || $0.event.type == .suppressed }
            .prefix(limit)
            .map { $0 }
    }

    @ViewBuilder
    private var recentEvents: some View {
        let records = recentSigningRecords
        if records.isEmpty {
            Text(Self.noEventsTitle)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 9)
                .padding(.vertical, 8)
        } else {
            VStack(spacing: 1) {
                ForEach(records, id: \.seq) { record in
                    MenuBarEventRow(record: record, viewModel: history, keys: appState.keys) {
                        openHistory(for: record)
                    }
                }
            }
        }
    }

    private func openHistory(for record: AuditRecord) {
        WindowManager.shared.dismissMenuBarExtra()
        WindowManager.shared.openKeyManager()
        appState.openHistoryPane(forKeyFingerprint: record.event.keyFingerprint)
    }

    private func openAllHistory() {
        WindowManager.shared.dismissMenuBarExtra()
        WindowManager.shared.openKeyManager()
        appState.openHistoryPane()
    }

    // MARK: - Copy public key

    private var copyPublicKeyMenu: some View {
        Menu {
            if appState.keys.isEmpty {
                Text(ClavisUIStrings.MenuBar.noKeysAvailable)
            }
            ForEach(appState.keys) { key in
                Button(key.label) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
                }
            }
        } label: {
            HStack(spacing: 9) {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .frame(width: 16)
                Text(Self.copyPublicKeyTitle)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundColor(.primary)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 7)
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .accessibilityLabel(Self.copyPublicKeyTitle)
    }

    // MARK: - Error banner

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: "exclamationmark.triangle")
                .frame(width: 16)
            Text(message)
                .font(.system(size: 11))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button { appState.clearError() } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.plain)
            .accessibilityLabel(ClavisUIStrings.Common.cancel)
        }
        .foregroundStyle(.red)
        .padding(9)
    }
}

/// One recent signing event: ✓/✕ mark + key · requesting app · time. Clicking opens History
/// scoped to the event's key.
struct MenuBarEventRow: View {
    let record: AuditRecord
    @ObservedObject var viewModel: HistoryViewModel
    let keys: [SSHKeyInfo]
    let onOpen: () -> Void

    @State private var isHovered = false

    private var event: AuditEvent { record.event }
    private var result: HistoryResult { HistoryResult(event.result) }

    private var keyName: String {
        if let fp = event.keyFingerprint,
           let current = keys.first(where: { $0.fingerprint == fp }) {
            return current.label
        }
        let sens = viewModel.resolvedSensitive(for: record)
        if let label = sens.keyLabel, !label.isEmpty { return label }
        if let fp = event.keyFingerprint { return String(fp.prefix(16)) }
        return "Unknown key"
    }

    private var callerName: String? {
        let sens = viewModel.resolvedSensitive(for: record)
        guard let name = sens.callerName, !name.isEmpty else { return nil }
        return name
    }

    private var timeText: String {
        event.time.formatted(Date.FormatStyle(date: .omitted, time: .shortened))
    }

    var body: some View {
        Button(action: onOpen) {
            HStack(spacing: 7) {
                Image(systemName: result == .approved ? "checkmark" : "xmark")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(result == .approved ? DesignTokens.accentGreen : .red)
                    .frame(width: 12)
                    .accessibilityHidden(true)
                Text(keyName)
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let callerName {
                    Text("· \(callerName)")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 6)
                Text(timeText)
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundStyle(.secondary)
                    .fixedSize()
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(isHovered ? Color.primary.opacity(0.08) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .help("\(keyName) · \(result.title) · \(timeText)")
        .accessibilityLabel("\(keyName), \(result.title), \(timeText)")
    }
}

struct MenuBarActionItem: View {
    let title: String
    let icon: String
    let shortcut: String
    let keyEquivalent: KeyEquivalent?
    let modifiers: EventModifiers
    var isDestructive: Bool = false
    let action: () -> Void

    @State private var isHovered = false

    init(
        title: String,
        icon: String,
        shortcut: String = "",
        keyEquivalent: KeyEquivalent? = nil,
        modifiers: EventModifiers? = nil,
        isDestructive: Bool = false,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.icon = icon
        self.shortcut = shortcut
        if let keyEquivalent {
            self.keyEquivalent = keyEquivalent
            self.modifiers = modifiers ?? .command
        } else if let parsed = Self.parseShortcut(shortcut) {
            self.keyEquivalent = parsed.key
            self.modifiers = modifiers ?? parsed.modifiers
        } else {
            self.keyEquivalent = nil
            self.modifiers = modifiers ?? .command
        }
        self.isDestructive = isDestructive
        self.action = action
    }

    static func parseShortcut(_ shortcut: String) -> (key: KeyEquivalent, modifiers: EventModifiers)? {
        guard !shortcut.isEmpty else { return nil }
        var modifiers: EventModifiers = []
        var character: Character?
        for char in shortcut {
            switch char {
            case "⌘":
                modifiers.insert(.command)
            case "⇧":
                modifiers.insert(.shift)
            case "⌥":
                modifiers.insert(.option)
            case "⌃":
                modifiers.insert(.control)
            default:
                character = char
            }
        }
        guard let char = character else { return nil }
        let lower = Character(char.lowercased())
        let resolvedModifiers = modifiers.isEmpty ? .command : modifiers
        return (KeyEquivalent(lower), resolvedModifiers)
    }

    @ViewBuilder
    var body: some View {
        let button = Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: icon)
                    .font(.system(size: 12))
                    .foregroundColor(isDestructive ? .red : .secondary)
                    .frame(width: 16)
                Text(title)
                    .font(.system(size: 12, weight: .regular))
                    .foregroundColor(isDestructive ? .red : .primary)
                Spacer()
                if !shortcut.isEmpty {
                    Text(shortcut)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(isHovered ? (isDestructive ? Color.red.opacity(0.12) : Color.primary.opacity(0.08)) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .onHover { isHovered = $0 }

        if let keyEquivalent {
            button.keyboardShortcut(keyEquivalent, modifiers: modifiers)
        } else {
            button
        }
    }
}

private struct MenuBarBackgroundModifier: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .glassEffect(
                    .regular,
                    in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                )
        } else {
            content
                .background(
                    VisualEffectView(material: .menu, blendingMode: .behindWindow)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .ignoresSafeArea()
                )
        }
    }
}

private struct WindowAccessor: NSViewRepresentable {
    let onWindow: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = WindowObserverView()
        view.onWindow = onWindow
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let window = nsView.window {
            onWindow(window)
        }
    }

    private final class WindowObserverView: NSView {
        var onWindow: ((NSWindow) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window {
                onWindow?(window)
            }
        }
    }
}