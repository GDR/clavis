import SwiftUI
import AppKit
import ClavisCore

@MainActor
public struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @ObservedObject var lock: PanelLockController
    @State private var confirmingRequestPolicy = false

    public init(lock: PanelLockController? = nil) {
        self.lock = lock ?? .shared
    }

    /// The panel lock protects key metadata; it does not stop background signing.
    func sessions(at date: Date) -> [MenuBarSession] {
        MenuBarSession.active(
            gitGraces: appState.activeGitGraces.isEmpty
                ? appState.activeGitGrace.map { [$0] } ?? []
                : appState.activeGitGraces,
            agentSessions: appState.agentSessions,
            keys: appState.keys,
            at: date
        )
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            header
            separator

            if let message = appState.errorMessage {
                errorBanner(message)
            }

            TimelineView(.periodic(from: .now, by: 1)) { context in
                let activeSessions = sessions(at: context.date)
                VStack(alignment: .leading, spacing: 1) {
                    if lock.isEffectivelyLocked {
                        emptyState(ClavisUIStrings.MenuBar.unlockToViewSessions)
                    } else if activeSessions.isEmpty {
                        emptyState(ClavisUIStrings.MenuBar.noActiveSessions)
                    } else {
                        // Keep long lists bounded while every authorization remains accessible.
                        ScrollView {
                            VStack(spacing: 1) {
                                ForEach(activeSessions) { session in
                                    MenuBarSessionRow(session: session, date: context.date) {
                                        endSession(session)
                                    }
                                }
                            }
                        }
                        .frame(height: min(CGFloat(activeSessions.count) * 49, 294))
                    }

                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.lockAllKeys,
                        icon: "lock"
                    ) {
                        appState.lockNow()
                        appState.refreshAgentSessions()
                    }
                    .disabled(activeSessions.isEmpty)
                }
            }

            separator

            MenuBarActionItem(
                title: appState.requestPolicy.isPaused ? "Resume Requests…" : "Activate Kill Switch…",
                icon: appState.requestPolicy.isPaused ? "play.circle" : "stop.circle"
            ) { confirmingRequestPolicy = true }
            .disabled(appState.requestPolicy.isBusy)

            MenuBarActionItem(
                title: appState.isSocketActive
                    ? ClavisUIStrings.MenuBar.restartAgent
                    : ClavisUIStrings.MenuBar.startAgent,
                icon: appState.isSocketActive ? "arrow.clockwise" : "play",
                keyEquivalent: appState.isSocketActive ? "r" : "s",
                modifiers: [.command, .shift]
            ) {
                if appState.isSocketActive {
                    appState.restartAgent()
                } else {
                    appState.startAgent()
                }
                appState.updateGitGraceState()
                appState.refreshAgentSessions()
            }

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.openClavis,
                icon: "macwindow",
                keyEquivalent: "o"
            ) {
                WindowManager.shared.openKeyManager()
            }

            separator

            MenuBarActionItem(
                title: ClavisUIStrings.MenuBar.quit,
                icon: "power",
                keyEquivalent: "q"
            ) {
                confirmQuit()
            }
        }
        .padding(6)
        .frame(width: 306)
        .modifier(MenuBarBackgroundModifier())
        .background(
            WindowAccessor { window in
                window.isOpaque = false
                window.backgroundColor = .clear
                window.hasShadow = false
                WindowManager.shared.menuBarWindow = window
            }
        )
        .onAppear { appState.refresh() }
        .task { await appState.requestPolicy.refresh() }
        .confirmationDialog(appState.requestPolicy.isPaused ? "Resume requests?" : "Activate kill switch?", isPresented: $confirmingRequestPolicy) {
            Button(appState.requestPolicy.isPaused ? "Resume Requests" : "Activate Kill Switch", role: .destructive) {
                Task { await appState.setRequestsPaused(!appState.requestPolicy.isPaused) }
            }
        } message: {
            Text(appState.requestPolicy.isPaused
                 ? "Authentication is required. Revoked approvals will not be restored."
                 : "Revoke approvals and pause new requests. Existing SSH connections may remain open.")
        }
        .task {
            // Snapshots come from the agent; the one-second timeline only updates display.
            while !Task.isCancelled {
                appState.updateGitGraceState()
                appState.refreshAgentSessions()
                do {
                    try await Task.sleep(nanoseconds: 5_000_000_000)
                } catch {
                    break
                }
            }
        }
    }

    private var header: some View {
        HStack(alignment: .center) {
            Text(ClavisUIStrings.Common.appName)
                .font(.system(size: 13, weight: .semibold))
            Spacer(minLength: 12)
            HStack(spacing: 6) {
                Circle()
                    .fill(appState.isSocketActive ? MenuBarSessionRow.keyColor : Color.secondary)
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

    private func emptyState(_ message: String) -> some View {
        Text(message)
            .font(.system(size: 12))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.leading, 34)
            .padding(.trailing, 9)
            .padding(.vertical, 12)
    }

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

    private func endSession(_ session: MenuBarSession) {
        switch session.target {
        case .git(let keyLabel):
            appState.revokeGitGrace(for: keyLabel)
            appState.refreshAgentSessions()
        case .agent(let sessionID):
            appState.endAgentSession(id: sessionID)
        }
    }

    private func confirmQuit() {
        WindowManager.shared.dismissMenuBarExtra()
        let alert = NSAlert()
        alert.messageText = ClavisUIStrings.MenuBar.quitConfirmationTitle
        alert.informativeText = appState.isSocketActive
            ? ClavisUIStrings.MenuBar.quitConfirmationDetailsWithAgent
            : ClavisUIStrings.MenuBar.quitConfirmationDetailsSimple
        alert.alertStyle = .informational
        alert.addButton(withTitle: ClavisUIStrings.MenuBar.quit)
        alert.addButton(withTitle: ClavisUIStrings.Common.cancel)
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            NSApplication.shared.terminate(nil)
        }
    }
}

struct MenuBarSessionRow: View {
    let session: MenuBarSession
    let date: Date
    let onLock: () -> Void

    static var keyColor: Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.isDarkMode
                ? NSColor(srgbRed: 0.61, green: 0.85, blue: 0.69, alpha: 1)
                : NSColor(srgbRed: 0.32, green: 0.57, blue: 0.39, alpha: 1)
        })
    }

    private var purpose: String {
        switch session.purpose {
        case .general: return ClavisUIStrings.MenuBar.purposeSSHAndGit
        case .gitSigningOnly: return ClavisUIStrings.MenuBar.purposeGit
        case .agent: return ClavisUIStrings.KeyPurposeStrings.agentTitle
        }
    }

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: "key")
                .font(.system(size: 14))
                .foregroundStyle(Self.keyColor)
                .frame(width: 16)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                Text(session.keyLabel)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(purpose)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .help(session.toolName.map { "\(session.keyLabel) · \(purpose) · \($0)" } ?? "\(session.keyLabel) · \(purpose)")

            Text(session.remainingTime(at: date))
                .font(.system(size: 12).monospacedDigit())
                .foregroundStyle(.secondary)
                .fixedSize()
                .frame(minWidth: 43, alignment: .trailing)
                .accessibilityLabel(ClavisUIStrings.MenuBar.timeRemaining(session.remainingTime(at: date)))

            Button(action: onLock) {
                Image(systemName: "lock")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .help(ClavisUIStrings.MenuBar.lockKey(session.keyLabel))
            .accessibilityLabel(ClavisUIStrings.MenuBar.lockKey(session.keyLabel))
        }
        .padding(.horizontal, 9)
        .frame(height: 49)
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
