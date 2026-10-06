import SwiftUI
import AppKit
import ClavisCore

public enum MenuBarSection: Hashable, CaseIterable {
    case unlock
    case lockNow
    case revokeAll
    case sessionCount
    case gitBanner
    case identities
    case newKey
    case importKey
    case openKeyManager
    case agentLifecycle
    case history
    case settings
    case quit

    public static let revoke: MenuBarSection = .revokeAll
    public static let gitSession: MenuBarSection = .gitBanner
}

public enum MenuBarSections {
    public static func visible(isLocked: Bool, hasSessions: Bool) -> Set<MenuBarSection> {
        if isLocked {
            var sections: Set<MenuBarSection> = [
                .unlock,
                .lockNow,
                .agentLifecycle,
                .quit
            ]
            if hasSessions {
                sections.insert(.revokeAll)
                sections.insert(.sessionCount)
            }
            return sections
        } else {
            var sections: Set<MenuBarSection> = [
                .gitBanner,
                .identities,
                .newKey,
                .importKey,
                .openKeyManager,
                .agentLifecycle,
                .history,
                .settings,
                .quit
            ]
            if hasSessions {
                sections.insert(.lockNow)
                sections.insert(.revokeAll)
                sections.insert(.sessionCount)
            }
            return sections
        }
    }
}

@MainActor
struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @ObservedObject var lock: PanelLockController = .shared
    @State private var copiedLabel: String? = nil

    private var sessionCount: Int {
        appState.cachedKeysCount + (appState.activeGitGrace != nil ? 1 : 0) + appState.agentSessions.count
    }

    private var hasSessions: Bool {
        sessionCount > 0
    }

    private var statusSubtitle: String {
        guard appState.isSocketActive else {
            return ClavisUIStrings.MenuBar.agentOffline
        }
        if let pid = appState.agentPID {
            return ClavisUIStrings.MenuBar.activeWithPID(pid)
        }
        if lock.isLocked {
            return ClavisUIStrings.PanelLock.title
        }
        return ClavisUIStrings.MenuBar.identitiesReady(count: appState.keys.count)
    }

    var body: some View {
        let visibleSections = MenuBarSections.visible(isLocked: lock.isLocked, hasSessions: hasSessions)

        VStack(alignment: .leading, spacing: 8) {
            // Header: Agent Status & Lock All
            HStack(alignment: .center) {
                HStack(spacing: 8) {
                    StatusDot(isActive: appState.isSocketActive)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(ClavisUIStrings.MenuBar.title)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(.primary)
                        Text(statusSubtitle)
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                if visibleSections.contains(.lockNow) && (hasSessions || lock.isLocked) {
                    Button(action: {
                        appState.lockNow()
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "lock.fill")
                                .font(.system(size: 10))
                            Text(ClavisUIStrings.MenuBar.lockAll)
                                .font(.system(size: 11, weight: .medium))
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.red.opacity(0.15))
                        .foregroundColor(.red)
                        .clipShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .focusable(false)
                }
            }
            .padding(.horizontal, 4)
            .padding(.top, 2)

            // Error banner if any
            if let errorMsg = appState.errorMessage {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.caption)
                    Text(errorMsg)
                        .font(.caption2)
                        .foregroundColor(.red)
                        .lineLimit(2)
                    Spacer()
                    Button(action: { appState.clearError() }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                }
                .padding(6)
                .background(Color.red.opacity(0.12))
                .cornerRadius(6)
            }

            // Locked active agent sessions count banner (D2)
            if lock.isLocked && visibleSections.contains(.sessionCount) {
                HStack(spacing: 8) {
                    Image(systemName: "key.fill")
                        .foregroundColor(.blue)
                        .font(.system(size: 12))
                    Text(ClavisUIStrings.PanelLock.agentSessionsCount(sessionCount))
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.primary)
                    Spacer()
                }
                .padding(6)
                .background(Color.blue.opacity(0.12))
                .cornerRadius(6)
            }

            // Active Git Grace Session Banner
            if visibleSections.contains(.gitBanner), let gitGrace = appState.activeGitGrace {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.triangle.branch")
                        .foregroundColor(.blue)
                        .font(.system(size: 13, weight: .bold))
                    VStack(alignment: .leading, spacing: 1) {
                        Text(ClavisUIStrings.MenuBar.gitSessionTitle(label: gitGrace.keyLabel))
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(.primary)
                        Text(ClavisUIStrings.MenuBar.gitSessionDetails(timeRemaining: gitGrace.formattedRemainingTime, opsLeft: gitGrace.remainingOperations))
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button(action: {
                        appState.endGitSigningSession()
                    }) {
                        Text(ClavisUIStrings.Common.end)
                            .font(.system(size: 10, weight: .medium))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(Color.secondary.opacity(0.15))
                            .cornerRadius(4)
                    }
                    .buttonStyle(.plain)
                }
                .padding(6)
                .background(Color.blue.opacity(0.12))
                .cornerRadius(6)
            }

            // Active Agent Sessions
            if !appState.agentSessions.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(ClavisUIStrings.AgentSession.menuSection)
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(.secondary)
                        Spacer()
                        Button(action: {
                            appState.revokeAllAgentSessions()
                        }) {
                            Text(ClavisUIStrings.AgentSession.revokeAll)
                                .font(.system(size: 10, weight: .medium))
                                .foregroundColor(.red)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 4)

                    ForEach(appState.agentSessions, id: \.id) { session in
                        HStack(spacing: 8) {
                            Image(systemName: "cpu")
                                .foregroundColor(.purple)
                                .font(.system(size: 12))
                            VStack(alignment: .leading, spacing: 1) {
                                Text("\(session.toolName) · \(session.keyLabel)")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(.primary)
                                let remainingMin = max(0, Int(session.expiresAt.timeIntervalSinceNow / 60))
                                Text(ClavisUIStrings.AgentSession.remainingFormat(minutes: remainingMin))
                                    .font(.system(size: 10))
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Menu {
                                Button(ClavisUIStrings.AgentSession.extend30m) {
                                    Task {
                                        _ = appState.extendAgentSession(id: session.id, minutes: 30)
                                    }
                                }
                                Button(ClavisUIStrings.AgentSession.extend1h) {
                                    Task {
                                        _ = appState.extendAgentSession(id: session.id, minutes: 60)
                                    }
                                }
                                Button(ClavisUIStrings.AgentSession.extend4h) {
                                    Task {
                                        _ = appState.extendAgentSession(id: session.id, minutes: 240)
                                    }
                                }
                            } label: {
                                Text(ClavisUIStrings.AgentSession.extend)
                                    .font(.system(size: 10, weight: .medium))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 3)
                                    .background(Color.secondary.opacity(0.15))
                                    .cornerRadius(4)
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()

                            Button(action: {
                                appState.endAgentSession(id: session.id)
                            }) {
                                Text(ClavisUIStrings.AgentSession.end)
                                    .font(.system(size: 10, weight: .medium))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 3)
                                    .background(Color.secondary.opacity(0.15))
                                    .cornerRadius(4)
                            }
                            .buttonStyle(.plain)
                        }
                        .padding(6)
                        .background(Color.purple.opacity(0.1))
                        .cornerRadius(6)
                    }
                }
            }

            if visibleSections.contains(.identities) {
                Divider()

                // Identities Section
                VStack(alignment: .leading, spacing: 4) {
                    Text(ClavisUIStrings.MenuBar.identitiesHeader)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 4)

                    if appState.keys.isEmpty {
                        VStack(spacing: 4) {
                            Text(ClavisUIStrings.MenuBar.noKeysAvailable)
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(ClavisUIStrings.MenuBar.useNewKeyHint)
                                .font(.caption2)
                                .foregroundColor(.secondary.opacity(0.8))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                    } else {
                        VStack(spacing: 2) {
                            ForEach(appState.keys.prefix(4)) { key in
                                MenuBarIdentityRow(
                                    key: key,
                                    isCopied: copiedLabel == key.label,
                                    onCopy: { copyKey(key) }
                                )
                            }
                        }
                    }
                }
            }

            Divider()

            // Menu Items (Control Center action style)
            VStack(spacing: 1) {
                if visibleSections.contains(.unlock) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.PanelLock.unlockMenu,
                        icon: "lock.open.fill",
                        shortcut: "⌘U"
                    ) {
                        Task {
                            await lock.unlock()
                            if !lock.isLocked {
                                WindowManager.shared.openKeyManager()
                            }
                        }
                    }
                }

                if lock.isLocked && visibleSections.contains(.lockNow) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.lockAll,
                        icon: "lock.fill",
                        shortcut: "⌘L"
                    ) {
                        appState.lockNow()
                    }
                }

                if visibleSections.contains(.newKey) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.newKey,
                        icon: "plus",
                        shortcut: "⌘N"
                    ) {
                        WindowManager.shared.openKeyManager(sheet: .create)
                    }
                }

                if visibleSections.contains(.importKey) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.importKey,
                        icon: "square.and.arrow.down",
                        shortcut: "⇧⌘I"
                    ) {
                        WindowManager.shared.openKeyManager(sheet: .importKey)
                    }
                }

                if visibleSections.contains(.openKeyManager) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.openKeyManager,
                        icon: "slider.horizontal.3",
                        shortcut: "⌘O"
                    ) {
                        WindowManager.shared.openKeyManager()
                    }
                }

                if visibleSections.contains(.agentLifecycle) {
                    if appState.isSocketActive {
                        MenuBarActionItem(
                            title: ClavisUIStrings.MenuBar.restartAgent,
                            icon: "arrow.clockwise",
                            shortcut: "⇧⌘R"
                        ) {
                            appState.restartAgent()
                        }
                    } else {
                        MenuBarActionItem(
                            title: ClavisUIStrings.MenuBar.startAgent,
                            icon: "play.fill",
                            shortcut: "⇧⌘S"
                        ) {
                            appState.startAgent()
                        }
                    }
                }

                if visibleSections.contains(.history) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.history,
                        icon: "clock.arrow.circlepath",
                        shortcut: "⌘Y"
                    ) {
                        WindowManager.shared.openHistory()
                    }
                }

                if visibleSections.contains(.settings) {
                    MenuBarActionItem(
                        title: ClavisUIStrings.MenuBar.settings,
                        icon: "gearshape",
                        shortcut: "⌘,"
                    ) {
                        WindowManager.shared.openSettings()
                    }
                }
            }

            if visibleSections.contains(.quit) {
                Divider()

                // Quit Action
                MenuBarActionItem(
                    title: ClavisUIStrings.MenuBar.quit,
                    icon: "power",
                    shortcut: "⌘Q",
                    isDestructive: true
                ) {
                    confirmQuit()
                }
            }
        }
        .padding(14)
        .frame(width: 320)
        .modifier(MenuBarBackgroundModifier())
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
        }
    }

    private func confirmQuit() {
        WindowManager.shared.dismissMenuBarExtra()
        let alert = NSAlert()
        alert.messageText = ClavisUIStrings.MenuBar.quitConfirmationTitle
        if appState.isSocketActive {
            alert.informativeText = ClavisUIStrings.MenuBar.quitConfirmationDetailsWithAgent
        } else {
            alert.informativeText = ClavisUIStrings.MenuBar.quitConfirmationDetailsSimple
        }
        alert.alertStyle = .informational
        alert.addButton(withTitle: ClavisUIStrings.MenuBar.quit)
        alert.addButton(withTitle: ClavisUIStrings.Common.cancel)

        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            NSApplication.shared.terminate(nil)
        }
    }

    private func copyKey(_ key: Ed25519KeyInfo) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.displayIdentifier, forType: .string)
        withAnimation {
            copiedLabel = key.label
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            withAnimation {
                if copiedLabel == key.label {
                    copiedLabel = nil
                }
            }
        }
    }
}

private struct MenuBarIdentityRow: View {
    let key: Ed25519KeyInfo
    let isCopied: Bool
    let onCopy: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle()
                    .fill(key.isHardware ? Color.green : Color.blue)
                    .frame(width: 26, height: 26)
                Image(systemName: key.isHardware ? "lock.shield.fill" : "key.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.white)
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(key.label)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.primary)
                        .lineLimit(1)
                    KeyBadge(isHardware: key.isHardware)
                    PurposeBadge(purpose: key.purpose)
                }
                Text(key.displayIdentifier)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            Button(action: onCopy) {
                HStack(spacing: 3) {
                    if isCopied {
                        Image(systemName: "checkmark")
                            .font(.system(size: 9, weight: .bold))
                    }
                    Text(isCopied ? ClavisUIStrings.Common.copied : ClavisUIStrings.Common.copy)
                        .font(.system(size: 11, weight: .medium))
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .background(isCopied ? Color.green.opacity(0.20) : Color.primary.opacity(0.08))
                .foregroundColor(isCopied ? .green : .primary)
                .clipShape(Capsule())
            }
            .buttonStyle(.plain)
            .focusable(false)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(isHovered ? Color.primary.opacity(0.08) : Color.clear)
        )
        .contentShape(Rectangle())
        .onHover { isHovered = $0 }
    }
}

private struct MenuBarActionItem: View {
    let title: String
    let icon: String
    let shortcut: String
    var isDestructive: Bool = false
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
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
            .padding(.horizontal, 6)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(isHovered ? (isDestructive ? Color.red.opacity(0.12) : Color.primary.opacity(0.08)) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { isHovered = $0 }
    }
}

private struct MenuBarBackgroundModifier: ViewModifier {
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .glassEffect(
                    .regular,
                    in: RoundedRectangle(cornerRadius: 18, style: .continuous)
                )
        } else {
            content
                .background(
                    VisualEffectView(material: .menu, blendingMode: .behindWindow)
                        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
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
