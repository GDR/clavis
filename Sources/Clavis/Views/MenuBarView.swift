import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @State private var copiedLabel: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Header: Agent Status & Lock All
            HStack(alignment: .center) {
                HStack(spacing: 8) {
                    StatusDot(isActive: appState.isSocketActive)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(ClavisUIStrings.MenuBar.title)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(.primary)
                        Text(appState.isSocketActive ? (appState.agentPID != nil ? ClavisUIStrings.MenuBar.activeWithPID(appState.agentPID!) : ClavisUIStrings.MenuBar.identitiesReady(count: appState.keys.count)) : ClavisUIStrings.MenuBar.agentOffline)
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                if appState.cachedKeysCount > 0 {
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

            // Active Git Grace Session Banner
            if let gitGrace = appState.activeGitGrace {
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

            Divider()

            // Menu Items (Control Center action style)
            VStack(spacing: 1) {
                MenuBarActionItem(
                    title: ClavisUIStrings.MenuBar.newKey,
                    icon: "plus",
                    shortcut: "⌘N"
                ) {
                    WindowManager.shared.openKeyManager(sheet: .create)
                }

                MenuBarActionItem(
                    title: ClavisUIStrings.MenuBar.importKey,
                    icon: "square.and.arrow.down",
                    shortcut: "⇧⌘I"
                ) {
                    WindowManager.shared.openKeyManager(sheet: .importKey)
                }

                MenuBarActionItem(
                    title: ClavisUIStrings.MenuBar.openKeyManager,
                    icon: "slider.horizontal.3",
                    shortcut: "⌘O"
                ) {
                    WindowManager.shared.openKeyManager()
                }

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

                MenuBarActionItem(
                    title: ClavisUIStrings.MenuBar.settings,
                    icon: "gearshape",
                    shortcut: "⌘,"
                ) {
                    WindowManager.shared.openSettings()
                }
            }

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
        .padding(14)
        .frame(width: 320)
        .background(
            VisualEffectView(material: .popover, blendingMode: .behindWindow)
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(Color.white.opacity(0.12), lineWidth: 0.5)
        )
        .onAppear {
            appState.refresh()
        }
    }

    private func confirmQuit() {
        let alert = NSAlert()
        alert.messageText = "Quit Clavis?"
        if appState.isSocketActive {
            alert.informativeText = "Clavis and its background SSH Agent will stop. Active caches and Git signing sessions will be cleared."
        } else {
            alert.informativeText = "Clavis will stop and active caches will be cleared."
        }
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Quit Clavis")
        alert.addButton(withTitle: "Cancel")

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
                    Text(isCopied ? "Copied" : "Copy")
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
