import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @State private var copiedLabel: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Header: Agent Status & Lock All
            HStack(alignment: .center) {
                HStack(spacing: 8) {
                    StatusDot(isActive: appState.isSocketActive)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Clavis Agent")
                            .font(.system(size: 13, weight: .semibold))
                        Text(appState.isSocketActive ? "\(appState.keys.count) identities ready" : "Agent offline")
                            .font(.system(size: 11))
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                }

                Spacer()

                Button(action: {
                    appState.lockNow()
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 10))
                        Text("Lock All")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Color.red.opacity(0.12))
                    .foregroundColor(appState.cachedKeysCount > 0 ? .red : DesignTokens.textSecondary)
                    .clipShape(Capsule())
                    .overlay(
                        Capsule()
                            .stroke(appState.cachedKeysCount > 0 ? Color.red.opacity(0.3) : DesignTokens.cardBorder, lineWidth: 0.8)
                    )
                }
                .buttonStyle(.plain)
                .focusable(false)
                .disabled(appState.cachedKeysCount == 0)
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

            Divider().background(DesignTokens.cardBorder)

            // Identities Section
            VStack(alignment: .leading, spacing: 6) {
                Text("IDENTITIES")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(DesignTokens.textTertiary)
                    .padding(.horizontal, 4)

                if appState.keys.isEmpty {
                    VStack(spacing: 6) {
                        Text("No keys available")
                            .font(.caption)
                            .foregroundColor(DesignTokens.textSecondary)
                        Text("Use 'New Key…' to generate an identity.")
                            .font(.caption2)
                            .foregroundColor(DesignTokens.textTertiary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                } else {
                    VStack(spacing: 6) {
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

            Divider().background(DesignTokens.cardBorder)

            // Menu Items (Figma frame 39:878 - 39:894)
            VStack(spacing: 2) {
                MenuBarActionItem(
                    title: "New Key…",
                    icon: "plus",
                    shortcut: "⌘N"
                ) {
                    WindowManager.shared.openKeyManager()
                }

                MenuBarActionItem(
                    title: "Import Key…",
                    icon: "square.and.arrow.down",
                    shortcut: "⇧⌘I"
                ) {
                    WindowManager.shared.openKeyManager()
                }

                MenuBarActionItem(
                    title: "Open Key Manager…",
                    icon: "slider.horizontal.3",
                    shortcut: "⌘O"
                ) {
                    WindowManager.shared.openKeyManager()
                }

                MenuBarActionItem(
                    title: "Settings…",
                    icon: "gearshape",
                    shortcut: "⌘,"
                ) {
                    WindowManager.shared.openSettings()
                }
            }

            Divider().background(DesignTokens.cardBorder)

            // Quit Action
            MenuBarActionItem(
                title: "Quit Clavis",
                icon: "power",
                shortcut: "⌘Q",
                isDestructive: true
            ) {
                SingleInstanceLock.shared.release()
                SSHAgentServer.sharedInstance.stop()
                NSApplication.shared.terminate(nil)
            }
        }
        .padding(12)
        .frame(width: 340)
        .onAppear {
            appState.refresh()
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
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(key.label)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.primary)
                        .lineLimit(1)
                    KeyBadge(isHardware: key.isHardware)
                }
                Text(key.displayIdentifier)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(DesignTokens.textSecondary)
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
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(
                    Capsule()
                        .fill(isCopied ? DesignTokens.accentGreen.opacity(0.18) : Color.white.opacity(0.10))
                        .background(.ultraThinMaterial, in: Capsule())
                )
                .overlay(
                    Capsule()
                        .stroke(
                            isCopied ? DesignTokens.accentGreen.opacity(0.40) : Color.white.opacity(0.18),
                            lineWidth: 0.8
                        )
                )
                .foregroundColor(isCopied ? DesignTokens.accentGreen : Color.white.opacity(0.92))
            }
            .buttonStyle(.plain)
            .focusable(false)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(isHovered ? 0.5 : 0.3))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(DesignTokens.cardBorder, lineWidth: 0.8)
        )
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
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(isDestructive ? .red : DesignTokens.textSecondary)
                    .frame(width: 16)
                Text(title)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(isDestructive ? .red : .primary)
                Spacer()
                Text(shortcut)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(DesignTokens.textTertiary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(isHovered ? (isDestructive ? Color.red.opacity(0.15) : Color(nsColor: .controlBackgroundColor).opacity(0.6)) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { isHovered = $0 }
    }
}
