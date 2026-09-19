import SwiftUI
import ClavisCore

public struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var copiedEnv = false

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // System Startup Section
                SettingsGroup(title: "SYSTEM STARTUP") {
                    SettingsRow(
                        icon: "power",
                        iconColor: Color(red: 0.0, green: 0.48, blue: 1.0),
                        title: "Launch at Login",
                        subtitle: "Automatically start Clavis daemon on user login"
                    ) {
                        Toggle("", isOn: Binding(
                            get: { appState.launchAtLogin },
                            set: { appState.setLaunchAtLogin($0) }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                    }
                }

                // Security & Session Timeout Section
                SettingsGroup(title: "SECURITY & CACHE") {
                    SettingsRow(
                        icon: "timer",
                        iconColor: Color(red: 1.0, green: 0.58, blue: 0.0),
                        title: "Session Timeout",
                        subtitle: "Require Touch ID authentication after inactivity"
                    ) {
                        Picker("", selection: Binding(
                            get: { appState.selectedTimeout },
                            set: { appState.setTimeout($0) }
                        )) {
                            ForEach(SessionTimeout.allCases) { timeout in
                                Text(timeout.rawValue).tag(timeout)
                            }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                        .frame(width: 150)
                    }

                    Divider()

                    SettingsRow(
                        icon: "lock.shield.fill",
                        iconColor: Color(red: 0.20, green: 0.78, blue: 0.35),
                        title: "Auto-Lock on Sleep",
                        subtitle: "Keys are purged from memory when macOS locks or sleeps"
                    ) {
                        Text("Active")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(DesignTokens.accentGreen)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(DesignTokens.accentGreen.opacity(0.12))
                            .clipShape(Capsule())
                    }

                    Divider()

                    SettingsRow(
                        icon: "key.fill",
                        iconColor: Color(red: 0.68, green: 0.32, blue: 0.88),
                        title: "Active Cache Status",
                        subtitle: "\(appState.cachedKeysCount) key(s) currently unlocked in memory"
                    ) {
                        Button("Lock All") {
                            appState.lockNow()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .disabled(appState.cachedKeysCount == 0)
                    }
                }

                // SSH Integration Section
                SettingsGroup(title: "SSH INTEGRATION") {
                    VStack(alignment: .leading, spacing: 10) {
                        SettingsRow(
                            icon: "terminal.fill",
                            iconColor: Color(red: 0.55, green: 0.58, blue: 0.62),
                            title: "Agent Socket",
                            subtitle: "~/.ssh/clavis.sock"
                        ) {
                            EmptyView()
                        }

                        Divider()

                        VStack(alignment: .leading, spacing: 6) {
                            Text("Terminal Environment Variable")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.secondary)

                            HStack(spacing: 8) {
                                Text("export SSH_AUTH_SOCK=~/.ssh/clavis.sock")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.primary)
                                    .lineLimit(1)
                                    .textSelection(.enabled)

                                Spacer()

                                Button(action: {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString("export SSH_AUTH_SOCK=~/.ssh/clavis.sock", forType: .string)
                                    copiedEnv = true
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                        copiedEnv = false
                                    }
                                }) {
                                    HStack(spacing: 4) {
                                        Image(systemName: copiedEnv ? "checkmark" : "doc.on.doc")
                                        Text(copiedEnv ? "Copied" : "Copy")
                                    }
                                    .font(.system(size: 11, weight: .medium))
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(Color(nsColor: .controlBackgroundColor).opacity(0.5))
                            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        }
                        .padding(.top, 2)
                    }
                }
            }
            .padding(20)
        }
        .frame(width: 480, height: 460)
    }
}

// Backward-compatible wrapper for any sheet callers
public struct SettingsSheet: View {
    @ObservedObject var appState: AppState

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        SettingsView()
            .environmentObject(appState)
    }
}

private struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
                .padding(.horizontal, 4)

            VStack(spacing: 0) {
                content()
            }
            .padding(12)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(Color.white.opacity(0.08), lineWidth: 0.8)
            )
        }
    }
}

private struct SettingsRow<Trailing: View>: View {
    let icon: String
    let iconColor: Color
    let title: String
    let subtitle: String
    @ViewBuilder let trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(iconColor)
                    .frame(width: 28, height: 28)
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.white)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.primary)
                Text(subtitle)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            trailing()
        }
        .padding(.vertical, 4)
    }
}
