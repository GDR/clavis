import SwiftUI
import ClavisCore

public struct SettingsSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var appState: AppState

    @State private var copiedEnv = false

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Settings")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("Configure agent startup, biometric session cache, and SSH integration.")
                        .font(.subheadline)
                        .foregroundColor(DesignTokens.textSecondary)
                }
                Spacer()
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 28))
                    .foregroundColor(DesignTokens.textSecondary.opacity(0.4))
            }

            Divider().background(DesignTokens.cardBorder)

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // System Startup Section
                    VStack(alignment: .leading, spacing: 10) {
                        Text("SYSTEM STARTUP")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(DesignTokens.textTertiary)

                        VStack(alignment: .leading, spacing: 12) {
                            HStack(alignment: .center) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("Launch at Login (Auto Start)")
                                        .font(.system(size: 13, weight: .medium))
                                    Text("Automatically start Clavis daemon on user login so SSH & age are always ready.")
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                }
                                Spacer()
                                Toggle("", isOn: Binding(
                                    get: { appState.launchAtLogin },
                                    set: { appState.setLaunchAtLogin($0) }
                                ))
                                .toggleStyle(.switch)
                                .tint(DesignTokens.accentBlue)
                            }
                        }
                        .padding(14)
                        .glassCard(cornerRadius: 10)
                    }

                    // Security & Session Timeout Section
                    VStack(alignment: .leading, spacing: 10) {
                        Text("SECURITY & BIOMETRIC CACHE")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(DesignTokens.textTertiary)

                        VStack(alignment: .leading, spacing: 14) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Session Timeout")
                                    .font(.system(size: 13, weight: .medium))
                                Text("How long keys remain unlocked in memory before requiring Touch ID again.")
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)

                                Picker("", selection: Binding(
                                    get: { appState.selectedTimeout },
                                    set: { appState.setTimeout($0) }
                                )) {
                                    ForEach(SessionTimeout.allCases) { timeout in
                                        Text(timeout.rawValue).tag(timeout)
                                    }
                                }
                                .pickerStyle(.segmented)
                                .padding(.top, 4)
                            }

                            Divider().background(DesignTokens.cardBorder)

                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Lock Screen & Sleep Auto-Lock")
                                        .font(.system(size: 12, weight: .medium))
                                    Text("Keys are purged from memory immediately when macOS locks or sleeps.")
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                }
                                Spacer()
                                Image(systemName: "checkmark.shield.fill")
                                    .foregroundColor(DesignTokens.accentGreen)
                                    .font(.title3)
                            }

                            Divider().background(DesignTokens.cardBorder)

                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Active Cache Status")
                                        .font(.system(size: 12, weight: .medium))
                                    Text("\(appState.cachedKeysCount) key(s) currently unlocked in memory")
                                        .font(.caption2)
                                        .foregroundColor(appState.cachedKeysCount > 0 ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                                }
                                Spacer()
                                Button("Lock All Now") {
                                    appState.lockNow()
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .disabled(appState.cachedKeysCount == 0)
                            }
                        }
                        .padding(14)
                        .glassCard(cornerRadius: 10)
                    }

                    // Shell Environment Section
                    VStack(alignment: .leading, spacing: 10) {
                        Text("SHELL ENVIRONMENT & NIX")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(DesignTokens.textTertiary)

                        VStack(alignment: .leading, spacing: 10) {
                            Text("To use Clavis as your system-wide SSH agent in terminal:")
                                .font(.caption2)
                                .foregroundColor(DesignTokens.textSecondary)

                            HStack {
                                Text("export SSH_AUTH_SOCK=~/.ssh/clavis.sock")
                                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                                    .foregroundColor(.primary)
                                    .lineLimit(1)
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
                                    .font(.caption)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                            .padding(10)
                            .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
                            .cornerRadius(6)
                        }
                        .padding(14)
                        .glassCard(cornerRadius: 10)
                    }
                }
            }

            Divider().background(DesignTokens.cardBorder)

            // Footer
            HStack {
                Spacer()
                Button("Done") {
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignTokens.accentBlue)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 540, height: 600)
    }
}
