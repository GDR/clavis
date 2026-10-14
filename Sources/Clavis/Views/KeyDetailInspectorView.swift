import SwiftUI
import ClavisCore

public struct KeyDetailInspectorView: View {
    public let key: SSHKeyInfo
    @ObservedObject var appState: AppState
    public let onDelete: () -> Void

    @State private var copyFeedback: String? = nil
    @State private var showingDeleteAlert: Bool = false

    public init(key: SSHKeyInfo, appState: AppState, onDelete: @escaping () -> Void) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
    }

    private var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: key.createdAt)
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Inspector Header
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 28))
                        .foregroundColor(DesignTokens.accentBlue)
                        .frame(width: 44, height: 44)
                        .background(DesignTokens.accentBlue.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 10))

                    VStack(alignment: .leading, spacing: 3) {
                        Text(key.label)
                            .font(.title2)
                            .fontWeight(.bold)
                            .foregroundColor(.primary)

                        Text(ClavisUIStrings.Inspector.keySubtitle(algorithm: key.algorithm, isHardware: key.isHardware))
                            .font(.subheadline)
                            .foregroundColor(DesignTokens.textSecondary)

                        HStack(spacing: 6) {
                            if key.isHardware {
                                Image(systemName: "lock.shield.fill")
                                    .font(.system(size: 11))
                                    .foregroundColor(DesignTokens.accentGreen)
                                Text(ClavisUIStrings.Inspector.hardwareIsolated)
                                    .font(.caption)
                                    .foregroundColor(DesignTokens.accentGreen)
                            }
                        }
                        .padding(.top, 2)
                    }

                    Spacer()

                    if key.isHardware {
                        HStack(spacing: 4) {
                            Image(systemName: "hand.raised.fill")
                                .font(.system(size: 10))
                            Text(ClavisUIStrings.Inspector.alwaysPromptBadge)
                                .font(.system(size: 11, weight: .medium))
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(DesignTokens.accentGreen.opacity(0.12))
                        .foregroundColor(DesignTokens.accentGreen)
                        .clipShape(Capsule())
                    }

                    Button(action: {
                        WindowManager.shared.openHistory(keyFingerprint: key.fingerprint)
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "clock.arrow.circlepath")
                            Text(ClavisUIStrings.History.showHistory)
                        }
                        .font(.caption)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.bordered)
                    .focusable(false)

                    // Context Menu
                    Menu {
                        if key.purpose == .agent {
                            Button(action: copyDeployKey) {
                                Label(ClavisUIStrings.KeyDetail.copyDeployKey, systemImage: "key.fill")
                            }
                        }
                        Button(action: copyOpenSSH) {
                            Label(ClavisUIStrings.Inspector.copyOpenSSHKeyMenu, systemImage: "terminal")
                        }
                        Button(action: copyFingerprint) {
                            Label(ClavisUIStrings.Inspector.copyFingerprintMenu, systemImage: "number")
                        }
                        Divider()
                        Button(action: {
                            WindowManager.shared.openHistory(keyFingerprint: key.fingerprint)
                        }) {
                            Label(ClavisUIStrings.History.showHistory, systemImage: "clock.arrow.circlepath")
                        }
                        Divider()
                        Button(role: .destructive, action: {
                            ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: displaying delete confirmation alert for '\(key.label)'")
                            showingDeleteAlert = true
                        }) {
                            Label(ClavisUIStrings.Inspector.deleteKeyMenu, systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis")
                            .frame(width: 28, height: 28)
                    }
                    .menuStyle(.borderlessButton)
                    .focusable(false)
                    .frame(width: 32)
                }
                .padding(.bottom, 4)

                // Copy notification banner if any
                if let feedback = copyFeedback {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(DesignTokens.accentGreen)
                        Text(feedback)
                            .font(.caption)
                            .foregroundColor(DesignTokens.accentGreen)
                        Spacer()
                    }
                    .padding(8)
                    .background(DesignTokens.accentGreen.opacity(0.12))
                    .cornerRadius(6)
                    .transition(.opacity)
                }

                // Public Identity Section
                VStack(alignment: .leading, spacing: 8) {
                    Text(ClavisUIStrings.Inspector.publicIdentitySection)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    VStack(alignment: .leading, spacing: 12) {
                        // OpenSSH Key (Primary for GitHub / servers)
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(ClavisUIStrings.Inspector.openSSHPublicKey)
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.primary)
                                Text(key.publicKeyOpenSSH)
                                    .font(.system(size: 11, design: .monospaced))
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .textSelection(.enabled)
                                Text(ClavisUIStrings.Inspector.openSSHDescription)
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            Spacer()
                            if key.purpose == .agent {
                                Button(ClavisUIStrings.KeyDetail.copyDeployKey, action: copyDeployKey)
                                    .buttonStyle(.borderedProminent)
                                    .tint(DesignTokens.accentPurple)
                                    .controlSize(.small)
                                    .focusable(false)
                            } else {
                                Button(ClavisUIStrings.Inspector.copySSHKeyButton, action: copyOpenSSH)
                                    .buttonStyle(.borderedProminent)
                                    .tint(DesignTokens.accentBlue)
                                    .controlSize(.small)
                                    .focusable(false)
                            }
                        }

                        Divider().background(DesignTokens.cardBorder)

                        // SHA-256 Fingerprint (Verification only)
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 4) {
                                    Text(ClavisUIStrings.Inspector.fingerprint)
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                    Text(ClavisUIStrings.Inspector.fingerprintVerificationHint)
                                        .font(.system(size: 10))
                                        .foregroundColor(DesignTokens.textTertiary)
                                }
                                Text(key.fingerprint)
                                    .font(.system(size: 11, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            Spacer()
                            Button(action: copyFingerprint) {
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.borderless)
                            .focusable(false)
                            .help(ClavisUIStrings.Inspector.copyFingerprintHelp)
                        }
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Used By / Integrations
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(ClavisUIStrings.Inspector.usedBySection)
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(DesignTokens.textTertiary)
                        Spacer()
                    }

                    VStack(spacing: 8) {
                        IntegrationRow(
                            name: "ssh-agent socket",
                            detail: "~/.ssh/clavis.sock",
                            status: appState.isSocketActive ? ClavisUIStrings.Inspector.statusActive : ClavisUIStrings.Inspector.statusOffline,
                            isActive: appState.isSocketActive
                        )
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Security Inspector
                VStack(alignment: .leading, spacing: 8) {
                    Text(ClavisUIStrings.Inspector.securitySection)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    VStack(spacing: 8) {
                        SecurityPropertyRow(
                            label: ClavisUIStrings.Inspector.storageLabel,
                            value: ClavisUIStrings.Inspector.storageHardwareEnclave
                        )
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(
                            label: ClavisUIStrings.Inspector.authenticationLabel,
                            value: key.biometricPolicy == .biometryCurrentSet ? ClavisUIStrings.Inspector.authTouchIdOnlyStrict : ClavisUIStrings.Inspector.authUserPresence
                        )
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(label: ClavisUIStrings.Inspector.created, value: formattedDate)
                        Divider().background(DesignTokens.cardBorder)
                        HStack {
                            Text(ClavisUIStrings.Inspector.keyPurpose)
                                .font(.caption)
                                .foregroundColor(DesignTokens.textSecondary)
                            Spacer()
                            Text(key.purpose.title)
                                .font(.caption)
                                .fontWeight(.medium)
                        }
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                if key.purpose == .agent {
                    AgentPolicyView(key: key, appState: appState)
                }

                if key.isHardware {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 12) {
                            Image(systemName: key.biometricPolicy == .biometryCurrentSet ? "touchid" : "lock.shield.fill")
                                .font(.system(size: 20))
                                .foregroundColor(DesignTokens.accentGreen)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(key.biometricPolicy == .biometryCurrentSet ? ClavisUIStrings.Inspector.hardwareIsolationStrictTitle : ClavisUIStrings.Inspector.hardwareIsolationPresenceTitle)
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(.primary)
                                Text(key.biometricPolicy == .biometryCurrentSet ? ClavisUIStrings.Inspector.hardwareIsolationStrictDesc : ClavisUIStrings.Inspector.hardwareIsolationPresenceDesc)
                                    .font(.caption)
                                    .foregroundColor(DesignTokens.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                        }
                        .padding(14)
                        .glassCard(cornerRadius: 10)
                    }
                }
            }
            .padding(24)
        }
        .background(Color.clear)
        .alert(ClavisUIStrings.Inspector.deleteAlertTitle, isPresented: $showingDeleteAlert) {
            Button(ClavisUIStrings.Common.delete, role: .destructive) {
                ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: user confirmed deletion of key '\(key.label)'")
                onDelete()
            }
            Button(ClavisUIStrings.Common.cancel, role: .cancel) {
                ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: user cancelled deletion of key '\(key.label)'")
            }
        } message: {
            Text(ClavisUIStrings.Inspector.deleteAlertMessage(label: key.label))
        }
    }

    private func copyDeployKey() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
        showFeedback(ClavisUIStrings.Inspector.feedbackCopiedOpenSSH)
    }

    private func copyFingerprint() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.fingerprint, forType: .string)
        showFeedback(ClavisUIStrings.Inspector.feedbackCopiedFingerprint)
    }

    private func copyOpenSSH() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
        showFeedback(ClavisUIStrings.Inspector.feedbackCopiedOpenSSH)
    }

    private func showFeedback(_ text: String) {
        withAnimation {
            copyFeedback = text
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            withAnimation {
                if copyFeedback == text {
                    copyFeedback = nil
                }
            }
        }
    }
}

private struct IntegrationRow: View {
    let name: String
    let detail: String
    let status: String
    let isActive: Bool

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(detail)
                    .font(.caption2)
                    .foregroundColor(DesignTokens.textSecondary)
            }
            Spacer()
            HStack(spacing: 5) {
                StatusDot(isActive: isActive)
                Text(status)
                    .font(.caption)
                    .foregroundColor(isActive ? DesignTokens.accentGreen : DesignTokens.textSecondary)
            }
        }
    }
}

private struct SecurityPropertyRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(DesignTokens.textSecondary)
            Spacer()
            Text(value)
                .font(.caption)
                .fontWeight(.medium)
        }
    }
}
