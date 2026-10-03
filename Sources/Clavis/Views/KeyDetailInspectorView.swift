import SwiftUI
import ClavisCore

public struct KeyDetailInspectorView: View {
    public let key: Ed25519KeyInfo
    @ObservedObject var appState: AppState
    public let onDelete: () -> Void

    @State private var copyFeedback: String? = nil
    @State private var showingDeleteAlert: Bool = false

    public init(key: Ed25519KeyInfo, appState: AppState, onDelete: @escaping () -> Void) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
    }

    private var isUnlocked: Bool {
        appState.isKeyUnlocked(label: key.label)
    }

    private var unlockStatusText: String {
        if isUnlocked {
            if let remaining = appState.remainingTimeFormatted(label: key.label) {
                return ClavisUIStrings.Inspector.unlockedWithTime(remaining)
            }
            return ClavisUIStrings.Inspector.unlockedActive
        }
        return ClavisUIStrings.Inspector.lockedTouchIdRequired
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
                            } else {
                                StatusDot(isActive: isUnlocked)
                                Text(unlockStatusText)
                                    .font(.caption)
                                    .foregroundColor(isUnlocked ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                            }
                        }
                        .padding(.top, 2)
                    }

                    Spacer()

                    // Lock revokes agent grants and clears any local cache. There is no unlock action.
                    if !key.isHardware {
                        Button(action: lockSelectedKey) {
                            HStack(spacing: 4) {
                                Image(systemName: "lock.fill")
                                Text(ClavisUIStrings.Inspector.lock)
                            }
                            .font(.caption)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                        }
                        .buttonStyle(.bordered)
                        .focusable(false)
                    } else {
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

                    // Context Menu
                    Menu {
                        if key.isAgeCompatible {
                            Button(action: copyRecipient) {
                                Label(ClavisUIStrings.Inspector.copyAgeRecipientMenu, systemImage: "doc.on.doc")
                            }
                        }
                        Button(action: copyOpenSSH) {
                            Label(ClavisUIStrings.Inspector.copyOpenSSHKeyMenu, systemImage: "terminal")
                        }
                        Button(action: copyFingerprint) {
                            Label(ClavisUIStrings.Inspector.copyFingerprintMenu, systemImage: "number")
                        }
                        Divider()
                        Button(role: .destructive, action: { showingDeleteAlert = true }) {
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
                        if key.isAgeCompatible {
                            // age Recipient
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(key.ageRecipient)
                                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                        .textSelection(.enabled)
                                    Text(ClavisUIStrings.Inspector.ageRecipientDescription)
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                }
                                Spacer()
                                Button(ClavisUIStrings.Inspector.copyRecipientButton, action: copyRecipient)
                                    .buttonStyle(.borderedProminent)
                                    .tint(DesignTokens.accentBlue)
                                    .controlSize(.small)
                                    .focusable(false)
                            }

                            Divider().background(DesignTokens.cardBorder)
                        } else {
                            HStack(spacing: 8) {
                                Image(systemName: "info.circle")
                                    .foregroundColor(DesignTokens.textTertiary)
                                Text(key.isHardware ? ClavisUIStrings.Inspector.hardwareAgeIncompatible : ClavisUIStrings.Inspector.algorithmAgeIncompatible(key.algorithm))
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.white.opacity(0.04))
                            .cornerRadius(6)

                            Divider().background(DesignTokens.cardBorder)
                        }

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
                            Button(ClavisUIStrings.Inspector.copySSHKeyButton, action: copyOpenSSH)
                                .buttonStyle(.borderedProminent)
                                .tint(DesignTokens.accentBlue)
                                .controlSize(.small)
                                .focusable(false)
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
                            name: "age-plugin-clavis",
                            detail: key.isAgeCompatible ? ClavisUIStrings.Inspector.agePluginRegistered : ClavisUIStrings.Inspector.agePluginIncompatible(key.algorithm),
                            status: key.isAgeCompatible ? ClavisUIStrings.Inspector.statusReady : ClavisUIStrings.Inspector.statusUnsupported,
                            isActive: key.isAgeCompatible
                        )
                        Divider().background(DesignTokens.cardBorder)
                        IntegrationRow(
                            name: "agenix",
                            detail: key.isAgeCompatible ? ClavisUIStrings.Inspector.agenixWorkflow : (key.isHardware ? ClavisUIStrings.Inspector.agenixHardwareIncompatible : ClavisUIStrings.Inspector.agenixAlgorithmIncompatible(key.algorithm)),
                            status: key.isAgeCompatible ? ClavisUIStrings.Inspector.statusConfigured : ClavisUIStrings.Inspector.statusIncompatible,
                            isActive: key.isAgeCompatible
                        )
                        Divider().background(DesignTokens.cardBorder)
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
                            value: key.isHardware ? ClavisUIStrings.Inspector.storageHardwareEnclave : ClavisUIStrings.Inspector.storageSoftwareKeychain
                        )
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(
                            label: ClavisUIStrings.Inspector.sessionCacheLabel,
                            value: key.isHardware ? ClavisUIStrings.Inspector.sessionCacheHardwarePrompt : (appState.selectedTimeout == .never ? ClavisUIStrings.Inspector.sessionCacheAlwaysPrompt : ClavisUIStrings.Inspector.sessionCacheActiveTimeout(appState.selectedTimeout.localizedTitle))
                        )
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(
                            label: ClavisUIStrings.Inspector.authenticationLabel,
                            value: key.isHardware ? (key.biometricPolicy == .biometryCurrentSet ? ClavisUIStrings.Inspector.authTouchIdOnlyStrict : ClavisUIStrings.Inspector.authUserPresence) : ClavisUIStrings.Inspector.authTouchIdProtectedSeed
                        )
                        Divider().background(DesignTokens.cardBorder)
                        SecurityPropertyRow(label: ClavisUIStrings.Inspector.created, value: formattedDate)
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Session Cache Section
                VStack(alignment: .leading, spacing: 8) {
                    Text(ClavisUIStrings.Inspector.sessionCacheSection)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    if key.isHardware {
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
                    } else {
                        VStack(spacing: 10) {
                            // Timeout Picker Row
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(ClavisUIStrings.Inspector.cacheTimeoutTitle)
                                        .font(.system(size: 13, weight: .semibold))
                                        .foregroundColor(.primary)
                                    Text(ClavisUIStrings.Inspector.cacheTimeoutSubtitle)
                                        .font(.caption)
                                        .foregroundColor(DesignTokens.textSecondary)
                                }
                                Spacer()
                                Picker("", selection: Binding(
                                    get: { appState.selectedTimeout },
                                    set: { appState.setTimeout($0) }
                                )) {
                                    ForEach(SessionTimeout.allCases) { timeout in
                                        Text(timeout.localizedTitle).tag(timeout)
                                    }
                                }
                                .pickerStyle(.menu)
                                .labelsHidden()
                                .frame(width: 160)
                            }

                            Divider().background(DesignTokens.cardBorder)

                            // Memory protection & auto-lock row
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(ClavisUIStrings.Inspector.memoryProtectionTitle)
                                        .font(.system(size: 12, weight: .medium))
                                    Text(ClavisUIStrings.Inspector.memoryProtectionSubtitle)
                                        .font(.caption2)
                                        .foregroundColor(DesignTokens.textSecondary)
                                }
                                Spacer()
                                Text(ClavisUIStrings.Inspector.statusActive)
                                    .font(.caption2)
                                    .fontWeight(.medium)
                                    .foregroundColor(DesignTokens.accentGreen)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 3)
                                    .background(DesignTokens.accentGreen.opacity(0.12))
                                    .clipShape(Capsule())
                            }
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
                onDelete()
            }
            Button(ClavisUIStrings.Common.cancel, role: .cancel) {}
        } message: {
            Text(ClavisUIStrings.Inspector.deleteAlertMessage(label: key.label))
        }
    }

    private func copyRecipient() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.ageRecipient, forType: .string)
        showFeedback(ClavisUIStrings.Inspector.feedbackCopiedRecipient)
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

    private func lockSelectedKey() {
        guard !key.isHardware else { return }
        do {
            try appState.lockKey(label: key.label)
            showFeedback(ClavisUIStrings.Inspector.feedbackLockedKey(key.label))
        } catch {
            appState.errorMessage = error.localizedDescription
        }
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
