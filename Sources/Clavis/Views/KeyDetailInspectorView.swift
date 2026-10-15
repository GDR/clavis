import SwiftUI
import ClavisCore

public extension SSHKeyInfo {
    var shortFingerprint: String {
        if fingerprint.count <= 16 {
            return fingerprint
        }
        return String(fingerprint.prefix(16))
    }
}

public struct KeyDetailInspectorView: View {
    public let key: SSHKeyInfo
    @ObservedObject var appState: AppState
    public let onDelete: () -> Void

    @State private var copyFeedback: String? = nil
    @State private var showingDeleteAlert: Bool = false
    @State private var showingChangeKindAlert: Bool = false
    @State private var changeKindError: String? = nil
    @State private var showingChangeKindError: Bool = false

    public init(key: SSHKeyInfo, appState: AppState, onDelete: @escaping () -> Void) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
    }

    private var currentAgentPolicy: AgentKeyPolicy? {
        appState.getAgentPolicy(fingerprint: key.fingerprint)
    }

    private var activeGitGraceSession: (remainingSeconds: Int, remainingOperations: Int, formattedTime: String)? {
        if let grace = appState.activeGitGraces.first(where: { $0.keyLabel == key.label }) {
            return (grace.remainingSeconds, grace.remainingOperations, grace.formattedRemainingTime)
        }
        if let grace = appState.activeGitGrace, grace.keyLabel == key.label {
            return (grace.remainingSeconds, grace.remainingOperations, grace.formattedRemainingTime)
        }
        if let grant = GitSigningGraceManager.shared.getValidGrant(for: key.label) {
            let mins = grant.remainingSeconds / 60
            let secs = grant.remainingSeconds % 60
            let timeStr = String(format: "%d:%02d", mins, secs)
            return (grant.remainingSeconds, grant.remainingOperations, timeStr)
        }
        return nil
    }

    private var securityBadgeText: String {
        Self.securityBadgeText(
            for: key,
            agentPolicy: currentAgentPolicy,
            hasActiveGitGrace: activeGitGraceSession != nil
        )
    }

    private var securitySubtitle: String {
        Self.dynamicSecuritySubtitle(
            for: key,
            agentPolicy: currentAgentPolicy,
            hasActiveGitGrace: activeGitGraceSession != nil
        )
    }

    private var securityPosture: (title: String, description: String) {
        Self.securityPostureInfo(
            for: key,
            agentPolicy: currentAgentPolicy,
            hasActiveGitGrace: activeGitGraceSession != nil
        )
    }

    private var socketInfo: (name: String, socketPath: String, status: String, isActive: Bool) {
        Self.socketStatusInfo(for: key, isSocketActive: appState.isSocketActive)
    }

    private var badgeIcon: String {
        switch key.purpose {
        case .agent:
            switch currentAgentPolicy?.mode ?? .none {
            case .none:
                return "bolt.shield.fill"
            case .notify:
                return "bell.badge.fill"
            case .ask:
                return "hand.raised.fill"
            }
        case .gitSigningOnly:
            return "arrow.triangle.branch"
        case .general:
            return "hand.raised.fill"
        }
    }

    private var badgeColor: Color {
        switch key.purpose {
        case .agent:
            return DesignTokens.accentPurple
        case .gitSigningOnly:
            return DesignTokens.accentBlue
        case .general:
            return DesignTokens.accentGreen
        }
    }

    private var postureIcon: String {
        switch key.purpose {
        case .agent:
            return "cpu"
        case .gitSigningOnly:
            return "arrow.triangle.branch"
        case .general:
            return key.biometricPolicy == .biometryCurrentSet ? "touchid" : "lock.shield.fill"
        }
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
                                Text(securitySubtitle)
                                    .font(.caption)
                                    .foregroundColor(DesignTokens.accentGreen)
                            }
                        }
                        .padding(.top, 2)
                    }

                    Spacer()

                    if key.isHardware {
                        HStack(spacing: 4) {
                            Image(systemName: badgeIcon)
                                .font(.system(size: 10))
                            Text(securityBadgeText)
                                .font(.system(size: 11, weight: .medium))
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(badgeColor.opacity(0.12))
                        .foregroundColor(badgeColor)
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
                        if key.purpose == .general || key.purpose == .agent {
                            Divider()
                            Button(action: {
                                showingChangeKindAlert = true
                            }) {
                                Label(ClavisUIStrings.Inspector.changeKind, systemImage: "arrow.triangle.2.circlepath")
                            }
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
                    .accessibilityLabel(ClavisUIStrings.Accessibility.moreActions)
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
                            } else {
                                Button(ClavisUIStrings.Inspector.copySSHKeyButton, action: copyOpenSSH)
                                    .buttonStyle(.borderedProminent)
                                    .tint(DesignTokens.accentBlue)
                                    .controlSize(.small)
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
                            .accessibilityLabel(ClavisUIStrings.Accessibility.copyFingerprint)
                            .help(ClavisUIStrings.Inspector.copyFingerprintHelp)
                        }
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                // Active Git Signing Grace Session (#94 UI)
                if let gitGrace = activeGitGraceSession {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("ACTIVE GIT SIGNING SESSION")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(DesignTokens.textTertiary)
                            Spacer()
                        }

                        HStack(alignment: .center, spacing: 12) {
                            Image(systemName: "arrow.triangle.branch")
                                .font(.system(size: 20))
                                .foregroundColor(DesignTokens.accentBlue)

                            VStack(alignment: .leading, spacing: 3) {
                                Text(ClavisUIStrings.MenuBar.gitSessionTitle(label: key.label))
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(.primary)

                                Text(ClavisUIStrings.MenuBar.gitSessionDetails(timeRemaining: gitGrace.formattedTime, opsLeft: gitGrace.remainingOperations))
                                    .font(.caption)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }

                            Spacer()

                            Button(action: {
                                appState.revokeGitGrace(keyLabel: key.label)
                            }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "xmark.circle")
                                    Text("Revoke")
                                }
                                .font(.caption)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.red.opacity(0.85))
                            .controlSize(.small)
                        }
                        .padding(14)
                        .glassCard(cornerRadius: 10)
                    }
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
                            name: socketInfo.name,
                            detail: socketInfo.socketPath,
                            status: socketInfo.status,
                            isActive: socketInfo.isActive
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
                            if key.purpose == .general || key.purpose == .agent {
                                Button(action: {
                                    showingChangeKindAlert = true
                                }) {
                                    Text(ClavisUIStrings.Inspector.changeKind)
                                        .font(.caption2)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.mini)
                            }
                        }
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }

                if key.purpose == .agent {
                    AgentPolicyView(key: key, appState: appState)
                }

                if key.isHardware {
                    let posture = securityPosture
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 12) {
                            Image(systemName: postureIcon)
                                .font(.system(size: 20))
                                .foregroundColor(DesignTokens.accentGreen)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(posture.title)
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(.primary)
                                Text(posture.description)
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

                // Danger Zone (#102: Separate Delete from Copy Public Key, isolated at bottom)
                VStack(alignment: .leading, spacing: 8) {
                    Text(ClavisUIStrings.Inspector.deleteKey.uppercased())
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(DesignTokens.textTertiary)

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ClavisUIStrings.Inspector.deleteKey)
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundColor(.red)
                            Text("Permanently remove '\(key.label)' (\(key.shortFingerprint)) from the Secure Enclave.")
                                .font(.caption)
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        Spacer()
                        Button(role: .destructive, action: {
                            ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: displaying delete confirmation alert for '\(key.label)'")
                            showingDeleteAlert = true
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "trash")
                                Text(ClavisUIStrings.Inspector.deleteKey)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                        .controlSize(.small)
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)
                }
                .padding(.top, 8)
            }
            .padding(24)
        }
        .background(Color.clear)
        .alert(Self.deleteConfirmationTitle(label: key.label), isPresented: $showingDeleteAlert) {
            Button(ClavisUIStrings.Common.delete, role: .destructive) {
                ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: user confirmed deletion of key '\(key.label)'")
                onDelete()
            }
            Button(ClavisUIStrings.Common.cancel, role: .cancel) {
                ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: user cancelled deletion of key '\(key.label)'")
            }
        } message: {
            Text(Self.deleteConfirmationMessage(label: key.label, shortFingerprint: key.shortFingerprint))
        }
        .alert(ClavisUIStrings.Inspector.changeKind, isPresented: $showingChangeKindAlert) {
            let target = (key.purpose == .agent) ? KeyPurpose.general : KeyPurpose.agent
            Button(ClavisUIStrings.KeyDetail.changeKindConfirm) {
                do {
                    try appState.changeKeyKind(label: key.label, to: target)
                    showFeedback(target == .agent ? "Changed purpose to Agent" : "Changed purpose to General")
                } catch {
                    changeKindError = error.localizedDescription
                    showingChangeKindError = true
                }
            }
            Button(ClavisUIStrings.Common.cancel, role: .cancel) {}
        } message: {
            let target = (key.purpose == .agent) ? KeyPurpose.general : KeyPurpose.agent
            Text(ClavisUIStrings.KeyDetail.changeKindAlertMessage(label: key.label, newPurpose: target))
        }
        .alert(ClavisUIStrings.Common.error, isPresented: $showingChangeKindError) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text(changeKindError ?? "")
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

// MARK: - Dynamic Security Posture & Alert Helpers

public extension KeyDetailInspectorView {
    static func deleteConfirmationTitle(label: String) -> String {
        "\(ClavisUIStrings.Inspector.deleteAlertTitle) (\(label))"
    }

    static func deleteConfirmationMessage(label: String, shortFingerprint: String) -> String {
        let base = ClavisUIStrings.Inspector.deleteAlertMessage(label: label)
        if base.contains("'\(label)'") {
            return base.replacingOccurrences(of: "'\(label)'", with: "'\(label)' (\(shortFingerprint))")
        } else if base.contains("«\(label)»") {
            return base.replacingOccurrences(of: "«\(label)»", with: "«\(label)» (\(shortFingerprint))")
        } else if base.contains(label) {
            return base.replacingOccurrences(of: label, with: "\(label) (\(shortFingerprint))")
        } else {
            return "Are you sure you want to delete '\(label)' (\(shortFingerprint))? This action cannot be undone."
        }
    }

    static func securityBadgeText(
        for key: SSHKeyInfo,
        agentPolicy: AgentKeyPolicy? = nil,
        hasActiveGitGrace: Bool = false
    ) -> String {
        switch key.purpose {
        case .agent:
            switch agentPolicy?.mode ?? .none {
            case .none:
                return "Silent"
            case .notify:
                return "Notify"
            case .ask:
                return ClavisUIStrings.Inspector.alwaysPromptBadge
            }
        case .gitSigningOnly:
            if hasActiveGitGrace {
                return "Grace Active"
            }
            return "Git Only"
        case .general:
            if hasActiveGitGrace {
                return "Grace Active"
            }
            return ClavisUIStrings.Inspector.alwaysPromptBadge
        }
    }

    static func dynamicSecuritySubtitle(
        for key: SSHKeyInfo,
        agentPolicy: AgentKeyPolicy? = nil,
        hasActiveGitGrace: Bool = false
    ) -> String {
        if hasActiveGitGrace {
            return "Hardware Isolated · Git signing grace active"
        }
        switch key.purpose {
        case .agent:
            switch agentPolicy?.mode ?? .none {
            case .none:
                return "Hardware Isolated · Silent agent lease"
            case .notify:
                return "Hardware Isolated · Agent lease with notification"
            case .ask:
                return "Hardware Isolated · Touch ID prompt per agent signature"
            }
        case .gitSigningOnly:
            return "Hardware Isolated · Git commit signing only"
        case .general:
            return ClavisUIStrings.Inspector.hardwareIsolated
        }
    }

    static func securityPostureInfo(
        for key: SSHKeyInfo,
        agentPolicy: AgentKeyPolicy? = nil,
        hasActiveGitGrace: Bool = false
    ) -> (title: String, description: String) {
        switch key.purpose {
        case .agent:
            let leaseMins = agentPolicy?.leaseMinutes ?? 480
            let leaseHours = leaseMins / 60
            let leaseStr = (leaseHours > 0 && leaseMins % 60 == 0) ? "\(leaseHours)h" : "\(leaseMins)m"
            let mode = agentPolicy?.mode ?? .none
            let title = "Hardware Isolation (Agent Policy)"
            let desc: String
            switch mode {
            case .none:
                desc = "Agent sessions operate silently without prompts for up to \(leaseStr) once authorized. Private key material remains hardware-bound in the Apple Secure Enclave."
            case .notify:
                desc = "Agent sessions post a notification on each signature without prompting for up to \(leaseStr). Private key material remains hardware-bound in the Apple Secure Enclave."
            case .ask:
                desc = "Every agent signature requires explicit Touch ID user confirmation. Private key material remains hardware-bound in the Apple Secure Enclave."
            }
            return (title, desc)

        case .gitSigningOnly:
            let title = "Hardware Isolation (Git Signing Only)"
            var desc = "Restricted strictly to local Git commit and tag signing. Forwarded agent requests are blocked. Every signature requires Touch ID per operation (optional 5-minute process-scoped Git signing grace window)."
            if hasActiveGitGrace {
                desc += " A 5-minute Git signing grace session is currently active for this key."
            }
            return (title, desc)

        case .general:
            let title = key.biometricPolicy == .biometryCurrentSet
                ? ClavisUIStrings.Inspector.hardwareIsolationStrictTitle
                : ClavisUIStrings.Inspector.hardwareIsolationPresenceTitle
            var desc: String
            if key.biometricPolicy == .biometryCurrentSet {
                desc = "Secure Enclave strictly requires Touch ID matching current biometric enrollment. Every signature requires explicit Touch ID per operation (optional 5-minute process-scoped Git signing grace window). Device password fallback is disabled."
            } else {
                desc = "Signatures require Touch ID user presence per operation (optional 5-minute process-scoped Git signing grace window). Keys cannot be cached in general session memory."
            }
            if hasActiveGitGrace {
                desc += " A 5-minute Git signing grace session is currently active for this key."
            }
            return (title, desc)
        }
    }

    static func socketStatusInfo(
        for key: SSHKeyInfo,
        isSocketActive: Bool
    ) -> (name: String, socketPath: String, status: String, isActive: Bool) {
        let name: String
        let path: String
        switch key.purpose {
        case .agent:
            name = "agent socket"
            path = "~/.ssh/clavis-agent.sock"
        case .general, .gitSigningOnly:
            name = "ssh-agent socket"
            path = "~/.ssh/clavis.sock"
        }
        let status = isSocketActive ? ClavisUIStrings.Inspector.statusActive : ClavisUIStrings.Inspector.statusOffline
        return (name: name, socketPath: path, status: status, isActive: isSocketActive)
    }
}

