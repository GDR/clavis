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
    @State private var showingChangePurposeAlert: Bool = false
    @State private var changePurposeError: String? = nil
    @State private var showingChangePurposeError: Bool = false

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
        Self.postureIcon(for: key)
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
                                showingChangePurposeAlert = true
                            }) {
                                Label(ClavisUIStrings.Inspector.changePurpose, systemImage: "arrow.triangle.2.circlepath")
                            }
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
                                HStack(spacing: 4) {
                                    Image(systemName: "doc.on.doc")
                                    Text(ClavisUIStrings.Common.copy)
                                }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
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
                            Text(ClavisUIStrings.Inspector.activeGitSessionSection)
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
                                    Text(ClavisUIStrings.Inspector.revokeGitSessionButton)
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
                                    showingChangePurposeAlert = true
                                }) {
                                    Text(ClavisUIStrings.Inspector.changePurpose)
                                        .font(.caption2)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.mini)
                            }
                        }
                        Divider().background(DesignTokens.cardBorder)
                        IntegrationRow(
                            name: socketInfo.name,
                            detail: socketInfo.socketPath,
                            status: socketInfo.status,
                            isActive: socketInfo.isActive
                        )
                    }
                    .padding(14)
                    .glassCard(cornerRadius: 10)

                    if key.isHardware {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: postureIcon)
                                .font(.caption)
                                .foregroundColor(DesignTokens.accentGreen)
                            Text(securityPosture.description)
                                .font(.caption)
                                .foregroundColor(DesignTokens.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(.horizontal, 4)
                        .padding(.top, 2)
                    }
                }

                if key.purpose == .agent {
                    AgentPolicyView(key: key, appState: appState)
                }

                // Inspector Footer: Clean Localized Destructive Delete Button (Milestone M5 / R5)
                HStack {
                    Spacer()
                    Button(role: .destructive, action: {
                        ClavisLogger.promptDebug("calvis-ui", "KeyDetailInspectorView: displaying delete confirmation alert for '\(key.label)'")
                        showingDeleteAlert = true
                    }) {
                        HStack(spacing: 5) {
                            Image(systemName: "trash")
                            Text(ClavisUIStrings.Inspector.deleteKey)
                        }
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                    .controlSize(.regular)
                    Spacer()
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
        .alert(ClavisUIStrings.Inspector.changePurpose, isPresented: $showingChangePurposeAlert) {
            let target = (key.purpose == .agent) ? KeyPurpose.general : KeyPurpose.agent
            Button(ClavisUIStrings.KeyDetail.changePurposeConfirm) {
                do {
                    try appState.changeKeyKind(label: key.label, to: target)
                    showFeedback(ClavisUIStrings.Inspector.feedbackChangedPurpose(to: target))
                } catch {
                    changePurposeError = error.localizedDescription
                    showingChangePurposeError = true
                }
            }
            Button(ClavisUIStrings.Common.cancel, role: .cancel) {}
        } message: {
            let target = (key.purpose == .agent) ? KeyPurpose.general : KeyPurpose.agent
            Text(ClavisUIStrings.KeyDetail.changePurposeAlertMessage(label: key.label, newPurpose: target))
        }
        .alert(ClavisUIStrings.Common.error, isPresented: $showingChangePurposeError) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text(changePurposeError ?? "")
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
                    .font(.caption)
                    .foregroundColor(DesignTokens.textSecondary)
                Text(detail)
                    .font(.caption2)
                    .foregroundColor(DesignTokens.textTertiary)
            }
            Spacer()
            HStack(spacing: 5) {
                StatusDot(isActive: isActive)
                Text(status)
                    .font(.caption)
                    .fontWeight(.medium)
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
        ClavisUIStrings.Inspector.deleteAlertMessage(label: label, fingerprint: shortFingerprint)
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
                return ClavisUIStrings.Inspector.badgeSilent
            case .notify:
                return ClavisUIStrings.Inspector.badgeNotify
            case .ask:
                return ClavisUIStrings.Inspector.alwaysPromptBadge
            }
        case .gitSigningOnly:
            if hasActiveGitGrace {
                return ClavisUIStrings.Inspector.badgeGraceActive
            }
            return ClavisUIStrings.Badges.gitOnly
        case .general:
            if hasActiveGitGrace {
                return ClavisUIStrings.Inspector.badgeGraceActive
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
            return ClavisUIStrings.Inspector.subtitleGitGraceActive
        }
        switch key.purpose {
        case .agent:
            switch agentPolicy?.mode ?? .none {
            case .none:
                return ClavisUIStrings.Inspector.subtitleAgentSilent
            case .notify:
                return ClavisUIStrings.Inspector.subtitleAgentNotify
            case .ask:
                return ClavisUIStrings.Inspector.subtitleAgentAsk
            }
        case .gitSigningOnly:
            return ClavisUIStrings.Inspector.subtitleGitSigningOnly
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
            let title = ClavisUIStrings.Inspector.postureAgentTitle
            let desc: String
            switch mode {
            case .none:
                desc = ClavisUIStrings.Inspector.postureAgentSilentDesc(lease: leaseStr)
            case .notify:
                desc = ClavisUIStrings.Inspector.postureAgentNotifyDesc(lease: leaseStr)
            case .ask:
                desc = ClavisUIStrings.Inspector.postureAgentAskDesc
            }
            return (title, desc)

        case .gitSigningOnly:
            let title = ClavisUIStrings.Inspector.postureGitSigningOnlyTitle
            var desc = ClavisUIStrings.Inspector.postureGitSigningOnlyDesc
            if hasActiveGitGrace {
                desc += ClavisUIStrings.Inspector.postureGitGraceActiveSuffix
            }
            return (title, desc)

        case .general:
            let title = key.biometricPolicy == .biometryCurrentSet
                ? ClavisUIStrings.Inspector.hardwareIsolationStrictTitle
                : ClavisUIStrings.Inspector.hardwareIsolationPresenceTitle
            var desc: String
            if key.biometricPolicy == .biometryCurrentSet {
                desc = ClavisUIStrings.Inspector.postureGeneralStrictDesc
            } else {
                desc = ClavisUIStrings.Inspector.postureGeneralPresenceDesc
            }
            if hasActiveGitGrace {
                desc += ClavisUIStrings.Inspector.postureGitGraceActiveSuffix
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
            name = ClavisUIStrings.Inspector.socketNameAgent
            path = "~/.ssh/clavis-agent.sock"
        case .general, .gitSigningOnly:
            name = ClavisUIStrings.Inspector.socketNameSSHAgent
            path = "~/.ssh/clavis.sock"
        }
        let status = isSocketActive ? ClavisUIStrings.Inspector.statusActive : ClavisUIStrings.Inspector.statusOffline
        return (name: name, socketPath: path, status: status, isActive: isSocketActive)
    }

    /// Semantic actions available in the header overflow (•••) menu.
    enum OverflowMenuAction: String, CaseIterable, Equatable, Sendable {
        case copyDeployKey
        case copyOpenSSH
        case copyFingerprint
        case changePurpose
        case deleteKey
    }

    /// Returns the ordered list of actions present in the overflow (•••) menu for the given key.
    static func overflowMenuActions(for key: SSHKeyInfo) -> [OverflowMenuAction] {
        var actions: [OverflowMenuAction] = []
        if key.purpose == .agent {
            actions.append(.copyDeployKey)
        }
        actions.append(.copyOpenSSH)
        actions.append(.copyFingerprint)
        if key.purpose == .general || key.purpose == .agent {
            actions.append(.changePurpose)
        }
        actions.append(.deleteKey)
        return actions
    }

    /// Returns the 2-line title stack strings (title and algorithm/storage subtitle).
    static func headerTitleStack(for key: SSHKeyInfo) -> (title: String, subtitle: String) {
        (
            title: key.label,
            subtitle: ClavisUIStrings.Inspector.keySubtitle(algorithm: key.algorithm, isHardware: key.isHardware)
        )
    }

    // MARK: - Public Identity Copy Controls (Milestone M2 / Refs clavis-m46)

    /// Semantic attributes for copy controls in the PUBLIC IDENTITY card.
    struct PublicIdentityCopyControls: Equatable, Sendable {
        public let publicKeyButtonTitle: String
        public let publicKeyFeedback: String
        public let fingerprintButtonLabel: String
        public let fingerprintAccessibilityLabel: String
        public let fingerprintHelp: String
        public let fingerprintFeedback: String

        public init(
            publicKeyButtonTitle: String,
            publicKeyFeedback: String,
            fingerprintButtonLabel: String,
            fingerprintAccessibilityLabel: String,
            fingerprintHelp: String,
            fingerprintFeedback: String
        ) {
            self.publicKeyButtonTitle = publicKeyButtonTitle
            self.publicKeyFeedback = publicKeyFeedback
            self.fingerprintButtonLabel = fingerprintButtonLabel
            self.fingerprintAccessibilityLabel = fingerprintAccessibilityLabel
            self.fingerprintHelp = fingerprintHelp
            self.fingerprintFeedback = fingerprintFeedback
        }
    }

    /// Computes the copy control attributes for the Public Identity card based on key purpose.
    static func publicIdentityCopyControls(for key: SSHKeyInfo) -> PublicIdentityCopyControls {
        PublicIdentityCopyControls(
            publicKeyButtonTitle: key.purpose == .agent
                ? ClavisUIStrings.KeyDetail.copyDeployKey
                : ClavisUIStrings.Inspector.copySSHKeyButton,
            publicKeyFeedback: ClavisUIStrings.Inspector.feedbackCopiedOpenSSH,
            fingerprintButtonLabel: ClavisUIStrings.Common.copy,
            fingerprintAccessibilityLabel: ClavisUIStrings.Accessibility.copyFingerprint,
            fingerprintHelp: ClavisUIStrings.Inspector.copyFingerprintHelp,
            fingerprintFeedback: ClavisUIStrings.Inspector.feedbackCopiedFingerprint
        )
    }

    /// Localized button title for copying the public identity key.
    static func publicKeyCopyButtonTitle(for key: SSHKeyInfo) -> String {
        publicIdentityCopyControls(for: key).publicKeyButtonTitle
    }

    /// Localized attributes for the fingerprint copy button.
    static func fingerprintCopyButtonAttributes() -> (label: String, accessibilityLabel: String, help: String) {
        (
            label: ClavisUIStrings.Common.copy,
            accessibilityLabel: ClavisUIStrings.Accessibility.copyFingerprint,
            help: ClavisUIStrings.Inspector.copyFingerprintHelp
        )
    }

    // MARK: - Security Posture & Card Consolidation (Milestone M3 / Refs clavis-cc3)

    /// Returns the posture SF symbol icon matching the key's cryptographic purpose and policy.
    static func postureIcon(for key: SSHKeyInfo) -> String {
        switch key.purpose {
        case .agent:
            return "cpu"
        case .gitSigningOnly:
            return "arrow.triangle.branch"
        case .general:
            return key.biometricPolicy == .biometryCurrentSet ? "touchid" : "lock.shield.fill"
        }
    }

    /// System icon associated with the compact security posture caption footnote.
    static func securityPostureIcon(for key: SSHKeyInfo) -> String {
        postureIcon(for: key)
    }

    /// Compact caption footnote text for hardware keys directly under the SECURITY card.
    static func securityPostureFootnote(
        for key: SSHKeyInfo,
        agentPolicy: AgentKeyPolicy? = nil,
        hasActiveGitGrace: Bool = false
    ) -> String {
        securityPostureInfo(for: key, agentPolicy: agentPolicy, hasActiveGitGrace: hasActiveGitGrace).description
    }

    /// Semantic attributes for the consolidated socket row inside the SECURITY card.
    struct SecurityCardSocketRow: Equatable, Sendable {
        public let name: String
        public let socketPath: String
        public let status: String
        public let isActive: Bool

        public init(name: String, socketPath: String, status: String, isActive: Bool) {
            self.name = name
            self.socketPath = socketPath
            self.status = status
            self.isActive = isActive
        }
    }

    /// Returns the consolidated socket row attributes for placement in the SECURITY card.
    static func securityCardSocketRow(for key: SSHKeyInfo, isSocketActive: Bool) -> SecurityCardSocketRow {
        let info = socketStatusInfo(for: key, isSocketActive: isSocketActive)
        return SecurityCardSocketRow(
            name: info.name,
            socketPath: info.socketPath,
            status: info.status,
            isActive: info.isActive
        )
    }

    /// Semantic properties consolidated into the SECURITY card and caption footnote.
    struct ConsolidatedSecurityInfo: Equatable, Sendable {
        public let storageValue: String
        public let authenticationValue: String
        public let socketName: String
        public let socketPath: String
        public let socketStatus: String
        public let isSocketActive: Bool
        public let postureIcon: String
        public let postureDescription: String

        public init(
            storageValue: String,
            authenticationValue: String,
            socketName: String,
            socketPath: String,
            socketStatus: String,
            isSocketActive: Bool,
            postureIcon: String,
            postureDescription: String
        ) {
            self.storageValue = storageValue
            self.authenticationValue = authenticationValue
            self.socketName = socketName
            self.socketPath = socketPath
            self.socketStatus = socketStatus
            self.isSocketActive = isSocketActive
            self.postureIcon = postureIcon
            self.postureDescription = postureDescription
        }
    }

    /// Computes consolidated security properties and posture footnote for the inspector view.
    static func consolidatedSecurityInfo(
        for key: SSHKeyInfo,
        isSocketActive: Bool,
        agentPolicy: AgentKeyPolicy? = nil,
        hasActiveGitGrace: Bool = false
    ) -> ConsolidatedSecurityInfo {
        let authValue = key.biometricPolicy == .biometryCurrentSet
            ? ClavisUIStrings.Inspector.authTouchIdOnlyStrict
            : ClavisUIStrings.Inspector.authUserPresence
        let socket = socketStatusInfo(for: key, isSocketActive: isSocketActive)
        let posture = securityPostureInfo(for: key, agentPolicy: agentPolicy, hasActiveGitGrace: hasActiveGitGrace)
        return ConsolidatedSecurityInfo(
            storageValue: ClavisUIStrings.Inspector.storageHardwareEnclave,
            authenticationValue: authValue,
            socketName: socket.name,
            socketPath: socket.socketPath,
            socketStatus: socket.status,
            isSocketActive: socket.isActive,
            postureIcon: postureIcon(for: key),
            postureDescription: posture.description
        )
    }

    // MARK: - Key Purpose Actions (Milestone M4 / Refs clavis-t53)

    /// Semantic labels and copy for Key Purpose actions and alerts.
    struct PurposeActionStrings: Equatable, Sendable {
        public let actionLabel: String
        public let confirmButton: String
        public let alertTitle: String

        public init(actionLabel: String, confirmButton: String, alertTitle: String) {
            self.actionLabel = actionLabel
            self.confirmButton = confirmButton
            self.alertTitle = alertTitle
        }

        public func alertMessage(label: String, targetPurpose: KeyPurpose) -> String {
            ClavisUIStrings.KeyDetail.changePurposeAlertMessage(label: label, newPurpose: targetPurpose)
        }
    }

    static var purposeActionStrings: PurposeActionStrings {
        PurposeActionStrings(
            actionLabel: ClavisUIStrings.Inspector.changePurpose,
            confirmButton: ClavisUIStrings.KeyDetail.changePurposeConfirm,
            alertTitle: ClavisUIStrings.Inspector.changePurpose
        )
    }

    // MARK: - Destructive Delete Footer Control (Milestone M5 / Refs clavis-uta)

    /// Semantic attributes for the localized destructive delete footer control.
    public struct DeleteFooterAttributes: Equatable, Sendable {
        public let buttonTitle: String
        public let iconSystemName: String
        public let alertTitle: String
        public let confirmButtonTitle: String
        public let cancelButtonTitle: String

        public init(
            buttonTitle: String,
            iconSystemName: String = "trash",
            alertTitle: String,
            confirmButtonTitle: String,
            cancelButtonTitle: String
        ) {
            self.buttonTitle = buttonTitle
            self.iconSystemName = iconSystemName
            self.alertTitle = alertTitle
            self.confirmButtonTitle = confirmButtonTitle
            self.cancelButtonTitle = cancelButtonTitle
        }
    }

    /// Computes semantic attributes for the inspector delete footer control.
    public static func deleteFooterAttributes(for key: SSHKeyInfo) -> DeleteFooterAttributes {
        DeleteFooterAttributes(
            buttonTitle: ClavisUIStrings.Inspector.deleteKey,
            iconSystemName: "trash",
            alertTitle: deleteConfirmationTitle(label: key.label),
            confirmButtonTitle: ClavisUIStrings.Common.delete,
            cancelButtonTitle: ClavisUIStrings.Common.cancel
        )
    }
}

