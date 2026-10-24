import SwiftUI
import AppKit
import ClavisCore

public extension SSHKeyInfo {
    var shortFingerprint: String {
        if fingerprint.count <= 16 {
            return fingerprint
        }
        return String(fingerprint.prefix(16))
    }
}

// MARK: - Native Inline Key Rename Field (Caret at End, Commit on Blur/Enter, Cancel on Escape)

struct InlineKeyRenameField: NSViewRepresentable {
    @Binding var text: String
    var onCommit: () -> Void
    var onCancel: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeNSView(context: Context) -> NSTextField {
        let textField = NSTextField()
        textField.stringValue = text
        textField.isBordered = false
        textField.drawsBackground = false
        textField.focusRingType = .none
        textField.font = NSFont.systemFont(ofSize: 23, weight: .semibold)
        textField.textColor = NSColor.labelColor
        textField.delegate = context.coordinator
        textField.lineBreakMode = .byTruncatingTail
        textField.cell?.isScrollable = true
        textField.cell?.wraps = false
        context.coordinator.textField = textField
        context.coordinator.installOutsideClickMonitor()

        DispatchQueue.main.async {
            guard let window = textField.window else { return }
            window.makeFirstResponder(textField)
            if let editor = textField.currentEditor() {
                let endPosition = (textField.stringValue as NSString).length
                editor.selectedRange = NSRange(location: endPosition, length: 0)
            }
        }
        return textField
    }

    func updateNSView(_ nsView: NSTextField, context: Context) {
        context.coordinator.parent = self
        context.coordinator.textField = nsView
        if nsView.stringValue != text {
            nsView.stringValue = text
        }
    }

    static func dismantleNSView(_ nsView: NSTextField, coordinator: Coordinator) {
        coordinator.removeOutsideClickMonitor()
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSTextField, context: Context) -> CGSize {
        CGSize(width: proposal.width ?? 220, height: 28)
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: InlineKeyRenameField
        weak var textField: NSTextField?
        private var didFinish = false
        private var outsideClickMonitor: Any?

        init(_ parent: InlineKeyRenameField) {
            self.parent = parent
        }

        deinit {
            if let monitor = outsideClickMonitor {
                NSEvent.removeMonitor(monitor)
            }
        }

        func installOutsideClickMonitor() {
            guard outsideClickMonitor == nil else { return }
            outsideClickMonitor = NSEvent.addLocalMonitorForEvents(
                matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
            ) { [weak self] event in
                self?.handleMouseDown(in: event.window, locationInWindow: event.locationInWindow)
                return event
            }
        }

        func removeOutsideClickMonitor() {
            if let monitor = outsideClickMonitor {
                NSEvent.removeMonitor(monitor)
                outsideClickMonitor = nil
            }
        }

        @discardableResult
        func handleMouseDown(in eventWindow: NSWindow?, locationInWindow: NSPoint) -> Bool {
            guard !didFinish, let textField else { return false }
            if let fieldWindow = textField.window, let eventWindow, eventWindow !== fieldWindow {
                return false
            }
            let fieldBoundsInWindow = textField.convert(textField.bounds, to: nil)
            guard !fieldBoundsInWindow.contains(locationInWindow) else { return false }
            textField.window?.makeFirstResponder(nil)
            parent.text = textField.stringValue
            if !didFinish {
                didFinish = true
                removeOutsideClickMonitor()
                parent.onCommit()
            }
            return true
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let field = obj.object as? NSTextField else { return }
            if field.stringValue.count > 60 {
                field.stringValue = String(field.stringValue.prefix(60))
            }
            parent.text = field.stringValue
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
            if commandSelector == #selector(NSResponder.insertNewline(_:)) {
                guard !didFinish else { return true }
                let trimmed = parent.text.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else {
                    NSSound.beep()
                    return true
                }
                didFinish = true
                removeOutsideClickMonitor()
                parent.onCommit()
                return true
            }
            if commandSelector == #selector(NSResponder.cancelOperation(_:)) {
                guard !didFinish else { return true }
                didFinish = true
                removeOutsideClickMonitor()
                parent.onCancel()
                return true
            }
            return false
        }

        func controlTextDidEndEditing(_ obj: Notification) {
            guard !didFinish else { return }
            if let field = obj.object as? NSTextField {
                parent.text = field.stringValue
            }
            didFinish = true
            removeOutsideClickMonitor()
            parent.onCommit()
        }
    }
}

public struct KeyDetailInspectorView: View {
    public let key: SSHKeyInfo
    @ObservedObject var appState: AppState
    public let onDelete: () -> Void
    public var onShowToast: ((String) -> Void)?

    @State private var isRenaming: Bool = false
    @State private var draftKeyName: String = ""
    @State private var showingDeleteAlert: Bool = false
    @State private var changePurposeError: String? = nil
    @State private var showingChangePurposeError: Bool = false
    @State private var lastActivityDate: Date? = nil

    public init(
        key: SSHKeyInfo,
        appState: AppState,
        onDelete: @escaping () -> Void,
        onShowToast: ((String) -> Void)? = nil
    ) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
        self.onShowToast = onShowToast
    }

    public static func trimIdentity(_ value: String) -> String {
        guard value.count > 51 else { return value }
        return "\(value.prefix(32))…\(value.suffix(14))"
    }

    public static func approvalSummaryText(
        for key: SSHKeyInfo,
        agentPolicy: AgentKeyPolicy? = nil
    ) -> String {
        if key.purpose == .agent, let policy = agentPolicy {
            switch policy.mode {
            case .none:
                return "Autonomous"
            case .notify:
                return "Notify only"
            case .ask:
                return key.biometricPolicy == .biometryCurrentSet ? "Strict biometrics" : "User presence"
            }
        }
        return key.biometricPolicy == .biometryCurrentSet ? "Strict biometrics" : "User presence"
    }

    public static func approvalDescriptionText(
        for key: SSHKeyInfo,
        agentPolicy: AgentKeyPolicy? = nil
    ) -> String {
        if key.purpose == .agent, let policy = agentPolicy {
            switch policy.mode {
            case .none:
                return "Only use with workflows and hosts you trust."
            case .notify:
                return "A notification appears each time this agent key is used."
            case .ask:
                break
            }
        }
        return key.biometricPolicy == .biometryCurrentSet
            ? "Touch ID only. Invalidated if enrolled fingerprints change."
            : "Touch ID, Apple Watch, or your Mac password."
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

    private var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: key.createdAt)
    }

    private var formattedLastActivity: String {
        guard let date = lastActivityDate else {
            return "Not used yet"
        }
        let calendar = Calendar.current
        let timeFormatter = DateFormatter()
        timeFormatter.dateFormat = "HH:mm"
        if calendar.isDateInToday(date) {
            return "Today at \(timeFormatter.string(from: date))"
        } else if calendar.isDateInYesterday(date) {
            return "Yesterday at \(timeFormatter.string(from: date))"
        } else {
            let dateFormatter = DateFormatter()
            dateFormatter.dateStyle = .medium
            dateFormatter.timeStyle = .none
            return dateFormatter.string(from: date)
        }
    }

    public var body: some View {
        Form {
            Section {
            } header: {
                detailHeading
                    .textCase(nil)
                    // Grouped section headers are inset ~10pt from the card edge; cancel it.
                    .padding(.horizontal, -10)
                    .padding(.bottom, 4)
            }

            publicIdentitySection
            activeSessionsSection
            operationSection(.ssh)
            operationSection(.signature)
            activitySection
            deleteSection
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .background(Color.clear)
        .onAppear {
            lastActivityDate = appState.lastActivityDate(for: key)
        }
        .onChange(of: key.id) { _ in
            isRenaming = false
            lastActivityDate = appState.lastActivityDate(for: key)
        }
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
        .alert(ClavisUIStrings.Common.error, isPresented: $showingChangePurposeError) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text(changePurposeError ?? "")
        }
    }

    // MARK: - Detail Heading

    private var detailHeading: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                Image(systemName: key.effectiveAccessProfile.type == .bot ? "desktopcomputer" : "person")
                    .font(.system(size: 20, weight: .medium))
                    .foregroundColor(DesignTokens.accentBlue)
            }
            .frame(width: 41, height: 43)
            .glassCard(cornerRadius: 11, tint: DesignTokens.accentBlue.opacity(0.09))

            VStack(alignment: .leading, spacing: 3) {
                if isRenaming {
                    InlineKeyRenameField(
                        text: $draftKeyName,
                        onCommit: commitInlineRename,
                        onCancel: cancelInlineRename
                    )
                    .frame(height: 28, alignment: .leading)
                    .overlay(alignment: .bottom) {
                        Rectangle()
                            .fill(DesignTokens.accentBlue)
                            .frame(height: 1)
                    }
                } else {
                    HStack(spacing: 8) {
                        Text(key.label)
                            .font(.system(size: 23, weight: .semibold))
                            .foregroundColor(.primary)
                            .lineLimit(1)

                        Button(action: beginInlineRename) {
                            Image(systemName: "pencil")
                                .font(.system(size: 13, weight: .medium))
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        .buttonStyle(.plain)
                        .help("Rename \(key.label)")
                        .accessibilityLabel("Rename \(key.label)")
                    }
                    .frame(height: 28, alignment: .leading)
                }

                Text("\(key.isHardware ? "Secure Enclave" : "Software") · \(key.algorithm)")
                    .font(.system(size: 11))
                    .foregroundColor(DesignTokens.textSecondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)


        }
        .frame(minHeight: 43)
    }

    private func beginInlineRename() {
        draftKeyName = key.label
        isRenaming = true
    }

    private func commitInlineRename() {
        let trimmed = draftKeyName.trimmingCharacters(in: .whitespacesAndNewlines)
        isRenaming = false
        guard !trimmed.isEmpty, trimmed != key.label else { return }
        do {
            try appState.renameKey(from: key.label, to: trimmed)
            onShowToast?("Key renamed")
        } catch {
            changePurposeError = error.localizedDescription
            showingChangePurposeError = true
        }
    }

    private func cancelInlineRename() {
        draftKeyName = key.label
        isRenaming = false
    }

    // MARK: - Section 1: Public identity

    private var publicIdentitySection: some View {
        let formattedFingerprint = key.fingerprint.hasPrefix("SHA256:")
            ? key.fingerprint
            : "SHA256:\(key.fingerprint)"

        return Section("Identity") {
            Picker("Type", selection: Binding(
                get: { key.effectiveAccessProfile.type },
                set: { type in changeProfile(type: type) }
            )) {
                ForEach(KeyType.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            .help("Changing key type requires fresh authentication and revokes approvals.")
            identityCopyRow(
                label: "Public key",
                fullValue: key.publicKeyOpenSSH,
                help: "Copy full public key",
                action: copyOpenSSH
            )

            identityCopyRow(
                label: "Fingerprint",
                fullValue: formattedFingerprint,
                help: "Copy full fingerprint",
                action: copyFingerprint
            )
        }
    }

    private func identityCopyRow(
        label: String,
        fullValue: String,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        HStack(spacing: 12) {
            Text(label)
                .font(.system(size: 13))
                .foregroundColor(.primary)
                .frame(width: 76, alignment: .leading)

            Text(Self.trimIdentity(fullValue))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(DesignTokens.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(fullValue)
                .frame(maxWidth: .infinity, alignment: .leading)

            Button(action: action) {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)
            }
            .buttonStyle(.borderless)
            .help(help)
            .accessibilityLabel(help)
        }
    }

    private func changeProfile(type: KeyType? = nil, capabilities: KeyCapabilities? = nil) {
        do {
            try appState.changeAccessProfile(label: key.label, type: type, capabilities: capabilities)
        } catch {
            changePurposeError = error.localizedDescription
            showingChangePurposeError = true
        }
    }

    private func operationSection(_ operation: KeyOperation) -> some View {
        let profile = key.effectiveAccessProfile
        return Section(operation == .ssh ? "SSH" : "Signature") {
            Toggle("Enabled", isOn: Binding(
                get: { profile.capabilities.permits(operation) },
                set: { enabled in
                    changeProfile(capabilities: KeyCapabilities(
                        ssh: operation == .ssh ? enabled : profile.capabilities.ssh,
                        signature: operation == .signature ? enabled : profile.capabilities.signature))
                }
            ))
            .toggleStyle(.switch)
            if profile.capabilities.permits(operation) {
                LabeledContent("Approval") {
                    Text(Self.approvalSummaryText(for: key)).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var activeSessionsSection: some View {
        let sessions = appState.agentSessions.filter { $0.keyFingerprint == key.fingerprint }
        return Section("Active Sessions") {
            VStack(spacing: 12) {
                if let grace = activeGitGraceSession {
                    HStack {
                        Label("Git signing", systemImage: "signature")
                        Spacer()
                        Text(grace.formattedTime).monospacedDigit().foregroundStyle(.secondary)
                        Button("Revoke") { appState.revokeGitGrace(keyLabel: key.label) }
                    }
                }
                ForEach(sessions, id: \.id) { session in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(session.toolName).lineLimit(1)
                            Text("SSH · expires \(session.expiresAt.formatted(date: .omitted, time: .shortened))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Revoke") { appState.endAgentSession(id: session.id) }
                    }
                }
                if sessions.isEmpty && activeGitGraceSession == nil {
                    Text("No active approvals. Clavis will ask on the next permitted request.")
                        .font(.callout).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(minHeight: 48)
        }
    }

    private var deleteSection: some View {
        Section("Delete Key") {
            HStack {
                Text("Delete this key and revoke its approvals.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
                Button("Delete Key…", role: .destructive) { showingDeleteAlert = true }
            }
        }
    }

    // MARK: - Section 3: Activity

    private var activitySection: some View {
        Section {
            LabeledContent("Created") {
                Text(formattedDate)
                    .foregroundColor(.secondary)
            }

            LabeledContent("Last activity") {
                Text(formattedLastActivity)
                    .foregroundColor(.secondary)
            }
        } header: {
            HStack {
                Text("Activity")
                Spacer()
                Button(action: {
                    appState.openHistoryPane(forKeyFingerprint: key.fingerprint)
                }) {
                    HStack(spacing: 4) {
                        Text("View activity")
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                    }
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(DesignTokens.accentBlue)
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func copyFingerprint() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.fingerprint, forType: .string)
        onShowToast?("Copied to clipboard")
    }

    private func copyOpenSSH() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
        onShowToast?("Copied to clipboard")
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
    struct DeleteFooterAttributes: Equatable, Sendable {
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
    static func deleteFooterAttributes(for key: SSHKeyInfo) -> DeleteFooterAttributes {
        DeleteFooterAttributes(
            buttonTitle: ClavisUIStrings.Inspector.deleteKey,
            iconSystemName: "trash",
            alertTitle: deleteConfirmationTitle(label: key.label),
            confirmButtonTitle: ClavisUIStrings.Common.delete,
            cancelButtonTitle: ClavisUIStrings.Common.cancel
        )
    }
}
