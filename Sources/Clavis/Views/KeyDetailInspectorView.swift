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
        if nsView.stringValue != text {
            nsView.stringValue = text
        }
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSTextField, context: Context) -> CGSize {
        CGSize(width: proposal.width ?? 220, height: 28)
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: InlineKeyRenameField
        private var didFinish = false

        init(_ parent: InlineKeyRenameField) {
            self.parent = parent
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
                parent.onCommit()
                return true
            }
            if commandSelector == #selector(NSResponder.cancelOperation(_:)) {
                guard !didFinish else { return true }
                didFinish = true
                parent.onCancel()
                return true
            }
            return false
        }

        func controlTextDidEndEditing(_ obj: Notification) {
            guard !didFinish else { return }
            didFinish = true
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
    @State private var showingPurposeSheet: Bool = false
    @State private var showingApprovalSheet: Bool = false
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

    private var currentAgentPolicy: AgentKeyPolicy? {
        appState.getAgentPolicy(fingerprint: key.fingerprint)
    }

    private var currentGracePeriod: KeyGracePeriod {
        appState.gracePeriod(for: key)
    }

    private var gracePeriodBinding: Binding<KeyGracePeriod> {
        Binding(
            get: { appState.gracePeriod(for: key) },
            set: { newValue in
                appState.setGracePeriod(newValue, for: key)
                onShowToast?("Key grace period updated")
            }
        )
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

    private var activeAgentSessionForKey: AgentSessionSummary? {
        appState.agentSessions.first(where: { $0.keyFingerprint == key.fingerprint })
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
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                detailHeading
                    .padding(.horizontal, 20)
                    .padding(.top, 14)
                    .padding(.bottom, 4)

                Form {
                    publicIdentitySection
                    signingSection
                    activitySection
                }
                .formStyle(.grouped)
                .scrollDisabled(true)
                .scrollContentBackground(.hidden)
            }
            .padding(.horizontal, 15)
            .padding(.bottom, 20)
        }
        .background(Color.clear)
        .onAppear {
            lastActivityDate = appState.lastActivityDate(for: key)
        }
        .onChange(of: key.id) { _ in
            isRenaming = false
            lastActivityDate = appState.lastActivityDate(for: key)
        }
        .sheet(isPresented: $showingPurposeSheet) {
            KeyPurposeEditorSheet(
                key: key,
                appState: appState,
                onSaved: { message in
                    onShowToast?(message)
                }
            )
        }
        .sheet(isPresented: $showingApprovalSheet) {
            KeyApprovalEditorSheet(
                key: key,
                appState: appState,
                onSaved: { message in
                    onShowToast?(message)
                }
            )
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
                Image(systemName: "key.fill")
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

            CircularGlassIconButton(
                icon: "trash",
                size: 34,
                iconSize: 15,
                isDanger: true,
                helpText: "Delete key",
                accessibilityLabel: "Delete \(key.label)"
            ) {
                showingDeleteAlert = true
            }
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

        return Section("Public identity") {
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

    // MARK: - Section 2: Signing

    private var signingSection: some View {
        let approvalText = Self.approvalSummaryText(for: key, agentPolicy: currentAgentPolicy)
        let approvalHelp = Self.approvalDescriptionText(for: key, agentPolicy: currentAgentPolicy)

        return Section("Signing") {
            LabeledContent("Purpose") {
                Button(action: { showingPurposeSheet = true }) {
                    HStack(spacing: 6) {
                        Text(key.purpose.inspectorLabel)
                            .font(.system(size: 13))
                            .foregroundColor(.primary)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                }
                .buttonStyle(.plain)
            }

            LabeledContent("Approval") {
                Button(action: { showingApprovalSheet = true }) {
                    HStack(spacing: 6) {
                        Text(approvalText)
                            .font(.system(size: 13))
                            .foregroundColor(.primary)
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                }
                .buttonStyle(.plain)
                .help("Edit signing approval: \(approvalHelp)")
            }

            Picker("Grace period", selection: gracePeriodBinding) {
                ForEach(KeyGracePeriod.allCases) { option in
                    Text(option.title).tag(option)
                }
            }
            .help("How long this key stays available after approval. Per session lasts until Clavis quits; locking the key ends the window immediately.")

            if currentGracePeriod != .always || activeGitGraceSession != nil || activeAgentSessionForKey != nil {
                activeWindowRow
            }

            if let gitGrace = activeGitGraceSession, key.purpose != .agent {
                LabeledContent("Git signing window") {
                    HStack(spacing: 8) {
                        Text("\(gitGrace.formattedTime) · \(gitGrace.remainingOperations) left")
                            .font(.system(size: 12).monospacedDigit())
                            .foregroundColor(DesignTokens.accentGreen)
                        Button("Revoke") {
                            appState.revokeGitGrace(keyLabel: key.label)
                            onShowToast?("Signing window revoked")
                        }
                        .liquidGlassButton()
                        .controlSize(.small)
                    }
                }
            }
        }
    }

    private var activeWindowRow: some View {
        let isUnlocked = appState.isKeyUnlocked(key)
        let statusText: String = {
            if let gitGrace = activeGitGraceSession {
                return "\(gitGrace.formattedTime) remaining"
            }
            if let session = activeAgentSessionForKey {
                let remaining = max(0, Int(session.expiresAt.timeIntervalSinceNow))
                let mins = remaining / 60
                let secs = remaining % 60
                return String(format: "%d:%02d remaining", mins, secs)
            }
            if currentGracePeriod == .session && isUnlocked {
                return "This session"
            }
            return "Approval required"
        }()

        return LabeledContent("Active window") {
            HStack(spacing: 8) {
                Text(statusText)
                    .font(.system(size: 12).monospacedDigit())
                    .foregroundColor(isUnlocked ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                    .lineLimit(1)

                if isUnlocked {
                    Button("Revoke") {
                        appState.revokeGitGrace(keyLabel: key.label)
                        if let session = activeAgentSessionForKey {
                            appState.endAgentSession(id: session.id)
                        }
                        onShowToast?("Grace window revoked · approval required")
                    }
                    .liquidGlassButton()
                    .controlSize(.small)
                }
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

// MARK: - Key Purpose Sheet

private struct KeyPurposeEditorSheet: View {
    let key: SSHKeyInfo
    @ObservedObject var appState: AppState
    var onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var selectedPurpose: KeyPurpose
    @State private var errorMessage: String?

    init(key: SSHKeyInfo, appState: AppState, onSaved: @escaping (String) -> Void) {
        self.key = key
        self.appState = appState
        self.onSaved = onSaved
        self._selectedPurpose = State(initialValue: key.purpose)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Key purpose")
                    .font(.system(size: 17, weight: .semibold))
                Spacer()
                CircularGlassIconButton(
                    icon: "xmark",
                    size: 26,
                    iconSize: 11,
                    helpText: ClavisUIStrings.Common.cancel,
                    accessibilityLabel: ClavisUIStrings.Common.cancel
                ) {
                    dismiss()
                }
            }
            .padding(.horizontal, 23)
            .padding(.top, 20)
            .padding(.bottom, 16)

            Divider()

            VStack(alignment: .leading, spacing: 16) {
                Text("Choose where you want to use \(key.label).")
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)

                if key.purpose == .gitSigningOnly {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "lock.shield")
                            .foregroundColor(DesignTokens.accentBlue)
                        Text("Git-signing-only keys are permanently scoped to local Git commit and tag signing and cannot be converted into SSH or Agent keys.")
                            .font(.system(size: 12))
                            .foregroundColor(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(12)
                    .glassCard(cornerRadius: 9)
                } else {
                    Form {
                        Section {
                            Picker("Purpose", selection: $selectedPurpose) {
                                Text(KeyPurpose.general.inspectorLabel).tag(KeyPurpose.general)
                                Text(KeyPurpose.agent.inspectorLabel).tag(KeyPurpose.agent)
                            }
                        }
                    }
                    .groupedEmbeddedForm(zeroMargins: true)

                    HStack(alignment: .center, spacing: 10) {
                        Image(systemName: "checkmark.shield")
                            .foregroundColor(DesignTokens.accentBlue)
                        Text("Changing purpose resets approval to “Always ask”. You can edit the policy afterward.")
                            .font(.system(size: 12))
                            .foregroundColor(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(12)
                    .glassCard(cornerRadius: 9)
                }

                if let errorMessage {
                    Text(errorMessage)
                        .font(.system(size: 11))
                        .foregroundColor(.red)
                }
            }
            .padding(.horizontal, 23)
            .padding(.vertical, 20)

            Divider()

            HStack {
                Spacer()
                Button(ClavisUIStrings.Common.cancel) {
                    dismiss()
                }
                .liquidGlassButton(prominent: false)
                .keyboardShortcut(.cancelAction)

                if key.purpose != .gitSigningOnly {
                    Button("Save purpose") {
                        savePurpose()
                    }
                    .liquidGlassButton(prominent: true)
                    .keyboardShortcut(.defaultAction)
                    .disabled(selectedPurpose == key.purpose)
                }
            }
            .padding(.horizontal, 23)
            .padding(.vertical, 14)
        }
        .frame(width: 440)
    }

    private func savePurpose() {
        do {
            try appState.changeKeyKind(label: key.label, to: selectedPurpose)
            dismiss()
            onSaved("Key purpose updated")
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Signing Approval Sheet

private struct KeyApprovalEditorSheet: View {
    let key: SSHKeyInfo
    @ObservedObject var appState: AppState
    var onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var selectedMode: AgentKeyPolicy.Mode
    @State private var maxRatePerMinute: Int
    @State private var allowedHostsText: String
    @State private var errorMessage: String?

    init(key: SSHKeyInfo, appState: AppState, onSaved: @escaping (String) -> Void) {
        self.key = key
        self.appState = appState
        self.onSaved = onSaved
        let policy = appState.getAgentPolicy(fingerprint: key.fingerprint) ?? AgentKeyPolicy()
        self._selectedMode = State(initialValue: policy.mode)
        self._maxRatePerMinute = State(initialValue: policy.refillPerMinute)
        self._allowedHostsText = State(
            initialValue: policy.allowedHosts.isEmpty
                ? "github.com"
                : policy.allowedHosts.map(\.name).joined(separator: ", ")
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Signing approval")
                    .font(.system(size: 17, weight: .semibold))
                Spacer()
                CircularGlassIconButton(
                    icon: "xmark",
                    size: 26,
                    iconSize: 11,
                    helpText: ClavisUIStrings.Common.cancel,
                    accessibilityLabel: ClavisUIStrings.Common.cancel
                ) {
                    dismiss()
                }
            }
            .padding(.horizontal, 23)
            .padding(.top, 20)
            .padding(.bottom, 16)

            Divider()

            VStack(alignment: .leading, spacing: 14) {
                Text("Choose how \(key.label) authorizes signatures.")
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)

                VStack(alignment: .leading, spacing: 6) {
                    Text("Authentication")
                        .font(.system(size: 12, weight: .semibold))
                    Text(key.biometricPolicy == .biometryCurrentSet ? "Strict biometrics (Touch ID only)" : "User presence (Touch ID, Apple Watch, or Mac password)")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.primary)
                    Text("Hardware access control is bound inside the Secure Enclave when the key is created.")
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                }

                if key.purpose == .agent {
                    VStack(alignment: .leading, spacing: 8) {
                        approvalRadioRow(
                            mode: .ask,
                            title: "Always ask for approval",
                            subtitle: "Use the hardware authentication method when approval is required."
                        )
                        approvalRadioRow(
                            mode: .notify,
                            title: "Notify only",
                            subtitle: "Show a notification for each signature. No approval required."
                        )
                        approvalRadioRow(
                            mode: .none,
                            title: "Autonomous",
                            subtitle: "Sign silently within your host and rate limits."
                        )
                    }

                    if selectedMode != .ask {
                        Text("Signatures can be approved without your presence. Only allow hosts you trust.")
                            .font(.system(size: 12))
                            .foregroundColor(DesignTokens.accentOrange)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(DesignTokens.accentOrange.opacity(0.10))
                            .cornerRadius(7)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Maximum signatures per minute")
                            .font(.system(size: 12, weight: .semibold))
                        TextField("20", value: $maxRatePerMinute, format: .number)
                            .textFieldStyle(.roundedBorder)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Allowed hosts")
                            .font(.system(size: 12, weight: .semibold))
                        TextField("github.com, *.internal", text: $allowedHostsText)
                            .textFieldStyle(.roundedBorder)
                        Text("Comma-separated host patterns, e.g. github.com, *.internal")
                            .font(.system(size: 11))
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                } else {
                    Text("Automated signing options are available for keys with the Agent purpose.")
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                }

                if let errorMessage {
                    Text(errorMessage)
                        .font(.system(size: 11))
                        .foregroundColor(.red)
                }
            }
            .padding(.horizontal, 23)
            .padding(.vertical, 18)

            Divider()

            HStack {
                Spacer()
                Button(ClavisUIStrings.Common.cancel) {
                    dismiss()
                }
                .liquidGlassButton(prominent: false)
                .keyboardShortcut(.cancelAction)

                if key.purpose == .agent {
                    Button("Save changes") {
                        saveApprovalPolicy()
                    }
                    .liquidGlassButton(prominent: true)
                    .keyboardShortcut(.defaultAction)
                } else {
                    Button("Done") {
                        dismiss()
                    }
                    .liquidGlassButton(prominent: true)
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.horizontal, 23)
            .padding(.vertical, 14)
        }
        .frame(width: 460)
    }

    private func approvalRadioRow(
        mode: AgentKeyPolicy.Mode,
        title: String,
        subtitle: String
    ) -> some View {
        let isSelected = (selectedMode == mode)
        return Button(action: { selectedMode = mode }) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                    .foregroundColor(isSelected ? DesignTokens.accentBlue : DesignTokens.textSecondary)
                    .font(.system(size: 13))
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.primary)
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                }
                Spacer()
            }
            .padding(10)
            .liquidGlassControl(cornerRadius: 9, isSelected: isSelected)
        }
        .buttonStyle(.plain)
    }

    private func saveApprovalPolicy() {
        var policy = appState.getAgentPolicy(fingerprint: key.fingerprint) ?? AgentKeyPolicy()
        policy.mode = selectedMode
        policy.refillPerMinute = max(1, min(600, maxRatePerMinute))
        do {
            try appState.setAgentPolicy(policy, fingerprint: key.fingerprint)
            dismiss()
            onSaved("Signing approval updated")
        } catch {
            errorMessage = error.localizedDescription
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
