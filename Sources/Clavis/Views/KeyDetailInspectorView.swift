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
        textField.font = NSFont.systemFont(ofSize: 20, weight: .bold)
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
        CGSize(width: proposal.width ?? 220, height: 24)
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
    /// Opens/toggles key-scoped History from the persistent header.
    public var onToggleHistory: (() -> Void)?

    @Environment(\.headerCenterOffset) private var headerCenterOffset
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @StateObject private var applicationsModel: ApplicationSettingsModel

    @State private var isRenaming: Bool = false
    @State private var draftKeyName: String = ""
    @State private var showingDeleteAlert: Bool = false
    @State private var showingRotateInfoAlert: Bool = false
    @State private var showingPolicyGuidance: Bool = false
    @State private var changePurposeError: String? = nil
    @State private var showingChangePurposeError: Bool = false
    @State private var lastActivityDate: Date? = nil
    @State private var lastActivityCaller: String? = nil

    @State private var copiedPublicKey: Bool = false
    @State private var copiedFingerprint: Bool = false
    @State private var copiedFilePath: Bool = false

    @State private var expandedAppIds: Set<UUID> = []
    @State private var isRemoveMode: Bool = false
    @State private var selectedForRemoval: Set<UUID> = []

    public init(
        key: SSHKeyInfo,
        appState: AppState,
        onDelete: @escaping () -> Void,
        onShowToast: ((String) -> Void)? = nil,
        onToggleHistory: (() -> Void)? = nil,
        applicationAgent: any AgentControlling = AgentLifecycleManager.shared
    ) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
        self.onShowToast = onShowToast
        self.onToggleHistory = onToggleHistory
        self._applicationsModel = StateObject(wrappedValue: ApplicationSettingsModel(agent: applicationAgent))
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

    private var isAgentKey: Bool {
        key.effectiveAccessProfile.type == .bot
    }

    private var isKeyEnabled: Bool {
        let caps = key.effectiveAccessProfile.capabilities
        return caps.ssh || caps.signature
    }

    private var capabilitySummary: String {
        let caps = key.effectiveAccessProfile.capabilities
        if caps.ssh && caps.signature {
            return "SSH & Git signing"
        } else if caps.ssh {
            return "SSH authentication"
        } else if caps.signature {
            return "Git signing"
        } else {
            return "Disabled"
        }
    }

    private var publicKeyFilePath: String {
        let sanitized = key.label
            .lowercased()
            .replacingOccurrences(of: " ", with: "-")
        return "~/.ssh/\(sanitized).pub"
    }

    private var formattedFingerprint: String {
        key.fingerprint.hasPrefix("SHA256:")
            ? key.fingerprint
            : "SHA256:\(key.fingerprint)"
    }

    private var displayedApplications: [RegisteredApplication] {
        if isAgentKey {
            return applicationsModel.applications
        } else {
            return applicationsModel.applications.filter { $0.classification == .block }
        }
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
        ScrollViewReader { scrollProxy in
        ScrollView {
            // Prototype rhythm: 28pt side inset, 15pt below the header band, 23pt between groups.
            VStack(alignment: .leading, spacing: 23) {
                if !isKeyEnabled {
                    disabledKeyCallout
                }

                publicKeySection
                confirmationSection
                accessSection
                recentActivitySection
                keyLifecycleSection
            }
            .id("inspectorTop")
            .padding(.horizontal, 28)
            .padding(.top, 15)
            .padding(.bottom, 36)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        // A newly selected key always opens at its top, not at the previous key's scroll offset.
        .onChange(of: key.id) {
            scrollProxy.scrollTo("inspectorTop", anchor: .top)
        }
        // One persistent header; form content scrolls underneath it (safe-area bar).
        .topLiquidGlassBar(alignment: .leading) {
            prominentHeader
        }
        }
        .scrollContentBackground(.hidden)
        .background(Color.clear)
        .task {
            await applicationsModel.load()
        }
        .onAppear {
            refreshLastActivity()
        }
        .onChange(of: key.id) {
            isRenaming = false
            isRemoveMode = false
            expandedAppIds.removeAll()
            selectedForRemoval.removeAll()
            refreshLastActivity()
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
        .alert("Rotate “\(key.label)”", isPresented: $showingRotateInfoAlert) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text("Key rotation will generate a replacement Secure Enclave keypair and keep existing policy grants.")
        }
        .alert("Change confirmation policy", isPresented: $showingPolicyGuidance) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text("The confirmation policy is fixed at creation. Rotate “\(key.label)” to create a replacement key with a different policy.")
        }
        .alert(ClavisUIStrings.Common.error, isPresented: $showingChangePurposeError) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text(changePurposeError ?? "")
        }
    }

    // MARK: - Integrated Detail Toolbar (S03.toolbar)

    /// One unified 52pt band on the traffic-light midline: key tile, title + exception-only status
    /// pill, owner/last-used subtitle, and a single trailing ⋯ action control.
    private var prominentHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            identityRow
            overflowMenu
        }
        .padding(.horizontal, 28)
        .frame(height: KeyListView.toolbarHeight)
        .offset(y: headerCenterOffset)
    }

    private var identityRow: some View {
        HStack(alignment: .center, spacing: 12) {
            keyTile(size: 36, cornerRadius: 9, iconSize: 18)

            VStack(alignment: .leading, spacing: 1) {
                if isRenaming {
                    InlineKeyRenameField(
                        text: $draftKeyName,
                        onCommit: commitInlineRename,
                        onCancel: cancelInlineRename
                    )
                    .frame(height: 20, alignment: .leading)
                    .overlay(alignment: .bottom) {
                        Rectangle()
                            .fill(Color.accentColor)
                            .frame(height: 1)
                    }
                    .accessibilityLabel("Key name")
                } else {
                    HStack(spacing: 8) {
                        Text(key.label)
                            .font(.system(size: 18, weight: .bold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .truncationMode(.tail)

                        Button(action: beginInlineRename) {
                            Image(systemName: "pencil")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                        .buttonStyle(.plain)
                        .help("Rename \(key.label)")
                        .accessibilityLabel("Rename \(key.label)")

                        // Exception-only status pill: Disabled is the only non-nominal badge.
                        if !isKeyEnabled {
                            Text("Disabled")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(DesignTokens.textSecondary)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(Capsule().fill(DesignTokens.cardBackground))
                                .overlay(Capsule().strokeBorder(DesignTokens.cardBorder, lineWidth: 1))
                                .fixedSize()
                        }
                    }
                    .frame(height: 20, alignment: .leading)
                }

                Text(toolbarSubtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .contain)
            .accessibilityValue(toolbarSubtitle)
        }
    }

    /// S03.hero.subtitle: owner profile + last used only (purpose/storage live in the form below).
    private var toolbarSubtitle: String {
        Self.toolbarSubtitle(isAgentKey: isAgentKey, lastUsed: lastUsedSummary)
    }

    private var lastUsedSummary: String? {
        guard let date = lastActivityDate else { return nil }
        let calendar = Calendar.current
        let timeFormatter = DateFormatter()
        timeFormatter.dateFormat = "HH:mm"
        var text: String
        if calendar.isDateInToday(date) {
            text = timeFormatter.string(from: date)
        } else if calendar.isDateInYesterday(date) {
            text = "Yesterday \(timeFormatter.string(from: date))"
        } else {
            let dateFormatter = DateFormatter()
            dateFormatter.dateStyle = .medium
            dateFormatter.timeStyle = .none
            text = "\(dateFormatter.string(from: date)) \(timeFormatter.string(from: date))"
        }
        if let caller = lastActivityCaller, !caller.isEmpty {
            text += " · \(caller)"
        }
        return text
    }

    /// S03.toolbar.more: the only trailing control (D-39): Connect & Test… plus key actions.
    private var overflowMenu: some View {
        Menu {
            Button {
                appState.connectTarget = key
                appState.activeSheet = .connect
            } label: {
                Label("Connect & Test…", systemImage: "arrow.triangle.2.circlepath")
            }
            Button {
                copyOpenSSHWithFeedback()
            } label: {
                Label("Copy Public Key", systemImage: "doc.on.doc")
            }
            Button {
                toggleKeyEnabled()
            } label: {
                Label(isKeyEnabled ? "Disable" : "Enable", systemImage: isKeyEnabled ? "pause.circle" : "play.circle")
            }
            Divider()
            Button {
                rotateKey()
            } label: {
                Label("Rotate…", systemImage: "arrow.triangle.2.circlepath")
            }
            Button(role: .destructive) {
                showingDeleteAlert = true
            } label: {
                Label("Delete…", systemImage: "trash")
            }
        } label: {
            Image(systemName: "ellipsis")
                .font(.system(size: 16.5, weight: .medium))
                .foregroundStyle(.primary)
                .frame(width: 28, height: 28)
                .contentShape(Circle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .frame(width: KeyListView.actionControlHeight, height: KeyListView.actionControlHeight)
        .modifier(CapsuleGlassBackground(isActive: false, isHovered: false, reduceTransparency: reduceTransparency))
        .help("Key actions")
        .accessibilityLabel("Key actions")
    }

    private func toggleKeyEnabled() {
        if isKeyEnabled {
            changeProfile(capabilities: KeyCapabilities(ssh: false, signature: false))
        } else {
            changeProfile(capabilities: KeyCapabilities(ssh: true, signature: true))
        }
    }

    private func rotateKey() {
        if let onShowToast {
            onShowToast("Key rotation will be connected in ClavisCore")
        } else {
            showingRotateInfoAlert = true
        }
    }

    /// Latest signing event for the subtitle: time plus requesting app when it can be read.
    private func refreshLastActivity() {
        lastActivityDate = appState.lastActivityDate(for: key)
        lastActivityCaller = nil
        var query = AuditQuery()
        query.keyFingerprint = key.fingerprint
        query.limit = 1
        guard let unlockContext = PanelLockController.shared.unlockContext,
              let store = try? AuditStore(),
              let record = (try? store.query(query))?.first else { return }
        let unsealer = AuditUnsealer(
            keyring: HistoryViewModel.makeDefaultKeyring(),
            store: store,
            context: unlockContext
        )
        if case .plaintext(let sens) = unsealer.open(record),
           let caller = sens.callerName, !caller.isEmpty {
            lastActivityCaller = caller
        }
    }

    private func keyTile(size: CGFloat, cornerRadius: CGFloat, iconSize: CGFloat) -> some View {
        let gradientColors: [Color] = isAgentKey
            ? [Color(red: 0.69, green: 0.35, blue: 0.94), Color(red: 0.54, green: 0.22, blue: 0.82)]
            : [Color(red: 0.12, green: 0.58, blue: 1.0), Color(red: 0.0, green: 0.45, blue: 0.96)]

        return ZStack {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: gradientColors,
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .strokeBorder(Color.white.opacity(0.18), lineWidth: 0.5)
            Image(systemName: isAgentKey ? "cpu" : "person.fill")
                .font(.system(size: iconSize, weight: .semibold))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .shadow(color: Color.black.opacity(0.18), radius: 2, x: 0, y: 1)
    }

    private var disabledKeyCallout: some View {
        HStack(spacing: 10) {
            Image(systemName: "pause.circle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(DesignTokens.accentOrange)
            Text("This key is disabled. Nothing can sign with it.")
                .font(.system(size: 12.5))
                .foregroundStyle(.primary)
            Spacer()
            settingsActionButton("Enable") {
                changeProfile(capabilities: KeyCapabilities(ssh: true, signature: true))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .modifier(SettingsGroupCardModifier())
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

    // MARK: - Section 1: Public Key

    private var publicKeySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle("Public Key")

            VStack(spacing: 0) {
                // Row 1: OpenSSH Public Key
                HStack(spacing: 12) {
                    Text("Public key")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Text(Self.trimIdentity(key.publicKeyOpenSSH))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .help(key.publicKeyOpenSSH)

                    Button(action: copyOpenSSHWithFeedback) {
                        Image(systemName: copiedPublicKey ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundStyle(copiedPublicKey ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                            .frame(width: 22, height: 22)
                    }
                    .buttonStyle(.borderless)
                    .help(Self.publicKeyCopyButtonTitle(for: key))
                    .accessibilityLabel(Self.publicKeyCopyButtonTitle(for: key))
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                // Row 2: Fingerprint
                HStack(spacing: 12) {
                    Text("Fingerprint")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Text(formattedFingerprint)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)

                    Button(action: copyFingerprintWithFeedback) {
                        Image(systemName: copiedFingerprint ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundStyle(copiedFingerprint ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                            .frame(width: 22, height: 22)
                    }
                    .buttonStyle(.borderless)
                    .help(ClavisUIStrings.Inspector.copyFingerprintHelp)
                    .accessibilityLabel(ClavisUIStrings.Accessibility.copyFingerprint)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                // Row 3: Public key file
                HStack(spacing: 12) {
                    Text("Public key file")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Text(publicKeyFilePath)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)

                    Button(action: copyFilePathWithFeedback) {
                        Image(systemName: copiedFilePath ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundStyle(copiedFilePath ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                            .frame(width: 22, height: 22)
                    }
                    .buttonStyle(.borderless)
                    .help("Copy public key file path")
                    .accessibilityLabel("Copy public key file path")
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)
            }
            .modifier(SettingsGroupCardModifier())

            // S03.public-key.footnote: storage guarantee lives here, not in the toolbar subtitle.
            Text(Self.publicKeyStorageFootnote)
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
                .padding(.horizontal, 2)
        }
    }

    // MARK: - Section 2: Confirmation

    private var confirmationSection: some View {
        let policy = key.effectiveBiometricPolicy
        let period = appState.gracePeriod(for: key)
        return VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle("Confirmation")

            VStack(spacing: 0) {
                // Row 1: Confirmation policy (D-40: how you prove presence)
                confirmationRow(
                    label: "Confirmation policy",
                    sublabel: "How you prove presence when a prompt fires"
                ) {
                    Menu {
                        ForEach(Self.confirmationPolicies, id: \.self) { option in
                            Button {
                                selectConfirmationPolicy(option)
                            } label: {
                                if policy == option {
                                    Label(option.title, systemImage: "checkmark")
                                } else {
                                    Text(option.title)
                                }
                            }
                            // INV-08: biometric-bound keys can never become password-only.
                            .disabled(option == .devicePasscode && Self.isBiometricBound(policy))
                        }
                        Divider()
                        // Legacy policy is read-only; moving off it requires a new key.
                        Button {} label: {
                            Text("\(BiometricPolicy.biometryCurrentSet.title) — Requires new key → Rotate")
                        }
                        .disabled(true)
                    } label: {
                        settingsPopupLabel(policy.title)
                    }
                    .menuStyle(.button)
                    .buttonStyle(.plain)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .help("The confirmation policy is fixed at creation; changing it requires Rotate.")
                    .accessibilityLabel("Confirmation policy")
                }

                insetDivider

                // Row 2: Unlocked timeout (D-40: how long one confirmation is reused)
                confirmationRow(
                    label: "Unlocked timeout",
                    sublabel: "How long one confirmation is reused (key + requesting app)"
                ) {
                    Menu {
                        ForEach(KeyGracePeriod.allCases, id: \.self) { option in
                            Button {
                                changeUnlockedTimeout(option)
                            } label: {
                                if period == option {
                                    Label(option.title, systemImage: "checkmark")
                                } else {
                                    Text(option.title)
                                }
                            }
                        }
                    } label: {
                        settingsPopupLabel(period.title)
                    }
                    .menuStyle(.button)
                    .buttonStyle(.plain)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .disabled(appState.policyMutations.isPending)
                    .accessibilityLabel("Unlocked timeout")
                }
            }
            .modifier(SettingsGroupCardModifier())

            // S03.confirmation.footnote: session semantics + hardware minimum when applicable.
            Text(Self.confirmationFootnote(for: key, period: period))
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
                .padding(.horizontal, 2)
        }
    }

    /// Grouped-form row with a regular-weight label and an explanatory sublabel (prototype `R(l,x,sub)`).
    private func confirmationRow<Control: View>(
        label: String,
        sublabel: String,
        @ViewBuilder control: () -> Control
    ) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.system(size: 13))
                    .foregroundStyle(.primary)
                Text(sublabel)
                    .font(.system(size: 11.5))
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            Spacer(minLength: 12)

            control()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .frame(minHeight: 38)
    }

    /// No in-place policy mutation exists (hardware minimum is fixed at creation), so choosing a
    /// different policy points at Rotate instead of silently changing nothing.
    private func selectConfirmationPolicy(_ option: BiometricPolicy) {
        guard option != key.effectiveBiometricPolicy else { return }
        showingPolicyGuidance = true
    }

    // MARK: - Section 3: Access / Never Allow (Expandable NSOutlineView Variant 3)

    private var accessSection: some View {
        let apps = displayedApplications
        let candidateAppsForPlus: [RegisteredApplication] = isAgentKey
            ? applicationsModel.applications.filter { $0.classification != .bot }
            : applicationsModel.applications.filter { $0.classification != .block }

        return VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle(isAgentKey ? "Access" : "Never Allow")

            VStack(spacing: 0) {
                if apps.isEmpty {
                    HStack {
                        Text(
                            isAgentKey
                                ? "No applications configured — unlisted apps ask on first use."
                                : "No blocked applications — any personal app can request Touch ID."
                        )
                        .font(.system(size: 13))
                        .foregroundStyle(DesignTokens.textSecondary)
                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 40)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(apps.enumerated()), id: \.element.id) { index, app in
                            let isExpanded = !isRemoveMode && expandedAppIds.contains(app.id)
                            let isSelected = isRemoveMode && selectedForRemoval.contains(app.id)

                            VStack(spacing: 0) {
                                HStack(spacing: 9) {
                                    // Disclosure chevron / Remove checkbox slot
                                    ZStack {
                                        if isRemoveMode {
                                            Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                                                .font(.system(size: 13, weight: .medium))
                                                .foregroundStyle(isSelected ? DesignTokens.accentBlue : DesignTokens.textSecondary)
                                        } else {
                                            Image(systemName: "chevron.right")
                                                .font(.system(size: 9.5, weight: .semibold))
                                                .foregroundStyle(isExpanded ? Color.primary : DesignTokens.textTertiary)
                                                .rotationEffect(.degrees(isExpanded ? 90 : 0))
                                        }
                                    }
                                    .frame(width: 14, height: 14)

                                    Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                                        .resizable()
                                        .frame(width: 20, height: 20)
                                        .accessibilityHidden(true)

                                    Text(app.name)
                                        .font(.system(size: 13))
                                        .foregroundStyle(.primary)
                                        .lineLimit(1)

                                    Spacer(minLength: 8)

                                    if isAgentKey {
                                        Menu {
                                            ForEach(ApplicationClassification.allCases, id: \.self) { classification in
                                                Button {
                                                    Task { await applicationsModel.classify(app, as: classification) }
                                                } label: {
                                                    if app.classification == classification {
                                                        Label(classification.title, systemImage: "checkmark")
                                                    } else {
                                                        Text(classification.title)
                                                    }
                                                }
                                            }
                                        } label: {
                                            settingsPopupLabel(app.classification.title)
                                        }
                                        .menuStyle(.button)
                                        .buttonStyle(.plain)
                                        .menuIndicator(.hidden)
                                        .fixedSize()
                                        .disabled(isRemoveMode || applicationsModel.isBusy)
                                        .accessibilityLabel("Access for \(app.name)")
                                    } else {
                                        Text("Blocked")
                                            .font(.system(size: 13))
                                            .foregroundStyle(DesignTokens.textSecondary)
                                    }
                                }
                                .padding(.horizontal, 12)
                                .frame(minHeight: 38)
                                .background(
                                    isSelected
                                        ? DesignTokens.accentBlue.opacity(0.14)
                                        : (isExpanded ? Color.primary.opacity(0.03) : Color.clear)
                                )
                                .contentShape(Rectangle())
                                .onTapGesture {
                                    withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                                        if isRemoveMode {
                                            if selectedForRemoval.contains(app.id) {
                                                selectedForRemoval.remove(app.id)
                                            } else {
                                                selectedForRemoval.insert(app.id)
                                            }
                                        } else {
                                            if expandedAppIds.contains(app.id) {
                                                expandedAppIds.remove(app.id)
                                            } else {
                                                expandedAppIds.insert(app.id)
                                            }
                                        }
                                    }
                                }

                                if isExpanded {
                                    expandedAccessDrawer(for: app)
                                        .transition(.opacity.combined(with: .move(edge: .top)))
                                }

                                if index < apps.count - 1 {
                                    insetDivider
                                }
                            }
                        }
                    }
                }

                Divider()
                    .overlay(DesignTokens.settingsRowDivider)

                // Bottom [+ | −] / [Delete | Cancel] Action Bar
                HStack(spacing: 2) {
                    if isRemoveMode {
                        Button(role: .destructive) {
                            let ids = selectedForRemoval
                            withAnimation(.spring(response: 0.26, dampingFraction: 0.82)) {
                                isRemoveMode = false
                                selectedForRemoval.removeAll()
                            }
                            Task {
                                await applicationsModel.remove(ids: ids)
                            }
                        } label: {
                            Text(selectedForRemoval.isEmpty ? "Delete" : "Delete (\(selectedForRemoval.count))")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(selectedForRemoval.isEmpty ? DesignTokens.textSecondary : Color.red)
                                .padding(.horizontal, 8)
                                .frame(height: 24)
                        }
                        .buttonStyle(.borderless)
                        .disabled(selectedForRemoval.isEmpty || applicationsModel.isBusy)

                        Divider().frame(height: 14)

                        Button {
                            withAnimation(.spring(response: 0.26, dampingFraction: 0.82)) {
                                isRemoveMode = false
                                selectedForRemoval.removeAll()
                            }
                        } label: {
                            Text("Cancel")
                                .font(.system(size: 12))
                                .padding(.horizontal, 8)
                                .frame(height: 24)
                        }
                        .buttonStyle(.borderless)

                        Spacer()
                    } else {
                        Menu {
                            if !candidateAppsForPlus.isEmpty {
                                Section("Registered Applications") {
                                    ForEach(candidateAppsForPlus) { app in
                                        Button {
                                            Task {
                                                await applicationsModel.classify(
                                                    app,
                                                    as: isAgentKey ? .bot : .block
                                                )
                                            }
                                        } label: {
                                            Text("\(app.name) (\(app.path))")
                                        }
                                    }
                                }
                                Divider()
                            }
                            Button("Choose from File System…") {
                                chooseApplicationFromFileSystem()
                            }
                        } label: {
                            Image(systemName: "plus")
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundStyle(DesignTokens.textSecondary)
                                .frame(width: 24, height: 22)
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.hidden)
                        .fixedSize()
                        .help("Add application from Registered Applications or File System")
                        .accessibilityLabel("Add application")

                        Divider().frame(height: 12)

                        Button {
                            withAnimation(.spring(response: 0.26, dampingFraction: 0.82)) {
                                isRemoveMode = true
                                expandedAppIds.removeAll()
                                selectedForRemoval.removeAll()
                            }
                        } label: {
                            Image(systemName: "minus")
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundStyle(apps.isEmpty ? DesignTokens.textTertiary : DesignTokens.textSecondary)
                                .frame(width: 24, height: 22)
                        }
                        .buttonStyle(.borderless)
                        .disabled(apps.isEmpty || applicationsModel.isBusy)
                        .help("Select applications to remove")
                        .accessibilityLabel("Remove applications")

                        Spacer()

                        if applicationsModel.isBusy {
                            ProgressView().controlSize(.small).padding(.trailing, 6)
                        }
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            }
            .modifier(SettingsGroupCardModifier())
        }
    }

    private func expandedAccessDrawer(for app: RegisteredApplication) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 4) {
                GridRow {
                    Text("Identity")
                        .font(.system(size: 11.5))
                        .foregroundStyle(DesignTokens.textSecondary)
                    Text(app.identity.kind == .designatedRequirement ? "Designated Requirement" : "Executable SHA-256")
                        .font(.system(size: 11.5))
                }
                GridRow {
                    Text("Requirement")
                        .font(.system(size: 11.5))
                        .foregroundStyle(DesignTokens.textSecondary)
                    Text(Self.trimIdentity(app.identity.value))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                GridRow {
                    Text("Path")
                        .font(.system(size: 11.5))
                        .foregroundStyle(DesignTokens.textSecondary)
                    HStack(spacing: 6) {
                        Text(app.path)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(DesignTokens.textSecondary)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(app.path, forType: .string)
                            onShowToast?("Copied executable path")
                        } label: {
                            Image(systemName: "doc.on.doc")
                                .font(.system(size: 10.5))
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                        .buttonStyle(.borderless)
                        .help("Copy executable path")
                    }
                }
            }
        }
        .padding(.leading, 36)
        .padding(.trailing, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.02))
    }

    private func chooseApplicationFromFileSystem() {
        let panel = NSOpenPanel()
        panel.title = "Add application or executable"
        panel.prompt = "Add"
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        let targetClassification: ApplicationClassification = isAgentKey ? .bot : .block
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in
                await applicationsModel.add(url: url, classification: targetClassification)
            }
        }
    }

    // MARK: - Section 4: Recent Activity

    private var recentActivitySection: some View {
        let paused = appState.requestPolicy.isPaused
        let sessions = paused ? [] : appState.agentSessions.filter { $0.keyFingerprint == key.fingerprint }

        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                sectionHeaderTitle("Recent Activity")
                Spacer()
                Button {
                    appState.openHistoryPane(forKeyFingerprint: key.fingerprint)
                } label: {
                    Text("Show All History…")
                        .font(.system(size: 12))
                        .foregroundStyle(DesignTokens.accentBlue)
                }
                .buttonStyle(.plain)
            }

            VStack(spacing: 0) {
                HStack(spacing: 12) {
                    Text("Created")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(formattedDate)
                        .font(.system(size: 13))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                HStack(spacing: 12) {
                    Text("Last activity")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(formattedLastActivity)
                        .font(.system(size: 13))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                if !paused, let grace = activeGitGraceSession {
                    insetDivider
                    HStack(spacing: 12) {
                        Text("Git signing session")
                            .font(.system(size: 13))
                        Spacer()
                        Text(grace.formattedTime)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(DesignTokens.textSecondary)
                        settingsActionButton("Revoke") {
                            appState.revokeGitGrace(keyLabel: key.label)
                        }
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 38)
                }

                ForEach(sessions, id: \.id) { session in
                    insetDivider
                    HStack(spacing: 12) {
                        Text(session.toolName)
                            .font(.system(size: 13))
                            .lineLimit(1)
                        Spacer()
                        Text("SSH · expires \(session.expiresAt.formatted(date: .omitted, time: .shortened))")
                            .font(.system(size: 12))
                            .foregroundStyle(DesignTokens.textSecondary)
                        settingsActionButton("Revoke") {
                            appState.endAgentSession(id: session.id)
                        }
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 38)
                }
            }
            .modifier(SettingsGroupCardModifier())
        }
    }

    // MARK: - Section 5: Key Lifecycle (calm neutral card, never a red "Danger Zone")

    private var keyLifecycleSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle("Key Lifecycle")

            VStack(spacing: 0) {
                // Disable this key / Enable this key
                lifecycleRow(
                    label: isKeyEnabled ? "Disable this key" : "Enable this key",
                    sublabel: isKeyEnabled
                        ? "Temporarily refuse all signing requests while keeping grants and settings intact."
                        : "This key is currently disabled. Re-enable it to allow signing again."
                ) {
                    settingsActionButton(isKeyEnabled ? "Disable Key" : "Enable Key") {
                        toggleKeyEnabled()
                    }
                }

                insetDivider

                // Rotate key
                lifecycleRow(
                    label: "Rotate key",
                    sublabel: "Create a replacement key with the same settings."
                ) {
                    settingsActionButton("Rotate Key…") {
                        rotateKey()
                    }
                }

                insetDivider

                // Delete this key (red label, neutral card)
                lifecycleRow(
                    label: "Delete this key",
                    sublabel: "Permanently destroy the private key on this Mac. Issued signatures cannot be revoked (INV-01)."
                ) {
                    Button {
                        showingDeleteAlert = true
                    } label: {
                        Text("Delete Key…")
                            .font(.system(size: 12, weight: .regular))
                            .foregroundStyle(.red)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .contentShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    }
                    .buttonStyle(.plain)
                }
            }
            .modifier(SettingsGroupCardModifier())
        }
    }

    private func lifecycleRow<Control: View>(
        label: String,
        sublabel: String,
        @ViewBuilder control: () -> Control
    ) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.system(size: 13))
                    .foregroundStyle(.primary)
                Text(sublabel)
                    .font(.system(size: 11.5))
                    .foregroundStyle(DesignTokens.textSecondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            control()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
    }

    // MARK: - Shared UI Helpers & Actions

    private var insetDivider: some View {
        Rectangle()
            .fill(DesignTokens.settingsRowDivider)
            .frame(height: 1)
            .padding(.horizontal, 12)
    }

    private func sectionHeaderTitle(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.primary)
    }

    private func settingsPopupLabel(_ text: String) -> some View {
        HStack(spacing: 5) {
            Text(text)
                .font(.system(size: 13))
                .foregroundStyle(DesignTokens.textSecondary)
            Image(systemName: "chevron.up.chevron.down")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(DesignTokens.textSecondary)
        }
        .padding(.vertical, 3)
        .padding(.horizontal, 4)
        .contentShape(Rectangle())
    }

    private func settingsActionButton(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 12, weight: .regular))
                .foregroundStyle(.primary)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.primary.opacity(0.08))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .strokeBorder(Color.primary.opacity(0.10), lineWidth: 0.5)
                )
        }
        .buttonStyle(.plain)
    }

    private func changeProfile(type: KeyType? = nil, capabilities: KeyCapabilities? = nil) {
        // Stages one authenticated request and shows the in-window tile. The effective setting stays
        // unchanged until the mutation layer persists it; reverting a control never restarts a request.
        appState.policyMutations.submit(
            key: key, type: type, capabilities: capabilities, appState: appState
        ) { error in
            guard let error else { return }
            changePurposeError = error.localizedDescription
            showingChangePurposeError = true
        }
    }

    private func changeUnlockedTimeout(_ option: KeyGracePeriod) {
        guard option != appState.gracePeriod(for: key) else { return }
        appState.policyMutations.submit(
            key: key, unlockedTimeout: option, appState: appState
        ) { error in
            if let error {
                changePurposeError = error.localizedDescription
                showingChangePurposeError = true
            } else {
                onShowToast?("Unlocked timeout set to \(option.title). Active sessions locked.")
            }
        }
    }

    private func copyOpenSSHWithFeedback() {
        copyOpenSSH()
        withAnimation(.easeInOut(duration: 0.15)) {
            copiedPublicKey = true
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
            withAnimation(.easeInOut(duration: 0.15)) {
                copiedPublicKey = false
            }
        }
    }

    private func copyFingerprintWithFeedback() {
        copyFingerprint()
        withAnimation(.easeInOut(duration: 0.15)) {
            copiedFingerprint = true
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
            withAnimation(.easeInOut(duration: 0.15)) {
                copiedFingerprint = false
            }
        }
    }

    private func copyFilePathWithFeedback() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(publicKeyFilePath, forType: .string)
        onShowToast?("Copied to clipboard")
        withAnimation(.easeInOut(duration: 0.15)) {
            copiedFilePath = true
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
            withAnimation(.easeInOut(duration: 0.15)) {
                copiedFilePath = false
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

    /// Semantic actions available in the toolbar overflow (⋯) menu — the only trailing control.
    enum OverflowMenuAction: String, CaseIterable, Equatable, Sendable {
        case copyPublicKey
        case toggleEnabled
        case rotateKey
        case deleteKey
    }

    /// Returns the ordered list of actions present in the overflow (⋯) menu for the given key.
    /// History never lives here (it has its own toolbar/sidebar entry points).
    static func overflowMenuActions(for key: SSHKeyInfo) -> [OverflowMenuAction] {
        [.copyPublicKey, .toggleEnabled, .rotateKey, .deleteKey]
    }

    // MARK: - D-40 Confirmation Copy (S03.confirmation)

    /// The three current confirmation policies, in prototype order.
    static let confirmationPolicies: [BiometricPolicy] = [.biometryOrPasscode, .userPresence, .devicePasscode]

    /// Biometric-bound keys carry a hardware minimum that can never be lowered to password-only.
    static func isBiometricBound(_ policy: BiometricPolicy) -> Bool {
        policy == .biometryCurrentSet || policy == .biometryOrPasscode
    }

    /// S03.confirmation.footnote: "Confirm with <policy subtitle>. One confirmation is reused for
    /// <timeout> per requesting app; inside that window, signing is silent." + hardware minimum.
    static func confirmationFootnote(for key: SSHKeyInfo, period: KeyGracePeriod) -> String {
        let policy = key.effectiveBiometricPolicy
        var text = "Confirm with \(policy.subtitle). One confirmation is reused for \(period.title) per requesting app; inside that window, signing is silent."
        if isBiometricBound(policy) {
            text += " Hardware minimum: biometric-bound (fixed at creation)."
        }
        return text
    }

    /// S03.public-key.footnote: the storage guarantee under the Public Key card.
    static var publicKeyStorageFootnote: String {
        "Private key stored in Secure Enclave · never leaves this Mac."
    }

    /// S03.hero.subtitle: owner profile + last used only.
    static func toolbarSubtitle(isAgentKey: Bool, lastUsed: String?) -> String {
        let owner = isAgentKey ? "Agent key" : "Personal key"
        if let lastUsed, !lastUsed.isEmpty {
            return "\(owner) · Last used \(lastUsed)"
        }
        return "\(owner) · Not used yet"
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
