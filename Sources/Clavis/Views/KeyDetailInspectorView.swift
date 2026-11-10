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
    @StateObject private var applicationsModel: ApplicationSettingsModel

    @State private var isRenaming: Bool = false
    @State private var draftKeyName: String = ""
    @State private var showingDeleteAlert: Bool = false
    @State private var showingRotateInfoAlert: Bool = false
    @State private var changePurposeError: String? = nil
    @State private var showingChangePurposeError: Bool = false
    @State private var lastActivityDate: Date? = nil

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

    private var isBotKey: Bool {
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
        if isBotKey {
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
                dangerZoneSection
            }
            .id("inspectorTop")
            .padding(.horizontal, 28)
            .padding(.top, 15)
            .padding(.bottom, 36)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        // A newly selected key always opens at its top, not at the previous key's scroll offset.
        .onChange(of: key.id) { _ in
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
            lastActivityDate = appState.lastActivityDate(for: key)
        }
        .onChange(of: key.id) { _ in
            isRenaming = false
            isRemoveMode = false
            expandedAppIds.removeAll()
            selectedForRemoval.removeAll()
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
        .alert("Rotate “\(key.label)”", isPresented: $showingRotateInfoAlert) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text("Key rotation will generate a replacement Secure Enclave keypair and keep existing policy grants.")
        }
        .alert(ClavisUIStrings.Common.error, isPresented: $showingChangePurposeError) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {}
        } message: {
            Text(changePurposeError ?? "")
        }
    }

    // MARK: - Prominent Header

    /// One row on the traffic-light line: key icon, title, History. The band is exactly the control
    /// height plus equal top/bottom padding, so the scroll-edge material sits symmetrically around it.
    private var prominentHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            identityRow
            if let onToggleHistory {
                ProminentHistoryButton(isActive: false, action: onToggleHistory)
            }
        }
        .padding(.horizontal, 28)
        .frame(height: KeyListView.toolbarHeight)
        .offset(y: headerCenterOffset)
    }

    private var identityRow: some View {
        HStack(alignment: .center, spacing: 12) {
            keyTile(size: 36, cornerRadius: 9, iconSize: 22)

            VStack(alignment: .leading, spacing: 0) {
                if isRenaming {
                    InlineKeyRenameField(
                        text: $draftKeyName,
                        onCommit: commitInlineRename,
                        onCancel: cancelInlineRename
                    )
                    .frame(height: 24, alignment: .leading)
                    .overlay(alignment: .bottom) {
                        Rectangle()
                            .fill(DesignTokens.accentBlue)
                            .frame(height: 1)
                    }
                    .accessibilityLabel("Key name")
                } else {
                    HStack(spacing: 7) {
                        Text(key.label)
                            .font(.system(size: 20, weight: .bold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .truncationMode(.tail)

                        Button(action: beginInlineRename) {
                            Image(systemName: "pencil")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                        .buttonStyle(.plain)
                        .help("Rename \(key.label)")
                        .accessibilityLabel("Rename \(key.label)")
                    }
                    .frame(height: 24, alignment: .leading)
                }

            }
            .frame(maxWidth: .infinity, alignment: .leading)
            // The removed visible caption stays available to assistive technology.
            .accessibilityElement(children: .contain)
            .accessibilityValue(heroSubtitleText)
        }
    }

    /// Type/storage/disabled summary, exposed only as an accessibility value (no visible caption).
    private var heroSubtitleText: String {
        var parts: [String] = [
            isBotKey ? "Bot" : "Personal",
            "Secure Enclave"
        ]
        if !isKeyEnabled {
            parts.append("Disabled")
        }
        return parts.joined(separator: " · ")
    }

    private func keyTile(size: CGFloat, cornerRadius: CGFloat, iconSize: CGFloat) -> some View {
        let gradientColors: [Color] = isBotKey
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
            Image(systemName: isBotKey ? "cpu" : "person.fill")
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
            Text("This key is disabled. All SSH and Git signing requests are refused.")
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
            HStack(alignment: .firstTextBaseline) {
                sectionHeaderTitle("Public Key")
                Spacer()
                Button(action: addToGitHub) {
                    Text("Add to GitHub…")
                        .font(.system(size: 12, weight: .regular))
                        .foregroundStyle(DesignTokens.accentBlue)
                }
                .buttonStyle(.plain)
                .help("Copy public key and open GitHub SSH settings")
            }

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

                // Storage and algorithm (full detail moved out of the compact header)
                HStack(spacing: 12) {
                    Text("Algorithm")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Text("Secure Enclave (\(key.algorithm))")
                        .font(.system(size: 12))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .textSelection(.enabled)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                // Row 4: Public key file
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
        }
    }

    // MARK: - Section 2: Confirmation

    private var confirmationSection: some View {
        let profile = key.effectiveAccessProfile
        return VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle("Confirmation")

            VStack(spacing: 0) {
                // Row 1: Key profile
                HStack(spacing: 12) {
                    Text("Key profile")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    settingsPopupLabel(profile.type.title)
                        .overlay {
                            Menu {
                                ForEach(KeyType.allCases, id: \.self) { type in
                                    Button {
                                        changeProfile(type: type)
                                    } label: {
                                        if profile.type == type {
                                            Label(type.title, systemImage: "checkmark")
                                        } else {
                                            Text(type.title)
                                        }
                                    }
                                }
                            } label: {
                                Color.clear
                            }
                            .menuStyle(.borderlessButton)
                            .menuIndicator(.hidden)
                        }
                        .help("Changing key type requires fresh authentication and revokes approvals.")
                        .accessibilityLabel("Key profile")
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                // Row 2: Confirmation level
                HStack(spacing: 12) {
                    Text("Confirmation level")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Text(Self.approvalSummaryText(for: key))
                        .font(.system(size: 13))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                // Row 3: SSH authentication
                HStack(spacing: 12) {
                    Text("SSH authentication")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Toggle("", isOn: Binding(
                        get: { profile.capabilities.ssh },
                        set: { enabled in
                            changeProfile(capabilities: KeyCapabilities(
                                ssh: enabled,
                                signature: profile.capabilities.signature
                            ))
                        }
                    ))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
                    .accessibilityLabel("SSH authentication enabled")
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)

                insetDivider

                // Row 4: Git signing
                HStack(spacing: 12) {
                    Text("Git signing")
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)

                    Spacer(minLength: 12)

                    Toggle("", isOn: Binding(
                        get: { profile.capabilities.signature },
                        set: { enabled in
                            changeProfile(capabilities: KeyCapabilities(
                                ssh: profile.capabilities.ssh,
                                signature: enabled
                            ))
                        }
                    ))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
                    .accessibilityLabel("Git signing enabled")
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 38)
            }
            .modifier(SettingsGroupCardModifier())

            Text(Self.approvalDescriptionText(for: key))
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
                .padding(.horizontal, 2)
        }
    }

    // MARK: - Section 3: Access / Never Allow (Expandable NSOutlineView Variant 3)

    private var accessSection: some View {
        let apps = displayedApplications
        let candidateAppsForPlus: [RegisteredApplication] = isBotKey
            ? applicationsModel.applications.filter { $0.classification != .bot }
            : applicationsModel.applications.filter { $0.classification != .block }

        return VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle(isBotKey ? "Access" : "Never Allow")

            VStack(spacing: 0) {
                if apps.isEmpty {
                    HStack {
                        Text(
                            isBotKey
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

                                    if isBotKey {
                                        settingsPopupLabel(app.classification.title)
                                            .overlay {
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
                                                    Color.clear
                                                }
                                                .menuStyle(.borderlessButton)
                                                .menuIndicator(.hidden)
                                            }
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
                                                    as: isBotKey ? .bot : .block
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
        let targetClassification: ApplicationClassification = isBotKey ? .bot : .block
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

    // MARK: - Section 5: Danger Zone

    private var dangerZoneSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeaderTitle("Danger Zone")

            VStack(spacing: 0) {
                // Disable Key / Enable Key
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(isKeyEnabled ? "Disable Key" : "Enable Key")
                            .font(.system(size: 13))
                            .foregroundStyle(.primary)
                        Text("Temporarily stop all SSH and Git signing requests for this key.")
                            .font(.system(size: 11.5))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    settingsActionButton(isKeyEnabled ? "Disable Key" : "Enable Key") {
                        if isKeyEnabled {
                            changeProfile(capabilities: KeyCapabilities(ssh: false, signature: false))
                        } else {
                            changeProfile(capabilities: KeyCapabilities(ssh: true, signature: true))
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)

                insetDivider

                // Rotate Key…
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Rotate Key")
                            .font(.system(size: 13))
                            .foregroundStyle(.primary)
                        Text("Generate a new Secure Enclave keypair and replace this key.")
                            .font(.system(size: 11.5))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    settingsActionButton("Rotate Key…") {
                        if let onShowToast {
                            onShowToast("Key rotation will be connected in ClavisCore")
                        } else {
                            showingRotateInfoAlert = true
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)

                insetDivider

                // Delete Key…
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Delete Key")
                            .font(.system(size: 13))
                            .foregroundStyle(.primary)
                        Text("Permanently destroy this key from the Secure Enclave and revoke its approvals.")
                            .font(.system(size: 11.5))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button("Delete Key…", role: .destructive) {
                        showingDeleteAlert = true
                    }
                    .controlSize(.small)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
            }
            .modifier(SettingsGroupCardModifier())
        }
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

    private func addToGitHub() {
        copyOpenSSH()
        if !ClavisEnvironment.isTesting, let url = URL(string: "https://github.com/settings/ssh/new") {
            NSWorkspace.shared.open(url)
        }
        onShowToast?("Public key copied — opening GitHub SSH settings")
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
