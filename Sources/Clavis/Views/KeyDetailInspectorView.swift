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

// MARK: - Scroll Offset Tracking

private struct InspectorScrollOffsetPreferenceKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
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
        textField.font = NSFont.systemFont(ofSize: 22, weight: .bold)
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

    @StateObject private var applicationsModel: ApplicationSettingsModel

    @State private var isRenaming: Bool = false
    @State private var draftKeyName: String = ""
    @State private var showingDeleteAlert: Bool = false
    @State private var showingRotateInfoAlert: Bool = false
    @State private var changePurposeError: String? = nil
    @State private var showingChangePurposeError: Bool = false
    @State private var lastActivityDate: Date? = nil
    @State private var isScrolled: Bool = false

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
        applicationAgent: any AgentControlling = AgentLifecycleManager.shared
    ) {
        self.key = key
        self.appState = appState
        self.onDelete = onDelete
        self.onShowToast = onShowToast
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
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                heroHeader

                if !isKeyEnabled {
                    disabledKeyCallout
                }

                publicKeySection
                confirmationSection
                accessSection
                recentActivitySection
                dangerZoneSection
            }
            .padding(22)
            .frame(maxWidth: 680, alignment: .leading)
            .frame(maxWidth: .infinity)
            .background(
                GeometryReader { proxy in
                    Color.clear.preference(
                        key: InspectorScrollOffsetPreferenceKey.self,
                        value: -proxy.frame(in: .named("inspectorScroll")).minY
                    )
                }
            )
        }
        .coordinateSpace(name: "inspectorScroll")
        .onPreferenceChange(InspectorScrollOffsetPreferenceKey.self) { offset in
            let shouldShow = offset > 8
            if isScrolled != shouldShow {
                withAnimation(.easeInOut(duration: 0.18)) {
                    isScrolled = shouldShow
                }
            }
        }
        .overlay(alignment: .top) {
            if isScrolled {
                stickyHeaderBar
                    .transition(.opacity.combined(with: .move(edge: .top)))
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

    // MARK: - Sticky Header & Hero Header

    private var stickyHeaderBar: some View {
        HStack(spacing: 10) {
            keyTile(size: 26, cornerRadius: 7, iconSize: 13, withAmbientShadow: false)

            Text(key.label)
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)

            statusPill

            Spacer(minLength: 8)

            Text("\(key.effectiveAccessProfile.type.title) key · \(capabilitySummary)")
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 22)
        .frame(height: 44)
        .background(.ultraThinMaterial)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(DesignTokens.cardBorder)
                .frame(height: 1)
        }
        .shadow(color: Color.black.opacity(0.06), radius: 8, x: 0, y: 3)
    }

    private var heroHeader: some View {
        HStack(alignment: .center, spacing: 14) {
            keyTile(size: 48, cornerRadius: 13, iconSize: 21, withAmbientShadow: true)

            VStack(alignment: .leading, spacing: 6) {
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
                            .font(.system(size: 22, weight: .bold))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .truncationMode(.tail)

                        Button(action: beginInlineRename) {
                            Image(systemName: "pencil")
                                .font(.system(size: 12.5, weight: .medium))
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                        .buttonStyle(.plain)
                        .help("Rename \(key.label)")
                        .accessibilityLabel("Rename \(key.label)")

                        statusPill
                    }
                    .frame(height: 28, alignment: .leading)
                }

                // Metadata chips row
                HStack(spacing: 6) {
                    metadataChip(
                        icon: isBotKey ? "cpu" : "person.fill",
                        text: isBotKey ? "Bot key" : "Personal key"
                    )

                    if key.effectiveAccessProfile.capabilities.ssh {
                        metadataChip(icon: "terminal", text: "SSH authentication")
                    }
                    if key.effectiveAccessProfile.capabilities.signature {
                        metadataChip(icon: "signature", text: "Git signing")
                    }

                    if lastActivityDate != nil {
                        metadataChip(icon: "clock", text: "Last used: \(formattedLastActivity)")
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.bottom, 2)
    }

    private func keyTile(size: CGFloat, cornerRadius: CGFloat, iconSize: CGFloat, withAmbientShadow: Bool) -> some View {
        let gradientColors: [Color] = isBotKey
            ? [Color(red: 0.64, green: 0.54, blue: 0.91), Color(red: 0.43, green: 0.32, blue: 0.78)]
            : [Color(red: 0.35, green: 0.64, blue: 1.0), DesignTokens.accentBlue]
        let glowColor: Color = isBotKey ? Color.purple : DesignTokens.accentBlue

        return ZStack {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: gradientColors,
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .strokeBorder(Color.white.opacity(0.28), lineWidth: 0.8)
            Image(systemName: isBotKey ? "cpu" : "person.fill")
                .font(.system(size: iconSize, weight: .semibold))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .shadow(
            color: withAmbientShadow ? glowColor.opacity(0.35) : Color.black.opacity(0.12),
            radius: withAmbientShadow ? 9 : 2,
            x: 0,
            y: withAmbientShadow ? 4 : 1
        )
    }

    private var statusPill: some View {
        let active = isKeyEnabled
        let pillColor = active ? DesignTokens.accentGreen : DesignTokens.accentOrange
        return HStack(spacing: 5) {
            Circle()
                .fill(pillColor)
                .frame(width: 6, height: 6)
            Text(active ? "Active" : "Disabled")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(pillColor)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 2.5)
        .background(
            Capsule()
                .fill(pillColor.opacity(0.13))
        )
        .overlay(
            Capsule()
                .strokeBorder(pillColor.opacity(0.26), lineWidth: 0.8)
        )
    }

    private func metadataChip(icon: String, text: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(DesignTokens.textSecondary)
            Text(text)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(DesignTokens.textSecondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 2.5)
        .background(
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .fill(Color.primary.opacity(0.05))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .strokeBorder(DesignTokens.cardBorder, lineWidth: 0.7)
        )
    }

    private var disabledKeyCallout: some View {
        HStack(spacing: 10) {
            Image(systemName: "pause.circle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(DesignTokens.accentOrange)
            Text("This key is disabled. All SSH and Git signing requests are refused.")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.primary)
            Spacer()
            Button("Enable") {
                changeProfile(capabilities: KeyCapabilities(ssh: true, signature: true))
            }
            .controlSize(.small)
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 9)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(DesignTokens.accentOrange.opacity(0.11))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(DesignTokens.accentOrange.opacity(0.32), lineWidth: 0.8)
        )
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

    // MARK: - Section 1: PUBLIC KEY

    private var publicKeySection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                sectionHeaderTitle("PUBLIC KEY")
                Spacer()
                Button(action: addToGitHub) {
                    Text("Add to GitHub… ↗")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(DesignTokens.accentBlue)
                }
                .buttonStyle(.plain)
                .help("Copy public key and open GitHub SSH settings")
            }

            VStack(spacing: 0) {
                // Featured OpenSSH Public Key Block
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Text(key.algorithm)
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                            .foregroundStyle(DesignTokens.accentBlue)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(
                                RoundedRectangle(cornerRadius: 4, style: .continuous)
                                    .fill(DesignTokens.accentBlue.opacity(0.12))
                            )

                        Text("OpenSSH Public Key")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(DesignTokens.textSecondary)

                        Spacer()

                        Button(action: copyOpenSSHWithFeedback) {
                            HStack(spacing: 4) {
                                Image(systemName: copiedPublicKey ? "checkmark" : "doc.on.doc")
                                    .font(.system(size: 10.5, weight: .semibold))
                                Text(copiedPublicKey ? "Copied" : "Copy Key")
                                    .font(.system(size: 11.5, weight: .medium))
                            }
                            .foregroundStyle(copiedPublicKey ? DesignTokens.accentGreen : .primary)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 3.5)
                            .background(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .fill(Color(nsColor: .controlBackgroundColor))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .strokeBorder(DesignTokens.cardBorder, lineWidth: 0.8)
                            )
                        }
                        .buttonStyle(.plain)
                        .help("Copy full OpenSSH public key")
                    }

                    Text(key.publicKeyOpenSSH)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(11)
                .background(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(Color.primary.opacity(0.04))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(DesignTokens.cardBorder, lineWidth: 0.7)
                )
                .padding(11)

                Divider()

                // Fingerprint row
                HStack(spacing: 11) {
                    rowIconBox(systemName: "touchid", tint: DesignTokens.accentBlue)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Fingerprint")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary)
                        Text(formattedFingerprint)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(DesignTokens.textSecondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button(action: copyFingerprintWithFeedback) {
                        Image(systemName: copiedFingerprint ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(copiedFingerprint ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                            .frame(width: 26, height: 26)
                    }
                    .buttonStyle(.borderless)
                    .help(ClavisUIStrings.Inspector.copyFingerprintHelp)
                    .accessibilityLabel(ClavisUIStrings.Accessibility.copyFingerprint)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                Divider()

                // Public key file row
                HStack(spacing: 11) {
                    rowIconBox(systemName: "doc.text", tint: DesignTokens.accentBlue)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Public key file")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary)
                        Text(publicKeyFilePath)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(DesignTokens.textSecondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button(action: copyFilePathWithFeedback) {
                        Image(systemName: copiedFilePath ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(copiedFilePath ? DesignTokens.accentGreen : DesignTokens.textSecondary)
                            .frame(width: 26, height: 26)
                    }
                    .buttonStyle(.borderless)
                    .help("Copy public key file path")
                    .accessibilityLabel("Copy public key file path")
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)
            }
            .glassCard(cornerRadius: 11)
        }
    }

    // MARK: - Section 2: CONFIRMATION

    private var confirmationSection: some View {
        let profile = key.effectiveAccessProfile
        return VStack(alignment: .leading, spacing: 6) {
            sectionHeaderTitle("CONFIRMATION")

            VStack(spacing: 0) {
                // Key Type row
                HStack(spacing: 11) {
                    rowIconBox(
                        systemName: "person.badge.key.fill",
                        tint: isBotKey ? Color.purple : DesignTokens.accentBlue
                    )

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Key profile")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary)
                        Text("Personal apps can use all keys; Bots can use Bot keys")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Picker("Type", selection: Binding(
                        get: { profile.type },
                        set: { type in changeProfile(type: type) }
                    )) {
                        ForEach(KeyType.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                    .labelsHidden()
                    .frame(width: 115)
                    .help("Changing key type requires fresh authentication and revokes approvals.")
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                Divider()

                // Confirmation level row
                HStack(spacing: 11) {
                    rowIconBox(systemName: "checkmark.shield", tint: DesignTokens.accentGreen)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Confirmation level")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary)
                        Text(Self.approvalDescriptionText(for: key))
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Text(Self.approvalSummaryText(for: key))
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(
                            RoundedRectangle(cornerRadius: 5, style: .continuous)
                                .fill(Color.primary.opacity(0.06))
                        )
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                Divider()

                // SSH authentication capability row
                HStack(spacing: 11) {
                    rowIconBox(systemName: "terminal", tint: DesignTokens.accentBlue)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("SSH authentication")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary)
                        Text("Authenticate to remote hosts and Git remotes over SSH")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

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
                    .labelsHidden()
                    .accessibilityLabel("SSH authentication enabled")
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                Divider()

                // Git signing capability row
                HStack(spacing: 11) {
                    rowIconBox(systemName: "signature", tint: DesignTokens.accentIndigo)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Git signing")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundStyle(.primary)
                        Text("Sign Git commits and tags locally with SSHSIG")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

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
                    .labelsHidden()
                    .accessibilityLabel("Git signing enabled")
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                Divider()

                // Integrated Touch ID Policy strip
                HStack(spacing: 10) {
                    Image(systemName: "touchid")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(DesignTokens.accentBlue)

                    VStack(alignment: .leading, spacing: 1) {
                        Text("Touch ID Policy")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.primary)
                        Text("Hardware-bound in Apple Secure Enclave · \(key.effectiveBiometricPolicy.title)")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Text("Touch ID enabled")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(DesignTokens.accentGreen)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2.5)
                        .background(
                            Capsule()
                                .fill(DesignTokens.accentGreen.opacity(0.14))
                        )
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)
                .background(DesignTokens.accentBlue.opacity(0.05))
            }
            .glassCard(cornerRadius: 11)
        }
    }

    // MARK: - Section 3: ACCESS / NEVER ALLOW (Expandable NSOutlineView Variant 3)

    private var accessSection: some View {
        let apps = displayedApplications
        let candidateAppsForPlus: [RegisteredApplication] = isBotKey
            ? applicationsModel.applications.filter { $0.classification != .bot }
            : applicationsModel.applications.filter { $0.classification != .block }

        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                sectionHeaderTitle(isBotKey ? "ACCESS" : "NEVER ALLOW")
                Spacer()
                Text("\(apps.count) \(apps.count == 1 ? "app" : "apps")")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Capsule().fill(Color.primary.opacity(0.06)))
            }

            VStack(spacing: 0) {
                // Column header bar
                HStack(spacing: 10) {
                    Text("Application")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .padding(.leading, 26)
                    Spacer()
                    Text("Trust Identity")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .padding(.trailing, 28)
                    Text(isBotKey ? "Permission" : "Rule")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .frame(width: 105, alignment: .trailing)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Color.primary.opacity(0.03))

                Divider()

                if apps.isEmpty {
                    Text(
                        isBotKey
                            ? "No applications configured. Unknown applications trigger a first-use request."
                            : "None — any application can ask for your Touch ID confirmation."
                    )
                    .font(.system(size: 12))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 16)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(apps.enumerated()), id: \.element.id) { index, app in
                            let isExpanded = !isRemoveMode && expandedAppIds.contains(app.id)
                            let isSelected = isRemoveMode && selectedForRemoval.contains(app.id)

                            VStack(spacing: 0) {
                                HStack(spacing: 10) {
                                    // Disclosure chevron / Remove checkbox slot
                                    ZStack {
                                        if isRemoveMode {
                                            Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                                                .font(.system(size: 13, weight: .medium))
                                                .foregroundStyle(isSelected ? DesignTokens.accentBlue : DesignTokens.textSecondary)
                                        } else {
                                            Image(systemName: "chevron.right")
                                                .font(.system(size: 10, weight: .bold))
                                                .foregroundStyle(isExpanded ? Color.primary : DesignTokens.textSecondary)
                                                .rotationEffect(.degrees(isExpanded ? 90 : 0))
                                        }
                                    }
                                    .frame(width: 18, height: 18)

                                    Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                                        .resizable()
                                        .frame(width: 28, height: 28)
                                        .accessibilityHidden(true)

                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 6) {
                                            Text(app.name)
                                                .font(.system(size: 13, weight: .semibold))
                                                .foregroundStyle(.primary)
                                                .lineLimit(1)

                                            identityBadge(for: app.identity)
                                        }
                                        Text(app.path)
                                            .font(.system(size: 11))
                                            .foregroundStyle(DesignTokens.textSecondary)
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)

                                    if isBotKey {
                                        Picker("Access for \(app.name)", selection: Binding(
                                            get: { app.classification },
                                            set: { newValue in
                                                Task { await applicationsModel.classify(app, as: newValue) }
                                            }
                                        )) {
                                            ForEach(ApplicationClassification.allCases, id: \.self) { classification in
                                                Text(classification.title).tag(classification)
                                            }
                                        }
                                        .labelsHidden()
                                        .frame(width: 105)
                                        .disabled(isRemoveMode || applicationsModel.isBusy)
                                    } else {
                                        Text("Blocked")
                                            .font(.system(size: 11, weight: .semibold))
                                            .foregroundStyle(Color.red)
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 2.5)
                                            .background(
                                                Capsule()
                                                    .fill(Color.red.opacity(0.12))
                                            )
                                    }
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 9)
                                .background(
                                    isSelected
                                        ? DesignTokens.accentBlue.opacity(0.12)
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
                                    Divider()
                                }
                            }
                        }
                    }
                }

                Divider()

                // Bottom [+ | −] / [Delete | Cancel] Action Bar
                HStack(spacing: 4) {
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
                                .font(.system(size: 12, weight: .semibold))
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
                                .font(.system(size: 12, weight: .medium))
                                .padding(.horizontal, 8)
                                .frame(height: 24)
                        }
                        .buttonStyle(.borderless)

                        Spacer()

                        Text(selectedForRemoval.isEmpty ? "Select applications to remove" : "\(selectedForRemoval.count) selected")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                            .padding(.trailing, 6)
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
                                .font(.system(size: 12, weight: .semibold))
                                .frame(width: 24, height: 22)
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.hidden)
                        .fixedSize()
                        .help("Add application from Registered Applications or File System")
                        .accessibilityLabel("Add application")

                        Divider().frame(height: 14)

                        Button {
                            withAnimation(.spring(response: 0.26, dampingFraction: 0.82)) {
                                isRemoveMode = true
                                expandedAppIds.removeAll()
                                selectedForRemoval.removeAll()
                            }
                        } label: {
                            Image(systemName: "minus")
                                .font(.system(size: 12, weight: .semibold))
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
                .padding(.vertical, 5)
                .background(Color.primary.opacity(0.03))
            }
            .glassCard(cornerRadius: 11)

            Text(
                isBotKey
                    ? "Bot applications allowed above can use this key. Unlisted apps ask on first use."
                    : "Personal apps can use this key with Touch ID. Applications in Never allow are always refused."
            )
            .font(.system(size: 11))
            .foregroundStyle(DesignTokens.textSecondary)
            .padding(.horizontal, 4)
        }
    }

    private func identityBadge(for identity: ApplicationIdentity) -> some View {
        let title = identity.kind == .designatedRequirement ? "Apple Notarized · DR" : "SHA-256"
        return Text(title)
            .font(.system(size: 10, weight: .medium))
            .foregroundStyle(DesignTokens.accentBlue)
            .padding(.horizontal, 6)
            .padding(.vertical, 1.5)
            .background(
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .fill(DesignTokens.accentBlue.opacity(0.11))
            )
    }

    private func expandedAccessDrawer(for app: RegisteredApplication) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 5) {
                GridRow {
                    Text("Identity Kind")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(DesignTokens.textSecondary)
                    Text(app.identity.kind == .designatedRequirement ? "Designated Requirement" : "Executable SHA-256")
                        .font(.system(size: 11.5))
                }
                GridRow {
                    Text("Identity Value")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(DesignTokens.textSecondary)
                    Text(Self.trimIdentity(app.identity.value))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                GridRow {
                    Text("Executable Path")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(DesignTokens.textSecondary)
                    HStack(spacing: 6) {
                        Text(app.path)
                            .font(.system(size: 11, design: .monospaced))
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
                GridRow {
                    Text("Access Policy")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(DesignTokens.textSecondary)
                    Text(app.classification.title)
                        .font(.system(size: 11.5, weight: .medium))
                }
            }

            Divider()

            HStack {
                Text("Removing \(app.name) with [−] unregisters it and revokes its approvals.")
                    .font(.system(size: 11))
                    .foregroundStyle(DesignTokens.textSecondary)
                Spacer()
                if app.classification != .block {
                    Button(role: .destructive) {
                        Task { await applicationsModel.classify(app, as: .block) }
                    } label: {
                        Text("Block \(app.name) on All Keys…")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(Color.red)
                    }
                    .buttonStyle(.borderless)
                }
            }
        }
        .padding(.leading, 36)
        .padding(.trailing, 14)
        .padding(.vertical, 10)
        .background(Color.primary.opacity(0.025))
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

    // MARK: - Section 4: RECENT ACTIVITY

    private var recentActivitySection: some View {
        let paused = appState.requestPolicy.isPaused
        let sessions = paused ? [] : appState.agentSessions.filter { $0.keyFingerprint == key.fingerprint }

        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                sectionHeaderTitle("RECENT ACTIVITY")
                Spacer()
                Button {
                    appState.openHistoryPane(forKeyFingerprint: key.fingerprint)
                } label: {
                    Text("Show All History →")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(DesignTokens.accentBlue)
                }
                .buttonStyle(.plain)
            }

            VStack(spacing: 0) {
                HStack(spacing: 11) {
                    rowIconBox(systemName: "calendar", tint: DesignTokens.accentBlue)
                    Text("Created")
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(formattedDate)
                        .font(.system(size: 12))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                Divider()

                HStack(spacing: 11) {
                    rowIconBox(systemName: "clock", tint: DesignTokens.accentBlue)
                    Text("Last activity")
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(formattedLastActivity)
                        .font(.system(size: 12))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 9)

                if !paused, let grace = activeGitGraceSession {
                    Divider()
                    HStack(spacing: 11) {
                        rowIconBox(systemName: "signature", tint: DesignTokens.accentGreen)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Git signing session")
                                .font(.system(size: 12.5, weight: .medium))
                            Text("Remaining time: \(grace.formattedTime)")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                        Spacer()
                        Button("Revoke") {
                            appState.revokeGitGrace(keyLabel: key.label)
                        }
                        .controlSize(.small)
                    }
                    .padding(.horizontal, 13)
                    .padding(.vertical, 9)
                }

                ForEach(sessions, id: \.id) { session in
                    Divider()
                    HStack(spacing: 11) {
                        rowIconBox(systemName: "terminal", tint: DesignTokens.accentGreen)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(session.toolName)
                                .font(.system(size: 12.5, weight: .medium))
                                .lineLimit(1)
                            Text("SSH · expires \(session.expiresAt.formatted(date: .omitted, time: .shortened))")
                                .font(.system(size: 11))
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                        Spacer()
                        Button("Revoke") {
                            appState.endAgentSession(id: session.id)
                        }
                        .controlSize(.small)
                    }
                    .padding(.horizontal, 13)
                    .padding(.vertical, 9)
                }
            }
            .glassCard(cornerRadius: 11)
        }
    }

    // MARK: - Section 5: DANGER ZONE

    private var dangerZoneSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("DANGER ZONE")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(Color.red)
                .padding(.horizontal, 2)

            VStack(spacing: 0) {
                // Disable Key / Enable Key
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(isKeyEnabled ? "Disable Key" : "Enable Key")
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(.primary)
                        Text("Temporarily stop all SSH and Git signing requests for this key.")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button(isKeyEnabled ? "Disable Key" : "Enable Key") {
                        if isKeyEnabled {
                            changeProfile(capabilities: KeyCapabilities(ssh: false, signature: false))
                        } else {
                            changeProfile(capabilities: KeyCapabilities(ssh: true, signature: true))
                        }
                    }
                    .controlSize(.small)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 10)

                Divider()
                    .overlay(Color.red.opacity(0.18))

                // Rotate Key…
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Rotate Key")
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(.primary)
                        Text("Generate a new Secure Enclave keypair and replace this key.")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button("Rotate Key…") {
                        if let onShowToast {
                            onShowToast("Key rotation will be connected in ClavisCore")
                        } else {
                            showingRotateInfoAlert = true
                        }
                    }
                    .controlSize(.small)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 10)

                Divider()
                    .overlay(Color.red.opacity(0.18))

                // Delete Key…
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Delete Key")
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(.primary)
                        Text("Permanently destroy this key from the Secure Enclave and revoke its approvals.")
                            .font(.system(size: 11))
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    Button("Delete Key…", role: .destructive) {
                        showingDeleteAlert = true
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .controlSize(.small)
                }
                .padding(.horizontal, 13)
                .padding(.vertical, 10)
            }
            .glassCard(
                cornerRadius: 11,
                strokeColor: Color.red.opacity(0.32),
                tint: Color.red.opacity(0.025)
            )
        }
    }

    // MARK: - Shared UI Helpers & Actions

    private func sectionHeaderTitle(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 11, weight: .bold))
            .foregroundStyle(DesignTokens.textSecondary)
            .padding(.horizontal, 2)
    }

    private func rowIconBox(systemName: String, tint: Color) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(tint.opacity(0.12))
                .frame(width: 30, height: 30)
            Image(systemName: systemName)
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundStyle(tint)
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
