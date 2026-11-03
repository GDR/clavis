import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct KeyListView: View {
    @EnvironmentObject var appState: AppState
    @StateObject private var historyViewModel = HistoryViewModel()
    @StateObject private var historyUI = HistoryUIState()

    @State private var selectedKeyId: String? = nil
    @State private var statusMessage: String? = nil
    @State private var kindFilter: KeyKindFilter = .all
    @State private var searchText: String = ""
    @State private var keyPendingDeletion: SSHKeyInfo? = nil
    @State private var confirmingRevokeAll = false
    @FocusState private var isSearchFieldFocused: Bool

    public static let sidebarWidth: CGFloat = 260
    public static let toolbarHeight: CGFloat = 52
    public static let searchCapsuleHeight: CGFloat = 36
    public static let emptyStateTitle = "A key that stays on your Mac."
    public static let emptyStateSubtitle = "Create a hardware-backed identity for SSH and Git. Your private key stays in the Secure Enclave."
    public static let emptyStateCreateButtonTitle = "Create your first key"
    public static let historyVerifiedTooltip = "The signing history's linked hashes have been checked for changes or missing records."

    static func filterKeys(_ keys: [SSHKeyInfo], query: String, kind: KeyKindFilter = .all) -> [SSHKeyInfo] {
        let kindFiltered = KeyKindFilter.apply(kind, to: keys)
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return kindFiltered }
        return kindFiltered.filter { key in
            key.label.localizedCaseInsensitiveContains(trimmed) ||
            key.algorithm.localizedCaseInsensitiveContains(trimmed) ||
            key.fingerprint.localizedCaseInsensitiveContains(trimmed)
        }
    }

    static func nextSelectedKeyId(keys: [SSHKeyInfo], currentId: String?) -> String? {
        guard !keys.isEmpty else { return nil }
        guard let currentId = currentId,
              let currentIndex = keys.firstIndex(where: { $0.id == currentId }) else {
            return keys.first?.id
        }
        if currentIndex < keys.count - 1 {
            return keys[currentIndex + 1].id
        } else {
            return keys[currentIndex].id
        }
    }

    static func previousSelectedKeyId(keys: [SSHKeyInfo], currentId: String?) -> String? {
        guard !keys.isEmpty else { return nil }
        guard let currentId = currentId,
              let currentIndex = keys.firstIndex(where: { $0.id == currentId }) else {
            return keys.first?.id
        }
        if currentIndex > 0 {
            return keys[currentIndex - 1].id
        } else {
            return keys[currentIndex].id
        }
    }

    private var filteredKeys: [SSHKeyInfo] {
        Self.filterKeys(appState.keys, query: searchText, kind: kindFilter)
    }

    private var selectedKey: SSHKeyInfo? {
        if let id = selectedKeyId {
            return filteredKeys.first(where: { $0.id == id })
        }
        return filteredKeys.first
    }

    private func selectNextKey() {
        if let nextId = Self.nextSelectedKeyId(keys: filteredKeys, currentId: selectedKey?.id) {
            selectedKeyId = nextId
            appState.activeMainPane = .keys
        }
    }

    private func selectPreviousKey() {
        if let prevId = Self.previousSelectedKeyId(keys: filteredKeys, currentId: selectedKey?.id) {
            selectedKeyId = prevId
            appState.activeMainPane = .keys
        }
    }

    private var isHistoryActive: Bool { appState.activeMainPane == .history }

    private func toggleHistoryPane() {
        if appState.activeMainPane == .history {
            leaveHistory()
        } else {
            // Opening from a key scopes History to exactly that key.
            appState.openHistoryPane(forKeyFingerprint: selectedKey?.fingerprint)
        }
    }

    /// Back restores the key/detail context; `selectedKeyId` is kept in step with the sidebar.
    private func leaveHistory() {
        historyUI.dismiss()
        appState.activeMainPane = .keys
    }

    private func focusSearch() {
        if isHistoryActive {
            historyViewModel.beginSuggesting()
            historyUI.requestSearchFocus(opensSuggestions: true)
        } else {
            isSearchFieldFocused = true
        }
    }

    private var isErrorAlertPresented: Binding<Bool> {
        Binding(
            get: { appState.errorMessage != nil },
            set: { if !$0 { appState.errorMessage = nil } }
        )
    }

    private var isDeleteAlertPresented: Binding<Bool> {
        Binding(
            get: { keyPendingDeletion != nil },
            set: { if !$0 { keyPendingDeletion = nil } }
        )
    }

    private var rootSplitView: some View {
        ZStack(alignment: .bottom) {
            VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
                .ignoresSafeArea()

            HStack(spacing: 0) {
                sidebarPane
                mainContentPane
            }
            .ignoresSafeArea()

            toastBanner
        }
        .ignoresSafeArea()
        .background {
            keyboardShortcutTriggers
        }
    }

    private var keyboardShortcutTriggers: some View {
        Group {
            Button("") { appState.activeSheet = .create }
                .keyboardShortcut("n", modifiers: .command)
            Button("") { toggleHistoryPane() }
                .keyboardShortcut("h", modifiers: [.command, .shift])
            Button("") { appState.activeSheet = .settings }
                .keyboardShortcut(",", modifiers: .command)
            Button("") { PanelLockController.shared.lock(reason: .lockNow) }
                .keyboardShortcut("l", modifiers: .command)
            Button("") { focusSearch() }
                .keyboardShortcut("f", modifiers: .command)
            Button("") { if isHistoryActive { leaveHistory() } }
                .keyboardShortcut("[", modifiers: .command)
            // Bare arrows would steal ↑/↓ from the History search dropdown.
            Button("") { selectPreviousKey() }
                .keyboardShortcut(.upArrow, modifiers: [])
                .disabled(isHistoryActive)
            Button("") { selectNextKey() }
                .keyboardShortcut(.downArrow, modifiers: [])
                .disabled(isHistoryActive)
        }
        .opacity(0)
        .allowsHitTesting(false)
    }

    private var sheetsAndAlertsView: some View {
        rootSplitView
            .sheet(item: $appState.activeSheet) { sheet in
                switch sheet {
                case .create:
                    CreateKeySheet(appState: appState)
                        .dismissOnOutsideClick {
                            appState.activeSheet = nil
                        }
                case .settings:
                    SettingsView()
                        .environmentObject(appState)
                        .dismissOnOutsideClick {
                            appState.activeSheet = nil
                        }
                }
            }
            .alert(ClavisUIStrings.Common.error, isPresented: isErrorAlertPresented) {
                Button(ClavisUIStrings.Common.ok, role: .cancel) {
                    appState.errorMessage = nil
                }
            } message: {
                if let msg = appState.errorMessage {
                    Text(msg)
                }
            }
            .alert(ClavisUIStrings.Inspector.deleteAlertTitle, isPresented: isDeleteAlertPresented) {
                Button(ClavisUIStrings.Common.delete, role: .destructive) {
                    if let key = keyPendingDeletion {
                        deleteKey(label: key.label)
                    }
                    keyPendingDeletion = nil
                }
                Button(ClavisUIStrings.Common.cancel, role: .cancel) {
                    keyPendingDeletion = nil
                }
            } message: {
                if let key = keyPendingDeletion {
                    Text(ClavisUIStrings.Inspector.deleteAlertMessage(label: key.label))
                }
            }
    }

    var body: some View {
        sheetsAndAlertsView
            .onMoveCommand { direction in
                switch direction {
                case .up:
                    selectPreviousKey()
                case .down:
                    selectNextKey()
                default:
                    break
                }
            }
            .onAppear {
                appState.refresh()
                if selectedKeyId == nil, let firstKey = appState.keys.first {
                    selectedKeyId = firstKey.id
                }
                if isHistoryActive { openHistoryFromRequest() }
            }
            .onChange(of: appState.keys) { newKeys in
                if selectedKeyId == nil || !newKeys.contains(where: { $0.id == selectedKeyId }) {
                    selectedKeyId = newKeys.first?.id
                }
            }
            .onChange(of: appState.activeMainPane) { newPane in
                if newPane == .history,
                   historyViewModel.integrityReport == nil && !historyViewModel.isCheckingIntegrity {
                    historyViewModel.checkIntegrity()
                }
                if newPane != .history { historyUI.dismiss() }
            }
            // Each open request resets the committed filter to exactly the requested key.
            .onChange(of: appState.historyOpenRequestID) { _ in
                openHistoryFromRequest()
            }
            .onChange(of: statusMessage) { newMessage in
                guard let msg = newMessage, !msg.isEmpty else { return }
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.6) {
                    if statusMessage == msg {
                        withAnimation {
                            statusMessage = nil
                        }
                    }
                }
            }
    }

    @ViewBuilder
    private var toastBanner: some View {
        if let status = statusMessage {
            HStack(spacing: 8) {
                Image(systemName: "checkmark")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(DesignTokens.accentGreen)
                Text(status)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.primary)
                    .lineLimit(1)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .glassCard(cornerRadius: 11)
            .shadow(color: Color.black.opacity(0.25), radius: 14, x: 0, y: 6)
            .padding(.bottom, 22)
            .transition(.opacity.combined(with: .move(edge: .bottom)))
            .zIndex(50)
        }
    }

    private func openHistoryFromRequest() {
        let fingerprint = appState.historyFilterKeyFingerprint
        historyViewModel.openForKey(fingerprint)
        if let fingerprint, let key = appState.keys.first(where: { $0.fingerprint == fingerprint }) {
            selectedKeyId = key.id
        }
        historyUI.dismiss()
    }

    /// Sidebar rows reflect the committed Key badges while History is open (derived, not stored).
    private func isSidebarRowSelected(_ key: SSHKeyInfo) -> Bool {
        if isHistoryActive { return historyViewModel.selectedKeyFingerprint == key.fingerprint }
        return selectedKey?.id == key.id
    }

    // MARK: - Key library sidebar

    private var sidebarHeader: some View {
        VStack(spacing: 10) {
            HStack(spacing: 7) {
                Spacer(minLength: 72)
                AdaptiveGlassCapsule(spacing: 2) {
                    SidebarHeaderPillButton(
                        icon: "plus",
                        isActive: appState.activeSheet == .create,
                        helpText: "New key (⌘N)",
                        accessibilityLabelText: ClavisUIStrings.Accessibility.addKey
                    ) {
                        appState.activeSheet = .create
                    }
                    SidebarHeaderPillButton(
                        icon: "clock.arrow.circlepath",
                        isActive: isHistoryActive,
                        helpText: "Activity History (⇧⌘H)",
                        accessibilityLabelText: "Activity History"
                    ) {
                        toggleHistoryPane()
                    }
                    SidebarHeaderPillButton(
                        icon: "lock",
                        isActive: false,
                        helpText: "Lock Clavis (⌘L)",
                        accessibilityLabelText: "Lock Clavis"
                    ) {
                        PanelLockController.shared.lock(reason: .lockNow)
                    }
                }
                .padding(2)
            }
            .padding(.horizontal, 12)
            .frame(height: Self.toolbarHeight)

            LibrarySearchField(text: $searchText, focused: Binding(
                get: { isSearchFieldFocused },
                set: { isSearchFieldFocused = $0 }
            ))
            .frame(height: 28)
            .padding(.horizontal, 12)
            .padding(.bottom, 8)
        }
        .task { await appState.requestPolicy.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await appState.requestPolicy.refresh() }
        }
        .confirmationDialog(appState.requestPolicy.isPaused ? "Resume requests?" : "Activate kill switch?", isPresented: $confirmingRevokeAll) {
            Button(appState.requestPolicy.isPaused ? "Resume Requests" : "Activate Kill Switch", role: .destructive) {
                Task { await appState.setRequestsPaused(!appState.requestPolicy.isPaused) }
            }
        } message: {
            Text(appState.requestPolicy.isPaused
                ? "Resuming requires authentication. Revoked approvals will not be restored."
                : "Revoke all approvals and pause new requests. Existing SSH connections may remain open.")
        }
    }

    private var sidebarPane: some View {
        ZStack(alignment: .topLeading) {
            DesignTokens.sidebarBackground
                .ignoresSafeArea()

            ScrollView {
                if filteredKeys.isEmpty {
                    Text(appState.keys.isEmpty ? "No keys yet" : "No matching keys")
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 18)
                        .padding(.horizontal, 8)
                } else {
                    LazyVStack(spacing: 1) {
                        ForEach(Array(filteredKeys.enumerated()), id: \.element.id) { index, key in
                            let isRowSelected = isSidebarRowSelected(key)
                            let nextIsSelected: Bool = {
                                guard index + 1 < filteredKeys.count else { return false }
                                return isSidebarRowSelected(filteredKeys[index + 1])
                            }()
                            KeySidebarRowView(
                                key: key,
                                isSelected: isRowSelected,
                                isUnlocked: appState.isKeyUnlocked(key),
                                showDivider: !isRowSelected && !nextIsSelected,
                                onSelect: {
                                    selectedKeyId = key.id
                                    if isHistoryActive {
                                        // Stay in History; replace the Key badge(s) with this key.
                                        historyViewModel.selectSidebarKey(key.fingerprint)
                                    } else {
                                        appState.activeMainPane = .keys
                                    }
                                },
                                onCopyPublicKey: {
                                    copyPublicKey(for: key)
                                },
                                onCopyFingerprint: {
                                    copyFingerprint(for: key)
                                },
                                onDelete: {
                                    keyPendingDeletion = key
                                }
                            )
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.bottom, 10)
                }
            }
            .topLiquidGlassBar(alignment: .leading) {
                sidebarHeader
            }
            .frame(maxHeight: .infinity)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                LibraryAgentStatus(
                    active: appState.isSocketActive,
                    requestState: appState.requestPolicy.state,
                    isBusy: appState.requestPolicy.isBusy,
                    onTogglePause: { confirmingRevokeAll = true },
                    onLock: { PanelLockController.shared.lock(reason: .lockNow) },
                    onOpenSettings: { appState.activeSheet = .settings }
                )
            }
        }
        .frame(width: Self.sidebarWidth)
        .frame(maxHeight: .infinity)
        .overlay(alignment: .trailing) {
            Rectangle()
                .fill(DesignTokens.cardBorder)
                .frame(width: 1)
                .ignoresSafeArea()
        }
    }

    // MARK: - Right Main Pane (Toolbar + Inspector / History / Empty State)

    private var mainContentPane: some View {
        ZStack(alignment: .top) {
            DesignTokens.inspectorBackground
                .ignoresSafeArea()

            Group {
                if appState.activeMainPane == .history {
                    HistoryView(viewModel: historyViewModel, ui: historyUI, keys: appState.keys)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if appState.keys.isEmpty {
                    emptyVaultFirstLaunchView
                } else if let key = selectedKey {
                    KeyDetailInspectorView(
                        key: key,
                        appState: appState,
                        onDelete: {
                            deleteKey(label: key.label)
                        },
                        onShowToast: { msg in
                            statusMessage = msg
                        }
                    )
                } else {
                    VStack(spacing: 10) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 28))
                            .foregroundColor(DesignTokens.textTertiary)
                        Text("No matching keys")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(DesignTokens.textSecondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .topLiquidGlassBar {
                VStack(spacing: 0) {
                    if isHistoryActive {
                        // One fixed region: search, badges and count never enter the scroll area.
                        HistoryFilterHeader(viewModel: historyViewModel, ui: historyUI)
                    }
                }
            }

        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyVaultFirstLaunchView: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 0) {
                ZStack {
                    Image(systemName: "key.fill")
                        .font(.system(size: 20, weight: .medium))
                        .foregroundColor(DesignTokens.accentBlue)
                }
                .frame(width: 41, height: 43)
                .glassCard(cornerRadius: 11, tint: DesignTokens.accentBlue.opacity(0.09))
                .padding(.bottom, 18)

                Text(Self.emptyStateTitle)
                    .font(.system(size: 23, weight: .semibold))
                    .foregroundColor(.primary)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 14)

                Text(Self.emptyStateSubtitle)
                    .font(.system(size: 13))
                    .foregroundColor(DesignTokens.textSecondary)
                    .multilineTextAlignment(.center)
                    .lineSpacing(3)
                    .frame(maxWidth: 320)
                    .padding(.bottom, 22)

                Button(action: {
                    appState.activeSheet = .create
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "plus")
                            .font(.system(size: 12, weight: .semibold))
                        Text(Self.emptyStateCreateButtonTitle)
                            .font(.system(size: 13, weight: .medium))
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                }
                .liquidGlassButton(prominent: true)
                .controlSize(.large)
            }
            .padding(.horizontal, 24)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Actions

    private func copyPublicKey(for key: SSHKeyInfo) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
        statusMessage = "Copied to clipboard"
    }

    private func copyFingerprint(for key: SSHKeyInfo) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.fingerprint, forType: .string)
        statusMessage = "Copied to clipboard"
    }

    private func deleteKey(label: String) {
        ClavisLogger.promptDebug("calvis-ui", "KeyListView: initiating delete for key '\(label)'")
        defer { appState.refresh() }
        do {
            try appState.deleteKey(label: label)
            statusMessage = ClavisUIStrings.KeyList.deletedKey(label: label)
        } catch {
            ClavisLogger.log("KEY_DELETE", "Failed to delete key '\(label)': \(error.localizedDescription)")
            appState.errorMessage = error.localizedDescription
        }
    }
}

struct KeySidebarRowView: View {
    let key: SSHKeyInfo
    let isSelected: Bool
    var isUnlocked: Bool = false
    var showDivider: Bool = true
    let onSelect: () -> Void
    var onCopyPublicKey: (() -> Void)? = nil
    var onCopyFingerprint: (() -> Void)? = nil
    var onDelete: (() -> Void)? = nil

    @State private var isHovered = false

    var subtitleText: String {
        "\(key.purpose.sidebarLabel) · \(isUnlocked ? "Unlocked" : "Locked")"
    }

    var body: some View {
        let profile = key.effectiveAccessProfile
        let presentation = LibraryKeyPresentation(profile: profile)
        let isBot = profile.type == .bot
        let squircleColors: [Color] = isBot
            ? [Color(red: 0.69, green: 0.35, blue: 0.94), Color(red: 0.54, green: 0.22, blue: 0.82)]
            : [Color(red: 0.12, green: 0.58, blue: 1.0), Color(red: 0.0, green: 0.45, blue: 0.96)]

        HStack(spacing: 9) {
            ZStack {
                RoundedRectangle(cornerRadius: 5.5, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: squircleColors,
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                RoundedRectangle(cornerRadius: 5.5, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.18), lineWidth: 0.5)
                Image(systemName: presentation.tileSymbol)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 22, height: 22)
            .shadow(color: Color.black.opacity(0.15), radius: 1, x: 0, y: 0.5)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                Text(key.label)
                    .font(.system(size: 13, weight: isSelected ? .medium : .regular))
                    .foregroundStyle(
                        isSelected
                            ? Color.white
                            : (presentation.isDisabled ? DesignTokens.textSecondary : .primary)
                    )
                    .strikethrough(presentation.isDisabled, color: isSelected ? Color.white.opacity(0.75) : DesignTokens.textSecondary)
                    .lineLimit(1)
                Text(presentation.purposeSummary)
                    .font(.system(size: 11))
                    .foregroundStyle(isSelected ? Color.white.opacity(0.78) : DesignTokens.textSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            if presentation.isDisabled {
                Image(systemName: "pause.fill")
                    .font(.system(size: 9.5, weight: .semibold))
                    .foregroundStyle(isSelected ? Color.white.opacity(0.85) : DesignTokens.textSecondary)
                    .help("Disabled")
                    .accessibilityHidden(true)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .frame(minHeight: 38)
        .background(FirstMouseView())
        .background(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(
                    isSelected
                        ? Color(nsColor: .controlAccentColor)
                        : (isHovered ? Color.primary.opacity(0.06) : Color.clear)
                )
        )
        .contentShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(key.label)
        .accessibilityValue(presentation.accessibilitySummary)
        .accessibilityAddTraits(isSelected ? [.isSelected, .isButton] : [.isButton])
        .accessibilityAction {
            onSelect()
        }
        .onTapGesture {
            onSelect()
        }
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.11)) {
                isHovered = hovering
            }
        }
        .contextMenu {
            Button {
                onCopyPublicKey?()
            } label: {
                Label(ClavisUIStrings.Inspector.copyPublicKey, systemImage: "doc.on.doc")
            }

            Button {
                onCopyFingerprint?()
            } label: {
                Label(ClavisUIStrings.Inspector.copyFingerprintMenu, systemImage: "number")
            }

            Divider()

            Button(role: .destructive) {
                onDelete?()
            } label: {
                Label(ClavisUIStrings.Inspector.deleteKeyMenu, systemImage: "trash")
            }
        }
    }
}

// MARK: - Legacy Toolbar Helpers Preserved for Test Compatibility

struct UnifiedGlassToolbarPill: View {
    @ObservedObject var appState: AppState
    @Binding var statusMessage: String?

    var body: some View {
        HStack(spacing: 2) {
            ToolbarCapsuleButton(
                icon: "plus",
                iconSize: 13,
                iconColor: Color.white.opacity(0.90),
                isActive: appState.activeSheet == .create,
                help: ClavisUIStrings.CreateKey.title,
                accessibilityLabelString: ClavisUIStrings.Accessibility.addKey,
                action: { appState.activeSheet = .create }
            )
        }
    }
}

struct ToolbarCapsuleButton: View {
    let icon: String
    var iconSize: CGFloat = 12
    var iconColor: Color = Color.white.opacity(0.90)
    var isActive: Bool = false
    var isDisabled: Bool = false
    let help: String
    var accessibilityLabelString: String? = nil
    var accessibilityValueString: String? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .help(help)
    }
}
