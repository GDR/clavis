import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct KeyListView: View {
    @Environment(AppState.self) var appState
    @State private var historyViewModel = HistoryViewModel()
    @State private var historyUI = HistoryUIState()

    @State private var selectedKeyId: String? = nil
    @State private var statusMessage: String? = nil
    @State private var kindFilter: KeyKindFilter = .all
    @State private var searchText: String = ""
    @State private var keyPendingDeletion: SSHKeyInfo? = nil
    @FocusState private var isSearchFieldFocused: Bool
    @State private var headerCenterOffset: CGFloat = 0
    @State private var hasUnfoldedSidebar: Bool = false
    @State private var hasUnfoldedDetail: Bool = false
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.shouldAnimateSplitPaneUnfold) private var shouldAnimateUnfold
    @Environment(\.hasWindowGlassBackdrop) private var hasWindowGlassBackdrop

    private var isSidebarUnfolded: Bool {
        !shouldAnimateUnfold || reduceMotion || hasUnfoldedSidebar
    }

    private var isDetailUnfolded: Bool {
        !shouldAnimateUnfold || reduceMotion || hasUnfoldedDetail
    }

    public static let sidebarWidth: CGFloat = 260
    /// First level shared by both panes: the 36pt controls/tile centered on the native traffic-light line
    /// with equal 8pt padding above and below (52 = 8 + 36 + 8).
    public static let toolbarHeight: CGFloat = DesignTokens.toolbarBandHeight
    public static let actionControlHeight: CGFloat = 36
    /// Sidebar only: second level (search) sits 6pt below the shared 52pt toolbar band.
    static let headerLevelGap: CGFloat = 6
    static let headerBottomPadding: CGFloat = 10
    /// Stable footer height across agent states; also the scroll inset that clears the last key.
    public static let sidebarFooterHeight: CGFloat = 48
    public static let searchCapsuleHeight: CGFloat = 34
    /// S-02 empty state: AppIcon emblem (72pt, 16pt corner radius) above "Welcome to Clavis".
    public static let emptyStateEmblemSize: CGFloat = 72
    public static let emptyStateEmblemCornerRadius: CGFloat = 16
    public static let emptyStateTitle = "Welcome to Clavis"
    public static let emptyStateSubtitle = "Clavis creates keys that never leave this Mac and signs SSH and Git requests for you and your agents."
    public static let emptyStateSteps = [
        "Create a key, protected by Touch ID",
        "Add it to GitHub",
        "Test it (about 2 minutes)"
    ]
    public static let emptyStateCreateButtonTitle = "Create Key…"
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

    private var isAuthenticationPending: Bool { appState.policyMutations.isPending }

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
            if !hasWindowGlassBackdrop {
                WindowGlassBackground()
            }

            HStack(spacing: 0) {
                sidebarPane
                    .offset(x: isSidebarUnfolded ? 0 : UnlockTransitionSpec.sidebarInitialOffsetX)
                    .opacity(isSidebarUnfolded ? 1 : 0)
                mainContentPane
                    .offset(
                        x: isDetailUnfolded ? 0 : UnlockTransitionSpec.detailInitialOffsetX,
                        y: isDetailUnfolded ? 0 : UnlockTransitionSpec.detailInitialOffsetY
                    )
                    .opacity(isDetailUnfolded ? 1 : 0)
            }
            .environment(\.headerCenterOffset, headerCenterOffset)
            // While an authenticated request is pending, nothing underneath (settings, sidebar
            // selection, toolbar actions) is interactive or exposed to VoiceOver.
            .disabled(isAuthenticationPending)
            .allowsHitTesting(!isAuthenticationPending)
            .accessibilityHidden(isAuthenticationPending)
            .ignoresSafeArea()

            toastBanner

            // Variant 07: compact tile in the detail pane, below the sticky identity header.
            AuthenticationTileHost(coordinator: appState.policyMutations)
                .padding(.leading, Self.sidebarWidth)
                .padding(.top, Self.toolbarHeight + 16 + headerCenterOffset)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .ignoresSafeArea()
        .background {
            keyboardShortcutTriggers
                .disabled(isAuthenticationPending)
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
            .sheet(item: Bindable(appState).activeSheet) { sheet in
                switch sheet {
                case .create:
                    CreateKeySheet(appState: appState)
                        .dismissOnOutsideClick {
                            appState.activeSheet = nil
                        }
                case .settings:
                    SettingsView()
                        .environment(appState)
                        .dismissOnOutsideClick {
                            appState.activeSheet = nil
                        }
                case .connect:
                    ConnectTestSheet(appState: appState)
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
            .task(id: shouldAnimateUnfold) {
                if !shouldAnimateUnfold || reduceMotion {
                    hasUnfoldedSidebar = true
                    hasUnfoldedDetail = true
                    return
                }
                if hasUnfoldedSidebar && hasUnfoldedDetail {
                    return
                }
                try? await Task.sleep(nanoseconds: 16_000_000)
                guard !Task.isCancelled else { return }
                withAnimation(UnlockTransitionSpec.sidebarAnimation) {
                    hasUnfoldedSidebar = true
                }
                withAnimation(UnlockTransitionSpec.detailAnimation) {
                    hasUnfoldedDetail = true
                }
            }
            .onDisappear { appState.policyMutations.cancel() }
            .onChange(of: appState.keys) { _, newKeys in
                appState.policyMutations.cancelIfTargetChanged(keys: newKeys)
                if selectedKeyId == nil || !newKeys.contains(where: { $0.id == selectedKeyId }) {
                    selectedKeyId = newKeys.first?.id
                }
            }
            .onChange(of: appState.activeMainPane) { _, newPane in
                if newPane == .history,
                   historyViewModel.integrityReport == nil && !historyViewModel.isCheckingIntegrity {
                    historyViewModel.checkIntegrity()
                }
                if newPane != .history { historyUI.dismiss() }
            }
            // Each open request resets the committed filter to exactly the requested key.
            .onChange(of: appState.historyOpenRequestID) {
                openHistoryFromRequest()
            }
            .onChange(of: statusMessage) { _, newMessage in
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
        VStack(spacing: Self.headerLevelGap) {
            // S02.toolbar-pill: one 36pt glass capsule cluster (New Key · History · Lock) at the
            // trailing edge of the sidebar, on the same center line as the native traffic lights.
            HStack(spacing: 10) {
                Spacer(minLength: 0)
                SidebarToolbarPill(
                    isHistoryActive: isHistoryActive,
                    isCreateSheetActive: false,
                    onNewKey: { appState.activeSheet = .create },
                    onToggleHistory: { toggleHistoryPane() },
                    onLock: { PanelLockController.shared.lock(reason: .lockNow) }
                )
            }
            .padding(.horizontal, 12)
            .frame(height: Self.toolbarHeight)
            .offset(y: headerCenterOffset)

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 13, weight: .regular))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                LibrarySearchField(text: $searchText, focused: Binding(
                    get: { isSearchFieldFocused },
                    set: { isSearchFieldFocused = $0 }
                ))
            }
            .padding(.horizontal, 12)
            .frame(height: Self.searchCapsuleHeight)
            .modifier(CapsuleGlassBackground(isActive: isSearchFieldFocused, isHovered: false, reduceTransparency: reduceTransparency))
            .padding(.horizontal, 14)
            .padding(.bottom, Self.headerBottomPadding)
        }
        .background(alignment: .top) {
            TrafficLightCenterReader(bandHeight: Self.toolbarHeight, offset: $headerCenterOffset)
                .frame(height: Self.toolbarHeight)
                .allowsHitTesting(false)
        }
        .task { await appState.requestPolicy.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await appState.requestPolicy.refresh() }
        }
    }

    private var sidebarPane: some View {
        ZStack(alignment: .topLeading) {
            WindowPaneBackground(isSidebar: true)

            ScrollView {
                if filteredKeys.isEmpty {
                    Text(appState.keys.isEmpty ? "No keys yet" : "No matching keys")
                        .font(.system(size: 11))
                        .foregroundColor(DesignTokens.textSecondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 18)
                        .padding(.horizontal, 8)
                } else {
                    LazyVStack(spacing: 2) {
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
                    .padding(.horizontal, 10)
                    .padding(.bottom, 10)
                }
            }
            .topLiquidGlassBar(alignment: .leading) {
                sidebarHeader
            }
            .frame(maxHeight: .infinity)
            // Pinned footer: same system scroll-edge treatment as the bar under the search field.
            // Rows passing underneath get the native progressive blur; no painted panel.
            .bottomLiquidGlassBar {
                LibraryAgentStatus(
                    active: appState.isSocketActive,
                    requestState: appState.requestPolicy.state,
                    onOpenSettings: { appState.activeSheet = .settings }
                )
                .frame(height: Self.sidebarFooterHeight)
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
            WindowPaneBackground(isSidebar: false)

            Group {
                if appState.activeMainPane == .history {
                    HistoryView(viewModel: historyViewModel, ui: historyUI, keys: appState.keys)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .topLiquidGlassBar {
                            VStack(spacing: 0) {
                                // S09.toolbar: one unified 52pt band — "History" title with the filter
                                // controls live on the same line, never a separate row below.
                                HStack(alignment: .center, spacing: 12) {
                                    Text("History")
                                        .font(.system(size: 18, weight: .semibold))
                                        .foregroundStyle(.primary)
                                        .lineLimit(1)
                                        .fixedSize()
                                        .accessibilityAddTraits(.isHeader)
                                    HistoryFilterHeader(viewModel: historyViewModel, ui: historyUI)
                                    ProminentHistoryButton(isActive: true) { toggleHistoryPane() }
                                }
                                .padding(.horizontal, 28)
                                .frame(height: Self.toolbarHeight)
                                .offset(y: headerCenterOffset)
                                // Applied badges, diagnostics and the matching count stay pinned too.
                                HistoryFilterSummary(viewModel: historyViewModel)
                            }
                        }
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
                        },
                        onToggleHistory: { toggleHistoryPane() }
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

        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyVaultFirstLaunchView: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 0) {
                // AppIcon emblem (72pt, 16pt continuous radius) above the welcome title.
                Group {
                    if let icon = LockedPlaceholderView.loadAppIcon() {
                        Image(nsImage: icon)
                            .resizable()
                            .interpolation(.high)
                            .aspectRatio(contentMode: .fit)
                    } else {
                        Image(systemName: "key.fill")
                            .font(.system(size: 34, weight: .medium))
                            .foregroundColor(DesignTokens.accentBlue)
                    }
                }
                .frame(width: Self.emptyStateEmblemSize, height: Self.emptyStateEmblemSize)
                .clipShape(RoundedRectangle(cornerRadius: Self.emptyStateEmblemCornerRadius, style: .continuous))
                .shadow(color: Color.black.opacity(0.30), radius: 14, x: 0, y: 10)
                .accessibilityHidden(true)
                .padding(.bottom, 12)

                Text(Self.emptyStateTitle)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundColor(.primary)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 6)

                Text(Self.emptyStateSubtitle)
                    .font(.system(size: 12))
                    .foregroundColor(DesignTokens.textSecondary)
                    .multilineTextAlignment(.center)
                    .lineSpacing(3)
                    .frame(maxWidth: 380)
                    .padding(.bottom, 12)

                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(Self.emptyStateSteps.enumerated()), id: \.offset) { index, step in
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text("\(index + 1).")
                                .font(.system(size: 12).monospacedDigit())
                                .foregroundColor(DesignTokens.textSecondary)
                            Text(step)
                                .font(.system(size: 12))
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                    }
                }
                .padding(.bottom, 16)

                Button(action: {
                    appState.activeSheet = .create
                }) {
                    Text(Self.emptyStateCreateButtonTitle)
                        .font(.system(size: 13, weight: .medium))
                        .padding(.horizontal, 18)
                        .frame(height: 32)
                }
                .liquidGlassButton(prominent: true)
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

    /// Translucent neutral row selection matching `.ux/style.css` (`--row-sel`) so KeyBadge never
    /// clashes against a solid accent block.
    private static let selectedRowPlatter = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedWhite: 1.0, alpha: 0.13)
            : NSColor(calibratedWhite: 0.0, alpha: 0.075)
    })

    /// S02.key-row subtitle: the capability summary only (lock state is not a row badge).
    var subtitleText: String {
        LibraryKeyPresentation(profile: key.effectiveAccessProfile).purposeSummary
    }

    var body: some View {
        let profile = key.effectiveAccessProfile
        let presentation = LibraryKeyPresentation(profile: profile)
        let isAgentKey = profile.type == .bot
        let squircleColors: [Color] = isAgentKey
            ? [Color(red: 0.69, green: 0.35, blue: 0.94), Color(red: 0.54, green: 0.22, blue: 0.82)]
            : [Color(red: 0.12, green: 0.58, blue: 1.0), Color(red: 0.0, green: 0.45, blue: 0.96)]

        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: squircleColors,
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.18), lineWidth: 0.5)
                Image(systemName: presentation.tileSymbol)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 28, height: 28)
            .shadow(color: Color.black.opacity(0.15), radius: 1, x: 0, y: 0.5)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                Text(key.label)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(presentation.isDisabled ? DesignTokens.textSecondary : .primary)
                    .strikethrough(presentation.isDisabled, color: DesignTokens.textSecondary)
                    .lineLimit(1)
                Text(presentation.purposeSummary)
                    .font(.system(size: 11))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            if presentation.isDisabled {
                Image(systemName: "pause.fill")
                    .font(.system(size: 9.5, weight: .semibold))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .help("Disabled")
                    .accessibilityHidden(true)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
        .frame(minHeight: 53)
        .background(FirstMouseView())
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(
                    isSelected
                        ? Self.selectedRowPlatter
                        : (isHovered ? Color.primary.opacity(0.06) : Color.clear)
                )
        )
        .contentShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
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
    var appState: AppState
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


/// Observes the coordinator and presents the authentication tile with host-owned insertion animation
/// (disabled under Reduce Motion).
private struct AuthenticationTileHost: View {
    var coordinator: PolicyMutationCoordinator
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if coordinator.isPending {
                // The pane's remaining width centers the 256pt tile.
                HStack(spacing: 0) {
                    Spacer(minLength: 0)
                    AuthenticationRequestView(
                        phase: coordinator.phase,
                        authenticationContext: coordinator.embeddedContext,
                        onPassword: { coordinator.usePassword() },
                        onRetry: { coordinator.retry() },
                        onCancel: { coordinator.cancel() }
                    )
                    Spacer(minLength: 0)
                }
                .transition(reduceMotion ? .identity : .opacity.combined(with: .move(edge: .top)))
            }
        }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.18), value: coordinator.isPending)
    }
}
