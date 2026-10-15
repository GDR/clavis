import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct KeyListView: View {
    @EnvironmentObject var appState: AppState

    @State private var selectedKeyId: String? = nil
    @State private var statusMessage: String? = nil
    @State private var kindFilter: KeyKindFilter = .all
    @State private var searchText: String = ""
    @State private var keyPendingDeletion: SSHKeyInfo? = nil
    @FocusState private var isSearchFieldFocused: Bool

    static func filterKeys(_ keys: [SSHKeyInfo], query: String, kind: KeyKindFilter) -> [SSHKeyInfo] {
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
        }
    }

    private func selectPreviousKey() {
        if let prevId = Self.previousSelectedKeyId(keys: filteredKeys, currentId: selectedKey?.id) {
            selectedKeyId = prevId
        }
    }

    var body: some View {
        ZStack {
            // Full-window base frosted blur ensures no 1px gaps or unblurred subpixel seams anywhere
            VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
                .ignoresSafeArea()

            HStack(spacing: 0) {
                // Sidebar: Key List Pane (318px)
                ZStack(alignment: .topLeading) {
                    // Let the full-window frost show through with a light tint for text contrast.
                    DesignTokens.sidebarBackground
                        .ignoresSafeArea()

                    VStack(alignment: .leading, spacing: 12) {
                        // Title header — top padding to clear macOS window controls (traffic lights)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(ClavisUIStrings.KeyList.title)
                                .font(.system(size: 24, weight: .semibold))
                                .foregroundColor(.primary)
                            Text(ClavisUIStrings.KeyList.identitiesAvailable(count: filteredKeys.count))
                                .font(.system(size: 12))
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 44)

                        // Search Box
                        HStack(spacing: 6) {
                            Image(systemName: "magnifyingglass")
                                .foregroundColor(DesignTokens.textTertiary)
                                .font(.system(size: 12))
                            TextField(ClavisUIStrings.MenuBar.searchPlaceholder, text: $searchText)
                                .textFieldStyle(.plain)
                                .font(.system(size: 12))
                                .focused($isSearchFieldFocused)
                                .accessibilityLabel(ClavisUIStrings.MenuBar.searchPlaceholder)
                            if !searchText.isEmpty {
                                Button(action: { searchText = "" }) {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundColor(DesignTokens.textTertiary)
                                        .font(.system(size: 12))
                                }
                                .buttonStyle(.plain)
                                .accessibilityLabel(ClavisUIStrings.Common.cancel)
                            }
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(Color.white.opacity(0.06))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(isSearchFieldFocused ? DesignTokens.accentBlue.opacity(0.7) : Color.white.opacity(0.12), lineWidth: 1)
                        )
                        .padding(.horizontal, 20)

                        // Kind Filter Picker
                        Picker("", selection: $kindFilter) {
                            Text(ClavisUIStrings.KeyList.filterAll).tag(KeyKindFilter.all)
                            Text(ClavisUIStrings.KeyList.filterPersonal).tag(KeyKindFilter.personal)
                            Text(ClavisUIStrings.KeyList.filterAgent).tag(KeyKindFilter.agent)
                        }
                        .pickerStyle(.segmented)
                        .padding(.horizontal, 20)

                        // Key List
                        if filteredKeys.isEmpty {
                            if !searchText.isEmpty {
                                VStack(spacing: 8) {
                                    Spacer()
                                    Image(systemName: "magnifyingglass")
                                        .font(.system(size: 24))
                                        .foregroundColor(DesignTokens.textTertiary)
                                    Text(ClavisUIStrings.MenuBar.noKeysFound)
                                        .font(.system(size: 12, weight: .medium))
                                        .foregroundColor(DesignTokens.textSecondary)
                                    Spacer()
                                }
                                .frame(maxWidth: .infinity)
                            } else {
                                Spacer()
                            }
                        } else {
                            ScrollView {
                                LazyVStack(spacing: 8) {
                                    ForEach(filteredKeys) { key in
                                        KeySidebarRowView(
                                            key: key,
                                            isSelected: (selectedKey?.id == key.id),
                                            onSelect: {
                                                selectedKeyId = key.id
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
                                .padding(.horizontal, 16)
                                .padding(.vertical, 6)
                            }
                        }

                        // Status feedback message if present (#92 Part 2)
                        if let status = statusMessage {
                            HStack(spacing: 8) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(DesignTokens.accentGreen)
                                    .font(.system(size: 12))
                                Text(status)
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(DesignTokens.accentGreen)
                                    .lineLimit(2)
                                Spacer()
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 8)
                            .background(
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(DesignTokens.accentGreen.opacity(0.12))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(DesignTokens.accentGreen.opacity(0.3), lineWidth: 0.8)
                            )
                            .padding(.horizontal, 16)
                            .transition(.opacity.combined(with: .move(edge: .bottom)))
                        }

                        // Bottom Toolbar: Unified 2x Liquid Glass Capsule placed bottom-right
                        HStack(spacing: 8) {
                            Spacer()

                            UnifiedGlassToolbarPill(
                                appState: appState,
                                statusMessage: $statusMessage
                            )
                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 16)
                    }
                    .frame(maxHeight: .infinity)
                }
                .frame(width: 318)
                .frame(maxHeight: .infinity)
                .overlay(alignment: .trailing) {
                    // 1px separator as an overlay so it never creates a layout gap or transparent slit
                    Rectangle()
                        .fill(Color.white.opacity(0.10))
                        .frame(width: 1)
                        .ignoresSafeArea()
                }

                // Right Pane: Key Detail Inspector (Flexible, ~562px)
                ZStack(alignment: .top) {
                    // Translucent slate tint
                    DesignTokens.inspectorBackground
                        .ignoresSafeArea()

                    // Inspector Details or Empty State
                    if let key = selectedKey {
                        KeyDetailInspectorView(
                            key: key,
                            appState: appState,
                            onDelete: {
                                deleteKey(label: key.label)
                            }
                        )
                    } else {
                        VStack(spacing: 12) {
                            Image(systemName: "key.fill")
                                .font(.system(size: 48))
                                .foregroundColor(DesignTokens.textSecondary.opacity(0.4))
                            Text(ClavisUIStrings.KeyList.noKeySelectedTitle)
                                .font(.title3)
                                .foregroundColor(DesignTokens.textSecondary)
                            Text(ClavisUIStrings.KeyList.noKeySelectedSubtitle)
                                .font(.caption)
                                .foregroundColor(DesignTokens.textTertiary)
                                .multilineTextAlignment(.center)
                                .frame(maxWidth: 300)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .ignoresSafeArea()
        }
        .ignoresSafeArea()
        .sheet(item: $appState.activeSheet) { sheet in
            switch sheet {
            case .create:
                CreateKeySheet(appState: appState)
            }
        }
        .alert(
            ClavisUIStrings.Common.error,
            isPresented: Binding(
                get: { appState.errorMessage != nil },
                set: { if !$0 { appState.errorMessage = nil } }
            )
        ) {
            Button(ClavisUIStrings.Common.ok, role: .cancel) {
                appState.errorMessage = nil
            }
        } message: {
            if let msg = appState.errorMessage {
                Text(msg)
            }
        }
        .alert(
            ClavisUIStrings.Inspector.deleteAlertTitle,
            isPresented: Binding(
                get: { keyPendingDeletion != nil },
                set: { if !$0 { keyPendingDeletion = nil } }
            )
        ) {
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
        .background {
            Group {
                Button("") { appState.activeSheet = .create }
                    .keyboardShortcut("n", modifiers: .command)
                Button("") { WindowManager.shared.openSettings() }
                    .keyboardShortcut(",", modifiers: .command)
                Button("") { isSearchFieldFocused = true }
                    .keyboardShortcut("f", modifiers: .command)
                Button("") { selectPreviousKey() }
                    .keyboardShortcut(.upArrow, modifiers: [])
                Button("") { selectNextKey() }
                    .keyboardShortcut(.downArrow, modifiers: [])
            }
            .opacity(0)
            .allowsHitTesting(false)
        }
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
        }
        .onChange(of: appState.keys) { newKeys in
            if selectedKeyId == nil || !newKeys.contains(where: { $0.id == selectedKeyId }) {
                selectedKeyId = newKeys.first?.id
            }
        }
        .onChange(of: statusMessage) { newMessage in
            guard let msg = newMessage, !msg.isEmpty else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                if statusMessage == msg {
                    withAnimation {
                        statusMessage = nil
                    }
                }
            }
        }
    }

    private func copyPublicKey(for key: SSHKeyInfo) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.publicKeyOpenSSH, forType: .string)
        statusMessage = ClavisUIStrings.Inspector.feedbackCopiedOpenSSH
    }

    private func copyFingerprint(for key: SSHKeyInfo) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key.fingerprint, forType: .string)
        statusMessage = ClavisUIStrings.Inspector.feedbackCopiedFingerprint
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
    let onSelect: () -> Void
    var onCopyPublicKey: (() -> Void)? = nil
    var onCopyFingerprint: (() -> Void)? = nil
    var onDelete: (() -> Void)? = nil

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 10) {
            // Status indicator: hardware shield for Secure Enclave
            if key.isHardware {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 11))
                    .foregroundColor(DesignTokens.accentGreen)
                    .frame(width: 8, height: 8)
            }

            // Key label & algorithm
            VStack(alignment: .leading, spacing: 3) {
                Text(key.label)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                Text(key.algorithm)
                    .font(.system(size: 11))
                    .foregroundColor(isSelected ? Color.white.opacity(0.80) : DesignTokens.textSecondary)
                    .lineLimit(1)
            }

            Spacer()

            // Hardware / Software and Purpose badges
            HStack(spacing: 4) {
                KeyBadge(isHardware: key.isHardware)
                PurposeBadge(purpose: key.purpose)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(FirstMouseView())
        .liquidGlassRowSelection(isSelected: isSelected, isHovered: isHovered)
        .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(key.label)
        .accessibilityValue(key.algorithm)
        .accessibilityAddTraits(isSelected ? [.isSelected, .isButton] : [.isButton])
        .accessibilityAction {
            onSelect()
        }
        .onTapGesture {
            onSelect()
        }
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.15)) {
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

// MARK: - Unified 2x Liquid Glass Toolbar Capsule

struct UnifiedGlassToolbarPill: View {
    @ObservedObject var appState: AppState
    @Binding var statusMessage: String?

    var body: some View {
        Group {
            if #available(macOS 26.0, *) {
                pillContent
                    .glassEffect(.regular.interactive(), in: .capsule)
            } else {
                pillContent
                    .background(
                        Capsule()
                            .fill(Color.white.opacity(0.08))
                            .background(.ultraThinMaterial, in: Capsule())
                    )
            }
        }
        .background(FirstMouseView())
        .overlay(
            Capsule()
                .stroke(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.32),
                            Color.white.opacity(0.08)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 0.8
                )
        )
        .shadow(color: Color.black.opacity(0.20), radius: 5, x: 0, y: 2)
    }

    private var pillContent: some View {
        HStack(spacing: 2) {
            // Add Key (+) — opens CreateKeySheet directly (#87, #90)
            ToolbarCapsuleButton(
                icon: "plus",
                iconSize: 13,
                iconColor: Color.white.opacity(0.90),
                isActive: appState.activeSheet == .create,
                help: ClavisUIStrings.CreateKey.title,
                accessibilityLabelString: ClavisUIStrings.Accessibility.addKey,
                action: { appState.activeSheet = .create }
            )

            // Lock All
            let hasActiveSessions = appState.activeGitGrace != nil || !appState.agentSessions.isEmpty
            ToolbarCapsuleButton(
                icon: "lock.fill",
                iconSize: 12,
                iconColor: hasActiveSessions ? DesignTokens.accentGreen : Color.white.opacity(0.40),
                isDisabled: !hasActiveSessions,
                help: hasActiveSessions ? ClavisUIStrings.KeyList.lockAllKeysHelp : ClavisUIStrings.KeyList.noUnlockedKeysHelp,
                accessibilityLabelString: ClavisUIStrings.Accessibility.lockAll,
                accessibilityValueString: hasActiveSessions ? ClavisUIStrings.Accessibility.statusActive : ClavisUIStrings.Accessibility.statusOffline,
                action: {
                    appState.lockNow()
                    statusMessage = ClavisUIStrings.KeyList.allCachedKeysLocked
                }
            )

            // Settings
            ToolbarCapsuleButton(
                icon: "gearshape",
                iconSize: 12,
                iconColor: Color.white.opacity(0.90),
                help: ClavisUIStrings.KeyList.settingsHelp,
                accessibilityLabelString: ClavisUIStrings.Accessibility.settings,
                action: { WindowManager.shared.openSettings() }
            )
        }
        .padding(.horizontal, 4)
        .frame(height: 32)
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

    @State private var isHovered: Bool = false

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: iconSize, weight: .medium))
                .foregroundColor(iconColor)
                .frame(width: 26, height: 26)
                .background(
                    Circle()
                        .fill(isActive ? Color.white.opacity(0.20) : (isHovered && !isDisabled ? Color.white.opacity(0.14) : Color.clear))
                )
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .help(help)
        .accessibilityLabel(accessibilityLabelString ?? help)
        .accessibilityValue(accessibilityValueString ?? "")
        .onHover { isHovered = $0 }
    }
}

