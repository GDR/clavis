import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct KeyListView: View {
    @EnvironmentObject var appState: AppState

    @State private var selectedKeyId: String? = nil
    @State private var showingAddPopover: Bool = false
    @State private var statusMessage: String? = nil

    private var selectedKey: Ed25519KeyInfo? {
        if let id = selectedKeyId {
            return appState.keys.first(where: { $0.id == id })
        }
        return appState.keys.first
    }

    var body: some View {
        ZStack {
            // Full-window base frosted blur ensures no 1px gaps or unblurred subpixel seams anywhere
            VisualEffectView(material: .underWindowBackground, blendingMode: .behindWindow)
                .ignoresSafeArea()

            HStack(spacing: 0) {
                // Sidebar: Key List Pane (318px)
                ZStack(alignment: .topLeading) {
                    // Sidebar Frosted Glass
                    VisualEffectView(material: .sidebar, blendingMode: .behindWindow)
                        .ignoresSafeArea()

                    // Translucent dark tint to preserve contrast
                    DesignTokens.sidebarBackground
                        .ignoresSafeArea()


                    VStack(alignment: .leading, spacing: 12) {
                        // Title header — top padding to clear macOS window controls (traffic lights)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Keys")
                                .font(.system(size: 24, weight: .semibold))
                                .foregroundColor(.primary)
                            Text("\(appState.keys.count) \(appState.keys.count == 1 ? "identity" : "identities") available")
                                .font(.system(size: 12))
                                .foregroundColor(DesignTokens.textSecondary)
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 44)

                        // Key List
                        if appState.keys.isEmpty {
                            Spacer()
                        } else {
                            ScrollView {
                                LazyVStack(spacing: 8) {
                                    ForEach(appState.keys) { key in
                                        KeySidebarRowView(
                                            key: key,
                                            isSelected: (selectedKey?.id == key.id),
                                            isUnlocked: appState.isKeyUnlocked(label: key.label),
                                            onSelect: {
                                                selectedKeyId = key.id
                                            }
                                        )
                                    }
                                }
                                .padding(.horizontal, 16)
                                .padding(.vertical, 6)
                            }
                        }

                        // Bottom Toolbar: Unified 2x Liquid Glass Capsule placed bottom-right
                        HStack(spacing: 8) {
                            Spacer()

                            UnifiedGlassToolbarPill(
                                appState: appState,
                                showingAddPopover: $showingAddPopover,
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
                            Text("No Key Selected")
                                .font(.title3)
                                .foregroundColor(DesignTokens.textSecondary)
                            Text("Select an identity from the sidebar to inspect its public credentials and security attributes.")
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
            case .importKey:
                ImportKeySheet(appState: appState)
            }
        }
        .alert(
            "Error",
            isPresented: Binding(
                get: { appState.errorMessage != nil },
                set: { if !$0 { appState.errorMessage = nil } }
            )
        ) {
            Button("OK", role: .cancel) {
                appState.errorMessage = nil
            }
        } message: {
            if let msg = appState.errorMessage {
                Text(msg)
            }
        }
        .background {
            Group {
                Button("") { appState.activeSheet = .create }
                    .keyboardShortcut("n", modifiers: .command)
                Button("") { appState.activeSheet = .importKey }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                Button("") { WindowManager.shared.openSettings() }
                    .keyboardShortcut(",", modifiers: .command)
            }
            .opacity(0)
            .allowsHitTesting(false)
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
    }

    private func deleteKey(label: String) {
        defer { appState.refresh() }
        do {
            try KeychainManager.shared.deleteKey(label: label)
            statusMessage = "Deleted key '\(label)'."
        } catch {
            ClavisLogger.log("KEY_DELETE", "Failed to delete key '\(label)': \(error.localizedDescription)")
            appState.errorMessage = error.localizedDescription
        }
    }
}

private struct KeySidebarRowView: View {
    let key: Ed25519KeyInfo
    let isSelected: Bool
    let isUnlocked: Bool
    let onSelect: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 10) {
            // Status indicator: hardware shield for Secure Enclave, cache status dot for software
            if key.isHardware {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 11))
                    .foregroundColor(DesignTokens.accentGreen)
                    .frame(width: 8, height: 8)
            } else {
                StatusDot(isActive: isUnlocked)
            }

            // Key label & algorithm
            VStack(alignment: .leading, spacing: 3) {
                Text(key.label)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                Text(key.isAgeCompatible ? "\(key.algorithm) · agenix" : key.algorithm)
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
        .onTapGesture {
            onSelect()
        }
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.15)) {
                isHovered = hovering
            }
        }
    }
}

// MARK: - Unified 2x Liquid Glass Toolbar Capsule

private struct UnifiedGlassToolbarPill: View {
    @ObservedObject var appState: AppState
    @Binding var showingAddPopover: Bool
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
            // Add Key (+)
            ToolbarCapsuleButton(
                icon: "plus",
                iconSize: 13,
                iconColor: Color.white.opacity(0.90),
                isActive: showingAddPopover,
                help: "Add or Import Key",
                action: { showingAddPopover.toggle() }
            )
            .popover(isPresented: $showingAddPopover, arrowEdge: .top) {
                AddKeyPopoverView(
                    onNewKey: {
                        showingAddPopover = false
                        appState.activeSheet = .create
                    },
                    onImportKey: {
                        showingAddPopover = false
                        appState.activeSheet = .importKey
                    }
                )
            }

            // Lock All
            ToolbarCapsuleButton(
                icon: "lock.fill",
                iconSize: 12,
                iconColor: appState.cachedKeysCount > 0 ? DesignTokens.accentGreen : Color.white.opacity(0.40),
                isDisabled: appState.cachedKeysCount == 0,
                help: appState.cachedKeysCount > 0 ? "Lock All Keys" : "No Unlocked Keys",
                action: {
                    appState.lockNow()
                    statusMessage = "All cached keys locked."
                }
            )

            // Settings
            ToolbarCapsuleButton(
                icon: "gearshape",
                iconSize: 12,
                iconColor: Color.white.opacity(0.90),
                help: "Settings (Auto Start, Timeout, Nix)",
                action: { WindowManager.shared.openSettings() }
            )
        }
        .padding(.horizontal, 4)
        .frame(height: 32)
    }
}

private struct ToolbarCapsuleButton: View {
    let icon: String
    var iconSize: CGFloat = 12
    var iconColor: Color = Color.white.opacity(0.90)
    var isActive: Bool = false
    var isDisabled: Bool = false
    let help: String
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
        .disableFocusEffect()
        .disabled(isDisabled)
        .help(help)
        .onHover { isHovered = $0 }
    }
}

