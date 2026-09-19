import SwiftUI
import AppKit
import ClavisCore

@MainActor
struct KeyListView: View {
    @EnvironmentObject var appState: AppState

    @State private var selectedKeyId: String? = nil
    @State private var showingCreateSheet: Bool = false
    @State private var showingImportSheet: Bool = false
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
                                        let isSelected = (selectedKey?.id == key.id)
                                        let isUnlocked = appState.isKeyUnlocked(label: key.label)

                                        HStack(spacing: 10) {
                                            // Status dot
                                            StatusDot(isActive: isUnlocked)

                                            // Key label & algorithm
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text(key.label)
                                                    .font(.system(size: 13, weight: .semibold))
                                                    .foregroundColor(isSelected ? .white : .primary)
                                                    .lineLimit(1)
                                                Text(key.isAgeCompatible ? "\(key.algorithm) · agenix" : key.algorithm)
                                                    .font(.system(size: 11))
                                                    .foregroundColor(isSelected ? Color.white.opacity(0.8) : DesignTokens.textSecondary)
                                                    .lineLimit(1)
                                            }

                                            Spacer()

                                            // Hardware / Software badge
                                            KeyBadge(isHardware: key.isHardware)
                                        }
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 10)
                                        .background(
                                            RoundedRectangle(cornerRadius: 10)
                                                .fill(isSelected ? DesignTokens.accentBlue : Color.clear)
                                        )
                                        .contentShape(RoundedRectangle(cornerRadius: 10))
                                        .onTapGesture {
                                            selectedKeyId = key.id
                                        }
                                    }
                                }
                                .padding(.horizontal, 16)
                                .padding(.vertical, 6)
                            }
                        }
                    }
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

                    VStack(spacing: 0) {
                        // Top Toolbar matching Figma node 39:185 & 39:191
                        HStack {
                            Spacer()

                            // Figma Liquid Glass Button Group
                            LiquidGlassButtonGroup {
                                // Add Key Button (+)
                                Button(action: {
                                    showingAddPopover.toggle()
                                }) {
                                    Image(systemName: "plus")
                                        .font(.system(size: 13, weight: .medium))
                                        .foregroundColor(Color.white.opacity(0.85))
                                        .frame(width: 28, height: 28)
                                        .contentShape(Circle())
                                }
                                .buttonStyle(.plain)
                                .liquidGlassCircle(size: 28)
                                .focusable(false)
                                .help("Add or Import Key")
                                .popover(isPresented: $showingAddPopover, arrowEdge: .bottom) {
                                    AddKeyPopoverView(
                                        onNewKey: {
                                            showingAddPopover = false
                                            showingCreateSheet = true
                                        },
                                        onImportKey: {
                                            showingAddPopover = false
                                            showingImportSheet = true
                                        }
                                    )
                                }

                                // Lock All Button
                                Button(action: {
                                    appState.lockNow()
                                    statusMessage = "All cached keys locked."
                                }) {
                                    Image(systemName: "lock.fill")
                                        .font(.system(size: 12, weight: .medium))
                                        .foregroundColor(appState.cachedKeysCount > 0 ? DesignTokens.accentGreen : Color.white.opacity(0.55))
                                        .frame(width: 28, height: 28)
                                        .contentShape(Circle())
                                }
                                .buttonStyle(.plain)
                                .liquidGlassCircle(size: 28)
                                .focusable(false)
                                .disabled(appState.cachedKeysCount == 0)
                                .help(appState.cachedKeysCount > 0 ? "Lock All Keys" : "No Unlocked Keys")

                                // Settings Button
                                Button(action: {
                                    WindowManager.shared.openSettings()
                                }) {
                                    Image(systemName: "gearshape")
                                        .font(.system(size: 12, weight: .medium))
                                        .foregroundColor(Color.white.opacity(0.85))
                                        .frame(width: 28, height: 28)
                                        .contentShape(Circle())
                                }
                                .buttonStyle(.plain)
                                .liquidGlassCircle(size: 28)
                                .focusable(false)
                                .help("Settings (Auto Start, Timeout, Nix)")
                            }
                            .padding(.trailing, 20)
                            .padding(.top, 10)
                        }
                        .frame(height: 48)

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
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .ignoresSafeArea()
        }
        .ignoresSafeArea()
        .sheet(isPresented: $showingCreateSheet) {
            CreateKeySheet(appState: appState)
        }
        .sheet(isPresented: $showingImportSheet) {
            ImportKeySheet(appState: appState)
        }
        .background {
            Group {
                Button("") { showingCreateSheet = true }
                    .keyboardShortcut("n", modifiers: .command)
                Button("") { showingImportSheet = true }
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
        do {
            try KeychainManager.shared.deleteKey(label: label)
            appState.refresh()
            statusMessage = "Deleted key '\(label)'."
        } catch {
            appState.errorMessage = "Failed to delete key: \(error.localizedDescription)"
        }
    }
}
