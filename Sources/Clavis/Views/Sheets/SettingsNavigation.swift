import SwiftUI
import AppKit
import ClavisCore

private enum SettingsTab: String, CaseIterable {
    case general = "General"
    case bots = "Bots"

    var symbol: String { self == .general ? "gearshape" : "desktopcomputer" }
    var displayTitle: String { self == .general ? "General" : "Applications" }
}

struct SettingsNavigation<General: View>: View {
    let general: General
    @AppStorage("clavis.settings.tab") private var selectedTab = SettingsTab.general.rawValue
    @StateObject private var applications: ApplicationSettingsModel
    @FocusState private var focusedTab: SettingsTab?

    init(general: General, agent: any AgentControlling) {
        self.general = general
        _applications = StateObject(wrappedValue: ApplicationSettingsModel(agent: agent))
    }

    private var activeTab: SettingsTab {
        if selectedTab == "Applications" || selectedTab == SettingsTab.bots.rawValue {
            return .bots
        }
        return .general
    }

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                general
                    .opacity(activeTab == .general ? 1 : 0)
                    .disabled(activeTab != .general)
                    .allowsHitTesting(activeTab == .general)
                    .accessibilityHidden(activeTab != .general)
                ApplicationSettingsPane(model: applications)
                    .opacity(activeTab == .bots ? 1 : 0)
                    .disabled(activeTab != .bots)
                    .allowsHitTesting(activeTab == .bots)
                    .accessibilityHidden(activeTab != .bots)
            }
            HStack(spacing: 3) {
                ForEach(SettingsTab.allCases, id: \.rawValue) { tab in
                    Button {
                        selectedTab = tab.rawValue
                        focusedTab = tab
                    } label: {
                        VStack(spacing: 3) {
                            Image(systemName: tab.symbol).font(.system(size: 14))
                            Text(tab.displayTitle).font(.system(size: 10, weight: .medium))
                        }
                        .foregroundStyle(activeTab == tab ? Color.accentColor : Color.secondary)
                        .frame(width: 72, height: 42)
                        .background {
                            if activeTab == tab {
                                Capsule().fill(.quaternary)
                            }
                        }
                        .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .focused($focusedTab, equals: tab)
                    .accessibilityIdentifier("settings-tab-\(tab.rawValue.lowercased())")
                    .accessibilityLabel("\(tab.displayTitle) settings")
                    .accessibilityAddTraits(activeTab == tab ? [.isSelected] : [])
                }
            }
            .onMoveCommand { direction in
                guard focusedTab != nil else { return }
                switch direction {
                case .left: selectedTab = SettingsTab.general.rawValue; focusedTab = .general
                case .right: selectedTab = SettingsTab.bots.rawValue; focusedTab = .bots
                default: break
                }
            }
            .padding(4)
            .liquidGlassCapsuleControl()
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity)
        }
        .onAppear {
            if selectedTab == "Applications" {
                selectedTab = SettingsTab.bots.rawValue
            } else if SettingsTab(rawValue: selectedTab) == nil {
                selectedTab = SettingsTab.general.rawValue
            }
        }
    }
}

private struct ApplicationSettingsPane: View {
    @ObservedObject var model: ApplicationSettingsModel
    @State private var expandedAppIds: Set<UUID> = []
    @State private var isRemoveMode: Bool = false
    @State private var selectedForRemoval: Set<UUID> = []

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Registered Applications")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("Personal apps can use all keys. Bots can use Bot keys. Blocked apps are always refused.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }

                VStack(spacing: 0) {
                    if model.applications.isEmpty {
                        Text(model.snapshot == nil ? "Applications unavailable" : "No applications added")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, minHeight: 72)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(model.applications.enumerated()), id: \.element.id) { index, app in
                                let isExpanded = !isRemoveMode && expandedAppIds.contains(app.id)
                                let isSelectedForRemoval = isRemoveMode && selectedForRemoval.contains(app.id)
                                let isRowSelected = model.selection == app.id || isSelectedForRemoval

                                VStack(spacing: 0) {
                                    HStack(spacing: 9) {
                                        // Disclosure chevron / Remove checkbox slot
                                        ZStack {
                                            if isRemoveMode {
                                                Image(systemName: isSelectedForRemoval ? "checkmark.square.fill" : "square")
                                                    .font(.system(size: 13, weight: .medium))
                                                    .foregroundStyle(isSelectedForRemoval ? DesignTokens.accentBlue : Color.secondary)
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
                                            .lineLimit(1)

                                        Spacer(minLength: 8)

                                        HStack(spacing: 5) {
                                            Text(app.classification.title)
                                                .font(.system(size: 13))
                                                .foregroundStyle(DesignTokens.textSecondary)
                                            Image(systemName: "chevron.up.chevron.down")
                                                .font(.system(size: 9, weight: .semibold))
                                                .foregroundStyle(DesignTokens.textSecondary)
                                        }
                                        .padding(.vertical, 3)
                                        .padding(.horizontal, 4)
                                        .contentShape(Rectangle())
                                        .overlay {
                                            Menu {
                                                ForEach(ApplicationClassification.allCases, id: \.self) { classification in
                                                    Button {
                                                        Task { await model.classify(app, as: classification) }
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
                                        .disabled(isRemoveMode || model.isBusy)
                                        .accessibilityLabel("Access for \(app.name)")
                                    }
                                    .padding(.horizontal, 12)
                                    .frame(minHeight: 38)
                                    .background(
                                        isRowSelected
                                            ? Color.accentColor.opacity(0.12)
                                            : (isExpanded ? Color.primary.opacity(0.03) : Color.clear)
                                    )
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        model.selection = app.id
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
                                        expandedApplicationDrawer(for: app)
                                            .transition(.opacity.combined(with: .move(edge: .top)))
                                    }

                                    if index < model.applications.count - 1 {
                                        Rectangle()
                                            .fill(DesignTokens.settingsRowDivider)
                                            .frame(height: 1)
                                            .padding(.horizontal, 12)
                                    }
                                }
                            }
                        }
                    }

                    Divider()
                        .overlay(DesignTokens.settingsRowDivider)

                    // Bottom [+ | −] / [Delete | Cancel] action bar
                    HStack(spacing: 2) {
                        if isRemoveMode {
                            Button(role: .destructive) {
                                let idsToRemove = selectedForRemoval
                                withAnimation(.spring(response: 0.26, dampingFraction: 0.82)) {
                                    isRemoveMode = false
                                    selectedForRemoval.removeAll()
                                }
                                Task {
                                    await model.remove(ids: idsToRemove)
                                }
                            } label: {
                                Text(selectedForRemoval.isEmpty ? "Delete" : "Delete (\(selectedForRemoval.count))")
                                    .font(.system(size: 12, weight: .medium))
                                    .foregroundStyle(selectedForRemoval.isEmpty ? Color.secondary : Color.red)
                                    .padding(.horizontal, 8)
                                    .frame(height: 24)
                            }
                            .buttonStyle(.borderless)
                            .disabled(selectedForRemoval.isEmpty || model.isBusy)
                            .accessibilityLabel("Confirm removal of selected applications")

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
                            Button(action: chooseApplication) {
                                Image(systemName: "plus")
                                    .font(.system(size: 11.5, weight: .medium))
                                    .foregroundStyle(DesignTokens.textSecondary)
                                    .frame(width: 24, height: 22)
                            }
                            .buttonStyle(.borderless)
                            .help("Add application or executable")
                            .accessibilityLabel("Add application or executable")
                            .disabled(model.snapshot == nil)

                            Divider().frame(height: 12)

                            Button {
                                withAnimation(.spring(response: 0.26, dampingFraction: 0.82)) {
                                    isRemoveMode = true
                                    expandedAppIds.removeAll()
                                    if let sel = model.selection {
                                        selectedForRemoval = [sel]
                                    } else {
                                        selectedForRemoval.removeAll()
                                    }
                                }
                            } label: {
                                Image(systemName: "minus")
                                    .font(.system(size: 11.5, weight: .medium))
                                    .foregroundStyle(model.applications.isEmpty ? DesignTokens.textTertiary : DesignTokens.textSecondary)
                                    .frame(width: 24, height: 22)
                            }
                            .buttonStyle(.borderless)
                            .help("Select applications to remove")
                            .accessibilityLabel("Remove selected application")
                            .disabled(model.applications.isEmpty)

                            Spacer()

                            if model.isBusy {
                                ProgressView().controlSize(.small).padding(.trailing, 6)
                            }
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                }
                .disabled(model.isBusy)
                .modifier(SettingsGroupCardModifier())

                Text("Changes require Touch ID or your macOS password. Removing an app blocks it and revokes its approvals.")
                    .font(.caption).foregroundStyle(.secondary)

                if let message = model.message {
                    Text(message).font(.callout).foregroundStyle(.secondary)
                    Button("Reload") { Task { await model.load() } }.disabled(model.isBusy)
                }
            }
            .padding(22)
        }
        .task { await model.load() }
    }

    private func identityKindBadge(for identity: ApplicationIdentity) -> some View {
        let label = identity.kind == .designatedRequirement ? "Designated Req" : "SHA-256"
        return Text(label)
            .font(.system(size: 10, weight: .medium))
            .foregroundStyle(DesignTokens.accentBlue)
            .padding(.horizontal, 6)
            .padding(.vertical, 1.5)
            .background(
                RoundedRectangle(cornerRadius: 4, style: .continuous)
                    .fill(DesignTokens.accentBlue.opacity(0.11))
            )
    }

    private func expandedApplicationDrawer(for app: RegisteredApplication) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 5) {
                GridRow {
                    Text("Identity Kind")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.secondary)
                    Text(app.identity.kind == .designatedRequirement ? "Designated Requirement (Code Signature)" : "Executable SHA-256 Digest")
                        .font(.system(size: 11.5))
                }
                GridRow {
                    Text("Identity Value")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.secondary)
                    Text(KeyDetailInspectorView.trimIdentity(app.identity.value))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                GridRow {
                    Text("Executable Path")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.secondary)
                    HStack(spacing: 6) {
                        Text(app.path)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(app.path, forType: .string)
                        } label: {
                            Image(systemName: "doc.on.doc")
                                .font(.system(size: 10.5))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .help("Copy executable path")
                    }
                }
                GridRow {
                    Text("Classification")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.secondary)
                    Text(classificationSummary(for: app.classification))
                        .font(.system(size: 11.5))
                }
            }

            Divider()

            HStack {
                Text("Removing \(app.name) with [−] unregisters it and revokes active approvals.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
                if app.classification != .block {
                    Button(role: .destructive) {
                        Task { await model.classify(app, as: .block) }
                    } label: {
                        Text("Block on All Keys")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                }
            }
        }
        .padding(.leading, 38)
        .padding(.trailing, 14)
        .padding(.vertical, 10)
        .background(Color.primary.opacity(0.025))
    }

    private func classificationSummary(for classification: ApplicationClassification) -> String {
        switch classification {
        case .personal:
            return "Personal — Allowed to request Personal and Bot keys"
        case .bot:
            return "Bot — Allowed to use Bot keys"
        case .block:
            return "Blocked — Always refused on all keys"
        }
    }

    private func chooseApplication() {
        let panel = NSOpenPanel()
        panel.title = "Add application or executable"
        panel.prompt = "Add"
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            Task { @MainActor in await model.add(url: url) }
        }
    }
}
