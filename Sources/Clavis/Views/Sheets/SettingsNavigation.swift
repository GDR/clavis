import SwiftUI
import AppKit
import ClavisCore

private enum SettingsTab: String, CaseIterable {
    case general = "General"
    case bots = "Bots"
    var symbol: String { self == .general ? "gearshape" : "desktopcomputer" }
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

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                general
                    .opacity(selectedTab == SettingsTab.general.rawValue ? 1 : 0)
                    .disabled(selectedTab != SettingsTab.general.rawValue)
                    .allowsHitTesting(selectedTab == SettingsTab.general.rawValue)
                    .accessibilityHidden(selectedTab != SettingsTab.general.rawValue)
                ApplicationSettingsPane(model: applications)
                    .opacity(selectedTab == SettingsTab.bots.rawValue ? 1 : 0)
                    .disabled(selectedTab != SettingsTab.bots.rawValue)
                    .allowsHitTesting(selectedTab == SettingsTab.bots.rawValue)
                    .accessibilityHidden(selectedTab != SettingsTab.bots.rawValue)
            }
            HStack(spacing: 3) {
                ForEach(SettingsTab.allCases, id: \.rawValue) { tab in
                    Button {
                        selectedTab = tab.rawValue
                        focusedTab = tab
                    } label: {
                        VStack(spacing: 3) {
                            Image(systemName: tab.symbol).font(.system(size: 14))
                            Text(tab.rawValue).font(.system(size: 10, weight: .medium))
                        }
                        .foregroundStyle(selectedTab == tab.rawValue ? Color.accentColor : Color.secondary)
                        .frame(width: 66, height: 42)
                        .background {
                            if selectedTab == tab.rawValue {
                                Capsule().fill(.quaternary)
                            }
                        }
                        .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .focused($focusedTab, equals: tab)
                    .accessibilityIdentifier("settings-tab-\(tab.rawValue.lowercased())")
                    .accessibilityLabel("\(tab.rawValue) settings")
                    .accessibilityAddTraits(selectedTab == tab.rawValue ? [.isSelected] : [])
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
            if SettingsTab(rawValue: selectedTab) == nil { selectedTab = SettingsTab.general.rawValue }
        }
    }
}

private struct ApplicationSettingsPane: View {
    @ObservedObject var model: ApplicationSettingsModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Applications").font(.headline)
                Text("Personal apps can use all keys. Bots can use Bot keys.")
                    .font(.callout).foregroundStyle(.secondary)
                VStack(spacing: 0) {
                    if model.applications.isEmpty {
                        Text(model.snapshot == nil ? "Applications unavailable" : "No applications added")
                            .font(.callout).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, minHeight: 84)
                    }
                    if !model.applications.isEmpty {
                        List(selection: $model.selection) {
                            ForEach(model.applications) { app in
                                HStack(spacing: 10) {
                                    Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                                        .resizable().frame(width: 28, height: 28)
                                        .accessibilityHidden(true)
                                    Text(app.name).font(.system(size: 12, weight: .medium))
                                        .lineLimit(1).truncationMode(.middle).help(app.path)
                                    Spacer(minLength: 8)
                                    Picker("Access for \(app.name)", selection: Binding(
                                        get: { app.classification },
                                        set: { value in Task { await model.classify(app, as: value) } }
                                    )) {
                                        ForEach(ApplicationClassification.allCases, id: \.self) { classification in
                                            Text(classification.title).tag(classification)
                                        }
                                    }
                                    .labelsHidden().frame(width: 110)
                                }
                                .padding(.horizontal, 14).padding(.vertical, 12)
                                .background(model.selection == app.id ? Color.accentColor.opacity(0.12) : .clear)
                                .contentShape(Rectangle())
                                .tag(app.id)
                                .listRowInsets(EdgeInsets())
                            }
                        }
                        .listStyle(.inset)
                        .scrollContentBackground(.hidden)
                        .frame(height: CGFloat(min(model.applications.count, 6)) * 54)
                        .onDeleteCommand { Task { await model.removeSelected() } }
                    }
                    HStack(spacing: 0) {
                        Button(action: chooseApplication) { Image(systemName: "plus").frame(width: 30, height: 28) }
                            .help("Add application or executable")
                            .accessibilityLabel("Add application or executable")
                            .disabled(model.snapshot == nil)
                        Divider().frame(height: 20)
                        Button { Task { await model.removeSelected() } } label: {
                            Image(systemName: "minus").frame(width: 30, height: 28)
                        }
                        .help("Remove selected application")
                        .accessibilityLabel("Remove selected application")
                        .disabled(model.selection == nil)
                        Spacer()
                        if model.isBusy { ProgressView().controlSize(.small).padding(.trailing, 10) }
                    }
                    .buttonStyle(.borderless)
                    .background(.quaternary.opacity(0.5))
                }
                .disabled(model.isBusy)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary))
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
