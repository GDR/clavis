import SwiftUI
import AppKit
import ClavisCore
import UniformTypeIdentifiers

/// D-37: Settings is a single scrollable pane — no tab bar. Section order:
/// General · Applications & Agents · SSH Agent · Security · Advanced.
/// `general` carries the General-area groups built by `SettingsView`.
struct SettingsNavigation<General: View>: View {
    let general: General
    @Environment(AppState.self) private var appState
    @State private var applications: ApplicationSettingsModel

    init(general: General, agent: any AgentControlling) {
        self.general = general
        _applications = State(initialValue: ApplicationSettingsModel(agent: agent))
    }

    var body: some View {
        Form {
            general
            ApplicationsAgentsSection(model: applications)
            SSHAgentSection()
            SecurityDefaultsSection()
            AdvancedSettingsSection()
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .task { await applications.load() }
    }
}

// MARK: - Applications & Agents (one unified registered-applications outline)

private struct ApplicationsAgentsSection: View {
    var model: ApplicationSettingsModel
    @State private var expandedAppIds: Set<UUID> = []
    @State private var isRemoveMode: Bool = false
    @State private var selectedForRemoval: Set<UUID> = []
    @State private var testResults: [UUID: String] = [:]

    // Copy ported from .ux settings (S-12); private until it lands in ClavisUIStrings.
    private static let sectionNote = "Applications Clavis has seen requesting keys or that you added from the file system — agents included. Expand a row for trust identity, routing and detection. These appear in the + dialog when configuring key access."
    private static let removalFootnote = "Changes require Touch ID or your macOS password. Removing an app blocks it and revokes its approvals."
    private static let detectionPlaceholder = "Not seen yet"

    var body: some View {
        Section("Applications & Agents") {
            Text(Self.sectionNote)
                .font(.system(size: 11.5))
                .foregroundStyle(DesignTokens.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(spacing: 0) {
                if model.applications.isEmpty {
                    Text(model.snapshot == nil ? "Applications unavailable" : "No applications added")
                        .font(.system(size: 13)).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, minHeight: 72)
                } else {
                    ForEach(Array(model.applications.enumerated()), id: \.element.id) { index, app in
                        let isExpanded = !isRemoveMode && expandedAppIds.contains(app.id)
                        let isSelectedForRemoval = isRemoveMode && selectedForRemoval.contains(app.id)
                        let isRowSelected = model.selection == app.id || isSelectedForRemoval

                        VStack(spacing: 0) {
                            applicationRow(app, isExpanded: isExpanded, isSelectedForRemoval: isSelectedForRemoval, isRowSelected: isRowSelected)

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

                Divider()
                    .overlay(DesignTokens.settingsRowDivider)

                actionBar
            }
            .disabled(model.isBusy)

            Text(Self.removalFootnote)
                .font(.caption).foregroundStyle(.secondary)

            if let message = model.message {
                Text(message).font(.callout).foregroundStyle(.secondary)
                Button("Reload") { Task { await model.load() } }.disabled(model.isBusy)
            }
        }
    }

    private func applicationRow(_ app: RegisteredApplication, isExpanded: Bool, isSelectedForRemoval: Bool, isRowSelected: Bool) -> some View {
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

            // Key-access badge + classification menu (Personal / Agent / Blocked).
            Menu {
                ForEach(ApplicationClassification.allCases, id: \.self) { classification in
                    Button {
                        Task { await model.classify(app, as: classification) }
                    } label: {
                        if app.classification == classification {
                            Label(Self.classificationTitle(classification), systemImage: "checkmark")
                        } else {
                            Text(Self.classificationTitle(classification))
                        }
                    }
                }
            } label: {
                HStack(spacing: 5) {
                    Text(Self.classificationTitle(app.classification))
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(
                            RoundedRectangle(cornerRadius: 5, style: .continuous)
                                .fill(DesignTokens.cardBackground)
                        )
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.vertical, 3)
                .padding(.horizontal, 4)
                .contentShape(Rectangle())
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
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
    }

    private var actionBar: some View {
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
                .help("Register Application from File System…")
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
                .help("Select applications to unregister")
                .accessibilityLabel("Remove selected application")
                .disabled(model.applications.isEmpty)

                Spacer()

                Text("\(model.applications.count) registered")
                    .font(.system(size: 11))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .padding(.trailing, 4)

                if model.isBusy {
                    ProgressView().controlSize(.small).padding(.trailing, 6)
                }
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    private func expandedApplicationDrawer(for app: RegisteredApplication) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 5) {
                GridRow {
                    drawerLabel("Trust identity")
                    Text(app.identity.kind == .designatedRequirement ? "Designated Requirement (Code Signature)" : "Executable SHA-256 Digest")
                        .font(.system(size: 11.5))
                }
                GridRow {
                    drawerLabel("Identity value")
                    Text(KeyDetailInspectorView.trimIdentity(app.identity.value))
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                GridRow {
                    drawerLabel("Binary path")
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
                    drawerLabel("Routing")
                    Text(Self.routingStatus(for: app.classification))
                        .font(.system(size: 11.5))
                }
                GridRow {
                    drawerLabel("Detected by")
                    // Detection telemetry is not exposed by the daemon registry yet;
                    // show the honest placeholder until it is.
                    Text(Self.detectionPlaceholder)
                        .font(.system(size: 11.5))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                GridRow {
                    drawerLabel("Classification")
                    Text(Self.classificationSummary(for: app.classification))
                        .font(.system(size: 11.5))
                }
            }

            Divider()

            HStack {
                Text("Unregistering with [−] removes \(app.name) from Registered Applications.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
                if let result = testResults[app.id] {
                    Text(result)
                        .font(.system(size: 11))
                        .foregroundStyle(result.hasPrefix("✓") ? DesignTokens.accentGreen : DesignTokens.accentOrange)
                }
                Button("Test") {
                    testRouting(for: app)
                }
                .buttonStyle(.borderless)
                .font(.system(size: 11, weight: .medium))
                .help("Check that the routed socket is listening")
                if app.classification != .block {
                    Button(role: .destructive) {
                        Task { await model.classify(app, as: .block) }
                    } label: {
                        Text("Block \(app.name) on All Keys…")
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

    private func drawerLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(.secondary)
    }

    /// Read-only reachability check of the socket this app is routed to.
    private func testRouting(for app: RegisteredApplication) {
        let isAgent = app.classification == .bot
        let path = isAgent ? SSHAgentServer.defaultAgentSocketPath : SSHAgentServer.defaultSocketPath
        let socketName = isAgent ? "Agent socket" : "Personal socket"
        let listening = SSHAgentServer.isSocketListening(atPath: path)
        testResults[app.id] = listening ? "✓ \(socketName) reachable" : "✕ \(socketName) not listening"
    }

    private static func routingStatus(for classification: ApplicationClassification) -> String {
        switch classification {
        case .personal: return "Personal socket"
        case .bot: return "Agent socket"
        case .block: return "Blocked on all keys"
        }
    }

    /// Glossary D-32: the `.bot` classification is displayed as "Agent".
    private static func classificationTitle(_ classification: ApplicationClassification) -> String {
        switch classification {
        case .personal: return "Personal"
        case .bot: return "Agent"
        case .block: return "Blocked"
        }
    }

    private static func classificationSummary(for classification: ApplicationClassification) -> String {
        switch classification {
        case .personal:
            return "Personal — Allowed to request Personal and Agent keys"
        case .bot:
            return "Agent — Allowed to use Agent keys"
        case .block:
            return "Blocked — Always refused on all keys"
        }
    }

    private func chooseApplication() {
        let panel = NSOpenPanel()
        panel.title = "Register Application from File System"
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

// MARK: - SSH Agent (sockets, public keys, self-routing check)

private struct SSHAgentSection: View {
    @State private var selfRouting = SSHAgentSection.checkSelfRouting()

    private static let routingFootnote = "Sockets are routing, not isolation."
    private static let publicKeysValue = "Login Keychain · shared by app, agent and CLI"

    var body: some View {
        Section("SSH Agent") {
            socketRow(title: "Personal socket", path: SSHAgentServer.defaultSocketPath)
            socketRow(title: "Agent socket", path: SSHAgentServer.defaultAgentSocketPath)

            PlainSettingsRow(title: "Public keys", subtitle: Self.publicKeysValue) {
                EmptyView()
            }

            PlainSettingsRow(
                title: "Self-routing",
                subtitle: selfRouting.configured
                    ? "~/.zshenv sources shell.sh (read-only check)"
                    : selfRouting.detail
            ) {
                if selfRouting.configured {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(DesignTokens.accentGreen)
                        .font(.system(size: 13))
                } else {
                    Text("Not configured")
                        .font(.system(size: 11.5))
                        .foregroundStyle(DesignTokens.textSecondary)
                }
            }

            Text(Self.routingFootnote)
                .font(.caption).foregroundStyle(.secondary)
        }
        .onAppear { selfRouting = Self.checkSelfRouting() }
    }

    private func socketRow(title: String, path: String) -> some View {
        PlainSettingsRow(title: title, subtitle: "") {
            HStack(spacing: 6) {
                Text(Self.tildePath(path))
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(DesignTokens.textSecondary)
                    .textSelection(.enabled)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(path, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help("Copy \(title.lowercased()) path")
                .accessibilityLabel("Copy \(title.lowercased()) path")
            }
        }
    }

    static func tildePath(_ path: String) -> String {
        let home = NSHomeDirectory()
        return path.hasPrefix(home) ? "~" + String(path.dropFirst(home.count)) : path
    }

    /// Read-only check: does `~/.zshenv` source the Clavis self-routing snippet?
    static func checkSelfRouting() -> (configured: Bool, detail: String) {
        let zshenvPath = NSString(string: "~/.zshenv").expandingTildeInPath
        guard let content = try? String(contentsOfFile: zshenvPath, encoding: .utf8) else {
            return (false, "~/.zshenv not found")
        }
        if content.contains(".clavis/shell.sh") {
            return (true, "~/.zshenv sources shell.sh")
        }
        return (false, "~/.zshenv does not source ~/.clavis/shell.sh")
    }
}

// MARK: - Security (per-owner default policy, one global default timeout, retention, monitor)

private struct SecurityDefaultsSection: View {
    // Local persistence until the daemon exposes these defaults (cross-cutting follow-up).
    @AppStorage("clavis.settings.defaultPolicy.personal") private var personalPolicyRaw = BiometricPolicy.userPresence.rawValue
    @AppStorage("clavis.settings.defaultPolicy.agent") private var agentPolicyRaw = BiometricPolicy.userPresence.rawValue
    @AppStorage("clavis.settings.defaultTimeout") private var defaultTimeoutRaw = KeyGracePeriod.fifteenMinutes.rawValue
    @AppStorage("clavis.settings.activityRetention") private var activityRetention = "90d"
    @AppStorage("clavis.settings.agentOnPersonal") private var agentOnPersonal = "ask"
    @AppStorage("clavis.settings.systemMonitor") private var systemMonitorEnabled = false

    private static let defaultsFootnote = "Defaults for new keys. Every key gets an unlocked timeout; one confirmation per key + requesting app lasts that long. Agent sessions survive lock until they expire."

    var body: some View {
        Section("Security") {
            policyRow(title: "Personal keys", selection: $personalPolicyRaw)
            policyRow(title: "Agent keys", selection: $agentPolicyRaw)

            PlainSettingsRow(title: "Default unlocked timeout", subtitle: "") {
                Picker("", selection: $defaultTimeoutRaw) {
                    ForEach(CreateKeySheet.unlockedTimeoutOptions, id: \.period) { option in
                        Text(option.title).tag(option.period.rawValue)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }

            Text(Self.defaultsFootnote)
                .font(.caption).foregroundStyle(.secondary)
        }

        Section {
            PlainSettingsRow(title: "Keep Activity for", subtitle: "") {
                Picker("", selection: $activityRetention) {
                    Text("90 days").tag("90d")
                    Text("1 year").tag("1y")
                    Text("Forever").tag("forever")
                }
                .labelsHidden()
                .fixedSize()
            }

            PlainSettingsRow(title: "When an agent reaches a Personal key", subtitle: "") {
                Picker("", selection: $agentOnPersonal) {
                    Text("Ask, naming the agent").tag("ask")
                    Text("Refuse").tag("refuse")
                }
                .labelsHidden()
                .fixedSize()
            }

            PlainSettingsRow(
                title: "System monitor (opt-in)",
                subtitle: "Endpoint Security visibility into agent launches."
            ) {
                Toggle("", isOn: $systemMonitorEnabled)
                    .toggleStyle(.switch)
                    .labelsHidden()
            }
        }
    }

    private func policyRow(title: String, selection: Binding<String>) -> some View {
        PlainSettingsRow(title: title, subtitle: "") {
            Picker("", selection: selection) {
                ForEach(CreateKeySheet.creationPolicies) { policy in
                    Text(policy.title).tag(policy.rawValue)
                }
            }
            .labelsHidden()
            .fixedSize()
        }
    }
}

// MARK: - Advanced (public inventory export — no private material)

private struct AdvancedSettingsSection: View {
    @Environment(AppState.self) private var appState
    @State private var exportMessage: String?

    private static let inventorySubtitle = "Names, public keys and fingerprints. No private material."

    var body: some View {
        Section("Advanced") {
            PlainSettingsRow(title: "Public inventory", subtitle: Self.inventorySubtitle) {
                Button("Export public inventory…") {
                    exportPublicInventory()
                }
                .fixedSize()
            }
            if let exportMessage {
                Text(exportMessage)
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private struct InventoryEntry: Codable {
        let name: String
        let publicKey: String
        let fingerprint: String
    }

    private func exportPublicInventory() {
        let entries = appState.keys.map {
            InventoryEntry(name: $0.label, publicKey: $0.publicKeyOpenSSH, fingerprint: $0.fingerprint)
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clavis-inventory.json"
        panel.allowedContentTypes = [.json]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                try encoder.encode(entries).write(to: url)
                Task { @MainActor in exportMessage = "Saved \(url.lastPathComponent) (no private keys)." }
            } catch {
                Task { @MainActor in exportMessage = "Export failed: \(error.localizedDescription)" }
            }
        }
    }
}

// MARK: - Plain row (label left, native control right — no icon tile)

private struct PlainSettingsRow<Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder let trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13))
                    .foregroundColor(.primary)
                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            trailing()
        }
        .padding(.vertical, 2)
    }
}
