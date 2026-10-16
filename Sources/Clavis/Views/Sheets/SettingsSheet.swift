import SwiftUI
import ClavisCore
import Security
import Darwin

public enum PinModeUI {
    public static func showsWeakPINWarning(_ mode: AuditReadMode) -> Bool {
        mode == .biometryOrPIN
    }
}

public struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var appState: AppState
    @ObservedObject var lock: PanelLockController
    private let modeChanger: PinModeChanger?
    @State private var globalMaxLease: Int = 1440
    @State private var lastSavedGlobalMaxLease: Int = 1440
    @State private var globalPolicyError: String? = nil
    private let globalMaxLeaseOptions = [60, 240, 480, 1440, 2880, 10080]

    @State private var copiedEnv = false
    @State private var activeSheet: ActiveSheet?
    @State private var showingResetAlert = false
    @State private var isSettingsAuthenticated: Bool
    @State private var isAuthenticating: Bool = false

    // Vault Sync & Repair State (#95)
    @State private var vaultSyncReport: VaultSyncReport? = nil
    @State private var isCheckingVault: Bool = false
    @State private var isRepairingVault: Bool = false
    @State private var vaultRepairSuccessMessage: String? = nil
    @State private var vaultRepairErrorMessage: String? = nil

    private enum ActiveSheet: Identifiable {
        case modeChange(AuditReadMode)
        case changePIN
        case resetPIN

        var id: String {
            switch self {
            case .modeChange(let m): return "mode-\(m.rawValue)"
            case .changePIN: return "changePIN"
            case .resetPIN: return "resetPIN"
            }
        }
    }

    public init(
        lock: PanelLockController? = nil,
        modeChanger: PinModeChanger? = nil,
        isSettingsAuthenticated: Bool = false
    ) {
        let resolvedLock = lock ?? PanelLockController.shared
        self.lock = resolvedLock
        self.modeChanger = modeChanger ?? PinModeChanger.makeDefault()
        self._isSettingsAuthenticated = State(
            initialValue: isSettingsAuthenticated || !resolvedLock.isEffectivelyLocked
        )
    }

    /// Settings is unlocked whenever Clavis itself is unlocked (`!lock.isEffectivelyLocked`)
    /// or when explicitly authenticated in-place.
    public var isUnlocked: Bool {
        isSettingsAuthenticated || !lock.isEffectivelyLocked
    }

    public var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(ClavisUIStrings.Settings.windowTitle)
                    .font(.system(size: 19, weight: .bold))
                Spacer()
                CircularGlassIconButton(
                    icon: "xmark",
                    size: 28,
                    iconSize: 11,
                    helpText: ClavisUIStrings.Common.cancel,
                    accessibilityLabel: ClavisUIStrings.Common.cancel
                ) {
                    dismiss()
                }
            }
            .padding(.horizontal, 22)
            .padding(.top, 18)
            .padding(.bottom, 12)

            Divider()

            if !isUnlocked {
                VStack(spacing: 16) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)

                    Text(ClavisUIStrings.Settings.windowTitle)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(.primary)

                    if lock.currentMode.requiresPIN {
                        PinEntryView(lock: lock, onUnlockSuccess: { _ in
                            isSettingsAuthenticated = true
                        })
                    } else {
                        Button(action: {
                            Task {
                                await authenticateSettings()
                            }
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "lock.open.fill")
                                Text(ClavisUIStrings.PanelLock.unlock)
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                        }
                        .liquidGlassButton(prominent: true)
                        .controlSize(.regular)
                        .keyboardShortcut(.defaultAction)
                        .disabled(isAuthenticating)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Form {
                    // Control Panel Lock Section
                    SettingsGroup(title: ClavisUIStrings.PanelLock.settingsSection) {
                        VStack(alignment: .leading, spacing: 10) {
                            SettingsRow(
                                icon: "lock.fill",
                                iconColor: Color(red: 0.88, green: 0.45, blue: 0.12),
                                title: ClavisUIStrings.PanelLock.settingsToggle,
                                subtitle: ""
                            ) {
                                Toggle("", isOn: Binding(
                                    get: { lock.isEnabled },
                                    set: { newValue in
                                        Task {
                                            _ = await lock.setEnabled(newValue, authenticated: true)
                                        }
                                    }
                                ))
                                .toggleStyle(.switch)
                                .labelsHidden()
                            }

                            if lock.isEnabled {
                                Divider()

                                SettingsRow(
                                    icon: "timer",
                                    iconColor: Color(red: 0.35, green: 0.78, blue: 0.98),
                                    title: "Grace period",
                                    subtitle: Self.inactivityGraceNote(minutes: lock.idleMinutes)
                                ) {
                                    Picker("", selection: Binding(
                                        get: { lock.idleMinutes },
                                        set: { lock.idleMinutes = $0 }
                                    )) {
                                        ForEach(PanelLockController.idleOptions, id: \.self) { minutes in
                                            Text(Self.inactivityOptionLabel(minutes: minutes))
                                                .tag(minutes)
                                        }
                                    }
                                    .labelsHidden()
                                }
                            }
                        }
                    }

                // Unlock Method Section
                SettingsGroup(title: ClavisUIStrings.PinUnlock.settingsSection) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach([AuditReadMode.passwordOrBiometry, .biometryOrPIN, .biometryAndPIN], id: \.self) { mode in
                            let isSelected = lock.currentMode == mode
                            let isAvailable = !mode.requiresPIN || PlatformSupport.hasSecureEnclave
                            Button(action: {
                                guard !isSelected && isAvailable else { return }
                                selectMode(mode)
                            }) {
                                HStack(spacing: 8) {
                                    Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                                        .foregroundColor(isSelected ? .accentColor : .secondary)
                                    Text(modeTitle(for: mode))
                                        .font(.system(size: 13))
                                        .foregroundColor(isAvailable ? .primary : .secondary)
                                    Spacer()
                                }
                            }
                            .buttonStyle(.plain)
                            .disabled(!isAvailable)
                            .accessibilityAddTraits(isSelected ? [.isSelected] : [])
                        }

                        if lock.currentMode.requiresPIN {
                            Divider()

                            HStack(spacing: 12) {
                                Button(ClavisUIStrings.PinUnlock.changePIN) {
                                    activeSheet = .changePIN
                                }
                                .liquidGlassButton()
                                .controlSize(.small)

                                Button(ClavisUIStrings.PinUnlock.forgotPIN) {
                                    ClavisLogger.promptDebug("calvis-ui", "SettingsSheet: displaying forgot PIN reset confirmation alert")
                                    showingResetAlert = true
                                }
                                .liquidGlassButton()
                                .controlSize(.small)
                            }
                            .padding(.top, 4)
                        }
                    }
                }

                // System Startup Section
                SettingsGroup(title: ClavisUIStrings.Settings.startupSection) {
                    SettingsRow(
                        icon: "power",
                        iconColor: Color(red: 0.0, green: 0.48, blue: 1.0),
                        title: ClavisUIStrings.Settings.launchAtLoginTitle,
                        subtitle: ClavisUIStrings.Settings.launchAtLoginSubtitle
                    ) {
                        Toggle("", isOn: Binding(
                            get: { appState.launchAtLogin },
                            set: { appState.setLaunchAtLogin($0) }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                    }
                }

                // SSH Integration Section
                SettingsGroup(title: ClavisUIStrings.Settings.sshSection) {
                    VStack(alignment: .leading, spacing: 10) {
                        SettingsRow(
                            icon: "terminal.fill",
                            iconColor: Color(red: 0.55, green: 0.58, blue: 0.62),
                            title: ClavisUIStrings.Settings.agentSocketTitle,
                            subtitle: SSHAgentServer.defaultSocketPath
                        ) {
                            EmptyView()
                        }

                        Divider()

                        VStack(alignment: .leading, spacing: 6) {
                            Text(ClavisUIStrings.Settings.envVarTitle)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(.secondary)

                            HStack(spacing: 8) {
                                Text(ClavisUIStrings.Settings.envVarCommand)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.primary)
                                    .lineLimit(1)
                                    .textSelection(.enabled)

                                Spacer()

                                Button(action: {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(ClavisUIStrings.Settings.envVarCommand, forType: .string)
                                    copiedEnv = true
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                        copiedEnv = false
                                    }
                                }) {
                                    HStack(spacing: 4) {
                                        Image(systemName: copiedEnv ? "checkmark" : "doc.on.doc")
                                        Text(copiedEnv ? ClavisUIStrings.Common.copied : ClavisUIStrings.Common.copy)
                                    }
                                    .font(.system(size: 11, weight: .medium))
                                }
                                .liquidGlassButton()
                                .controlSize(.small)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .liquidGlassControl(cornerRadius: 6)
                        }
                        .padding(.top, 2)
                    }
                }

                // Agent Session Policy Section
                SettingsGroup(title: ClavisUIStrings.AgentPolicy.sectionTitle) {
                    SettingsRow(
                        icon: "person.crop.circle.badge.clock",
                        iconColor: Color(red: 0.58, green: 0.35, blue: 0.88),
                        title: ClavisUIStrings.AgentPolicy.globalMaxLease,
                        subtitle: ""
                    ) {
                        Picker("", selection: $globalMaxLease) {
                            ForEach(globalMaxLeaseOptions, id: \.self) { minutes in
                                Text(ClavisUIStrings.PanelLock.minutesFormat(minutes))
                                    .tag(minutes)
                            }
                        }
                        .labelsHidden()
                        .onChange(of: globalMaxLease) { newValue in
                            guard newValue != lastSavedGlobalMaxLease else { return }
                            globalPolicyError = nil
                            Task { @MainActor in
                                do {
                                    try appState.setGlobalPolicy(AgentGlobalPolicy(maxLeaseMinutes: newValue))
                                    lastSavedGlobalMaxLease = newValue
                                } catch {
                                    globalMaxLease = lastSavedGlobalMaxLease
                                    globalPolicyError = error.localizedDescription
                                }
                            }
                        }
                    }
                    if let err = globalPolicyError {
                        Text(err).font(.caption2).foregroundColor(.red)
                    }
                }

                // Vault Integrity & Repair Section (#95)
                SettingsGroup(title: ClavisUIStrings.Settings.vaultSection) {
                    VStack(alignment: .leading, spacing: 10) {
                        if let report = vaultSyncReport, report.isDesynchronized {
                            // Surface Vault Desync Warning Banner
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(DesignTokens.accentOrange)
                                    .font(.system(size: 16))
                                    .accessibilityLabel("Warning")

                                VStack(alignment: .leading, spacing: 4) {
                                    Text(ClavisUIStrings.Settings.vaultDesyncWarning)
                                        .font(.system(size: 13, weight: .semibold))
                                        .foregroundColor(.primary)

                                    let count = report.detectedAnomalies.count
                                    Text(ClavisUIStrings.Settings.vaultDesyncDetails(count))
                                        .font(.system(size: 11))
                                        .foregroundColor(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }

                                Spacer()
                            }
                            .padding(10)
                            .background(DesignTokens.accentOrange.opacity(0.12))
                            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                            .overlay(
                                RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    .stroke(DesignTokens.accentOrange.opacity(0.4), lineWidth: 1)
                            )
                        }

                        // Status Row & Action
                        SettingsRow(
                            icon: vaultSyncReport?.isDesynchronized == true ? "exclamationmark.shield.fill" : "checkmark.shield.fill",
                            iconColor: vaultSyncReport?.isDesynchronized == true ? DesignTokens.accentOrange : DesignTokens.accentGreen,
                            title: ClavisUIStrings.Settings.vaultSection,
                            subtitle: vaultSyncReport?.isDesynchronized == true
                                ? ClavisUIStrings.Settings.vaultDesyncWarning
                                : ClavisUIStrings.Settings.vaultHealthy
                        ) {
                            Button(action: performVaultRepair) {
                                HStack(spacing: 4) {
                                    if isRepairingVault {
                                        ProgressView()
                                            .controlSize(.small)
                                    }
                                    Text(ClavisUIStrings.Settings.vaultRepairButton)
                                }
                            }
                            .liquidGlassButton(prominent: true)
                            .controlSize(.small)
                            .disabled(isRepairingVault)
                        }

                        if let success = vaultRepairSuccessMessage {
                            HStack(spacing: 6) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(DesignTokens.accentGreen)
                                Text(success)
                                    .font(.caption2)
                                    .foregroundColor(DesignTokens.accentGreen)
                            }
                        }

                        if let err = vaultRepairErrorMessage {
                            HStack(spacing: 6) {
                                Image(systemName: "exclamationmark.circle.fill")
                                    .foregroundColor(.red)
                                Text(err)
                                    .font(.caption2)
                                    .foregroundColor(.red)
                            }
                        }
                    }
                }

                // About Clavis Section (#96)
                SettingsGroup(title: ClavisUIStrings.Settings.aboutSection) {
                    VStack(alignment: .leading, spacing: 10) {
                        // Version
                        SettingsRow(
                            icon: "info.circle.fill",
                            iconColor: DesignTokens.accentBlue,
                            title: ClavisUIStrings.Settings.versionLabel,
                            subtitle: ""
                        ) {
                            Text(AboutProvenance.appVersion)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundColor(.secondary)
                                .textSelection(.enabled)
                        }

                        Divider()

                        // Git Commit SHA
                        SettingsRow(
                            icon: "number",
                            iconColor: Color(red: 0.60, green: 0.35, blue: 0.85),
                            title: ClavisUIStrings.Settings.commitShaLabel,
                            subtitle: ""
                        ) {
                            Text(AboutProvenance.gitCommitSHA)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                                .textSelection(.enabled)
                        }

                        Divider()

                        // Code Signing Identity
                        SettingsRow(
                            icon: "signature",
                            iconColor: DesignTokens.accentOrange,
                            title: ClavisUIStrings.Settings.codeSigningLabel,
                            subtitle: ""
                        ) {
                            Text(AboutProvenance.codeSigningIdentity)
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                                .textSelection(.enabled)
                        }

                        Divider()

                        // Daemon Version Parity
                        let parity = AboutProvenance.daemonParity(
                            isSocketActive: appState.isSocketActive,
                            agentPID: appState.agentPID
                        )
                        SettingsRow(
                            icon: "arrow.triangle.2.circlepath",
                            iconColor: parity == .matching ? DesignTokens.accentGreen : (parity == .mismatch ? DesignTokens.accentOrange : Color(red: 0.55, green: 0.58, blue: 0.62)),
                            title: ClavisUIStrings.Settings.daemonParityLabel,
                            subtitle: ""
                        ) {
                            switch parity {
                            case .matching:
                                HStack(spacing: 4) {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(DesignTokens.accentGreen)
                                    Text(ClavisUIStrings.Settings.daemonParityMatch)
                                        .font(.system(size: 12, weight: .medium))
                                        .foregroundColor(DesignTokens.accentGreen)
                                }
                            case .mismatch:
                                HStack(spacing: 4) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(DesignTokens.accentOrange)
                                    Text(ClavisUIStrings.Settings.daemonParityMismatch)
                                        .font(.system(size: 12, weight: .medium))
                                        .foregroundColor(DesignTokens.accentOrange)
                                }
                            case .offline:
                                Text(ClavisUIStrings.MenuBar.agentOffline)
                                    .font(.system(size: 12))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                }
                .formStyle(.grouped)
                .scrollContentBackground(.hidden)
                .onAppear {
                    if let global = appState.getGlobalPolicy() {
                        globalMaxLease = global.maxLeaseMinutes
                        lastSavedGlobalMaxLease = global.maxLeaseMinutes
                    }
                    checkVaultSync()
                }
            }
    }
    .frame(width: 480, height: 600)
    .onExitCommand {
        dismiss()
    }
    .onChange(of: lock.state) { _ in
        isSettingsAuthenticated = !lock.isEffectivelyLocked
    }
        .alert(ClavisUIStrings.PinUnlock.forgotPIN, isPresented: $showingResetAlert) {
            Button(ClavisUIStrings.PinUnlock.setPinTitle, role: .destructive) {
                ClavisLogger.promptDebug("calvis-ui", "SettingsSheet: user confirmed reset PIN dialog")
                activeSheet = .resetPIN
            }
            Button(ClavisUIStrings.Common.cancel, role: .cancel) {
                ClavisLogger.promptDebug("calvis-ui", "SettingsSheet: user cancelled reset PIN dialog")
            }
        } message: {
            Text(ClavisUIStrings.PinUnlock.resetWarning)
        }
        .sheet(item: $activeSheet) { sheet in
            let title: String = {
                switch sheet {
                case .modeChange: return ClavisUIStrings.PinUnlock.setPinTitle
                case .changePIN: return ClavisUIStrings.PinUnlock.changePIN
                case .resetPIN: return ClavisUIStrings.PinUnlock.forgotPIN
                }
            }()
            let subtitle: String? = {
                if case .modeChange(let m) = sheet { return modeTitle(for: m) }
                return nil
            }()
            let warning: String? = {
                switch sheet {
                case .modeChange(let m): return PinModeUI.showsWeakPINWarning(m) ? ClavisUIStrings.PinUnlock.warningOrMode : nil
                case .changePIN: return nil
                case .resetPIN: return ClavisUIStrings.PinUnlock.resetWarning
                }
            }()
            PinModeChangeSheet(
                title: title,
                subtitle: subtitle,
                warning: warning,
                onSave: { pin, confirmPin in
                    switch sheet {
                    case .modeChange(let targetMode):
                        _ = try await modeChanger?.changeMode(to: targetMode, newPIN: pin, confirmPIN: confirmPin, oldContext: lock.unlockContext, skipPasswordAuth: true)
                    case .changePIN:
                        _ = try await modeChanger?.changeMode(to: lock.currentMode, newPIN: pin, confirmPIN: confirmPin, oldContext: lock.unlockContext, skipPasswordAuth: true)
                    case .resetPIN:
                        try await modeChanger?.resetPIN(newPIN: pin, confirmPIN: confirmPin, skipPasswordAuth: true)
                    }
                    await MainActor.run { lock.objectWillChange.send() }
                },
                onDismiss: { activeSheet = nil }
            )
            .dismissOnOutsideClick {
                activeSheet = nil
            }
        }
    }

    private func authenticateSettings() async {
        guard !isAuthenticating && !isUnlocked else { return }
        isAuthenticating = true
        defer { isAuthenticating = false }
        await lock.unlock()
        if !lock.isEffectivelyLocked {
            isSettingsAuthenticated = true
        }
    }

    private func selectMode(_ mode: AuditReadMode) {
        if mode == .passwordOrBiometry {
            Task {
                do {
                    _ = try await modeChanger?.changeMode(
                        to: .passwordOrBiometry,
                        newPIN: nil,
                        confirmPIN: nil,
                        oldContext: lock.unlockContext,
                        skipPasswordAuth: true
                    )
                    await MainActor.run {
                        lock.objectWillChange.send()
                    }
                } catch {
                    // Password authentication cancelled or failed
                }
            }
        } else {
            activeSheet = .modeChange(mode)
        }
    }

    public static func inactivityGraceNote(minutes: Int) -> String {
        let unit = minutes == 1 ? "minute" : "minutes"
        return "Lock the Clavis window after \(minutes) \(unit) of inactivity."
    }

    public static func inactivityOptionLabel(minutes: Int) -> String {
        minutes == 1 ? "1 minute" : "\(minutes) minutes"
    }

    private func modeTitle(for mode: AuditReadMode) -> String {
        switch mode {
        case .passwordOrBiometry:
            return ClavisUIStrings.PinUnlock.modePasswordOrBiometry
        case .biometryOrPIN:
            return ClavisUIStrings.PinUnlock.modeBiometryOrPIN
        case .biometryAndPIN:
            return ClavisUIStrings.PinUnlock.modeBiometryAndPIN
        }
    }

    private func checkVaultSync() {
        guard !isCheckingVault else { return }
        isCheckingVault = true
        Task { @MainActor in
            do {
                let report = try appState.syncVault(repair: false)
                self.vaultSyncReport = report
                self.isCheckingVault = false
            } catch {
                self.vaultRepairErrorMessage = error.localizedDescription
                self.isCheckingVault = false
            }
        }
    }

    private func performVaultRepair() {
        guard !isRepairingVault else { return }
        isRepairingVault = true
        vaultRepairSuccessMessage = nil
        vaultRepairErrorMessage = nil
        Task { @MainActor in
            do {
                let report = try appState.syncVault(repair: true)
                if !ClavisEnvironment.isTesting {
                    _ = try? KeychainManager.shared.repairVault(replacePin: false)
                }
                self.vaultSyncReport = report
                self.isRepairingVault = false
                self.vaultRepairSuccessMessage = ClavisUIStrings.Settings.vaultRepaired
                self.appState.refresh()
            } catch {
                self.isRepairingVault = false
                self.vaultRepairErrorMessage = error.localizedDescription
            }
        }
    }
}

struct PinModeChangeSheet: View {
    let title: String
    let subtitle: String?
    let warning: String?
    let onSave: (String, String) async throws -> Void
    let onDismiss: () -> Void

    @State private var pin: String = ""
    @State private var confirmPin: String = ""
    @State private var errorMessage: String?
    @State private var isProcessing: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                if let subtitle = subtitle {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }

            if let warning = warning {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                        .font(.system(size: 14))
                    Text(warning)
                        .font(.system(size: 11))
                        .foregroundColor(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(8)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            }

            VStack(alignment: .leading, spacing: 10) {
                SecureField(ClavisUIStrings.PinUnlock.pinPlaceholder, text: $pin)
                    .textFieldStyle(.roundedBorder)
                    .disabled(isProcessing)

                SecureField(ClavisUIStrings.PinUnlock.confirmPinPlaceholder, text: $confirmPin)
                    .textFieldStyle(.roundedBorder)
                    .disabled(isProcessing)
            }

            if pin.count > 0 && pin.count < 6 {
                Text(ClavisUIStrings.PinUnlock.tooShort)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
            } else if confirmPin.count > 0 && pin != confirmPin {
                Text(ClavisUIStrings.PinUnlock.pinMismatch)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
            } else if let errorMessage = errorMessage {
                Text(errorMessage)
                    .font(.system(size: 11))
                    .foregroundColor(.red)
            }

            HStack {
                Button(ClavisUIStrings.Common.cancel) {
                    onDismiss()
                }
                .liquidGlassButton()
                .disabled(isProcessing)

                Spacer()

                Button(action: save) {
                    HStack(spacing: 4) {
                        if isProcessing {
                            ProgressView()
                                .controlSize(.small)
                        }
                        Text(ClavisUIStrings.PinUnlock.setPinTitle)
                    }
                }
                .liquidGlassButton(prominent: true)
                .disabled(pin.count < 6 || pin != confirmPin || isProcessing)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func save() {
        guard pin.count >= 6, pin == confirmPin, !isProcessing else { return }
        isProcessing = true
        errorMessage = nil
        Task {
            do {
                try await onSave(pin, confirmPin)
                await MainActor.run {
                    isProcessing = false
                    onDismiss()
                }
            } catch {
                await MainActor.run {
                    isProcessing = false
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
}

// Backward-compatible wrapper for any sheet callers
public struct SettingsSheet: View {
    @ObservedObject var appState: AppState

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        SettingsView()
            .environmentObject(appState)
    }
}

private struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        Section(title) {
            content()
        }
    }
}

private struct SettingsRow<Trailing: View>: View {
    let icon: String
    let iconColor: Color
    let title: String
    let subtitle: String
    @ViewBuilder let trailing: () -> Trailing

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(iconColor)
                    .frame(width: 28, height: 28)
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.white)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
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
        .padding(.vertical, 4)
    }
}

public enum DaemonParityStatus: Equatable, Sendable {
    case matching
    case mismatch
    case offline
}

public struct AboutProvenance: Sendable {
    public static var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
        if let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String, !build.isEmpty, build != version {
            return "v\(version) (\(build))"
        }
        return "v\(version)"
    }

    public static var rawVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    public static var gitCommitSHA: String {
        if let env = ProcessInfo.processInfo.environment["CLAVIS_GIT_COMMIT"], !env.isEmpty {
            return env
        }
        if let plist = Bundle.main.infoDictionary?["GitCommitHash"] as? String, !plist.isEmpty {
            return plist
        }
        if let plist = Bundle.main.infoDictionary?["GitRevision"] as? String, !plist.isEmpty {
            return plist
        }
        if let head = readGitHeadCommit() {
            return head
        }
        return "1995c78"
    }

    public static var codeSigningIdentity: String {
        var selfCode: SecCode?
        var staticSelf: SecStaticCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode,
              SecCodeCopyStaticCode(selfCode, [], &staticSelf) == errSecSuccess, let staticSelf else {
            return "Ad-hoc / Development"
        }

        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticSelf, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any] else {
            return "Ad-hoc / Development"
        }

        if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first {
            var commonName: CFString?
            SecCertificateCopyCommonName(leaf, &commonName)
            if let name = commonName as String?, !name.isEmpty {
                return name
            }
            if let summary = SecCertificateCopySubjectSummary(leaf) as String?, !summary.isEmpty {
                return summary
            }
        }

        if let team = dict[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty {
            return "Team ID: \(team)"
        }

        if let identifier = dict[kSecCodeInfoIdentifier as String] as? String, !identifier.isEmpty {
            return "\(identifier) (Ad-hoc)"
        }

        return "Ad-hoc / Development"
    }

    public static func daemonParity(isSocketActive: Bool, agentPID: pid_t?) -> DaemonParityStatus {
        guard isSocketActive else {
            return .offline
        }
        guard let pid = agentPID, pid > 0 else {
            return .matching
        }
        if let daemonPath = ProcessInspector.getProcessPath(pid: pid) {
            let appBundlePath = Bundle.main.bundleURL.path
            if appBundlePath.hasSuffix(".app") && !daemonPath.hasPrefix(appBundlePath) {
                return .mismatch
            }
        }
        return .matching
    }

    private static func readGitHeadCommit() -> String? {
        let cwd = FileManager.default.currentDirectoryPath
        let headPath = (cwd as NSString).appendingPathComponent(".git/HEAD")
        guard let content = try? String(contentsOfFile: headPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) else {
            return nil
        }
        if content.hasPrefix("ref: ") {
            let ref = String(content.dropFirst(5))
            let refPath = (cwd as NSString).appendingPathComponent(".git/\(ref)")
            if let sha = try? String(contentsOfFile: refPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), !sha.isEmpty {
                return String(sha.prefix(7))
            }
        } else if content.count >= 7 {
            return String(content.prefix(7))
        }
        return nil
    }
}

