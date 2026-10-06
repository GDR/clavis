import SwiftUI
import ClavisCore

public enum PinModeUI {
    public static func showsWeakPINWarning(_ mode: AuditReadMode) -> Bool {
        mode == .biometryOrPIN
    }
}

public struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @ObservedObject var lock = PanelLockController.shared
    private let modeChanger: PinModeChanger?
    @State private var globalMaxLease: Int = 1440
    private let globalMaxLeaseOptions = [60, 240, 480, 1440, 2880, 10080]

    @State private var copiedEnv = false
    @State private var activeSheet: ActiveSheet?
    @State private var showingResetAlert = false

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

    public init(modeChanger: PinModeChanger? = nil) {
        self.modeChanger = modeChanger ?? PinModeChanger.makeDefault()
    }

    public var body: some View {
        ScrollView {
            VStack(spacing: 16) {
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
                                        _ = await lock.setEnabled(newValue)
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
                                title: ClavisUIStrings.PanelLock.settingsIdle,
                                subtitle: ""
                            ) {
                                Picker("", selection: Binding(
                                    get: { lock.idleMinutes },
                                    set: { lock.idleMinutes = $0 }
                                )) {
                                    ForEach(PanelLockController.idleOptions, id: \.self) { minutes in
                                        Text(ClavisUIStrings.PanelLock.minutesFormat(minutes))
                                            .tag(minutes)
                                    }
                                }
                                .pickerStyle(.menu)
                                .frame(width: 120)
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
                        }

                        if lock.currentMode.requiresPIN {
                            Divider()

                            HStack(spacing: 12) {
                                Button(ClavisUIStrings.PinUnlock.changePIN) {
                                    activeSheet = .changePIN
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)

                                Button(ClavisUIStrings.PinUnlock.forgotPIN) {
                                    ClavisLogger.promptDebug("calvis-ui", "SettingsSheet: displaying forgot PIN reset confirmation alert")
                                    showingResetAlert = true
                                }
                                .buttonStyle(.bordered)
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
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(Color(nsColor: .controlBackgroundColor).opacity(0.5))
                            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
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
                        .pickerStyle(.menu)
                        .frame(width: 120)
                        .onChange(of: globalMaxLease) { newValue in
                            Task {
                                try? appState.setGlobalPolicy(AgentGlobalPolicy(maxLeaseMinutes: newValue))
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
        .frame(width: 480, height: 560)
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
                        _ = try await modeChanger?.changeMode(to: targetMode, newPIN: pin, confirmPIN: confirmPin, oldContext: lock.unlockContext)
                    case .changePIN:
                        _ = try await modeChanger?.changeMode(to: lock.currentMode, newPIN: pin, confirmPIN: confirmPin, oldContext: lock.unlockContext)
                    case .resetPIN:
                        try await modeChanger?.resetPIN(newPIN: pin, confirmPIN: confirmPin)
                    }
                    await MainActor.run { lock.objectWillChange.send() }
                },
                onDismiss: { activeSheet = nil }
            )
        }
        .onAppear {
            if let global = appState.getGlobalPolicy() {
                globalMaxLease = global.maxLeaseMinutes
            }
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
                        oldContext: lock.unlockContext
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
                .buttonStyle(.borderedProminent)
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
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
                .padding(.horizontal, 4)

            VStack(spacing: 0) {
                content()
            }
            .padding(12)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.4))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(Color.white.opacity(0.08), lineWidth: 0.8)
            )
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
