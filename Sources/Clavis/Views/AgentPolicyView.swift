import SwiftUI
import AppKit
import UserNotifications
import ClavisCore

// MARK: - Agent Policy Validator

public enum AgentPolicyValidator {
    /// Validates a rate limit string (representing "Max Signatures / Min" or refill per minute).
    /// Non-numeric or <= 0 input triggers an inline error.
    public static func validateMaxSignaturesPerMinute(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return "Max Signatures / Min cannot be empty"
        }
        guard let value = Int(trimmed) else {
            return "Max Signatures / Min must be a valid positive integer"
        }
        if value <= 0 {
            return "Max Signatures / Min must be greater than 0"
        }
        if value > 600 {
            return "Max Signatures / Min must be between 1 and 600"
        }
        return nil
    }

    /// Validates a host pattern for Allowed Hosts.
    /// Rejects URL schemes (e.g. ssh://), ports (e.g. :22), usernames, and invalid syntax.
    public static func validateHostPattern(_ host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return "Host pattern cannot be empty"
        }
        if trimmed.range(of: "^[A-Za-z][A-Za-z0-9+.-]*://", options: .regularExpression) != nil || trimmed.contains("://") {
            return "URL schemes (e.g. 'ssh://') are not allowed. Enter only the hostname or IP pattern"
        }
        if trimmed.range(of: "^(\\[[^\\]]+\\]|[^:]+):([0-9]+)$", options: .regularExpression) != nil {
            return "Port numbers (e.g. ':22') are not allowed in host patterns"
        }
        if trimmed.contains("@") {
            return "Usernames (e.g. 'user@') are not allowed in host patterns"
        }
        if trimmed.contains("/") {
            return "Paths (e.g. '/path') are not allowed in host patterns"
        }
        if trimmed.count > 255 {
            return "Host pattern must not exceed 255 characters"
        }
        if trimmed.range(of: "^[A-Za-z0-9._\\-:*?\\[\\]]{1,255}$", options: .regularExpression) == nil {
            return "Invalid host pattern '\(trimmed)'. Use valid hostname, IP, or wildcard syntax"
        }
        return nil
    }
}

// MARK: - Agent Policy Form State

public struct AgentPolicyFormState: Equatable {
    public var baselinePolicy: AgentKeyPolicy
    public var mode: AgentKeyPolicy.Mode
    public var leaseMinutes: Int
    public var allowedHosts: [AgentAllowedHost]
    public var burst: Int
    public var refillPerMinute: Int
    public var maxSignaturesPerMinuteText: String
    public var isNotificationPermissionDenied: Bool
    public var hostError: String?

    public init(
        baseline: AgentKeyPolicy = AgentKeyPolicy(),
        mode: AgentKeyPolicy.Mode? = nil,
        leaseMinutes: Int? = nil,
        allowedHosts: [AgentAllowedHost]? = nil,
        burst: Int? = nil,
        refillPerMinute: Int? = nil,
        maxSignaturesPerMinuteText: String? = nil,
        isNotificationPermissionDenied: Bool = false,
        hostError: String? = nil
    ) {
        self.baselinePolicy = baseline
        self.mode = mode ?? baseline.mode
        self.leaseMinutes = leaseMinutes ?? baseline.leaseMinutes
        self.allowedHosts = allowedHosts ?? baseline.allowedHosts
        let refill = refillPerMinute ?? baseline.refillPerMinute
        self.burst = burst ?? baseline.burst
        self.refillPerMinute = refill
        self.maxSignaturesPerMinuteText = maxSignaturesPerMinuteText ?? "\(refill)"
        self.isNotificationPermissionDenied = isNotificationPermissionDenied
        self.hostError = hostError
    }

    public var isModeDirty: Bool {
        mode != baselinePolicy.mode
    }

    public var isLeaseDirty: Bool {
        leaseMinutes != baselinePolicy.leaseMinutes
    }

    public var isAllowedHostsDirty: Bool {
        allowedHosts != baselinePolicy.allowedHosts
    }

    public var isBurstDirty: Bool {
        burst != baselinePolicy.burst
    }

    public var isRefillDirty: Bool {
        let trimmed = maxSignaturesPerMinuteText.trimmingCharacters(in: .whitespacesAndNewlines)
        if let parsed = Int(trimmed) {
            return parsed != baselinePolicy.refillPerMinute
        }
        return true
    }

    public var hasUnsavedChanges: Bool {
        isModeDirty || isLeaseDirty || isAllowedHostsDirty || isBurstDirty || isRefillDirty
    }

    public var rateLimitValidationError: String? {
        AgentPolicyValidator.validateMaxSignaturesPerMinute(maxSignaturesPerMinuteText)
    }

    public var isSaveDisabled: Bool {
        !hasUnsavedChanges || rateLimitValidationError != nil
    }

    public var showNotificationWarning: Bool {
        mode == .notify && isNotificationPermissionDenied
    }

    @discardableResult
    public mutating func addHost(_ text: String, lookup: ((String) throws -> [AgentAllowedHost])? = nil) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if let error = AgentPolicyValidator.validateHostPattern(trimmed) {
            self.hostError = error
            return error
        }

        let lookupFn = lookup ?? { host in try KnownHosts.lookup(host: host) }
        do {
            let found = try lookupFn(trimmed)
            if found.isEmpty {
                let err = ClavisUIStrings.AgentPolicy.hostNotFound
                self.hostError = err
                return err
            }
            for h in found where !allowedHosts.contains(where: { $0.hostKeyBlob == h.hostKeyBlob }) {
                allowedHosts.append(h)
            }
            self.hostError = nil
            return nil
        } catch {
            let err = ClavisUIStrings.AgentPolicy.hostNotFound
            self.hostError = err
            return err
        }
    }

    public mutating func revert() {
        self.mode = baselinePolicy.mode
        self.leaseMinutes = baselinePolicy.leaseMinutes
        self.allowedHosts = baselinePolicy.allowedHosts
        self.burst = baselinePolicy.burst
        self.refillPerMinute = baselinePolicy.refillPerMinute
        self.maxSignaturesPerMinuteText = "\(baselinePolicy.refillPerMinute)"
        self.hostError = nil
    }
}

// MARK: - Unsaved Changes Indicator

public struct AgentPolicyUnsavedBadge: View {
    public let text: String

    public init(text: String = "Modified") {
        self.text = text
    }

    public var body: some View {
        HStack(spacing: 3) {
            Circle()
                .fill(Color.orange)
                .frame(width: 5, height: 5)
            Text(text)
                .font(.system(size: 9, weight: .semibold))
                .foregroundColor(.orange)
        }
        .padding(.horizontal, 5)
        .padding(.vertical, 2)
        .background(Color.orange.opacity(0.12))
        .cornerRadius(4)
        .accessibilityLabel(text)
    }
}

// MARK: - Agent Policy View

public struct AgentPolicyView: View {
    public let key: SSHKeyInfo
    @ObservedObject var appState: AppState

    public static let leaseOptions = [15, 60, 240, 480, 1440]

    @State internal var baselinePolicy: AgentKeyPolicy? = nil

    @State internal var mode: AgentKeyPolicy.Mode = .none
    @State internal var leaseMinutes: Int = 480
    @State internal var allowedHosts: [AgentAllowedHost] = []
    @State internal var burst: Int = 30
    @State internal var refillPerMinute: Int = 6
    @State internal var maxSignaturesPerMinuteText: String = "6"

    @State internal var isAddingHost: Bool = false
    @State internal var newHostText: String = ""
    @State internal var hostError: String? = nil

    @State internal var isSaving: Bool = false
    @State internal var saveFeedback: String? = nil
    @State internal var saveError: String? = nil

    @State internal var localPermissionDenied: Bool = false

    /// Optional override for testing notification permission denial warning banner.
    public var notificationPermissionDeniedOverride: Bool? = nil

    public init(
        key: SSHKeyInfo,
        appState: AppState,
        notificationPermissionDeniedOverride: Bool? = nil
    ) {
        self.key = key
        self.appState = appState
        self.notificationPermissionDeniedOverride = notificationPermissionDeniedOverride
    }

    // MARK: - Computed Properties

    public var rateLimitValidationError: String? {
        AgentPolicyValidator.validateMaxSignaturesPerMinute(maxSignaturesPerMinuteText)
    }

    public var isModeDirty: Bool {
        guard let baseline = baselinePolicy else { return false }
        return mode != baseline.mode
    }

    public var isLeaseDirty: Bool {
        guard let baseline = baselinePolicy else { return false }
        return leaseMinutes != baseline.leaseMinutes
    }

    public var isAllowedHostsDirty: Bool {
        guard let baseline = baselinePolicy else { return false }
        return allowedHosts != baseline.allowedHosts
    }

    public var isBurstDirty: Bool {
        guard let baseline = baselinePolicy else { return false }
        return burst != baseline.burst
    }

    public var isRefillDirty: Bool {
        guard let baseline = baselinePolicy else { return false }
        let trimmed = maxSignaturesPerMinuteText.trimmingCharacters(in: .whitespacesAndNewlines)
        if let parsed = Int(trimmed) {
            return parsed != baseline.refillPerMinute
        }
        return true
    }

    public var hasUnsavedChanges: Bool {
        isModeDirty || isLeaseDirty || isAllowedHostsDirty || isBurstDirty || isRefillDirty
    }

    public var isNotificationPermissionDenied: Bool {
        if let override = notificationPermissionDeniedOverride {
            return override
        }
        return localPermissionDenied || appState.agentSessionViewModel.isNotificationPermissionDenied
    }

    public var showNotificationWarning: Bool {
        mode == .notify && isNotificationPermissionDenied
    }

    public var isSaveDisabled: Bool {
        !hasUnsavedChanges || isSaving || rateLimitValidationError != nil
    }

    public var currentFormState: AgentPolicyFormState {
        AgentPolicyFormState(
            baseline: baselinePolicy ?? AgentKeyPolicy(),
            mode: mode,
            leaseMinutes: leaseMinutes,
            allowedHosts: allowedHosts,
            burst: burst,
            refillPerMinute: refillPerMinute,
            maxSignaturesPerMinuteText: maxSignaturesPerMinuteText,
            isNotificationPermissionDenied: isNotificationPermissionDenied
        )
    }

    // MARK: - Body

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(ClavisUIStrings.AgentPolicy.sectionTitle)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(DesignTokens.textTertiary)
                Spacer()
                if hasUnsavedChanges {
                    AgentPolicyUnsavedBadge(text: "Unsaved Changes")
                }
            }

            Form {
                Section {
                    VStack(alignment: .leading, spacing: 14) {
                        // Approval Mode
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                HStack(spacing: 6) {
                                    Text(ClavisUIStrings.AgentPolicy.modeTitle)
                                        .font(.system(size: 13, weight: .semibold))
                                    if isModeDirty {
                                        AgentPolicyUnsavedBadge()
                                    }
                                }
                                Spacer()
                                Picker("", selection: $mode) {
                                    Text(ClavisUIStrings.AgentPolicy.modeNone).tag(AgentKeyPolicy.Mode.none)
                                    Text(ClavisUIStrings.AgentPolicy.modeNotify).tag(AgentKeyPolicy.Mode.notify)
                                    Text(ClavisUIStrings.AgentPolicy.modeAsk).tag(AgentKeyPolicy.Mode.ask)
                                }
                                .labelsHidden()
                            }

                            // Notification permissions warning banner (#98)
                            if showNotificationWarning {
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.orange)
                                        .font(.system(size: 13))
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Notifications Disabled")
                                            .font(.system(size: 12, weight: .semibold))
                                            .foregroundColor(.primary)
                                        Text("Clavis notification banners are disabled in macOS System Settings. In Notify mode, agent signatures will proceed without visual alerts.")
                                            .font(.system(size: 11))
                                            .foregroundColor(DesignTokens.textSecondary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    Spacer()
                                    Button("Open Settings") {
                                        openNotificationSettings()
                                    }
                                    .liquidGlassButton()
                                    .controlSize(.small)
                                }
                                .padding(10)
                                .background(Color.orange.opacity(0.12))
                                .cornerRadius(8)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(Color.orange.opacity(0.3), lineWidth: 1)
                                )
                            }
                        }

                        Divider().background(DesignTokens.cardBorder)

                        // Session Length
                        HStack {
                            HStack(spacing: 6) {
                                Text(ClavisUIStrings.AgentPolicy.leaseTitle)
                                    .font(.system(size: 13, weight: .semibold))
                                if isLeaseDirty {
                                    AgentPolicyUnsavedBadge()
                                }
                            }
                            Spacer()
                            Picker("", selection: $leaseMinutes) {
                                ForEach(Self.leaseOptions, id: \.self) { minutes in
                                    Text(ClavisUIStrings.PanelLock.minutesFormat(minutes)).tag(minutes)
                                }
                            }
                            .labelsHidden()
                        }

                        Divider().background(DesignTokens.cardBorder)

                // Allowed Hosts (#97)
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        HStack(spacing: 6) {
                            Text(ClavisUIStrings.AgentPolicy.allowedHostsTitle)
                                .font(.system(size: 13, weight: .semibold))
                            if isAllowedHostsDirty {
                                AgentPolicyUnsavedBadge()
                            }
                        }
                        Spacer()
                        if !isAddingHost {
                            Button(action: { isAddingHost = true; hostError = nil }) {
                                Label(ClavisUIStrings.AgentPolicy.addHost, systemImage: "plus")
                            }
                            .buttonStyle(.borderless)
                            .font(.caption)
                        }
                    }

                    if isAddingHost {
                        HStack(spacing: 6) {
                            TextField("host.example.com", text: $newHostText)
                                .textFieldStyle(.roundedBorder)
                                .onSubmit(addHost)
                            Button(ClavisUIStrings.AgentPolicy.addHostButton, action: addHost)
                                .liquidGlassButton(prominent: true)
                                .controlSize(.small)
                            Button(ClavisUIStrings.Common.cancel) {
                                isAddingHost = false
                                newHostText = ""
                                hostError = nil
                            }
                            .liquidGlassButton()
                            .controlSize(.small)
                        }
                        if let err = hostError {
                            Text(err)
                                .font(.caption2)
                                .foregroundColor(.red)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    if allowedHosts.isEmpty {
                        Text(ClavisUIStrings.AgentPolicy.allowedHostsAny)
                            .font(.caption)
                            .foregroundColor(DesignTokens.textSecondary)
                    } else {
                        VStack(spacing: 6) {
                            ForEach(allowedHosts, id: \.hostKeyBlob) { host in
                                HStack {
                                    Image(systemName: "server.rack")
                                        .font(.caption)
                                        .foregroundColor(DesignTokens.textSecondary)
                                    Text(host.name)
                                        .font(.system(size: 12, design: .monospaced))
                                    Spacer()
                                    Button(action: {
                                        allowedHosts.removeAll(where: { $0.hostKeyBlob == host.hostKeyBlob })
                                    }) {
                                        Image(systemName: "trash")
                                            .font(.caption)
                                            .foregroundColor(.red.opacity(0.8))
                                    }
                                    .buttonStyle(.borderless)
                                    .accessibilityLabel(ClavisUIStrings.Accessibility.deleteHost)
                                }
                            }
                        }
                    }
                }

                Divider().background(DesignTokens.cardBorder)

                // Rate Limit (#97)
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 6) {
                        Text(ClavisUIStrings.AgentPolicy.rateLimitTitle)
                            .font(.system(size: 13, weight: .semibold))
                        if isBurstDirty || isRefillDirty {
                            AgentPolicyUnsavedBadge()
                        }
                    }

                    HStack(alignment: .top, spacing: 16) {
                        HStack {
                            Text(ClavisUIStrings.AgentPolicy.burstTitle)
                                .font(.caption)
                                .foregroundColor(DesignTokens.textSecondary)
                            Stepper("\(burst)", value: $burst, in: 1...1000)
                                .font(.caption)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("Max Signatures / Min")
                                    .font(.caption)
                                    .foregroundColor(DesignTokens.textSecondary)
                                TextField("6", text: $maxSignaturesPerMinuteText)
                                    .textFieldStyle(.roundedBorder)
                                    .frame(width: 55)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 6)
                                            .stroke(
                                                rateLimitValidationError != nil ? Color.red : (isRefillDirty ? Color.orange : Color.clear),
                                                lineWidth: 1
                                            )
                                    )
                                Stepper("", value: Binding(
                                    get: {
                                        Int(maxSignaturesPerMinuteText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? refillPerMinute
                                    },
                                    set: { newValue in
                                        maxSignaturesPerMinuteText = "\(newValue)"
                                        refillPerMinute = newValue
                                    }
                                ), in: 1...600)
                                .labelsHidden()
                            }
                            if let err = rateLimitValidationError {
                                Text(err)
                                    .font(.caption2)
                                    .foregroundColor(.red)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }

                Divider().background(DesignTokens.cardBorder)

                // Actions & Dirty State Status (#89)
                HStack {
                    if let feedback = saveFeedback {
                        Label(feedback, systemImage: "checkmark.circle.fill")
                            .font(.caption)
                            .foregroundColor(DesignTokens.accentGreen)
                    } else if let error = saveError {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundColor(.red)
                    } else if hasUnsavedChanges {
                        HStack(spacing: 8) {
                            HStack(spacing: 4) {
                                Circle().fill(Color.orange).frame(width: 6, height: 6)
                                Text("Unsaved changes")
                                    .font(.caption)
                                    .foregroundColor(DesignTokens.textSecondary)
                            }
                            Button("Revert") {
                                revertChanges()
                            }
                            .buttonStyle(.borderless)
                            .font(.caption)
                            .foregroundColor(DesignTokens.accentBlue)
                        }
                    }
                    Spacer()
                    Button(action: savePolicy) {
                        HStack(spacing: 6) {
                            if isSaving { ProgressView().controlSize(.small) }
                            Text(ClavisUIStrings.AgentPolicy.saveButton)
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .liquidGlassButton(prominent: true)
                    .tint(DesignTokens.accentBlue)
                    .disabled(isSaveDisabled)
                        }
                    }
                }
            }
            .groupedEmbeddedForm(zeroMargins: true)
        }
        .onAppear {
            loadPolicy()
            checkNotificationStatus()
        }
        .onChange(of: key.fingerprint) { _ in
            loadPolicy()
        }
        .onChange(of: mode) { newMode in
            if newMode == .notify {
                checkNotificationStatus()
            }
        }
    }

    // MARK: - Actions

    public func addHost() {
        _ = addHost(newHostText)
    }

    @discardableResult
    public func addHost(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        if let error = AgentPolicyValidator.validateHostPattern(trimmed) {
            self.hostError = error
            return error
        }

        do {
            let found = try KnownHosts.lookup(host: trimmed)
            if found.isEmpty {
                let err = ClavisUIStrings.AgentPolicy.hostNotFound
                self.hostError = err
                return err
            }
            for h in found where !allowedHosts.contains(where: { $0.hostKeyBlob == h.hostKeyBlob }) {
                allowedHosts.append(h)
            }
            newHostText = ""
            hostError = nil
            isAddingHost = false
            return nil
        } catch {
            let err = ClavisUIStrings.AgentPolicy.hostNotFound
            self.hostError = err
            return err
        }
    }

    public func loadPolicy() {
        let policy = appState.getAgentPolicy(fingerprint: key.fingerprint) ?? AgentKeyPolicy()
        self.baselinePolicy = policy
        self.mode = policy.mode
        self.leaseMinutes = policy.leaseMinutes
        self.allowedHosts = policy.allowedHosts
        self.burst = policy.burst
        self.refillPerMinute = policy.refillPerMinute
        self.maxSignaturesPerMinuteText = "\(policy.refillPerMinute)"
        self.hostError = nil
        self.saveError = nil
        self.saveFeedback = nil
    }

    public func revertChanges() {
        guard let baseline = baselinePolicy else { return }
        self.mode = baseline.mode
        self.leaseMinutes = baseline.leaseMinutes
        self.allowedHosts = baseline.allowedHosts
        self.burst = baseline.burst
        self.refillPerMinute = baseline.refillPerMinute
        self.maxSignaturesPerMinuteText = "\(baseline.refillPerMinute)"
        self.hostError = nil
        self.saveError = nil
        self.saveFeedback = nil
    }

    public func checkNotificationStatus() {
        guard mode == .notify else { return }
        Task { @MainActor in
            let status = await appState.agentSessionViewModel.checkNotificationAuthorizationStatus()
            self.localPermissionDenied = (status == .denied)
        }
    }

    public func savePolicy() {
        guard hasUnsavedChanges else { return }
        guard rateLimitValidationError == nil else { return }
        guard let parsedRefill = Int(maxSignaturesPerMinuteText.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return
        }

        saveError = nil
        saveFeedback = nil
        isSaving = true

        let policy = AgentKeyPolicy(
            mode: mode,
            leaseMinutes: leaseMinutes,
            allowedHosts: allowedHosts,
            burst: burst,
            refillPerMinute: parsedRefill
        )

        Task {
            do {
                try appState.setAgentPolicy(policy, fingerprint: key.fingerprint)
                await MainActor.run {
                    self.baselinePolicy = policy
                    self.refillPerMinute = parsedRefill
                    self.isSaving = false
                    self.saveFeedback = ClavisUIStrings.AgentPolicy.savedFeedback
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        self.saveFeedback = nil
                    }
                }
            } catch {
                await MainActor.run {
                    self.isSaving = false
                    self.saveError = error.localizedDescription
                }
            }
        }
    }

    private func openNotificationSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
            NSWorkspace.shared.open(url)
        } else if let url = URL(string: "x-apple.systempreferences:") {
            NSWorkspace.shared.open(url)
        }
    }
}
