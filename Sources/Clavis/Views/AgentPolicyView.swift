import SwiftUI
import ClavisCore

public struct AgentPolicyView: View {
    public let key: Ed25519KeyInfo
    @ObservedObject var appState: AppState

    public static let leaseOptions = [15, 60, 240, 480, 1440]

    @State private var mode: AgentKeyPolicy.Mode = .none
    @State private var leaseMinutes: Int = 480
    @State private var allowedHosts: [AgentAllowedHost] = []
    @State private var burst: Int = 30
    @State private var refillPerMinute: Int = 6

    @State private var isAddingHost: Bool = false
    @State private var newHostText: String = ""
    @State private var hostError: String? = nil

    @State private var isSaving: Bool = false
    @State private var saveFeedback: String? = nil
    @State private var saveError: String? = nil

    public init(key: Ed25519KeyInfo, appState: AppState) {
        self.key = key
        self.appState = appState
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(ClavisUIStrings.AgentPolicy.sectionTitle)
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(DesignTokens.textTertiary)

            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text(ClavisUIStrings.AgentPolicy.modeTitle).font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Picker("", selection: $mode) {
                        Text(ClavisUIStrings.AgentPolicy.modeNone).tag(AgentKeyPolicy.Mode.none)
                        Text(ClavisUIStrings.AgentPolicy.modeNotify).tag(AgentKeyPolicy.Mode.notify)
                        Text(ClavisUIStrings.AgentPolicy.modeAsk).tag(AgentKeyPolicy.Mode.ask)
                    }
                    .pickerStyle(.menu).labelsHidden().frame(width: 170)
                }

                Divider().background(DesignTokens.cardBorder)

                HStack {
                    Text(ClavisUIStrings.AgentPolicy.leaseTitle).font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Picker("", selection: $leaseMinutes) {
                        ForEach(Self.leaseOptions, id: \.self) { minutes in
                            Text(ClavisUIStrings.PanelLock.minutesFormat(minutes)).tag(minutes)
                        }
                    }
                    .pickerStyle(.menu).labelsHidden().frame(width: 120)
                }

                Divider().background(DesignTokens.cardBorder)

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(ClavisUIStrings.AgentPolicy.allowedHostsTitle).font(.system(size: 13, weight: .semibold))
                        Spacer()
                        if !isAddingHost {
                            Button(action: { isAddingHost = true; hostError = nil }) {
                                Label(ClavisUIStrings.AgentPolicy.addHost, systemImage: "plus")
                            }
                            .buttonStyle(.borderless).font(.caption)
                        }
                    }

                    if isAddingHost {
                        HStack(spacing: 6) {
                            TextField("host.example.com", text: $newHostText).textFieldStyle(.roundedBorder).onSubmit(addHost)
                            Button(ClavisUIStrings.AgentPolicy.addHostButton, action: addHost).buttonStyle(.borderedProminent).controlSize(.small)
                            Button(ClavisUIStrings.Common.cancel) { isAddingHost = false; newHostText = ""; hostError = nil }.buttonStyle(.bordered).controlSize(.small)
                        }
                        if let err = hostError {
                            Text(err).font(.caption2).foregroundColor(.red)
                        }
                    }

                    if allowedHosts.isEmpty {
                        Text(ClavisUIStrings.AgentPolicy.allowedHostsAny).font(.caption).foregroundColor(DesignTokens.textSecondary)
                    } else {
                        VStack(spacing: 6) {
                            ForEach(allowedHosts, id: \.hostKeyBlob) { host in
                                HStack {
                                    Image(systemName: "server.rack").font(.caption).foregroundColor(DesignTokens.textSecondary)
                                    Text(host.name).font(.system(size: 12, design: .monospaced))
                                    Spacer()
                                    Button(action: { allowedHosts.removeAll(where: { $0.hostKeyBlob == host.hostKeyBlob }) }) {
                                        Image(systemName: "trash").font(.caption).foregroundColor(.red.opacity(0.8))
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                        }
                    }
                }

                Divider().background(DesignTokens.cardBorder)

                VStack(alignment: .leading, spacing: 8) {
                    Text(ClavisUIStrings.AgentPolicy.rateLimitTitle).font(.system(size: 13, weight: .semibold))
                    HStack(spacing: 16) {
                        HStack {
                            Text(ClavisUIStrings.AgentPolicy.burstTitle).font(.caption).foregroundColor(DesignTokens.textSecondary)
                            Stepper("\(burst)", value: $burst, in: 1...1000).font(.caption)
                        }
                        HStack {
                            Text(ClavisUIStrings.AgentPolicy.refillTitle).font(.caption).foregroundColor(DesignTokens.textSecondary)
                            Stepper("\(refillPerMinute)", value: $refillPerMinute, in: 1...600).font(.caption)
                        }
                    }
                }

                Divider().background(DesignTokens.cardBorder)

                HStack {
                    if let feedback = saveFeedback {
                        Label(feedback, systemImage: "checkmark.circle.fill").font(.caption).foregroundColor(DesignTokens.accentGreen)
                    } else if let error = saveError {
                        Label(error, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundColor(.red)
                    }
                    Spacer()
                    Button(action: savePolicy) {
                        HStack(spacing: 6) {
                            if isSaving { ProgressView().controlSize(.small) }
                            Text(ClavisUIStrings.AgentPolicy.saveButton)
                        }
                        .font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.borderedProminent).tint(DesignTokens.accentBlue).disabled(isSaving)
                }
            }
            .padding(14).glassCard(cornerRadius: 10)
        }
        .onAppear(perform: loadPolicy)
    }

    private func addHost() {
        let trimmed = newHostText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        do {
            let found = try KnownHosts.lookup(host: trimmed)
            if found.isEmpty {
                hostError = ClavisUIStrings.AgentPolicy.hostNotFound
                return
            }
            for h in found where !allowedHosts.contains(where: { $0.hostKeyBlob == h.hostKeyBlob }) {
                allowedHosts.append(h)
            }
            newHostText = ""; hostError = nil; isAddingHost = false
        } catch {
            hostError = ClavisUIStrings.AgentPolicy.hostNotFound
        }
    }

    private func loadPolicy() {
        if let policy = appState.getAgentPolicy(fingerprint: key.fingerprint) {
            self.mode = policy.mode; self.leaseMinutes = policy.leaseMinutes
            self.allowedHosts = policy.allowedHosts; self.burst = policy.burst
            self.refillPerMinute = policy.refillPerMinute
        }
    }

    private func savePolicy() {
        saveError = nil; saveFeedback = nil; isSaving = true
        let policy = AgentKeyPolicy(mode: mode, leaseMinutes: leaseMinutes, allowedHosts: allowedHosts, burst: burst, refillPerMinute: refillPerMinute)
        Task {
            do {
                try appState.setAgentPolicy(policy, fingerprint: key.fingerprint)
                await MainActor.run {
                    isSaving = false; saveFeedback = ClavisUIStrings.AgentPolicy.savedFeedback
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { saveFeedback = nil }
                }
            } catch {
                await MainActor.run { isSaving = false; saveError = error.localizedDescription }
            }
        }
    }
}
