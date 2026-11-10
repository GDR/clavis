import SwiftUI
import LocalAuthentication
import AuthExpShared

// App 1 — baseline: LAContext + SecAccessControl.userPresence with the standard system dialog.

enum SystemPromptMode: String, CaseIterable, Identifiable {
    case implicitKeyPrompt = "Implicit: SecKeyCreateSignature triggers the prompt"
    case evaluateOwnerAuth = "Explicit: evaluatePolicy(.deviceOwnerAuthentication)"
    case evaluateBiometrics = "Explicit: evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)"
    case evaluateAccessControl = "Explicit: evaluateAccessControl(key ACL, .useKeySign)"
    var id: String { rawValue }
}

@MainActor
final class SystemPromptState: ObservableObject {
    @Published var mode: SystemPromptMode = .implicitKeyPrompt
    @Published var hideFallback = false
    @Published var reuseSeconds: Double = 0
}

@main
struct SystemPromptApp: App {
    @StateObject private var model: LabModel
    @StateObject private var state = SystemPromptState()

    init() {
        // When spawned as the signing agent child process, never show UI.
        CrossProcessAgentRunner.handleAgentCommandLineIfPresent()
        _model = StateObject(wrappedValue: LabModel(
            title: "App 1 — System prompt (LocalAuthentication)",
            profile: "system-prompt",
            mechanismLabel: "system-prompt",
            allowedPresets: [.userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode]))
    }

    var body: some Scene {
        WindowGroup {
            LabRootView(model: model,
                        blurb: "Standard system authentication sheet. Test Touch ID, password fallback, cancel, wrong password, machines without Touch ID.") {
                SystemPromptControls(model: model, state: state)
            }
        }
    }
}

struct SystemPromptControls: View {
    @ObservedObject var model: LabModel
    @ObservedObject var state: SystemPromptState

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Picker("Mode", selection: $state.mode) {
                ForEach(SystemPromptMode.allCases) { Text($0.rawValue).tag($0) }
            }
            Toggle("Hide \"Use Password…\" fallback button", isOn: $state.hideFallback)
            HStack {
                Text("touchIDAuthenticationAllowableReuseDuration: \(Int(state.reuseSeconds)) s").font(.caption)
                Slider(value: $state.reuseSeconds, in: 0...300, step: 10)
            }
        }
        .onAppear { install() }
        .onChange(of: state.mode) { _, _ in install() }
    }

    private func install() {
        let model = model, state = state
        model.mechanismLabel = "system-prompt/\(state.mode.rawValue.prefix(8))"
        model.primaryProvider = {
            try await ApprovalPopup.present(
                challenge: model.challenge,
                content: { _ in
                    Text("Approve opens the standard macOS authentication sheet (\(state.mode.rawValue)).")
                        .font(.caption).foregroundStyle(.secondary)
                },
                authenticate: { _ in
                    let ctx = LAContext()
                    ctx.touchIDAuthenticationAllowableReuseDuration = state.reuseSeconds
                    if state.hideFallback { ctx.localizedFallbackTitle = "" }
                    let reason = "sign: \(model.challenge.operationSummary)"
                    ctx.localizedReason = reason
                    switch state.mode {
                    case .implicitKeyPrompt:
                        // No explicit evaluation: macOS prompts from inside SecKeyCreateSignature.
                        break
                    case .evaluateOwnerAuth:
                        _ = try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
                    case .evaluateBiometrics:
                        _ = try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
                    case .evaluateAccessControl:
                        guard let r = model.record else { throw LAError(.invalidContext) }
                        let ac = try r.preset.makeAccessControl()
                        _ = try await ctx.evaluateAccessControl(ac, operation: .useKeySign, localizedReason: reason)
                    }
                    return ctx
                })
        }
    }
}
