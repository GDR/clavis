import SwiftUI
import LocalAuthentication
import AuthExpShared

// App 2 — embedded LocalAuthenticationView paired with an explicit LAContext.
// Key question: does an evaluation shown in the embedded view authorize the *Keychain/SEP*
// operation (evaluateAccessControl + same context in SecKeyCreateSignature), or only return a boolean?

enum EmbeddedMode: String, CaseIterable, Identifiable {
    case accessControl = "evaluateAccessControl(key ACL, .useKeySign)"
    case biometricsOrCompanion = "evaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrCompanion)"
    case biometrics = "evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)"
    case ownerAuth = "evaluatePolicy(.deviceOwnerAuthentication) (docs: fails w/o Touch ID/Watch)"
    case selfEvaluating = "Simple init: view evaluates by itself (result callback)"
    var id: String { rawValue }
}

@MainActor
final class EmbeddedState: ObservableObject {
    @Published var mode: EmbeddedMode = .accessControl
}

@main
struct EmbeddedAuthApp: App {
    @StateObject private var model: LabModel
    @StateObject private var state = EmbeddedState()

    init() {
        CrossProcessAgentRunner.handleAgentCommandLineIfPresent()
        _model = StateObject(wrappedValue: LabModel(
            title: "App 2 — Embedded LocalAuthenticationView",
            profile: "embedded",
            mechanismLabel: "embedded",
            allowedPresets: [.userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode]))
    }

    var body: some Scene {
        WindowGroup {
            LabRootView(model: model,
                        blurb: "Authentication control embedded in the window instead of a system sheet. Test with/without Touch ID, password fallback and whether the embedded evaluation authorizes the signing key.") {
                EmbeddedControls(model: model, state: state)
            }
        }
    }
}

struct EmbeddedControls: View {
    @ObservedObject var model: LabModel
    @ObservedObject var state: EmbeddedState

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Picker("Evaluation", selection: $state.mode) {
                ForEach(EmbeddedMode.allCases) { Text($0.rawValue).tag($0) }
            }
            Text("The popup embeds the authentication control; there is no Approve button, it starts evaluating immediately.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .onAppear { install() }
    }

    private func install() {
        let model = model, state = state
        model.mechanismLabel = "embedded"
        model.primaryProvider = {
            try await ApprovalPopup.present(
                challenge: model.challenge,
                autoStart: true,
                content: { session in EmbeddedAuthContent(session: session, selfEvaluating: state.mode == .selfEvaluating) },
                authenticate: { session in
                    let ctx = LAContext()
                    session.context = ctx
                    let reason = "sign: \(model.challenge.operationSummary)"
                    // Let SwiftUI attach the view to the context before evaluating.
                    try? await Task.sleep(nanoseconds: 200_000_000)
                    switch state.mode {
                    case .accessControl:
                        guard let r = model.record else { throw LAError(.invalidContext) }
                        let ac = try r.preset.makeAccessControl()
                        _ = try await ctx.evaluateAccessControl(ac, operation: .useKeySign, localizedReason: reason)
                    case .biometricsOrCompanion:
                        _ = try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrCompanion, localizedReason: reason)
                    case .biometrics:
                        _ = try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
                    case .ownerAuth:
                        _ = try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
                    case .selfEvaluating:
                        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                            session.viewResultHandler = { c.resume(with: $0) }
                        }
                    }
                    return ctx
                })
        }
    }
}

struct EmbeddedAuthContent: View {
    @ObservedObject var session: ApprovalSession
    let selfEvaluating: Bool

    var body: some View {
        HStack {
            Text("Authenticate with").font(.callout)
            if let ctx = session.context {
                if selfEvaluating {
                    LocalAuthenticationView("Sign", reason: Text(session.challenge.operationSummary), context: ctx) { result in
                        session.viewResultHandler?(result)
                    }
                } else {
                    LocalAuthenticationView("Sign", context: ctx)
                }
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}
