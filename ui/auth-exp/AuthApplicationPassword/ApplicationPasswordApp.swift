import SwiftUI
import LocalAuthentication
import AuthExpShared

// App 3 — SecAccessControl.applicationPassword on a Secure Enclave key.
// The passphrase is mixed into the SEP key wrapping: wrong/missing password => hardware refuses to sign.

@MainActor
final class AppPasswordState: ObservableObject {
    @Published var password = ""
    @Published var supplyFromApp = true
    @Published var cacheContext = false
    var cachedContext: LAContext?
}

@main
struct ApplicationPasswordApp: App {
    @StateObject private var model: LabModel
    @StateObject private var state = AppPasswordState()

    init() {
        CrossProcessAgentRunner.handleAgentCommandLineIfPresent()
        _model = StateObject(wrappedValue: LabModel(
            title: "App 3 — Application password",
            profile: "app-password",
            mechanismLabel: "app-password",
            allowedPresets: [.applicationPassword, .userPresenceAndAppPassword]))
    }

    var body: some Scene {
        WindowGroup {
            LabRootView(model: model,
                        blurb: "Passphrase bound to the SEP key via .applicationPassword. Test app-supplied vs system-prompted password, wrong password retry, credential caching.") {
                AppPasswordControls(model: model, state: state)
            }
        }
    }
}

struct AppPasswordControls: View {
    @ObservedObject var model: LabModel
    @ObservedObject var state: AppPasswordState

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle("Supply password from the app's own field", isOn: $state.supplyFromApp)
            if state.supplyFromApp {
                SecureField("Password used at key creation (popup asks again)", text: $state.password)
            } else {
                Text("System prompts for the password (creation also uses system prompt).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Toggle("Cache LAContext between signs (credential caching)", isOn: $state.cacheContext)
        }
        .onAppear { install() }
    }

    private func install() {
        let model = model, state = state
        model.mechanismLabel = "app-password"
        model.keyCreationContext = {
            let ctx = LAContext()
            if state.supplyFromApp { _ = ctx.setCredential(Data(state.password.utf8), type: .applicationPassword) }
            return ctx
        }
        model.agentPassword = { state.supplyFromApp ? Data(state.password.utf8) : nil }
        model.primaryProvider = {
            if state.cacheContext, let cached = state.cachedContext { return cached }
            let ctx = try await ApprovalPopup.present(
                challenge: model.challenge,
                content: { session in
                    if state.supplyFromApp {
                        AnyView(SecureField("Key password", text: Binding(get: { session.secret }, set: { session.secret = $0 }))
                            .onSubmit { session.approve() })
                    } else {
                        AnyView(Text("Approve lets macOS show its own password prompt.")
                            .font(.caption).foregroundStyle(.secondary))
                    }
                },
                authenticate: { session in
                    let ctx = LAContext()
                    ctx.localizedReason = "Enter the Clavis key password"
                    if state.supplyFromApp {
                        _ = ctx.setCredential(Data(session.secret.utf8), type: .applicationPassword)
                    }
                    // A wrong password is only detected by the SEP at signing time, so verify here
                    // with a real signature to keep the popup open for retry.
                    if let r = model.record {
                        let km = model.keyManager
                        nonisolated(unsafe) let unsafeCtx = ctx
                        _ = try await Task.detached {
                            try km.sign(challengeData: Data("password-check".utf8), using: r, context: unsafeCtx)
                        }.value
                    }
                    return ctx
                })
            state.cachedContext = ctx
            return ctx
        }
    }
}
