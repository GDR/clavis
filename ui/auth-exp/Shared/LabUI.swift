import SwiftUI
import AppKit
import LocalAuthentication

// MARK: - Shared test harness model
//
// Every prototype runs the same sequence: generate SEP P-256 key -> show request ->
// authenticate (mechanism-specific `primaryProvider`) -> SecKeyCreateSignature -> verify.
// Only the provider that produces the authenticated LAContext differs between apps.

@MainActor
public final class LabModel: ObservableObject {
    public let title: String
    public let profile: String
    public let allowedPresets: [SEPKeyAccessPreset]
    public let keyManager: SecureEnclaveKeyManager
    public let log = AuthenticationLog()

    @Published public var record: PersistedSEPKeyRecord?
    @Published public var preset: SEPKeyAccessPreset
    @Published public var challenge: SigningChallenge
    @Published public private(set) var outcomes: [SigningAttemptOutcome] = []
    @Published public private(set) var inFlight = 0
    @Published public var environment = HardwareAuthEnvironment.inspect()

    /// Context from the last successful authentication (for reuse / agent-handoff tests).
    public var lastContext: LAContext?
    /// Mechanism-specific authentication step; returns the context to sign with.
    public var primaryProvider: @MainActor () async throws -> LAContext = { LAContext() }
    public var mechanismLabel: String
    /// Optional context used at key creation (e.g. carries the application password).
    public var keyCreationContext: () -> LAContext? = { nil }
    /// Optional application password forwarded to the agent child process.
    public var agentPassword: () -> Data? = { nil }

    private var sequence = 1

    public init(title: String, profile: String, mechanismLabel: String, allowedPresets: [SEPKeyAccessPreset]) {
        self.title = title
        self.profile = profile
        self.mechanismLabel = mechanismLabel
        self.allowedPresets = allowedPresets
        self.keyManager = SecureEnclaveKeyManager(profileName: profile)
        let loaded = keyManager.loadPersistedKey()
        self.record = loaded
        self.preset = loaded?.preset ?? allowedPresets[0]
        self.challenge = SigningChallenge.fromPreset(SigningChallengePreset.presets[0])
        if let loaded {
            log.record(category: .lifecycle, outcome: .info, title: "Restored persisted key after launch",
                       details: "\(loaded.keyId) preset=\(loaded.preset.rawValue). Sign now to detect session persistence across restarts.")
        }
    }

    // MARK: Key lifecycle

    public func generateKey() {
        let start = Date()
        do {
            let r = try keyManager.generateKey(preset: preset, creationContext: keyCreationContext())
            record = r
            log.record(category: .keygen, outcome: .success, title: "Generated SEP P-256 key \(r.keyId)",
                       details: "ACL: \(r.hardwareACLDescription)", elapsedMs: Date().timeIntervalSince(start) * 1000)
        } catch {
            log.record(category: .keygen, outcome: .error, title: "Key generation failed",
                       details: "preset=\(preset.rawValue)", error: error)
        }
    }

    public func deleteKey() {
        try? keyManager.deletePersistedKey()
        record = nil
        lastContext = nil
        log.record(category: .keygen, outcome: .info, title: "Deleted persisted key record", details: "")
    }

    public func applyPreset(_ p: SEPKeyAccessPreset) { preset = p }

    public func selectChallenge(_ p: SigningChallengePreset) {
        challenge = SigningChallenge.fromPreset(p, sequenceNumber: sequence)
    }

    private func advanceChallenge() {
        sequence += 1
        challenge = SigningChallenge(sequenceNumber: sequence, clientProcess: challenge.clientProcess,
                                     operationSummary: challenge.operationSummary, payloadText: challenge.payloadText)
    }

    // MARK: Core signing flow

    @discardableResult
    public func runSign(
        label: String? = nil,
        reused: Bool = false,
        provider: (@MainActor () async throws -> LAContext)? = nil
    ) async -> Bool {
        guard let record else {
            log.record(category: .sepSign, outcome: .error, title: "No key", details: "Generate a key first.")
            return false
        }
        let ch = challenge
        let mech = label ?? mechanismLabel
        let start = Date()
        inFlight += 1
        defer { inFlight -= 1 }
        do {
            let ctx = try await (provider ?? primaryProvider)()
            log.record(category: .auth, outcome: .success, title: "Authentication step finished (\(mech))",
                       details: "context \(reused ? "REUSED" : "fresh")", elapsedMs: Date().timeIntervalSince(start) * 1000)
            let data = ch.rawChallengeData
            let km = keyManager
            nonisolated(unsafe) let unsafeCtx = ctx
            let result = try await Task.detached { try km.sign(challengeData: data, using: record, context: unsafeCtx) }.value
            lastContext = ctx
            let ms = Date().timeIntervalSince(start) * 1000
            outcomes.insert(SigningAttemptOutcome(
                challengeSequence: ch.sequenceNumber, challengeDigestHex: ch.sha256DigestHex, mechanismLabel: mech,
                succeeded: true, signatureDER: result.signatureDER, signatureVerifiedWithPublicKey: result.verified,
                elapsedMilliseconds: ms, wasContextReused: reused), at: 0)
            log.record(category: .sepSign, outcome: .success, title: "Signed seq=\(ch.sequenceNumber) (\(mech))",
                       details: "verified=\(result.verified) sig=\(result.signatureDER.count)B", elapsedMs: ms)
            advanceChallenge()
            return true
        } catch {
            let ms = Date().timeIntervalSince(start) * 1000
            outcomes.insert(SigningAttemptOutcome(
                challengeSequence: ch.sequenceNumber, challengeDigestHex: ch.sha256DigestHex, mechanismLabel: mech,
                succeeded: false, signatureDER: nil, signatureVerifiedWithPublicKey: false, elapsedMilliseconds: ms,
                wasContextReused: reused, errorSummary: error.localizedDescription,
                errorSymbolicDetails: AuthErrorInspector.describe(error)), at: 0)
            log.record(category: .sepSign, outcome: .denied, title: "No signature (\(mech))",
                       details: "Expected for cancel / wrong credential.", elapsedMs: ms, error: error)
            return false
        }
    }

    // MARK: Standard scenarios

    public func signPrimary() async { await runSign() }

    public func signTwiceSequentially() async {
        log.record(category: .reuseTest, outcome: .info, title: "Sign twice: 2 consecutive requests",
                   details: "A second prompt appearing means no authentication reuse.")
        await runSign()
        await runSign()
    }

    public func signReusingLastContext() async {
        guard let ctx = lastContext else {
            log.record(category: .reuseTest, outcome: .error, title: "No previous context", details: "Sign once first.")
            return
        }
        // interactionNotAllowed makes any needed re-authentication fail instead of prompting,
        // so success means the old context genuinely still authorizes the key.
        let copyFlag = ctx.interactionNotAllowed
        ctx.interactionNotAllowed = true
        let ok = await runSign(label: "\(mechanismLabel) [reused ctx]", reused: true) { ctx }
        ctx.interactionNotAllowed = copyFlag
        log.record(category: .reuseTest, outcome: ok ? .info : .info,
                   title: ok ? "Context reuse WORKS (authorization persisted)" : "Context reuse rejected (fresh auth required)",
                   details: "")
    }

    public func signConcurrently(count: Int = 3) async {
        log.record(category: .concurrency, outcome: .info, title: "Launching \(count) concurrent signing requests",
                   details: "Count the number of prompts shown.")
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<count {
                group.addTask { @MainActor in await self.runSign(label: "\(self.mechanismLabel) [concurrent]") }
            }
        }
    }

    // MARK: Security criterion: signature must not be obtainable by bypassing UI approval

    public func bypassUnauthenticatedInProcess() async {
        guard let record else { return }
        let km = keyManager
        let data = Data("bypass-in-process".utf8)
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        nonisolated(unsafe) let unsafeCtx = ctx
        do {
            _ = try await Task.detached { try km.sign(challengeData: data, using: record, context: unsafeCtx) }.value
            log.record(category: .bypassTest, outcome: .securityFail, title: "BYPASS SUCCEEDED in-process",
                       details: "Signature obtained without any authentication!")
        } catch {
            log.record(category: .bypassTest, outcome: .securityPass, title: "In-process bypass blocked by SEP",
                       details: "App code skipped UI approval, key refused.", error: error)
        }
    }

    public func bypassUnauthenticatedAgent() async {
        guard let record else { return }
        do {
            let r = try await CrossProcessAgentRunner.spawnAgentSign(
                mode: "unauthenticated-bypass", profileName: record.profileName, challengeData: Data("bypass-agent".utf8))
            log.record(category: .bypassTest, outcome: r.succeeded ? .securityFail : .securityPass,
                       title: r.succeeded ? "BYPASS SUCCEEDED from other process (PID \(r.agentPID))"
                                          : "Other-process bypass blocked (PID \(r.agentPID))",
                       details: r.errorDescription ?? "signature obtained without authentication", elapsedMs: r.elapsedMs)
        } catch {
            log.record(category: .ipcAgent, outcome: .error, title: "Agent spawn failed", details: "", error: error)
        }
    }

    public func agentWithHandedOffContext() async {
        guard let record, let ctx = lastContext else {
            log.record(category: .ipcAgent, outcome: .error, title: "No authenticated context", details: "Sign once first.")
            return
        }
        guard let ext = SecureEnclaveKeyManager.extractExternalizedContext(ctx) else {
            log.record(category: .ipcAgent, outcome: .error, title: "externalizedContext unavailable", details: "")
            return
        }
        do {
            let r = try await CrossProcessAgentRunner.spawnAgentSign(
                mode: "with-externalized-context", profileName: record.profileName,
                challengeData: Data("agent-handoff".utf8), externalizedContext: ext)
            log.record(category: .ipcAgent, outcome: r.succeeded ? .success : .denied,
                       title: "GUI->Agent context handoff \(r.succeeded ? "signed" : "rejected") (PID \(r.agentPID))",
                       details: r.errorDescription ?? "verified=\(r.signatureVerified). Matches Clavis GUI/agent split.",
                       elapsedMs: r.elapsedMs)
        } catch {
            log.record(category: .ipcAgent, outcome: .error, title: "Agent spawn failed", details: "", error: error)
        }
    }

    public func agentOwnPrompt() async {
        guard let record else { return }
        do {
            let r = try await CrossProcessAgentRunner.spawnAgentSign(
                mode: "agent-direct-prompt", profileName: record.profileName,
                challengeData: Data("agent-own-prompt".utf8), appPassword: agentPassword())
            log.record(category: .ipcAgent, outcome: r.succeeded ? .success : .denied,
                       title: "Agent-owned authentication \(r.succeeded ? "signed" : "failed") (PID \(r.agentPID))",
                       details: r.errorDescription ?? "verified=\(r.signatureVerified)", elapsedMs: r.elapsedMs)
        } catch {
            log.record(category: .ipcAgent, outcome: .error, title: "Agent spawn failed", details: "", error: error)
        }
    }

    public func refreshEnvironment() {
        environment = HardwareAuthEnvironment.inspect()
        log.record(category: .lifecycle, outcome: .info, title: "Environment refreshed",
                   details: "bio=\(environment.biometrySummary); companion=\(environment.companionSummary)")
    }
}

// MARK: - Shared root view

public struct LabRootView<Accessory: View>: View {
    @ObservedObject var model: LabModel
    let blurb: String
    let accessory: Accessory

    public init(model: LabModel, blurb: String, @ViewBuilder accessory: () -> Accessory) {
        self.model = model
        self.blurb = blurb
        self.accessory = accessory()
    }

    public var body: some View {
        HSplitView {
            ScrollView { controls.padding() }.frame(minWidth: 460, idealWidth: 500)
            LogPanel(log: model.log, title: model.title).frame(minWidth: 420)
        }
        .frame(minWidth: 960, minHeight: 680)
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(model.title).font(.title2.bold())
            Text(blurb).font(.callout).foregroundStyle(.secondary)

            GroupBox("Environment") {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Secure Enclave: \(model.environment.secureEnclaveAvailable ? "yes" : "NO")")
                    Text("Biometry: \(model.environment.biometrySummary)")
                    Text("Companion: \(model.environment.companionSummary)")
                    Text("Password usable: \(model.environment.passwordUsable ? "yes" : "no")")
                    Button("Refresh") { model.refreshEnvironment() }
                }.font(.caption).frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("1. Secure Enclave key") {
                VStack(alignment: .leading, spacing: 6) {
                    Picker("Access control", selection: $model.preset) {
                        ForEach(model.allowedPresets) { Text($0.displayName).tag($0) }
                    }
                    HStack {
                        Button("Generate key") { model.generateKey() }
                        Button("Delete key") { model.deleteKey() }.disabled(model.record == nil)
                    }
                    if let r = model.record {
                        Text("\(r.keyId)  \(r.publicKeyFingerprint)\n\(r.hardwareACLDescription)")
                            .font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
                    } else {
                        Text("No key").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            GroupBox("2. Signing request") {
                VStack(alignment: .leading, spacing: 6) {
                    Menu("Load preset request") {
                        ForEach(SigningChallengePreset.presets) { p in
                            Button(p.title) { model.selectChallenge(p) }
                        }
                    }
                    Text(model.challenge.clientProcess).font(.headline)
                    Text(model.challenge.operationSummary)
                    Text("seq \(model.challenge.sequenceNumber)  nonce \(model.challenge.nonceHex)\nsha256 \(model.challenge.sha256DigestHex.prefix(32))…")
                        .font(.system(.caption2, design: .monospaced))
                }.frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("3. Authenticate & sign (opens approval popup)") {
                VStack(alignment: .leading, spacing: 8) {
                    accessory
                    HStack {
                        Button("Simulate sign request") { Task { await model.signPrimary() } }
                            .buttonStyle(.borderedProminent).disabled(model.record == nil)
                        if model.inFlight > 0 { ProgressView().controlSize(.small); Text("\(model.inFlight) in flight").font(.caption) }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("4. Scenarios") {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Button("Sign twice") { Task { await model.signTwiceSequentially() } }
                        Button("Reuse last context (no prompt)") { Task { await model.signReusingLastContext() } }
                    }
                    HStack {
                        Button("3 concurrent requests") { Task { await model.signConcurrently() } }
                        Button("Agent: own auth") { Task { await model.agentOwnPrompt() } }
                        Button("Agent: handed-off ctx") { Task { await model.agentWithHandedOffContext() } }
                    }
                    Text("Restart / lock-unlock tests: quit & relaunch (`just auth-exp-run …`) or lock the Mac, then use \"Reuse last context\" / \"Sign\".")
                        .font(.caption2).foregroundStyle(.secondary)
                }.disabled(model.record == nil)
            }

            GroupBox("5. Bypass attempts (must FAIL)") {
                HStack {
                    Button("Skip UI, sign in-process") { Task { await model.bypassUnauthenticatedInProcess() } }
                    Button("Skip UI, sign from other process") { Task { await model.bypassUnauthenticatedAgent() } }
                }.disabled(model.record == nil)
            }
        }
    }
}

public struct LogPanel: View {
    @ObservedObject var log: AuthenticationLog
    let title: String

    public var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Log").font(.headline)
                Spacer()
                Text(log.lastLockStateChange).font(.caption2).foregroundStyle(.secondary)
                Button("Copy report") { log.copyMarkdownReport(experimentTitle: title) }
                Button("Clear") { log.clear() }
            }
            List(log.entries) { e in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(AuthenticationLog.formatTimestamp(e.timestamp)).font(.system(.caption, design: .monospaced))
                        Text(e.outcome.rawValue).font(.caption.bold()).foregroundStyle(color(e.outcome))
                        Text(e.category.rawValue).font(.caption).foregroundStyle(.secondary)
                        if let ms = e.elapsedMs { Text(String(format: "%.0f ms", ms)).font(.caption).foregroundStyle(.secondary) }
                    }
                    Text(e.title).font(.callout)
                    if !e.details.isEmpty { Text(e.details).font(.caption).foregroundStyle(.secondary) }
                    if let b = e.errorBreakdown {
                        Text(b).font(.system(.caption2, design: .monospaced)).foregroundStyle(.red).textSelection(.enabled)
                    }
                }
            }
        }.padding()
    }

    private func color(_ o: AuthLogOutcome) -> Color {
        switch o {
        case .success, .securityPass: return .green
        case .denied: return .orange
        case .error, .securityFail: return .red
        case .info: return .secondary
        }
    }
}
