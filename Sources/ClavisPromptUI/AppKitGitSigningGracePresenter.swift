import AppKit
import Foundation
import ClavisCore

/// Presents the MacBook Notch Touch ID prompt (`S-08` / `NotchPromptWindowController`) for Git signing bursts (`US-45`),
/// falling back to `CFUserNotificationGitSigningGracePresenter` in headless or non-GUI environments.
public struct AppKitGitSigningGracePresenter: GitSigningGracePresenter {
    public let defaultTimeout: TimeInterval

    public init(defaultTimeout: TimeInterval = 30.0) {
        self.defaultTimeout = defaultTimeout
    }

    public func prompt(keyLabel: String, clientDesc: String, timeout: TimeInterval) -> GitSigningPromptChoice {
        guard GitSigningPrompt.sessionCheckProvider() else {
            return .singleShot
        }

        #if DEBUG
        guard !ClavisEnvironment.isTesting else {
            return .cancel
        }
        #endif

        let semaphore = DispatchSemaphore(value: 0)
        let box = ResultBox()

        Task { @MainActor in
            box.choice = await self.presentNotchPrompt(
                keyLabel: keyLabel,
                clientDesc: clientDesc
            )
            semaphore.signal()
        }

        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            Task { @MainActor in
                NotchPromptWindowController.shared.dismiss()
            }
            return .cancel
        }
        return box.choice
    }

    public func prompt(keyLabel: String, clientDesc: String) -> GitSigningPromptChoice {
        prompt(keyLabel: keyLabel, clientDesc: clientDesc, timeout: defaultTimeout)
    }

    private final class ResultBox: @unchecked Sendable {
        var choice: GitSigningPromptChoice = .cancel
    }

    /// Builds a `NotchPromptRequest` for a Git / SSH signing prompt (`S-08` / `INV-09`) using real key and caller metadata.
    public static func makePromptRequest(
        keyLabel: String,
        clientDesc: String,
        keyType: KeyType? = nil,
        operation: String = "Sign a Git commit",
        initialScope: NotchSessionScope = .untilLock
    ) -> NotchPromptRequest {
        let matchedKey = PublicKeyStore.loadAll().first(where: { $0.label == keyLabel })
        let resolvedKeyType = keyType ?? matchedKey?.effectiveAccessProfile.type ?? .personal
        let policy = matchedKey?.effectiveBiometricPolicy ?? .userPresence
        let confirmationMode = NotchConfirmationMode(biometricPolicy: policy)
        let allowsPassword = NotchConfirmationMode.allowsPasswordFallback(for: policy)

        let callerInfo = resolveCallerMetadata(from: clientDesc, keyType: resolvedKeyType)

        return NotchPromptRequest(
            callerName: callerInfo.callerName,
            callerPath: callerInfo.callerPath,
            processChain: callerInfo.processChain,
            keyLabel: keyLabel,
            keyType: resolvedKeyType,
            keyTypeSubtitle: resolvedKeyType == .bot ? "Agent key" : "Personal key",
            operation: operation,
            agentWarning: callerInfo.agentWarning,
            initialScope: initialScope,
            showsScopeSelector: true,
            allowsPasswordFallback: allowsPassword,
            confirmationMode: confirmationMode
        )
    }

    /// Maps a `NotchPromptResult` into `GitSigningPromptChoice`, preserving the chosen scope duration.
    public static func mapResultToGraceChoice(_ result: NotchPromptResult) -> GitSigningPromptChoice {
        switch result {
        case .approved(let scope, _):
            return scope.gitSigningPromptChoice
        case .denied:
            return .cancel
        }
    }

    @MainActor
    public func presentNotchPrompt(
        keyLabel: String,
        clientDesc: String,
        keyType: KeyType? = nil,
        operation: String = "Sign a Git commit",
        initialScope: NotchSessionScope = .untilLock
    ) async -> GitSigningPromptChoice {
        let request = Self.makePromptRequest(
            keyLabel: keyLabel,
            clientDesc: clientDesc,
            keyType: keyType,
            operation: operation,
            initialScope: initialScope
        )
        let result = await NotchPromptWindowController.shared.present(request: request)
        return Self.mapResultToGraceChoice(result)
    }

    // MARK: - Caller & Agent Metadata Resolution

    internal struct ResolvedCallerMetadata {
        let callerName: String
        let callerPath: String?
        let processChain: String
        let agentWarning: NotchAgentWarning?
    }

    internal static func resolveCallerMetadata(
        from clientDesc: String,
        keyType: KeyType
    ) -> ResolvedCallerMetadata {
        let trimmed = clientDesc.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return ResolvedCallerMetadata(
                callerName: "Terminal",
                callerPath: "/System/Applications/Utilities/Terminal.app",
                processChain: "git → ssh-keygen",
                agentWarning: nil
            )
        }

        // Parse optional "(PID N)" suffix from SigningPolicyEvaluator.requesterDescription
        var rawPathOrName = trimmed
        var parsedPID: pid_t?
        if let pidRange = trimmed.range(of: #"\s*\((?:PID|pid)\s+(\d+)\)$"#, options: .regularExpression) {
            let suffix = String(trimmed[pidRange])
            let digits = suffix.filter(\.isNumber)
            if let pidVal = Int32(digits), pidVal > 1 {
                parsedPID = pidVal
            }
            rawPathOrName = String(trimmed[..<pidRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        }

        return resolveCallerMetadata(
            rawDescription: trimmed,
            pid: parsedPID,
            executablePath: rawPathOrName,
            overrideCallerName: nil,
            keyType: keyType,
            fallbackProcessChain: "git → ssh-keygen"
        )
    }

    internal static func resolveCallerMetadata(
        rawDescription: String,
        pid: pid_t?,
        executablePath: String,
        overrideCallerName: String?,
        keyType: KeyType,
        fallbackProcessChain: String? = nil,
        auditChainOverride: [AuditProcess]? = nil
    ) -> ResolvedCallerMetadata {
        var chainNames: [String] = []
        var candidateAppPath: String? = enclosingAppBundlePath(for: executablePath)
            ?? (executablePath.hasPrefix("/") ? executablePath : nil)

        let resolvedChain: [AuditProcess]
        if let auditChainOverride {
            resolvedChain = auditChainOverride
        } else if let pid, pid > 1 {
            let execPath = executablePath.hasPrefix("/")
                ? executablePath
                : (SSHAgentServer.getProcessPath(pid: pid) ?? executablePath)
            resolvedChain = AuditProcessChain.build(pid: pid, executablePath: execPath, maxDepth: 16)
        } else {
            resolvedChain = []
        }

        for proc in resolvedChain {
            let name = URL(fileURLWithPath: proc.executablePath).lastPathComponent
            if !name.isEmpty && chainNames.last != name {
                chainNames.append(name)
            }
            if candidateAppPath == nil || !(candidateAppPath?.hasSuffix(".app") ?? false) {
                if let bundlePath = enclosingAppBundlePath(for: proc.executablePath) {
                    candidateAppPath = bundlePath
                }
            }
        }

        // Detect known AI coding agents in process ancestry (nearest first) or caller description (`US-72` / `US-73`)
        let detectedAgent = detectAgent(in: rawDescription, resolvedChain: resolvedChain)

        let callerName: String
        if let overrideCallerName, !overrideCallerName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            callerName = overrideCallerName
        } else if let agent = detectedAgent {
            callerName = agent.displayName
            if let agentPath = agent.executablePath {
                candidateAppPath = enclosingAppBundlePath(for: agentPath) ?? agentPath
            }
        } else if let bundlePath = candidateAppPath, bundlePath.hasSuffix(".app") {
            callerName = URL(fileURLWithPath: bundlePath).deletingPathExtension().lastPathComponent
        } else if executablePath.hasPrefix("/") {
            callerName = URL(fileURLWithPath: executablePath).lastPathComponent
        } else {
            callerName = executablePath
        }

        if candidateAppPath == nil && callerName == "Terminal" {
            candidateAppPath = "/System/Applications/Utilities/Terminal.app"
        }

        let processChain: String
        if chainNames.count >= 2 {
            // Order from parent toward leaf tool (e.g. `Ghostty → zsh → ssh`)
            let displayChain = Array(chainNames.prefix(3).reversed())
            processChain = displayChain.joined(separator: " → ")
        } else if let fallbackProcessChain {
            processChain = fallbackProcessChain
        } else {
            let leafName = chainNames.first ?? (executablePath.hasPrefix("/") ? URL(fileURLWithPath: executablePath).lastPathComponent : executablePath)
            processChain = leafName.isEmpty ? "unknown" : leafName
        }

        let warning: NotchAgentWarning?
        if let agent = detectedAgent, keyType == .personal {
            warning = NotchAgentWarning(
                title: "Agent requests your Personal key",
                detail: "Detected by: \(agent.evidence)"
            )
        } else {
            warning = nil
        }

        return ResolvedCallerMetadata(
            callerName: callerName,
            callerPath: candidateAppPath,
            processChain: processChain,
            agentWarning: warning
        )
    }

    internal static func enclosingAppBundlePath(for path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        if path.hasSuffix(".app") {
            return path
        }
        guard let range = path.range(of: ".app/") else {
            return nil
        }
        let bundlePath = String(path[..<path.index(before: range.upperBound)])
        let suffix = path[range.upperBound...]
        // Apple's `xcrun` git/toolchain shims exec binaries inside Xcode.app/Contents/Developer/;
        // skip them so attribution resolves to the launching terminal/app rather than Xcode.
        if suffix.hasPrefix("Contents/Developer/") {
            return nil
        }
        return bundlePath
    }

    private static func detectAgent(
        in rawDescription: String,
        resolvedChain: [AuditProcess]
    ) -> (displayName: String, evidence: String, executablePath: String?)? {
        let knownAgents: [(token: String, displayName: String)] = [
            ("claude", "Claude Code"),
            ("codex", "Codex"),
            ("opencode", "OpenCode"),
            ("antigravity", "Antigravity"),
            ("aider", "Aider"),
            ("cursor-agent", "Cursor Agent")
        ]

        // Walk leaf -> root so the nearest agent wins even inside a terminal/IDE host app.
        for proc in resolvedChain {
            let name = URL(fileURLWithPath: proc.executablePath).lastPathComponent.lowercased()
            let lowerPath = proc.executablePath.lowercased()
            for candidate in knownAgents {
                if name == candidate.token || name.contains(candidate.token) || lowerPath.contains(candidate.token) {
                    return (candidate.displayName, "process tree (\(candidate.token))", proc.executablePath)
                }
            }
        }

        let lowerDesc = rawDescription.lowercased()
        for candidate in knownAgents {
            if lowerDesc.contains(candidate.token) {
                return (candidate.displayName, "caller identity (\(candidate.displayName))", nil)
            }
        }
        return nil
    }
}
