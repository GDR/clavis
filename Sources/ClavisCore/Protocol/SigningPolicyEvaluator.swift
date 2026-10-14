import Foundation
import LocalAuthentication
import Darwin

public typealias ClientConnectionContext = AgentConnectionState

public enum SigningDecision: Equatable, Sendable {
    case approved(signature: Data)
    case denied
    case dropConnection

    public var responseData: Data {
        switch self {
        case .approved(let sig):
            var response = Data([14]) // SSH2_AGENT_SIGN_RESPONSE
            response.appendWireData(sig)
            return response
        case .denied:
            return Data([5]) // SSH_AGENT_FAILURE
        case .dropConnection:
            return Data()
        }
    }
}

/// Evaluates signing authorization policies: socket role purposes, OpenSSH SSHSIG
/// payloads, Git signing grace grant reuse/escalation, rate limiting, and session registry lookup.
public final class SigningPolicyEvaluator {
    public let keyManager: KeychainManager
    public let gitSigningGraceManager: GitSigningGraceManager
    public let promptGate: SigningPromptGate
    public let agentSessions: AgentSessionRegistry
    public let auditRecorder: AuditRecording
    public let agentPolicies: AgentPolicyStoring
    public let authenticator: UserAuthenticating
    public let notificationPoster: (String, [String: String]) -> Void
    public let peerProcessValidator: (pid_t, String, UInt64) -> Bool

    private let stateLock = NSLock()
    private var lastRateLimitAlertTimes: [String: Date] = [:]

    private struct PendingSignAudit {
        var result: AuditResult = .failed
        var reason: AuditReason? = .signingError
        var keyFingerprint: String?
        var keyKind: AuditKeyKind? = .personal
        var keyLabel: String?
        var sessionID: String?
        var chain: [AuditProcess] = []
        var host: String?

        func makeEvent() -> AuditEvent {
            AuditEvent(
                type: .signature,
                result: result,
                reason: reason,
                keyFingerprint: keyFingerprint,
                keyKind: keyKind,
                sessionID: sessionID,
                count: 1,
                sensitive: AuditSensitive(
                    keyLabel: keyLabel,
                    processChain: chain,
                    host: host
                )
            )
        }
    }

    public init(
        keyManager: KeychainManager = .shared,
        gitSigningGraceManager: GitSigningGraceManager = .shared,
        promptGate: SigningPromptGate = SigningPromptGate(),
        agentSessions: AgentSessionRegistry = AgentSessionRegistry(),
        auditRecorder: AuditRecording = AuditRecorder.shared,
        agentPolicies: AgentPolicyStoring = KeychainAgentPolicyStore(),
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        notificationPoster: @escaping (String, [String: String]) -> Void = { name, userInfo in
            DistributedNotificationCenter.default().postNotificationName(
                NSNotification.Name(name),
                object: nil,
                userInfo: userInfo,
                deliverImmediately: true
            )
        },
        peerProcessValidator: ((pid_t, String, UInt64) -> Bool)? = nil
    ) {
        self.keyManager = keyManager
        self.gitSigningGraceManager = gitSigningGraceManager
        self.promptGate = promptGate
        self.agentSessions = agentSessions
        self.auditRecorder = auditRecorder
        self.agentPolicies = agentPolicies
        self.authenticator = authenticator
        self.notificationPoster = notificationPoster
        self.peerProcessValidator = peerProcessValidator ?? { ProcessInspector.peerProcessUnchanged(pid: $0, path: $1, startTime: $2) }
    }

    public func evaluateSigningRequest(
        keyBlob: Data,
        dataToSign: Data,
        flags: UInt32,
        role: AgentSocketRole,
        clientPid: pid_t,
        connection: ClientConnectionContext? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil
    ) throws -> SigningDecision {
        var audit = PendingSignAudit()
        defer { auditRecorder.record(audit.makeEvent()) }

        guard flags == 0 else {
            audit.result = .denied
            audit.reason = .malformedRequest
            ClavisLogger.log("SSH_AGENT_REJECT", "Failed to parse sign request wire payload: non-zero flags.")
            return .denied
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let matchingKey = keys.first(where: { $0.publicKeyBlob == keyBlob }) else {
            audit.result = .denied
            audit.reason = .unknownKey
            ClavisLogger.log("SSH_AGENT_REJECT", "No matching key found for requested public key blob.")
            return .denied
        }

        audit.keyFingerprint = matchingKey.fingerprint
        audit.keyLabel = matchingKey.label
        audit.keyKind = matchingKey.purpose.auditKind

        let pid = clientPid
        guard let processPath = clientExecutablePath ?? ProcessInspector.getProcessPath(pid: pid) else {
            audit.result = .denied
            audit.reason = .noPeerAttribution
            ClavisLogger.log("SSH_AGENT_REJECT", "Rejected signing request because peer process attribution was unavailable.")
            return .denied
        }

        audit.chain = AuditProcessChain.build(pid: pid, executablePath: processPath)

        let clientDesc = "\(Self.safeProcessPath(processPath)) (PID \(pid))"

        guard role.allowedPurposes.contains(matchingKey.purpose) else {
            audit.result = .denied
            audit.reason = .wrongKeyKind
            ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' with purpose '\(matchingKey.purpose.rawValue)' is not allowed on \(role.rawValue) socket. Refusing request from \(clientDesc).")
            return .denied
        }

        // Domain verification: Parse signed payload as OpenSSH SSHSIG (strict Git format)
        let gitSSHSIG = SSHSIGPayload.parse(from: dataToSign)

        if matchingKey.purpose == .agent && gitSSHSIG != nil {
            audit.result = .denied
            audit.reason = .wrongKeyKind
            ClavisLogger.log("SECURITY_ALERT", "Agent key '\(matchingKey.label)' cannot be used for SSHSIG signing. Refusing request from \(clientDesc).")
            return .denied
        }

        if role == .agent {
            if connection?.hasForwarding == true || connection?.hasFailedBind == true {
                audit.result = .denied
                audit.reason = .forwardingRefused
                ClavisLogger.log("SECURITY_ALERT", "Agent key signature refused because connection has forwarding or a failed session-bind.")
                return .denied
            }
            switch agentSessions.session(forKeyFingerprint: matchingKey.fingerprint, peerPid: pid) {
            case .found(let session):
                audit.sessionID = session.id
                if !session.policy.allowedHosts.isEmpty {
                    guard let authBinding = connection?.authBinding else {
                        audit.result = .denied
                        audit.reason = .hostNotAllowed
                        ClavisLogger.log("SECURITY_ALERT", "Agent key requires allowed host but connection has no host authentication binding.")
                        return .denied
                    }
                    guard let matchingHost = session.policy.allowedHosts.first(where: { $0.hostKeyBlob == authBinding.hostKeyBlob }) else {
                        audit.result = .denied
                        audit.reason = .hostNotAllowed
                        ClavisLogger.log("SECURITY_ALERT", "Agent key signing refused: host key not in allowed hosts list.")
                        return .denied
                    }
                    var sessionIDPrefix = Data()
                    sessionIDPrefix.appendWireData(authBinding.sessionID)
                    guard dataToSign.starts(with: sessionIDPrefix),
                          SessionBind.isValidSSH2UserAuthRequest(
                              dataToSign,
                              expectedSessionID: authBinding.sessionID,
                              expectedKeyBlob: matchingKey.publicKeyBlob,
                              expectedHostKeyBlob: authBinding.hostKeyBlob
                          ) else {
                        audit.result = .denied
                        audit.reason = .hostNotAllowed
                        ClavisLogger.log("SECURITY_ALERT", "Agent key signing refused: signature data does not start with session ID or is not a valid RFC 4252 userauth request matching key blob.")
                        return .denied
                    }
                    audit.host = matchingHost.name
                }
                guard agentSessions.takeToken(id: session.id) else {
                    audit.result = .denied
                    audit.reason = .rateLimited
                    recordRateLimitAlertIfNeeded(session: session, chain: audit.chain)
                    return .denied
                }
                switch session.policy.mode {
                case .none:
                    do {
                        let sigBlob = try session.grant.sign(dataToSign, using: keyManager)
                        audit.result = .allowed
                        audit.reason = .viaAgentSession
                        return .approved(signature: sigBlob)
                    } catch {
                        agentSessions.end(id: session.id, reason: .signingError)
                        audit.result = .failed
                        audit.reason = .signingError
                        return .denied
                    }
                case .notify:
                    do {
                        let sigBlob = try session.grant.sign(dataToSign, using: keyManager)
                        audit.result = .allowed
                        audit.reason = .viaAgentSession
                        notificationPoster(
                            "com.clavis.agentSigned",
                            ["sessionID": session.id, "fingerprint": session.keyFingerprint]
                        )
                        return .approved(signature: sigBlob)
                    } catch {
                        agentSessions.end(id: session.id, reason: .signingError)
                        audit.result = .failed
                        audit.reason = .signingError
                        return .denied
                    }
                case .ask:
                    let requester = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
                    let clientDesc = Self.requesterDescription(processPath: processPath, pid: pid)
                    let prompt = ClavisUIStrings.AgentSession.askPrompt(
                        keyLabel: matchingKey.label,
                        tool: session.toolName,
                        requester: clientDesc,
                        host: audit.host
                    )
                    do {
                        let sigBlob = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                            try keyManager.signSSH(
                                key: matchingKey,
                                data: dataToSign,
                                prompt: prompt,
                                useCache: false,
                                existingContext: nil,
                                allowedPurposes: [.agent]
                            )
                        }
                        audit.result = .allowed
                        audit.reason = .viaPrompt
                        return .approved(signature: sigBlob)
                    } catch {
                        let isCancelled = AuditEvent.isUserCancellation(error)
                        audit.result = isCancelled ? .cancelled : .denied
                        audit.reason = isCancelled ? .userCancelled : .authenticationFailed
                        return .denied
                    }
                }
            case .noSession:
                audit.result = .denied
                audit.reason = .noAgentSession
                return .denied
            case .outsideTree:
                audit.result = .denied
                audit.reason = .outsideSessionTree
                return .denied
            case .expired:
                audit.result = .denied
                audit.reason = .leaseExpired
                return .denied
            }
        }

        let requester = Self.requesterDescription(processPath: processPath, pid: pid)
        let requesterIdentity = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let clientIdentity = ProcessInspector.resolveClientIdentity(pid: pid, processPath: processPath)
        let attributedStartTime = clientStartTime ?? ProcessInspector.processStartTime(pid: pid)
        let peerProcess = attributedStartTime.map {
            GitApprovedProcess(pid: pid, startTime: $0, path: processPath)
        }

        let isPeerGitHelper = ProcessInspector.isSignerHelper(path: processPath) || ProcessInspector.isTrustedGitExecutable(path: processPath)

        // Security invariant: If key is restricted to Git signing, reject any non-Git payload or unverified peer
        if matchingKey.purpose == .gitSigningOnly {
            if gitSSHSIG == nil {
                audit.result = .denied
                audit.reason = .gitOnlyKeyNonGitPayload
                ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' is restricted to Git signing. Refusing non-Git signature request from \(clientDesc).")
                return .denied
            }
            if !isPeerGitHelper {
                audit.result = .denied
                audit.reason = .wrongKeyKind
                ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' is restricted to Git signing. Refusing SSHSIG request from unverified peer \(clientDesc).")
                return .denied
            }
        }

        do {
            let sigBlob: Data
            var isFromGitGrant = false

            if let _ = gitSSHSIG {
                // Git signing request
                if let grantedSignature = try self.gitSigningGraceManager.withGrant(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    peerProcess: peerProcess,
                    operation: { (grant: GitSigningGrant) in
                        try grant.sign(dataToSign, using: keyManager, role: role)
                    }
                ) {
                    // Fast-path: Active 5-minute grant
                    ClavisLogger.log("GIT_GRACE", "Using active client-bound Git signing grant for '\(matchingKey.label)'. 0 Touch ID prompts.")
                    sigBlob = grantedSignature
                    isFromGitGrant = true
                } else if self.gitSigningGraceManager.hasRecentGitSignature(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    windowSeconds: 30.0
                ) {
                    // Rebase / repeated commit pattern detected (Commit #2+ within 30s)
                    ClavisLogger.log("GIT_GRACE", "Detected rapid Git signing pattern (<30s) for '\(matchingKey.label)'. Prompting user for session...")
                    let gitAnchor = ProcessInspector.grantAnchor(peerPid: pid, peerPath: processPath)
                    let anchorPath = gitAnchor?.path
                    let anchorPid = gitAnchor?.pid
                    let promptDesc = Self.requesterDescription(
                        processPath: anchorPath ?? processPath,
                        pid: anchorPid ?? pid
                    )
                    let choice = promptGate.runExclusive {
                        self.gitSigningGraceManager.prompt(keyLabel: matchingKey.label, clientDesc: promptDesc)
                    }
                    switch choice {
                    case .cancel:
                        audit.result = .cancelled
                        audit.reason = .userCancelled
                        ClavisLogger.log("GIT_GRACE", "User cancelled Git signing session.")
                        return .denied

                    case .grantFiveMinutes:
                        guard let anchor = gitAnchor else {
                            audit.result = .denied
                            audit.reason = .gitAnchorUnavailable
                            ClavisLogger.log("SECURITY_ALERT", "Refusing Git signing grant: peer PID \(pid) (\(processPath)) cannot be anchored on a valid Git process.")
                            return .denied
                        }
                        ClavisLogger.log("GIT_GRACE", "User approved 5-minute Git signing session for \(promptDesc). Authorizing via Touch ID...")
                        let authPrompt = Self.gitSigningSessionReason(keyLabel: matchingKey.label)
                        let grant = try promptGate.run(requester: requesterIdentity, clientSocket: clientSocket) {
                            try keyManager.authorizeGitSigningGrant(
                                key: matchingKey,
                                prompt: authPrompt,
                                clientIdentity: clientIdentity,
                                duration: 300.0,
                                maxOperations: 200,
                                approvedProcess: anchor
                            )
                        }
                        // Perform the commit #2 signature under the newly created grant.
                        let grantedSignature: Data
                        do {
                            guard let signature = try self.gitSigningGraceManager.withGrant(
                                for: matchingKey.label,
                                clientIdentity: clientIdentity,
                                peerProcess: peerProcess,
                                operation: { (grant: GitSigningGrant) in
                                    try grant.sign(dataToSign, using: keyManager, role: role)
                                }
                            ) else {
                                grant.invalidate()
                                audit.result = .failed
                                audit.reason = .signingError
                                return .denied
                            }
                            grantedSignature = signature
                        } catch {
                            grant.invalidate()
                            throw error
                        }
                        sigBlob = grantedSignature
                        isFromGitGrant = true

                    case .singleShot:
                        ClavisLogger.log("GIT_GRACE", "User chose single-shot signing.")
                        let prompt = isPeerGitHelper
                            ? Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                            : Self.dataSigningReason(keyLabel: matchingKey.label, requester: requester)
                        sigBlob = try promptedSign(
                            key: matchingKey,
                            data: dataToSign,
                            prompt: prompt,
                            role: role,
                            requester: requesterIdentity,
                            clientSocket: clientSocket
                        )
                        self.gitSigningGraceManager.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                    }
                } else {
                    // Commit #1 (single commit / first in a potential sequence) -> standard Touch ID, no dialog
                    let prompt = isPeerGitHelper
                        ? Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                        : Self.dataSigningReason(keyLabel: matchingKey.label, requester: requester)
                    sigBlob = try promptedSign(
                        key: matchingKey,
                        data: dataToSign,
                        prompt: prompt,
                        role: role,
                        requester: requesterIdentity,
                        clientSocket: clientSocket
                    )
                    self.gitSigningGraceManager.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                }
            } else {
                let prompt = Self.signatureReason(
                    keyLabel: matchingKey.label,
                    requester: requester,
                    processPath: processPath,
                    dataToSign: dataToSign,
                    keyBlob: matchingKey.publicKeyBlob,
                    hasForwarding: (connection?.hasForwarding == true) || (connection?.hasFailedBind == true)
                )
                ClavisLogger.log("SSH_AGENT_SIGN", "Initiating signature for key '\(matchingKey.label)' requested by \(clientDesc)...")
                sigBlob = try promptedSign(
                    key: matchingKey,
                    data: dataToSign,
                    prompt: prompt,
                    role: role,
                    requester: requesterIdentity,
                    clientSocket: clientSocket
                )
            }

            // TOCTOU check: re-run peerProcessUnchanged after signing prompt returns and before sending signature
            guard let start = attributedStartTime, self.peerProcessValidator(pid, processPath, start) else {
                audit.result = .denied
                audit.reason = .peerChanged
                ClavisLogger.log("SECURITY_ALERT", "Dropping connection: peer process changed during signing prompt (TOCTOU violation for PID \(pid)).")
                self.gitSigningGraceManager.invalidateAll(broadcast: false)
                return .dropConnection
            }

            if isFromGitGrant {
                audit.result = .allowed
                audit.reason = .viaGitGrant
            } else {
                audit.result = .allowed
                audit.reason = .viaPrompt
            }

            ClavisLogger.log("SSH_AGENT_SIGN", "Signature completed successfully for '\(matchingKey.label)' (\(clientDesc)).")
            return .approved(signature: sigBlob)
        } catch {
            if error is KeyPurposeError {
                audit.result = .denied
                audit.reason = .wrongKeyKind
            } else if AuditEvent.isUserCancellation(error) {
                audit.result = .cancelled
                audit.reason = .userCancelled
            } else if case UserAuthenticationError.rejected = error {
                audit.result = .denied
                audit.reason = .authenticationFailed
            } else {
                audit.result = .failed
                audit.reason = .signingError
            }
            ClavisLogger.log("SSH_AGENT_SIGN", "Signature failed for '\(matchingKey.label)' (\(clientDesc)): \(error.localizedDescription)")
            return .denied
        }
    }

    public func handleSignRequest(
        payload: Data,
        role: AgentSocketRole,
        clientPid: pid_t? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil,
        connection: AgentConnectionState? = nil
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let keyBlob = reader.readWireData(),
              let dataToSign = reader.readWireData(),
              let flags = reader.readUInt32(),
              reader.isEOF else {
            let audit = AuditEvent(
                type: .signature,
                result: .denied,
                reason: .malformedRequest,
                count: 1
            )
            auditRecorder.record(audit)
            ClavisLogger.log("SSH_AGENT_REJECT", "Failed to parse sign request wire payload.")
            return Data([5]) // SSH_AGENT_FAILURE
        }

        guard let pid = clientPid else {
            let audit = AuditEvent(
                type: .signature,
                result: .denied,
                reason: .noPeerAttribution,
                count: 1
            )
            auditRecorder.record(audit)
            ClavisLogger.log("SSH_AGENT_REJECT", "Rejected signing request because peer process attribution was unavailable.")
            return Data([5])
        }

        do {
            let decision = try evaluateSigningRequest(
                keyBlob: keyBlob,
                dataToSign: dataToSign,
                flags: flags,
                role: role,
                clientPid: pid,
                connection: connection,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
            return decision.responseData
        } catch {
            return Data([5])
        }
    }

    private func recordRateLimitAlertIfNeeded(session: AgentSession, chain: [AuditProcess]) {
        let now = Date()
        stateLock.lock()
        let shouldAlert: Bool
        if let last = lastRateLimitAlertTimes[session.id], now.timeIntervalSince(last) < 60.0 {
            shouldAlert = false
        } else {
            lastRateLimitAlertTimes[session.id] = now
            shouldAlert = true
        }
        stateLock.unlock()

        if shouldAlert {
            auditRecorder.record(
                AuditEvent(
                    type: .securityAlert,
                    result: .info,
                    reason: .rateLimited,
                    keyFingerprint: session.keyFingerprint,
                    keyKind: .agent,
                    sessionID: session.id,
                    sensitive: AuditSensitive(keyLabel: session.keyLabel, processChain: chain)
                )
            )
            notificationPoster(
                "com.clavis.agentRateLimited",
                ["sessionID": session.id, "fingerprint": session.keyFingerprint]
            )
        }
    }

    private func promptedSign(
        key: SSHKeyInfo,
        data: Data,
        prompt: String,
        role: AgentSocketRole,
        requester: SigningPromptGate.Requester? = nil,
        clientSocket: Int32? = nil
    ) throws -> Data {
        try promptGate.run(requester: requester, clientSocket: clientSocket) {
            try keyManager.signSSH(
                key: key,
                data: data,
                prompt: prompt,
                useCache: false,
                existingContext: nil,
                allowedPurposes: role.allowedPurposes
            )
        }
    }

    public static func sshAuthenticationReason(keyLabel: String) -> String {
        ClavisUIStrings.Prompt.sshAuthentication(keyLabel: keyLabel)
    }

    public static func sshAuthenticationReason(keyLabel: String, requester: String) -> String {
        ClavisUIStrings.Prompt.sshAuthentication(keyLabel: keyLabel, requester: requester)
    }

    public static func signatureReason(
        keyLabel: String,
        requester: String,
        processPath: String,
        dataToSign: Data,
        keyBlob: Data? = nil,
        hasForwarding: Bool = false
    ) -> String {
        if ProcessInspector.isTrustedSshBinary(path: processPath) && SessionBind.isValidSSH2UserAuthRequest(dataToSign, expectedKeyBlob: keyBlob) {
            if hasForwarding {
                return ClavisUIStrings.Prompt.sshAuthenticationFromForwardedAgent(keyLabel: keyLabel, requester: requester)
            }
            return ClavisUIStrings.Prompt.sshAuthentication(keyLabel: keyLabel, requester: requester)
        }
        return dataSigningReason(keyLabel: keyLabel, requester: requester)
    }

    public static func signatureReason(keyLabel: String, requester: String, processPath: String) -> String {
        if ProcessInspector.isTrustedSshBinary(path: processPath) {
            return ClavisUIStrings.Prompt.sshAuthenticationFromForwardedAgent(keyLabel: keyLabel, requester: requester)
        }
        return dataSigningReason(keyLabel: keyLabel, requester: requester)
    }

    public static func dataSigningReason(keyLabel: String, requester: String) -> String {
        ClavisUIStrings.Prompt.dataSigning(keyLabel: keyLabel, requester: requester)
    }

    public static func gitCommitSigningReason(keyLabel: String, requester: String) -> String {
        ClavisUIStrings.Prompt.gitCommitSigning(keyLabel: keyLabel, requester: requester)
    }

    public static func gitCommitSigningReason(keyLabel: String) -> String {
        ClavisUIStrings.Prompt.gitCommitSigning(keyLabel: keyLabel)
    }

    public static func gitSigningSessionReason(keyLabel: String) -> String {
        ClavisUIStrings.Prompt.gitSigningSession(keyLabel: keyLabel)
    }

    public static func requesterDescription(processPath: String, pid: pid_t) -> String {
        let sanitized = AuditEvent.sanitizedPath(processPath, maxLength: nil)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        var collapsed = String.UnicodeScalarView()
        var previousWasWhitespace = false
        for scalar in sanitized.unicodeScalars {
            if CharacterSet.whitespacesAndNewlines.contains(scalar) || scalar.properties.isWhitespace {
                if !previousWasWhitespace {
                    collapsed.append(" ")
                    previousWasWhitespace = true
                }
            } else {
                collapsed.append(scalar)
                previousWasWhitespace = false
            }
        }
        let cleaned = String(collapsed)
        let maxPathScalars = 80
        let bounded: String
        if cleaned.count > maxPathScalars {
            // Preserve both leading root directory context and trailing binary name to prevent padding/truncation spoofing.
            bounded = "\(cleaned.prefix(32))…\(cleaned.suffix(maxPathScalars - 33))"
        } else {
            bounded = cleaned
        }
        return "\(bounded.isEmpty ? "unknown" : bounded) (PID \(pid))"
    }

    public static func safeProcessPath(_ path: String) -> String {
        let sanitized = path.unicodeScalars.map { scalar -> Character in
            CharacterSet.controlCharacters.contains(scalar) ? "?" : Character(String(scalar))
        }
        return String(sanitized.prefix(512))
    }
}
