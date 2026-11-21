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

    private let applicationAccess: ApplicationRequestAuthorizing
    private let stateLock = NSLock()
    private var lastRateLimitAlertTimes: [String: Date] = [:]
    private var _signingPromptPresenter: SigningPromptAuthenticating?

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
        applicationAccess: ApplicationRequestAuthorizing = ApplicationRequestAuthorization(),
        keyManager: KeychainManager = .shared,
        gitSigningGraceManager: GitSigningGraceManager = .shared,
        promptGate: SigningPromptGate = SigningPromptGate(),
        agentSessions: AgentSessionRegistry = AgentSessionRegistry(),
        auditRecorder: AuditRecording = AuditRecorder.shared,
        agentPolicies: AgentPolicyStoring = KeychainAgentPolicyStore(),
        authenticator: UserAuthenticating = LocalUserAuthenticator(),
        signingPromptPresenter: SigningPromptAuthenticating? = nil,
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
        self.applicationAccess = applicationAccess
        self.keyManager = keyManager
        self.gitSigningGraceManager = gitSigningGraceManager
        self.promptGate = promptGate
        self.agentSessions = agentSessions
        self.auditRecorder = auditRecorder
        self.agentPolicies = agentPolicies
        self.authenticator = authenticator
        self._signingPromptPresenter = signingPromptPresenter
        self.notificationPoster = notificationPoster
        self.peerProcessValidator = peerProcessValidator ?? { ProcessInspector.peerProcessUnchanged(pid: $0, path: $1, startTime: $2) }
    }

    public func setSigningPromptPresenter(_ presenter: SigningPromptAuthenticating?) {
        stateLock.lock()
        _signingPromptPresenter = presenter
        stateLock.unlock()
    }

    private var currentSigningPromptPresenter: SigningPromptAuthenticating? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _signingPromptPresenter
    }

    private static func operationLabel(for dataToSign: Data, operation: KeyOperation) -> String {
        switch operation {
        case .ssh:
            return "Authenticate with SSH"
        case .signature:
            return SSHSIGPayload.parse(from: dataToSign) != nil ? "Sign a Git commit" : "Sign data"
        }
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
        // Eligibility precedes every session/grant path, including direct sign
        // requests that never enumerated identities.
        guard flags == 0, let key = try keyManager.listKeys().first(where: { $0.publicKeyBlob == keyBlob }) else {
            return try evaluateAuthorizedSigningRequest(keyBlob: keyBlob, dataToSign: dataToSign, flags: flags, role: role, clientPid: clientPid, connection: connection, clientExecutablePath: clientExecutablePath, clientStartTime: clientStartTime, clientSocket: clientSocket)
        }
        let operation: KeyOperation = dataToSign.starts(with: SSHSIGPayload.magic) ? .signature : .ssh
        guard let path = clientExecutablePath ?? ProcessInspector.getProcessPath(pid: clientPid),
              let start = clientStartTime ?? ProcessInspector.processStartTime(pid: clientPid) else {
            recordApplicationDecision(key: key, result: .denied, reason: .noPeerAttribution, pid: clientPid, path: clientExecutablePath ?? "", operation: operation)
            return .denied
        }
        if key.purpose == .gitSigningOnly {
            guard SSHSIGPayload.parse(from: dataToSign) != nil else {
                recordApplicationDecision(key: key, result: .denied, reason: .gitOnlyKeyNonGitPayload, pid: clientPid, path: path, operation: operation)
                return .denied
            }
            guard ProcessInspector.isTrustedGitExecutable(path: path) || ProcessInspector.isSignerHelper(path: path) else {
                recordApplicationDecision(key: key, result: .denied, reason: .wrongKeyKind, pid: clientPid, path: path, operation: operation)
                return .denied
            }
        }
        guard role.permits(key) else {
            recordApplicationDecision(key: key, result: .denied, reason: .wrongKeyKind, pid: clientPid, path: path, operation: operation)
            return .denied
        }
        let lease: ApplicationRequestLease
        do {
            lease = try applicationAccess.authorize(key: key, operation: operation, role: role, pid: clientPid, path: path, start: start)
        } catch {
            recordApplicationDecision(key: key, result: .denied, reason: .policyUnavailable, pid: clientPid, path: path, operation: operation)
            return .denied
        }
        let decision: SigningDecision
        var pendingAudit: AuditEvent?
        var authenticatedOnceUsedCachedGrant = false
        switch lease.eligibility {
        case .denied:
            recordApplicationDecision(key: key, result: .denied, reason: .wrongKeyKind, pid: clientPid, path: path, operation: operation, lease: lease)
            return .denied
        case .authenticatedOnceOnly:
            guard !(role == .agent && (connection?.hasForwarding == true || connection?.hasFailedBind == true)) else { return .denied }
            let reason = "Allow one \(operation == .ssh ? "SSH" : "Signature") request for '\(key.label)'? Caller identity is uncertain (\(Self.safeProcessPath(path)))."
            let isForwarded = (connection?.hasForwarding == true) || (connection?.hasFailedBind == true)
            let configuredTimeout = key.effectiveUnlockedTimeout
            let isCacheableOperation = (operation == .ssh) || (operation == .signature && SSHSIGPayload.parse(from: dataToSign) != nil)
            let canUsePersonalUnlockGrant = (self.currentSigningPromptPresenter != nil)
                && (key.effectiveAccessProfile.type == .personal)
                && !isForwarded
                && (configuredTimeout != .always)
                && isCacheableOperation
            let sharedIdentity = Self.sharedPersonalUnlockIdentity(for: key)

            if canUsePersonalUnlockGrant,
               let grantedSignature = trySigningWithPersonalGrant(
                   keyLabel: key.label,
                   approvalIdentity: sharedIdentity,
                   operation: operation,
                   dataToSign: dataToSign
               ) {
                ClavisLogger.log("SSH_AGENT_SIGN", "Using active Personal unlock grant for '\(key.label)'. 0 Touch ID prompts.")
                authenticatedOnceUsedCachedGrant = true
                decision = .approved(signature: grantedSignature)
            } else {
                do {
                    let signature = try promptGate.run(
                        requester: .init(executablePath: path, pid: clientPid), clientSocket: clientSocket
                    ) {
                        if let presenter = self.currentSigningPromptPresenter {
                            let destination = Self.resolveSigningDestination(
                                operation: operation,
                                dataToSign: dataToSign,
                                keyBlob: key.publicKeyBlob,
                                connection: connection,
                                isForwardedAgent: isForwarded,
                                peerPid: clientPid,
                                peerPath: path
                            )
                            let authRequest = SigningAuthenticationRequest(
                                key: key,
                                operation: operation,
                                operationLabel: Self.operationLabel(for: dataToSign, operation: operation),
                                callerName: nil,
                                peerPid: clientPid,
                                peerPath: path,
                                allowsSessionScope: canUsePersonalUnlockGrant,
                                defaultScope: canUsePersonalUnlockGrant ? configuredTimeout : .always,
                                reason: reason,
                                isUncertainCaller: true,
                                isForwardedAgent: isForwarded,
                                destination: destination
                            )
                            let outcome = try presenter.authenticateSigningRequest(authRequest)
                            if canUsePersonalUnlockGrant,
                               outcome.selectedScope != .always,
                               let duration = outcome.selectedScope.grantDurationSeconds {
                                let grant: PersonalUnlockGrant
                                do {
                                    grant = try keyManager.authorizePersonalSSHGrant(
                                        key: key,
                                        prompt: "",
                                        approvalIdentity: sharedIdentity,
                                        duration: duration,
                                        operation: operation,
                                        existingContext: outcome.context
                                    )
                                } catch {
                                    outcome.context.invalidate()
                                    throw error
                                }
                                do {
                                    guard let grantedSignature = try self.gitSigningGraceManager.withPersonalSSHGrant(
                                        for: key.label,
                                        approvalIdentity: sharedIdentity,
                                        operationType: operation,
                                        operation: { try $0.sign(dataToSign) }
                                    ) else {
                                        grant.invalidate()
                                        throw AgentSessionGrantError.grantInvalidated
                                    }
                                    return grantedSignature
                                } catch {
                                    grant.invalidate()
                                    self.gitSigningGraceManager.invalidatePersonalSSHGrant(
                                        keyLabel: key.label,
                                        approvalIdentity: sharedIdentity,
                                        broadcast: true
                                    )
                                    throw error
                                }
                            } else {
                                defer { outcome.context.invalidate() }
                                return try keyManager.signSSH(key: key, data: dataToSign, prompt: "", useCache: false, existingContext: outcome.context, allowedPurposes: role.allowedPurposes)
                            }
                        } else {
                            let context = try authenticator.authenticate(
                                reason: reason,
                                policy: .deviceOwnerAuthentication
                            )
                            defer { context.invalidate() }
                            return try keyManager.signSSH(key: key, data: dataToSign, prompt: "", useCache: false, existingContext: context, allowedPurposes: role.allowedPurposes)
                        }
                    }
                    decision = .approved(signature: signature)
                } catch {
                    recordApplicationDecision(key: key, result: AuditEvent.isUserCancellation(error) ? .cancelled : .denied, reason: .authenticationFailed, pid: clientPid, path: path, operation: operation, lease: lease)
                    return .denied
                }
            }
        case .eligible:
            decision = try evaluateAuthorizedSigningRequest(
                keyBlob: keyBlob, dataToSign: dataToSign, flags: flags, role: role, clientPid: clientPid,
                connection: connection, clientExecutablePath: path, clientStartTime: start, clientSocket: clientSocket,
                approvalIdentity: lease.approvalIdentity, callerName: lease.caller?.application.name,
                auditSink: { pendingAudit = $0 }
            )
        }
        if case .approved = decision {
            guard let currentKey = try? keyManager.listKeys().first(where: { $0.fingerprint == key.fingerprint }),
                  currentKey.effectiveAccessProfile == key.effectiveAccessProfile,
                  currentKey.effectiveUnlockedTimeout == key.effectiveUnlockedTimeout,
                  peerProcessValidator(clientPid, path, start),
                  (try? applicationAccess.validate(lease, pid: clientPid, path: path, start: start)) == true else {
                gitSigningGraceManager.invalidateAll(broadcast: false)
                agentSessions.endAll(reason: .keyChanged)
                recordApplicationDecision(key: key, result: .denied, reason: .peerChanged, pid: clientPid, path: path, operation: operation, lease: lease)
                return .dropConnection
            }
            if lease.eligibility == .authenticatedOnceOnly {
                recordApplicationDecision(
                    key: key,
                    result: .allowed,
                    reason: authenticatedOnceUsedCachedGrant ? .viaGitGrant : .viaPrompt,
                    pid: clientPid,
                    path: path,
                    operation: operation,
                    lease: lease
                )
            }
        }
        if let pendingAudit {
            auditRecorder.record(pendingAudit.withRequestContext(operation: operation,
                callerName: lease.caller?.application.name, uncertain: false))
        }
        return decision
    }

    private func recordApplicationDecision(key: SSHKeyInfo, result: AuditResult, reason: AuditReason, pid: pid_t, path: String,
                                           operation: KeyOperation? = nil, lease: ApplicationRequestLease? = nil) {
        auditRecorder.record(AuditEvent(type: .signature, result: result, reason: reason,
            keyFingerprint: key.fingerprint, keyKind: key.effectiveAccessProfile.type == .bot ? .agent : .personal, count: 1,
            sensitive: .init(keyLabel: key.label, processChain: AuditProcessChain.build(pid: pid, executablePath: path)))
            .withRequestContext(operation: operation, callerName: lease?.caller?.application.name,
                                uncertain: lease.map { $0.caller == nil }))
    }

    private func evaluateAuthorizedSigningRequest(
        keyBlob: Data,
        dataToSign: Data,
        flags: UInt32,
        role: AgentSocketRole,
        clientPid: pid_t,
        connection: ClientConnectionContext? = nil,
        clientExecutablePath: String? = nil,
        clientStartTime: UInt64? = nil,
        clientSocket: Int32? = nil,
        approvalIdentity: String? = nil,
        callerName: String? = nil,
        auditSink: ((AuditEvent) -> Void)? = nil
    ) throws -> SigningDecision {
        var audit = PendingSignAudit()
        defer {
            if let auditSink { auditSink(audit.makeEvent()) }
            else { auditRecorder.record(audit.makeEvent()) }
        }

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
        audit.keyKind = matchingKey.effectiveAccessProfile.type == .bot ? .agent : .personal

        let pid = clientPid
        guard let processPath = clientExecutablePath ?? ProcessInspector.getProcessPath(pid: pid) else {
            audit.result = .denied
            audit.reason = .noPeerAttribution
            ClavisLogger.log("SSH_AGENT_REJECT", "Rejected signing request because peer process attribution was unavailable.")
            return .denied
        }

        audit.chain = AuditProcessChain.build(pid: pid, executablePath: processPath)

        let clientDesc = "\(Self.safeProcessPath(processPath)) (PID \(pid))"

        guard role.permits(matchingKey) else {
            audit.result = .denied
            audit.reason = .wrongKeyKind
            ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' with purpose '\(matchingKey.purpose.rawValue)' is not allowed on \(role.rawValue) socket. Refusing request from \(clientDesc).")
            return .denied
        }

        // Domain verification: Parse signed payload as OpenSSH SSHSIG (strict Git format)
        let gitSSHSIG = SSHSIGPayload.parse(from: dataToSign)

        if !matchingKey.effectiveAccessProfile.capabilities.signature && gitSSHSIG != nil {
            audit.result = .denied
            audit.reason = .wrongKeyKind
            ClavisLogger.log("SECURITY_ALERT", "Agent key '\(matchingKey.label)' cannot be used for SSHSIG signing. Refusing request from \(clientDesc).")
            return .denied
        }

        if role == .agent && (connection?.hasForwarding == true || connection?.hasFailedBind == true) {
            audit.result = .denied
            audit.reason = .forwardingRefused
            return .denied
        }
        if role == .agent && matchingKey.purpose == .agent && !dataToSign.starts(with: SSHSIGPayload.magic) {
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
                            if let presenter = self.currentSigningPromptPresenter {
                                let destination = Self.resolveSigningDestination(
                                    operation: .ssh,
                                    dataToSign: dataToSign,
                                    keyBlob: matchingKey.publicKeyBlob,
                                    connection: connection,
                                    isForwardedAgent: false,
                                    peerPid: pid,
                                    peerPath: processPath,
                                    knownHostName: audit.host
                                )
                                let authRequest = SigningAuthenticationRequest(
                                    key: matchingKey,
                                    operation: .ssh,
                                    operationLabel: "Authenticate with SSH",
                                    callerName: session.toolName,
                                    peerPid: pid,
                                    peerPath: processPath,
                                    allowsSessionScope: false,
                                    defaultScope: .always,
                                    reason: prompt,
                                    isUncertainCaller: false,
                                    isForwardedAgent: false,
                                    destination: destination
                                )
                                let outcome = try presenter.authenticateSigningRequest(authRequest)
                                defer { outcome.context.invalidate() }
                                return try keyManager.signSSH(
                                    key: matchingKey,
                                    data: dataToSign,
                                    prompt: "",
                                    useCache: false,
                                    existingContext: outcome.context,
                                    allowedPurposes: [.agent]
                                )
                            } else {
                                return try keyManager.signSSH(
                                    key: matchingKey,
                                    data: dataToSign,
                                    prompt: prompt,
                                    useCache: false,
                                    existingContext: nil,
                                    allowedPurposes: [.agent]
                                )
                            }
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

        let requester = callerName ?? Self.requesterDescription(processPath: processPath, pid: pid)
        let requesterIdentity = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let clientIdentity = approvalIdentity ?? ProcessInspector.resolveClientIdentity(pid: pid, processPath: processPath)
        let attributedStartTime = clientStartTime ?? ProcessInspector.processStartTime(pid: pid)
        let peerProcess = attributedStartTime.map {
            GitApprovedProcess(pid: pid, startTime: $0, path: processPath)
        }

        var cachedIsPeerGitHelper: Bool?
        func isPeerGitHelper() -> Bool {
            if let cached = cachedIsPeerGitHelper { return cached }
            let result = ProcessInspector.isTrustedGitExecutable(path: processPath) || ProcessInspector.isSignerHelper(path: processPath)
            cachedIsPeerGitHelper = result
            return result
        }

        // Security invariant: If key is restricted to Git signing, reject any non-Git payload or unverified peer
        if matchingKey.purpose == .gitSigningOnly {
            if gitSSHSIG == nil {
                audit.result = .denied
                audit.reason = .gitOnlyKeyNonGitPayload
                ClavisLogger.log("SECURITY_ALERT", "Key '\(matchingKey.label)' is restricted to Git signing. Refusing non-Git signature request from \(clientDesc).")
                return .denied
            }
            if !isPeerGitHelper() {
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
                let configuredTimeout = matchingKey.effectiveUnlockedTimeout
                if configuredTimeout != .always,
                   let grantedSignature = try self.gitSigningGraceManager.withGrant(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    peerProcess: peerProcess,
                    operation: { (grant: GitSigningGrant) in
                        try grant.sign(dataToSign, using: keyManager, role: role)
                    }
                ) {
                    // Fast-path: Active Git signing grant
                    ClavisLogger.log("GIT_GRACE", "Using active client-bound Git signing grant for '\(matchingKey.label)'. 0 Touch ID prompts.")
                    sigBlob = grantedSignature
                    isFromGitGrant = true
                } else if configuredTimeout != .always && self.gitSigningGraceManager.hasRecentGitSignature(
                    for: matchingKey.label,
                    clientIdentity: clientIdentity,
                    windowSeconds: 30.0
                ) {
                    // Rebase / repeated commit pattern detected (Commit #2+ within 30s)
                    ClavisLogger.log("GIT_GRACE", "Detected rapid Git signing pattern (<30s) for '\(matchingKey.label)'. Prompting user for session...")
                    let gitAnchor = ProcessInspector.grantAnchor(peerPid: pid, peerPath: processPath)
                    let anchorPath = gitAnchor?.path
                    let anchorPid = gitAnchor?.pid
                    let promptDesc = callerName ?? Self.requesterDescription(
                        processPath: anchorPath ?? processPath,
                        pid: anchorPid ?? pid
                    )
                    let isForwarded = (connection?.hasForwarding == true) || (connection?.hasFailedBind == true)

                    func performGrantAndSign(
                        duration: TimeInterval,
                        existingContext: LAContext?
                    ) throws -> Data? {
                        guard let anchor = gitAnchor else {
                            existingContext?.invalidate()
                            audit.result = .denied
                            audit.reason = .gitAnchorUnavailable
                            ClavisLogger.log("SECURITY_ALERT", "Refusing Git signing grant: peer PID \(pid) (\(processPath)) cannot be anchored on a valid Git process.")
                            return nil
                        }
                        let grantDuration = max(1.0, duration)
                        ClavisLogger.log("GIT_GRACE", "User approved \(Int(grantDuration))s Git signing session for \(promptDesc). Authorizing via Touch ID...")
                        let authPrompt = Self.gitSigningSessionReason(keyLabel: matchingKey.label) + " Requested by \(requester)."
                        let grant: GitSigningGrant
                        if let existingContext {
                            do {
                                grant = try keyManager.authorizeGitSigningGrant(
                                    key: matchingKey,
                                    prompt: "",
                                    clientIdentity: clientIdentity,
                                    duration: grantDuration,
                                    maxOperations: 200,
                                    approvedProcess: anchor,
                                    existingContext: existingContext
                                )
                            } catch {
                                existingContext.invalidate()
                                throw error
                            }
                        } else {
                            grant = try promptGate.run(requester: requesterIdentity, clientSocket: clientSocket) {
                                try keyManager.authorizeGitSigningGrant(
                                    key: matchingKey,
                                    prompt: authPrompt,
                                    clientIdentity: clientIdentity,
                                    duration: grantDuration,
                                    maxOperations: 200,
                                    approvedProcess: anchor
                                )
                            }
                        }
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
                                return nil
                            }
                            return signature
                        } catch {
                            grant.invalidate()
                            throw error
                        }
                    }

                    if let presenter = self.currentSigningPromptPresenter {
                        let authPrompt = Self.gitSigningSessionReason(keyLabel: matchingKey.label) + " Requested by \(requester)."
                        let destination = Self.resolveSigningDestination(
                            operation: .signature,
                            dataToSign: dataToSign,
                            keyBlob: matchingKey.publicKeyBlob,
                            connection: connection,
                            isForwardedAgent: isForwarded,
                            peerPid: pid,
                            peerPath: processPath,
                            fallbackPid: anchorPid
                        )
                        let authRequest = SigningAuthenticationRequest(
                            key: matchingKey,
                            operation: .signature,
                            operationLabel: "Sign a Git commit",
                            callerName: callerName,
                            peerPid: anchorPid ?? pid,
                            peerPath: anchorPath ?? processPath,
                            allowsSessionScope: true,
                            defaultScope: configuredTimeout,
                            reason: authPrompt,
                            isUncertainCaller: false,
                            isForwardedAgent: isForwarded,
                            destination: destination
                        )
                        let outcome = try promptGate.run(requester: requesterIdentity, clientSocket: clientSocket) {
                            try presenter.authenticateSigningRequest(authRequest)
                        }
                        if outcome.selectedScope == .always {
                            defer { outcome.context.invalidate() }
                            sigBlob = try keyManager.signSSH(
                                key: matchingKey,
                                data: dataToSign,
                                prompt: "",
                                useCache: false,
                                existingContext: outcome.context,
                                allowedPurposes: role.allowedPurposes
                            )
                            self.gitSigningGraceManager.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                        } else {
                            guard let grantedSignature = try performGrantAndSign(
                                duration: outcome.selectedScope.grantDurationSeconds ?? 300.0,
                                existingContext: outcome.context
                            ) else {
                                return .denied
                            }
                            sigBlob = grantedSignature
                            isFromGitGrant = true
                        }
                    } else {
                        let choice = promptGate.runExclusive {
                            self.gitSigningGraceManager.prompt(keyLabel: matchingKey.label, clientDesc: promptDesc)
                        }
                        switch choice {
                        case .cancel:
                            audit.result = .cancelled
                            audit.reason = .userCancelled
                            ClavisLogger.log("GIT_GRACE", "User cancelled Git signing session.")
                            return .denied

                        case .grantFiveMinutes, .grantSession:
                            guard let grantedSignature = try performGrantAndSign(
                                duration: choice.grantDurationSeconds ?? 300.0,
                                existingContext: nil
                            ) else {
                                return .denied
                            }
                            sigBlob = grantedSignature
                            isFromGitGrant = true

                        case .singleShot:
                            ClavisLogger.log("GIT_GRACE", "User chose single-shot signing.")
                            let prompt = isPeerGitHelper()
                                ? Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                                : Self.dataSigningReason(keyLabel: matchingKey.label, requester: requester)
                            sigBlob = try promptedSign(
                                key: matchingKey,
                                data: dataToSign,
                                prompt: prompt,
                                role: role,
                                requester: requesterIdentity,
                                clientSocket: clientSocket,
                                operation: .signature,
                                callerName: callerName,
                                isForwardedAgent: isForwarded,
                                connection: connection
                            )
                            self.gitSigningGraceManager.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                        }
                    }
                } else {
                    // Commit #1 (single commit / first in a potential sequence) -> standard Touch ID, no dialog
                    let prompt = isPeerGitHelper()
                        ? Self.gitCommitSigningReason(keyLabel: matchingKey.label, requester: requester)
                        : Self.dataSigningReason(keyLabel: matchingKey.label, requester: requester)
                    sigBlob = try promptedSign(
                        key: matchingKey,
                        data: dataToSign,
                        prompt: prompt,
                        role: role,
                        requester: requesterIdentity,
                        clientSocket: clientSocket,
                        operation: .signature,
                        callerName: callerName,
                        isForwardedAgent: (connection?.hasForwarding == true) || (connection?.hasFailedBind == true),
                        connection: connection
                    )
                    self.gitSigningGraceManager.recordGitSignature(for: matchingKey.label, clientIdentity: clientIdentity)
                }
            } else {
                let isForwarded = (connection?.hasForwarding == true) || (connection?.hasFailedBind == true)
                let configuredTimeout = matchingKey.effectiveUnlockedTimeout
                let prompt = Self.signatureReason(
                    keyLabel: matchingKey.label,
                    requester: requester,
                    processPath: processPath,
                    dataToSign: dataToSign,
                    keyBlob: matchingKey.publicKeyBlob,
                    hasForwarding: isForwarded
                )
                ClavisLogger.log("SSH_AGENT_SIGN", "Initiating signature for key '\(matchingKey.label)' requested by \(clientDesc)...")
                if configuredTimeout != .always && !isForwarded, let approvalIdentity {
                    if let grantedSignature = trySigningWithPersonalGrant(
                        keyLabel: matchingKey.label,
                        approvalIdentity: approvalIdentity,
                        operation: .ssh,
                        dataToSign: dataToSign
                    ) {
                        ClavisLogger.log("SSH_AGENT_SIGN", "Using active app-bound Personal SSH grant for '\(matchingKey.label)'. 0 Touch ID prompts.")
                        sigBlob = grantedSignature
                        isFromGitGrant = true
                    } else if let presenter = self.currentSigningPromptPresenter {
                        let destination = Self.resolveSigningDestination(
                            operation: .ssh,
                            dataToSign: dataToSign,
                            keyBlob: matchingKey.publicKeyBlob,
                            connection: connection,
                            isForwardedAgent: false,
                            peerPid: pid,
                            peerPath: processPath
                        )
                        let authRequest = SigningAuthenticationRequest(
                            key: matchingKey,
                            operation: .ssh,
                            operationLabel: Self.operationLabel(for: dataToSign, operation: .ssh),
                            callerName: callerName,
                            peerPid: pid,
                            peerPath: processPath,
                            allowsSessionScope: true,
                            defaultScope: configuredTimeout,
                            reason: prompt,
                            isUncertainCaller: false,
                            isForwardedAgent: false,
                            destination: destination
                        )
                        let outcome = try promptGate.run(requester: requesterIdentity, clientSocket: clientSocket) {
                            try presenter.authenticateSigningRequest(authRequest)
                        }
                        if outcome.selectedScope == .always || outcome.selectedScope.grantDurationSeconds == nil {
                            defer { outcome.context.invalidate() }
                            sigBlob = try keyManager.signSSH(
                                key: matchingKey,
                                data: dataToSign,
                                prompt: "",
                                useCache: false,
                                existingContext: outcome.context,
                                allowedPurposes: role.allowedPurposes
                            )
                        } else {
                            let duration = outcome.selectedScope.grantDurationSeconds ?? 900.0
                            let grant: PersonalUnlockGrant
                            do {
                                grant = try keyManager.authorizePersonalSSHGrant(
                                    key: matchingKey,
                                    prompt: "",
                                    approvalIdentity: approvalIdentity,
                                    duration: duration,
                                    existingContext: outcome.context
                                )
                            } catch {
                                outcome.context.invalidate()
                                throw error
                            }
                            do {
                                guard let grantedSignature = try self.gitSigningGraceManager.withPersonalSSHGrant(
                                    for: matchingKey.label,
                                    approvalIdentity: approvalIdentity,
                                    operation: { try $0.sign(dataToSign) }
                                ) else {
                                    grant.invalidate()
                                    audit.result = .failed
                                    audit.reason = .signingError
                                    return .denied
                                }
                                sigBlob = grantedSignature
                                isFromGitGrant = true
                            } catch {
                                grant.invalidate()
                                throw error
                            }
                        }
                    } else {
                        sigBlob = try promptedSign(
                            key: matchingKey,
                            data: dataToSign,
                            prompt: prompt,
                            role: role,
                            requester: requesterIdentity,
                            clientSocket: clientSocket,
                            operation: .ssh,
                            callerName: callerName,
                            isForwardedAgent: isForwarded,
                            connection: connection
                        )
                    }
                } else {
                    sigBlob = try promptedSign(
                        key: matchingKey,
                        data: dataToSign,
                        prompt: prompt,
                        role: role,
                        requester: requesterIdentity,
                        clientSocket: clientSocket,
                        operation: .ssh,
                        callerName: callerName,
                        isForwardedAgent: isForwarded,
                        connection: connection
                    )
                }
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

    internal static func sharedPersonalUnlockIdentity(for key: SSHKeyInfo) -> String {
        "personal-unlock:\(key.fingerprint)"
    }

    private func trySigningWithPersonalGrant(
        keyLabel: String,
        approvalIdentity: String,
        operation: KeyOperation,
        dataToSign: Data
    ) -> Data? {
        do {
            return try self.gitSigningGraceManager.withPersonalSSHGrant(
                for: keyLabel,
                approvalIdentity: approvalIdentity,
                operationType: operation,
                operation: { try $0.sign(dataToSign) }
            )
        } catch {
            ClavisLogger.log(
                "SSH_AGENT_SIGN",
                "Cached Personal unlock grant failed for '\(keyLabel)' (\(error.localizedDescription)); invalidating and re-prompting."
            )
            self.gitSigningGraceManager.invalidatePersonalSSHGrant(
                keyLabel: keyLabel,
                approvalIdentity: approvalIdentity,
                broadcast: true
            )
            return nil
        }
    }

    private func promptedSign(
        key: SSHKeyInfo,
        data: Data,
        prompt: String,
        role: AgentSocketRole,
        requester: SigningPromptGate.Requester? = nil,
        clientSocket: Int32? = nil,
        operation: KeyOperation? = nil,
        callerName: String? = nil,
        isForwardedAgent: Bool = false,
        connection: ClientConnectionContext? = nil
    ) throws -> Data {
        try promptGate.run(requester: requester, clientSocket: clientSocket) {
            if let presenter = self.currentSigningPromptPresenter, let requester {
                let resolvedOp: KeyOperation = operation ?? (data.starts(with: SSHSIGPayload.magic) ? .signature : .ssh)
                let destination = Self.resolveSigningDestination(
                    operation: resolvedOp,
                    dataToSign: data,
                    keyBlob: key.publicKeyBlob,
                    connection: connection,
                    isForwardedAgent: isForwardedAgent,
                    peerPid: requester.pid,
                    peerPath: requester.executablePath
                )
                let authRequest = SigningAuthenticationRequest(
                    key: key,
                    operation: resolvedOp,
                    operationLabel: Self.operationLabel(for: data, operation: resolvedOp),
                    callerName: callerName,
                    peerPid: requester.pid,
                    peerPath: requester.executablePath,
                    allowsSessionScope: false,
                    defaultScope: .always,
                    reason: prompt,
                    isUncertainCaller: false,
                    isForwardedAgent: isForwardedAgent,
                    destination: destination
                )
                let outcome = try presenter.authenticateSigningRequest(authRequest)
                defer { outcome.context.invalidate() }
                return try keyManager.signSSH(
                    key: key,
                    data: data,
                    prompt: "",
                    useCache: false,
                    existingContext: outcome.context,
                    allowedPurposes: role.allowedPurposes
                )
            }
            return try keyManager.signSSH(
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

    private static let maxDestinationLength = 120

    private static func sanitizeDestination(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let cleaned = raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        let trimmed = String(String.UnicodeScalarView(cleaned)).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.count <= maxDestinationLength {
            return trimmed
        }
        return String(trimmed.prefix(maxDestinationLength))
    }

    /// Resolves a concise signing destination (e.g. `git@github.com` for SSH, repository name for Git commits).
    /// When `isForwardedAgent` is true, never inspects local `connection.authBinding` or local `ssh` argv.
    internal static func resolveSigningDestination(
        operation: KeyOperation,
        dataToSign: Data,
        keyBlob: Data,
        connection: ClientConnectionContext?,
        isForwardedAgent: Bool,
        peerPid: pid_t,
        peerPath: String,
        fallbackPid: pid_t? = nil,
        knownHostName: String? = nil,
        knownHostsReverseLookup: (Data) -> String? = { KnownHosts.reverseLookup(hostKeyBlob: $0) },
        processArgumentsLookup: (pid_t) -> [String]? = { ProcessInspector.processArguments(pid: $0) },
        processWorkingDirectoryLookup: (pid_t) -> String? = { ProcessInspector.processWorkingDirectory(pid: $0) }
    ) -> String? {
        switch operation {
        case .ssh:
            let userAuth = SessionBind.parseUserAuthRequest(dataToSign, expectedKeyBlob: keyBlob)
            var username = sanitizeDestination(userAuth?.username)
            let resolvedHost: String?

            if let knownHost = sanitizeDestination(knownHostName) {
                resolvedHost = knownHost
            } else {
                let hostKeyBlob = isForwardedAgent
                    ? userAuth?.hostKeyBlob
                    : (userAuth?.hostKeyBlob ?? connection?.authBinding?.hostKeyBlob)
                if let blob = hostKeyBlob,
                   let lookedUpHost = sanitizeDestination(knownHostsReverseLookup(blob)) {
                    resolvedHost = lookedUpHost
                } else if !isForwardedAgent,
                          ProcessInspector.isTrustedSshBinary(path: peerPath),
                          let args = processArgumentsLookup(peerPid),
                          let commandDestination = ProcessInspector.extractSSHDestination(fromArguments: args),
                          let commandHost = sanitizeDestination(commandDestination.host) {
                    resolvedHost = commandHost
                    if username == nil {
                        username = sanitizeDestination(commandDestination.username)
                    }
                } else {
                    resolvedHost = nil
                }
            }

            guard let host = resolvedHost else { return nil }
            let combined = username.map { "\($0)@\(host)" } ?? host
            return sanitizeDestination(combined)

        case .signature:
            guard SSHSIGPayload.parse(from: dataToSign) != nil,
                  ProcessInspector.isTrustedGitExecutable(path: peerPath) || ProcessInspector.isSignerHelper(path: peerPath) else {
                return nil
            }
            if let cwd = processWorkingDirectoryLookup(peerPid),
               let repo = sanitizeDestination(ProcessInspector.gitRepositoryName(forWorkingDirectory: cwd)) {
                return repo
            }
            if let fallbackPid,
               let cwd = processWorkingDirectoryLookup(fallbackPid),
               let repo = sanitizeDestination(ProcessInspector.gitRepositoryName(forWorkingDirectory: cwd)) {
                return repo
            }
            return nil
        }
    }
}
