import Foundation
import Darwin

internal struct AgentControlDispatcher {
    let keyManager: KeychainManager
    let auditRecorder: AuditRecording
    let agentSessions: AgentSessionRegistry
    let agentPolicies: AgentPolicyStoring
    let authenticator: UserAuthenticating
    let promptGate: SigningPromptGate
    let peerProcessValidator: (pid_t, String, UInt64) -> Bool
    let gitSigningGraceManager: GitSigningGraceManager

    init(
        keyManager: KeychainManager,
        auditRecorder: AuditRecording,
        agentSessions: AgentSessionRegistry,
        agentPolicies: AgentPolicyStoring,
        authenticator: UserAuthenticating,
        promptGate: SigningPromptGate,
        peerProcessValidator: @escaping (pid_t, String, UInt64) -> Bool,
        gitSigningGraceManager: GitSigningGraceManager = .shared
    ) {
        self.keyManager = keyManager
        self.auditRecorder = auditRecorder
        self.agentSessions = agentSessions
        self.agentPolicies = agentPolicies
        self.authenticator = authenticator
        self.promptGate = promptGate
        self.peerProcessValidator = peerProcessValidator
        self.gitSigningGraceManager = gitSigningGraceManager
    }

    static func isControlOpcode(_ msgType: UInt8) -> Bool {
        msgType == SSHAgentServer.invalidateKeyRequest
            || msgType == SSHAgentServer.queryGitGraceRequest
            || msgType == SSHAgentServer.lockAllRequest
            || msgType == SSHAgentServer.registerAgentSessionRequest
            || msgType == SSHAgentServer.endAgentSessionRequest
            || msgType == SSHAgentServer.listAgentSessionsRequest
            || msgType == SSHAgentServer.revokeAllAgentSessionsRequest
            || msgType == SSHAgentServer.extendAgentSessionRequest
            || msgType == SSHAgentServer.setAgentPolicyRequest
            || msgType == SSHAgentServer.getAgentPolicyRequest
    }

    func dispatch(
        msgType: UInt8,
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        switch msgType {
        case SSHAgentServer.invalidateKeyRequest:
            return handleInvalidateKey(payload: Data(payload.dropFirst()))
        case SSHAgentServer.queryGitGraceRequest:
            return handleQueryGitGrace(payload: payload)
        case SSHAgentServer.lockAllRequest:
            return handleLockAll(payload: payload)
        case SSHAgentServer.registerAgentSessionRequest:
            return handleRegisterAgentSession(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case SSHAgentServer.endAgentSessionRequest:
            return handleEndAgentSession(payload: Data(payload.dropFirst()))
        case SSHAgentServer.listAgentSessionsRequest:
            return handleListAgentSessions(payload: Data(payload.dropFirst()))
        case SSHAgentServer.revokeAllAgentSessionsRequest:
            return handleRevokeAllAgentSessions(payload: Data(payload.dropFirst()))
        case SSHAgentServer.extendAgentSessionRequest:
            return handleExtendAgentSession(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case SSHAgentServer.setAgentPolicyRequest:
            return handleSetAgentPolicy(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        case SSHAgentServer.getAgentPolicyRequest:
            return handleGetAgentPolicy(payload: Data(payload.dropFirst()))
        default:
            return Data([5])
        }
    }

    func handleInvalidateKey(payload: Data) -> Data {
        var reader = DataReader(data: payload)
        guard let label = reader.readWireString(), !label.isEmpty, reader.isEOF else {
            return Data([5])
        }
        gitSigningGraceManager.invalidate(keyLabel: label)
        agentSessions.endAll(keyLabel: label, reason: .keyChanged)
        return Data([6]) // SSH_AGENT_SUCCESS
    }

    func handleQueryGitGrace(payload: Data) -> Data {
        guard payload.count == 1 else { return Data([5]) }
        var response = Data([6])
        if let grant = gitSigningGraceManager.currentActiveGrant {
            response.appendWireString(grant.keyLabel)
            response.appendWireUInt32(UInt32(grant.remainingSeconds))
            response.appendWireUInt32(UInt32(grant.remainingOperations))
        } else {
            response.appendWireString("")
            response.appendWireUInt32(0)
            response.appendWireUInt32(0)
        }
        return response
    }

    func handleLockAll(payload: Data) -> Data {
        guard payload.count == 1 else { return Data([5]) }
        gitSigningGraceManager.invalidateAll(broadcast: false)
        agentSessions.endAll(reason: .lockAll)
        auditRecorder.record(
            AuditEvent(
                type: .lock,
                result: .info,
                reason: .lockNow
            )
        )
        return Data([6]) // SSH_AGENT_SUCCESS
    }

    func handleEndAgentSession(payload: Data) -> Data {
        var reader = DataReader(data: payload)
        guard let sessionId = reader.readWireString(), !sessionId.isEmpty, reader.isEOF else {
            return Data([5])
        }
        let ended = agentSessions.end(id: sessionId, reason: .revokedByUser)
        return ended ? Data([6]) : Data([5])
    }

    func handleListAgentSessions(payload: Data) -> Data {
        let reader = DataReader(data: payload)
        guard reader.isEOF else { return Data([5]) }
        let summaries = agentSessions.summaries()
        var response = Data([6])
        response.appendWireUInt32(UInt32(summaries.count))
        for s in summaries {
            response.appendWireString(s.id)
            response.appendWireString(s.keyLabel)
            response.appendWireString(s.keyFingerprint)
            response.appendWireString(s.toolName)
            response.appendWireUInt32(UInt32(s.rootPid))
            response.appendWireUInt32(UInt32(s.startedAt.timeIntervalSince1970))
            response.appendWireUInt32(UInt32(s.expiresAt.timeIntervalSince1970))
        }
        return response
    }

    func handleRevokeAllAgentSessions(payload: Data) -> Data {
        let reader = DataReader(data: payload)
        guard reader.isEOF else { return Data([5]) }
        let ended = agentSessions.endAll(reason: .revokedByUser)
        var response = Data([6])
        response.appendWireUInt32(UInt32(ended))
        return response
    }

    func handleRegisterAgentSession(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let keyLabel = reader.readWireString(),
              let toolName = reader.readWireString(),
              let leaseMinutes = reader.readUInt32(),
              reader.isEOF else {
            return Data([5])
        }

        guard !toolName.isEmpty, toolName.utf8.count <= 256, !keyLabel.isEmpty else {
            return Data([5])
        }

        guard let pid = clientPid, let startTime = clientStartTime else {
            return Data([5])
        }

        let processPath = clientExecutablePath ?? SSHAgentServer.getProcessPath(pid: pid) ?? ""
        let chain = AuditProcessChain.build(pid: pid, executablePath: processPath)

        let keys = (try? keyManager.listKeys()) ?? []
        guard let key = keys.first(where: { $0.label == keyLabel }) else {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .unknownKey,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        guard key.purpose == .agent else {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .wrongKeyKind,
                    keyFingerprint: key.fingerprint,
                    keyKind: key.purpose.auditKind,
                    sensitive: AuditSensitive(keyLabel: keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        let policy: AgentKeyPolicy
        let global: AgentGlobalPolicy
        do {
            policy = try agentPolicies.policy(forFingerprint: key.fingerprint)
            global = try agentPolicies.global()
        } catch {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .policyUnavailable,
                    keyFingerprint: key.fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        let requested = Int(leaseMinutes)
        let leaseMinutesActual = min(requested == 0 ? policy.leaseMinutes : requested, global.maxLeaseMinutes)
        let leaseSeconds = UInt32(leaseMinutesActual * 60)

        let requester = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let grant: AgentSessionGrant
        do {
            grant = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                let promptText = ClavisUIStrings.AgentSession.approvePrompt(
                    tool: toolName,
                    keyLabel: key.label,
                    minutes: Int(leaseMinutesActual)
                )
                return try keyManager.authorizeAgentSession(key: key, prompt: promptText)
            }
        } catch {
            let isCancelled = AuditEvent.isUserCancellation(error)
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: isCancelled ? .cancelled : .denied,
                    reason: isCancelled ? .userCancelled : .authenticationFailed,
                    keyFingerprint: key.fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }

        guard peerProcessValidator(pid, processPath, startTime) else {
            grant.invalidate()
            auditRecorder.record(
                AuditEvent(
                    type: .sessionStart,
                    result: .denied,
                    reason: .peerChanged,
                    keyFingerprint: key.fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }

        let startedAt = Date()
        let expiresAt = startedAt.addingTimeInterval(TimeInterval(leaseSeconds))
        let maxExpiresAt = startedAt.addingTimeInterval(Double(global.maxLeaseMinutes * 60))
        let session = AgentSession(
            keyLabel: key.label,
            keyFingerprint: key.fingerprint,
            toolName: toolName,
            root: AgentSessionRoot(pid: pid, startTime: startTime),
            startedAt: startedAt,
            expiresAt: expiresAt,
            maxExpiresAt: maxExpiresAt,
            policy: policy,
            grant: grant
        )
        agentSessions.add(session)

        auditRecorder.record(
            AuditEvent(
                type: .sessionStart,
                result: .allowed,
                reason: .sessionApproved,
                keyFingerprint: key.fingerprint,
                keyKind: .agent,
                sessionID: session.id,
                sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
            )
        )

        var response = Data([6])
        response.appendWireString(session.id)
        response.appendWireUInt32(leaseSeconds)
        return response
    }

    func handleSetAgentPolicy(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let fingerprint = reader.readWireString(),
              let jsonString = reader.readWireString(),
              reader.isEOF else {
            return Data([5])
        }

        guard let jsonData = jsonString.data(using: .utf8) else {
            return Data([5])
        }

        let pid = clientPid ?? 0
        let processPath = clientExecutablePath ?? (clientPid.flatMap { SSHAgentServer.getProcessPath(pid: $0) }) ?? ""
        let chain = clientPid != nil ? AuditProcessChain.build(pid: pid, executablePath: processPath) : []
        let gateRequester = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let requester = SSHAgentServer.requesterDescription(processPath: processPath, pid: pid)

        if fingerprint == KeychainAgentPolicyStore.globalAccount {
            guard let globalPolicy = try? JSONDecoder().decode(AgentGlobalPolicy.self, from: jsonData) else {
                return Data([5])
            }
            do {
                try globalPolicy.validate()
            } catch {
                return Data([5])
            }

            let reason = ClavisUIStrings.AgentPolicy.authReason(
                keyLabel: KeychainAgentPolicyStore.globalAccount,
                requester: requester
            )
            do {
                _ = try promptGate.run(requester: gateRequester, clientSocket: clientSocket) {
                    try authenticator.authenticate(
                        reason: reason,
                        policy: .deviceOwnerAuthentication
                    )
                }
            } catch {
                let isCancelled = AuditEvent.isUserCancellation(error)
                auditRecorder.record(
                    AuditEvent(
                        type: .policyChange,
                        result: isCancelled ? .cancelled : .denied,
                        reason: isCancelled ? .userCancelled : .authenticationFailed,
                        sensitive: AuditSensitive(keyLabel: KeychainAgentPolicyStore.globalAccount, processChain: chain)
                    )
                )
                return Data([5])
            }

            do {
                try agentPolicies.saveGlobal(globalPolicy)
                auditRecorder.record(
                    AuditEvent(
                        type: .policyChange,
                        result: .allowed,
                        sensitive: AuditSensitive(keyLabel: KeychainAgentPolicyStore.globalAccount, processChain: chain)
                    )
                )
                return Data([6])
            } catch {
                auditRecorder.record(
                    AuditEvent(
                        type: .policyChange,
                        result: .failed,
                        sensitive: AuditSensitive(keyLabel: KeychainAgentPolicyStore.globalAccount, processChain: chain)
                    )
                )
                return Data([5])
            }
        }

        guard let policy = try? JSONDecoder().decode(AgentKeyPolicy.self, from: jsonData) else {
            return Data([5])
        }

        do {
            try policy.validate()
        } catch {
            return Data([5])
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let key = keys.first(where: { $0.fingerprint == fingerprint }) else {
            return Data([5])
        }

        guard key.purpose == .agent else {
            return Data([5])
        }

        let promptReason = ClavisUIStrings.AgentPolicy.authReason(keyLabel: key.label, requester: requester)

        do {
            _ = try promptGate.run(requester: gateRequester, clientSocket: clientSocket) {
                try authenticator.authenticate(
                    reason: promptReason,
                    policy: key.effectiveBiometricPolicy.laPolicy
                )
            }
        } catch {
            let isCancelled = AuditEvent.isUserCancellation(error)
            auditRecorder.record(
                AuditEvent(
                    type: .policyChange,
                    result: isCancelled ? .cancelled : .denied,
                    reason: isCancelled ? .userCancelled : .authenticationFailed,
                    keyFingerprint: fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }

        do {
            try agentPolicies.save(policy, forFingerprint: fingerprint)
            auditRecorder.record(
                AuditEvent(
                    type: .policyChange,
                    result: .allowed,
                    keyFingerprint: fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([6])
        } catch {
            auditRecorder.record(
                AuditEvent(
                    type: .policyChange,
                    result: .failed,
                    keyFingerprint: fingerprint,
                    keyKind: .agent,
                    sensitive: AuditSensitive(keyLabel: key.label, processChain: chain)
                )
            )
            return Data([5])
        }
    }

    func handleGetAgentPolicy(payload: Data) -> Data {
        var reader = DataReader(data: payload)
        guard let fingerprint = reader.readWireString(), reader.isEOF else {
            return Data([5])
        }

        if fingerprint == KeychainAgentPolicyStore.globalAccount {
            do {
                let globalPolicy = try agentPolicies.global()
                let data = try JSONEncoder().encode(globalPolicy)
                guard let jsonString = String(data: data, encoding: .utf8) else {
                    return Data([5])
                }
                var response = Data([6])
                response.appendWireString(jsonString)
                return response
            } catch {
                return Data([5])
            }
        }

        let keys = (try? keyManager.listKeys()) ?? []
        guard let key = keys.first(where: { $0.fingerprint == fingerprint }) else {
            return Data([5])
        }

        guard key.purpose == .agent else {
            return Data([5])
        }

        do {
            let policy = try agentPolicies.policy(forFingerprint: fingerprint)
            let data = try JSONEncoder().encode(policy)
            guard let jsonString = String(data: data, encoding: .utf8) else {
                return Data([5])
            }
            var response = Data([6])
            response.appendWireString(jsonString)
            return response
        } catch {
            return Data([5])
        }
    }

    func handleExtendAgentSession(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let sessionId = reader.readWireString(),
              let minutes32 = reader.readUInt32(),
              reader.isEOF else {
            return Data([5])
        }

        let minutes = Int(minutes32)
        guard minutes > 0 else {
            return Data([5])
        }

        let summaries = agentSessions.summaries()
        guard let summary = summaries.first(where: { $0.id == sessionId }) else {
            return Data([5])
        }

        let pid = clientPid ?? 0
        let processPath = clientExecutablePath ?? (clientPid.flatMap { SSHAgentServer.getProcessPath(pid: $0) }) ?? ""
        let chain = clientPid != nil ? AuditProcessChain.build(pid: pid, executablePath: processPath) : []
        let requesterIdentity = SigningPromptGate.Requester(executablePath: processPath, pid: pid)
        let clientDesc = SSHAgentServer.requesterDescription(processPath: processPath, pid: pid)
        let keys = (try? keyManager.listKeys()) ?? []
        let matchedKey = keys.first(where: { $0.fingerprint == summary.keyFingerprint })
        let promptReason = ClavisUIStrings.AgentSession.extendAuthReason(
            keyLabel: summary.keyLabel,
            tool: summary.toolName,
            minutes: minutes,
            requester: clientDesc
        )

        do {
            _ = try promptGate.run(requester: requesterIdentity, clientSocket: clientSocket) {
                try authenticator.authenticate(
                    reason: promptReason,
                    policy: matchedKey?.effectiveBiometricPolicy.laPolicy ?? .deviceOwnerAuthentication
                )
            }
        } catch {
            let isCancelled = AuditEvent.isUserCancellation(error)
            auditRecorder.record(
                AuditEvent(
                    type: .sessionExtend,
                    result: isCancelled ? .cancelled : .denied,
                    reason: isCancelled ? .userCancelled : .authenticationFailed,
                    keyFingerprint: summary.keyFingerprint,
                    keyKind: .agent,
                    sessionID: sessionId,
                    sensitive: AuditSensitive(keyLabel: summary.keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        guard let newExpiry = agentSessions.extend(id: sessionId, by: minutes) else {
            auditRecorder.record(
                AuditEvent(
                    type: .sessionExtend,
                    result: .failed,
                    keyFingerprint: summary.keyFingerprint,
                    keyKind: .agent,
                    sessionID: sessionId,
                    sensitive: AuditSensitive(keyLabel: summary.keyLabel, processChain: chain)
                )
            )
            return Data([5])
        }

        auditRecorder.record(
            AuditEvent(
                type: .sessionExtend,
                result: .allowed,
                keyFingerprint: summary.keyFingerprint,
                keyKind: .agent,
                sessionID: sessionId,
                sensitive: AuditSensitive(keyLabel: summary.keyLabel, processChain: chain)
            )
        )

        var response = Data([6])
        response.appendWireUInt32(UInt32(newExpiry.timeIntervalSince1970))
        return response
    }
}
