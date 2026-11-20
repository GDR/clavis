import Foundation
import Darwin
import CryptoKit

private enum CLIControlServerError: Error {
    case peerProcessChanged
}

internal struct AgentControlDispatcher {
    let applicationRegistry: ApplicationRegistryStoring
    let keyPolicyGenerations: KeyPolicyGenerations
    let keyManager: KeychainManager
    let auditRecorder: AuditRecording
    let agentSessions: AgentSessionRegistry
    let agentPolicies: AgentPolicyStoring
    let authenticator: UserAuthenticating
    let promptGate: SigningPromptGate
    let peerProcessValidator: (pid_t, String, UInt64) -> Bool
    let gitSigningGraceManager: GitSigningGraceManager
    let vaultStore: EncryptedVaultStore

    init(
        keyManager: KeychainManager,
        auditRecorder: AuditRecording,
        agentSessions: AgentSessionRegistry,
        agentPolicies: AgentPolicyStoring,
        authenticator: UserAuthenticating,
        promptGate: SigningPromptGate,
        peerProcessValidator: @escaping (pid_t, String, UInt64) -> Bool,
        gitSigningGraceManager: GitSigningGraceManager = .shared,
        applicationRegistry: ApplicationRegistryStoring = KeychainApplicationRegistry.shared,
        keyPolicyGenerations: KeyPolicyGenerations = .shared,
        vaultStore: EncryptedVaultStore = .shared
    ) {
        self.applicationRegistry = applicationRegistry
        self.keyPolicyGenerations = keyPolicyGenerations
        self.keyManager = keyManager
        self.auditRecorder = auditRecorder
        self.agentSessions = agentSessions
        self.agentPolicies = agentPolicies
        self.authenticator = authenticator
        self.promptGate = promptGate
        self.peerProcessValidator = peerProcessValidator
        self.gitSigningGraceManager = gitSigningGraceManager
        self.vaultStore = vaultStore
    }

    static func isControlOpcode(_ msgType: UInt8) -> Bool {
        msgType == SSHAgentServer.applicationRegistryRequest
            || msgType == SSHAgentServer.applicationPolicyChangeRequest
            || msgType == SSHAgentServer.cliControlRequest
            || msgType == SSHAgentServer.invalidateKeyRequest
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
        case SSHAgentServer.applicationRegistryRequest:
            return handleApplicationRegistry(payload: payload)
        case SSHAgentServer.applicationPolicyChangeRequest:
            return handleApplicationPolicyChange(payload: Data(payload.dropFirst()), clientPid: clientPid, clientExecutablePath: clientExecutablePath, clientStartTime: clientStartTime, clientSocket: clientSocket)
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
        case SSHAgentServer.cliControlRequest:
            return handleCLIControl(
                payload: Data(payload.dropFirst()),
                clientPid: clientPid,
                clientExecutablePath: clientExecutablePath,
                clientStartTime: clientStartTime,
                clientSocket: clientSocket
            )
        default:
            return Data([5])
        }
    }

    func handleInvalidateKey(payload: Data) -> Data {
        var reader = DataReader(data: payload)
        guard let label = reader.readWireString(), !label.isEmpty, reader.isEOF else {
            return Data([5])
        }
        let fingerprint = (try? keyManager.fetchKeyInfo(label: label))?.fingerprint
        keyPolicyGenerations.invalidate(label: label, fingerprint: fingerprint)
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
        // INV-21 (D-40): lock clears Personal sessions (git grace + app-side LA sessions);
        // valid Agent sessions keep signing until their lease expires.
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
        let requesterDesc = SSHAgentServer.requesterDescription(processPath: processPath, pid: pid)
        let grant: AgentSessionGrant
        do {
            grant = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                let promptText = ClavisUIStrings.AgentSession.approvePrompt(
                    tool: toolName,
                    keyLabel: key.label,
                    minutes: Int(leaseMinutesActual),
                    requester: requesterDesc,
                    mode: policy.mode,
                    allowedHosts: policy.allowedHosts
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

            let keys = (try? keyManager.listKeys()) ?? []
            let requiresStrictBiometry = keys.contains {
                $0.purpose == .agent && $0.effectiveBiometricPolicy == .biometryCurrentSet
            }
            let authPolicy = requiresStrictBiometry
                ? BiometricPolicy.biometryCurrentSet.laPolicy
                : BiometricPolicy.userPresence.laPolicy

            let reason = ClavisUIStrings.AgentPolicy.authReason(
                keyLabel: KeychainAgentPolicyStore.globalAccount,
                requester: requester,
                leaseMinutes: globalPolicy.maxLeaseMinutes
            )
            do {
                _ = try promptGate.run(requester: gateRequester, clientSocket: clientSocket) {
                    try authenticator.authenticate(
                        reason: reason,
                        policy: authPolicy
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

        let promptReason = ClavisUIStrings.AgentPolicy.authReason(
            keyLabel: key.label,
            requester: requester,
            mode: policy.mode,
            leaseMinutes: policy.leaseMinutes
        )

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

    func handleCLIControl(
        payload: Data,
        clientPid: pid_t?,
        clientExecutablePath: String?,
        clientStartTime: UInt64?,
        clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let json = reader.readWireData(),
              json.count <= 65_536,
              reader.isEOF,
              let request = try? JSONDecoder().decode(CLIControlRequest.self, from: json) else {
            return Data([5])
        }

        if case .listKeys = request {
            do {
                let keys = try keyManager.listKeys()
                return encodeCLIResponse(.keys(keys))
            } catch {
                return encodeCLIResponse(.failure(message: error.localizedDescription))
            }
        }

        guard let pid = clientPid,
              let path = clientExecutablePath,
              let start = clientStartTime,
              peerProcessValidator(pid, path, start) else {
            return Data([5])
        }

        // Re-validate peer process after waiting in the prompt queue and before committing any
        // mutation so a peer that exited or exec'd (inheriting the socket FD) cannot commit changes.
        let verifyPeerUnchanged: () throws -> Void = {
            guard peerProcessValidator(pid, path, start) else {
                ClavisLogger.log("SECURITY_ALERT", "Rejected CLI control request from PID \(pid): peer process changed before completion.")
                throw CLIControlServerError.peerProcessChanged
            }
        }

        // Revoke local daemon state directly instead of dialing our own socket via AgentLifecycleManager.
        let localRevoker: (String) throws -> Void = { label in
            try verifyPeerUnchanged()
            let fp = (try? keyManager.fetchKeyInfo(label: label))?.fingerprint
            keyPolicyGenerations.invalidate(label: label, fingerprint: fp)
            gitSigningGraceManager.invalidate(keyLabel: label)
            _ = agentSessions.endAll(keyLabel: label, reason: .keyChanged)
        }
        let requester = SigningPromptGate.Requester(executablePath: path, pid: pid)

        do {
            switch request {
            case .listKeys:
                let keys = try keyManager.listKeys()
                return encodeCLIResponse(.keys(keys))

            case .generateKey(let label, let algorithm, let storageType, let biometricPolicy, let keyPurpose):
                let info = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                    try verifyPeerUnchanged()
                    return try keyManager.generateKey(
                        label: label,
                        algorithm: algorithm,
                        storageType: storageType,
                        biometricPolicy: biometricPolicy,
                        keyPurpose: keyPurpose,
                        beforeCommit: verifyPeerUnchanged
                    )
                }
                return encodeCLIResponse(.key(info))

            case .changeKind(let label, let newPurpose):
                try promptGate.run(requester: requester, clientSocket: clientSocket) {
                    try verifyPeerUnchanged()
                    try keyManager.changeKind(
                        label: label,
                        to: newPurpose,
                        customRevoker: localRevoker,
                        beforeCommit: verifyPeerUnchanged
                    )
                }
                return encodeCLIResponse(.ok)

            case .deleteKey(let label):
                try promptGate.run(requester: requester, clientSocket: clientSocket) {
                    try verifyPeerUnchanged()
                    try keyManager.deleteKey(
                        label: label,
                        customRevoker: localRevoker,
                        beforeCommit: verifyPeerUnchanged
                    )
                }
                return encodeCLIResponse(.ok)

            case .inspectVaultMasterKey:
                let inspection: VaultMasterKeyInspection = try promptGate.run(requester: requester, clientSocket: clientSocket) {
                    try verifyPeerUnchanged()
                    let pubKey: P256.KeyAgreement.PublicKey
                    let fingerprint: String
                    do {
                        (pubKey, fingerprint) = try vaultStore.verifyMasterKey()
                    } catch {
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed during verification: \(error.localizedDescription)")
                        throw error
                    }
                    try verifyPeerUnchanged()
                    let expectedPin = Data(SHA256.hash(data: pubKey.rawRepresentation))
                    let masterKeyURL = vaultStore.vaultDirectoryURL.appendingPathComponent("master.key")
                    let createdAtISO8601: String?
                    if let created = (try? FileManager.default.attributesOfItem(atPath: masterKeyURL.path))?[.creationDate] as? Date {
                        createdAtISO8601 = ISO8601DateFormatter().string(from: created)
                    } else {
                        createdAtISO8601 = nil
                    }
                    let existingPin: Data?
                    do {
                        existingPin = try vaultStore.activePinStore.loadPin()
                    } catch {
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed reading Keychain pin: \(error.localizedDescription)")
                        throw error
                    }
                    return VaultMasterKeyInspection(
                        fingerprint: fingerprint,
                        createdAtISO8601: createdAtISO8601,
                        existingPin: existingPin,
                        expectedPin: expectedPin
                    )
                }
                return encodeCLIResponse(.vaultInspection(inspection))

            case .saveVaultMasterKeyPin(let expectedPin, let replacePin):
                try promptGate.run(requester: requester, clientSocket: clientSocket) {
                    try verifyPeerUnchanged()
                    guard expectedPin.count == 32 else {
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt rejected: invalid pin length (\(expectedPin.count) bytes).")
                        throw EncryptedVaultStore.VaultError.masterKeyTampered
                    }
                    let pubKey: P256.KeyAgreement.PublicKey
                    let verifiedFingerprint: String
                    do {
                        (pubKey, verifiedFingerprint) = try vaultStore.verifyMasterKey()
                    } catch {
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed during verification: \(error.localizedDescription)")
                        throw error
                    }
                    try verifyPeerUnchanged()
                    let serverExpectedPin = Data(SHA256.hash(data: pubKey.rawRepresentation))
                    guard expectedPin == serverExpectedPin else {
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt rejected: supplied pin does not match verified master key (\(verifiedFingerprint)).")
                        throw EncryptedVaultStore.VaultError.masterKeyTampered
                    }
                    let existingPin: Data?
                    do {
                        existingPin = try vaultStore.activePinStore.loadPin()
                    } catch {
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed reading Keychain pin: \(error.localizedDescription)")
                        throw error
                    }
                    if let existingPin, existingPin != serverExpectedPin {
                        guard replacePin else {
                            ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt rejected: existing pin mismatch requires --replace-pin flag.")
                            throw EncryptedVaultStore.VaultError.masterKeyTampered
                        }
                        let previousPinnedFingerprint = EncryptedVaultStore.fingerprint(forPin: existingPin)
                        ClavisLogger.log("SECURITY_ALERT", "Vault repair replacing pin \(previousPinnedFingerprint) with \(verifiedFingerprint).")
                    }
                    try verifyPeerUnchanged()
                    try vaultStore.activePinStore.savePin(serverExpectedPin)
                    ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt succeeded: master key pin restored (fingerprint: \(verifiedFingerprint)).")
                }
                return encodeCLIResponse(.ok)
            }
        } catch CLIControlServerError.peerProcessChanged {
            return Data([5])
        } catch {
            return encodeCLIResponse(.failure(message: error.localizedDescription))
        }
    }

    private func encodeCLIResponse(_ response: CLIControlResponse) -> Data {
        guard let data = try? JSONEncoder().encode(response) else {
            return Data([5])
        }
        var frame = Data([6])
        frame.appendWireData(data)
        return frame
    }
}
