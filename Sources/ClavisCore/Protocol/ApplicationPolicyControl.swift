import Foundation
import Darwin

public enum ApplicationPolicyChange: Codable, Equatable, Sendable {
    case set(RegisteredApplication)
    case remove(ApplicationIdentity)
    case pause
    case resume
}

extension AgentControlDispatcher {
    func handleApplicationRegistry(payload: Data) -> Data {
        guard payload.count == 1,
              let snapshot = try? applicationRegistry.load(),
              let data = try? JSONEncoder().encode(snapshot) else { return Data([5]) }
        var response = Data([6])
        response.appendWireData(data)
        return response
    }

    func handleApplicationPolicyChange(
        payload: Data, clientPid: pid_t?, clientExecutablePath: String?,
        clientStartTime: UInt64?, clientSocket: Int32?
    ) -> Data {
        var reader = DataReader(data: payload)
        guard let json = reader.readWireData(), json.count <= 65_536, reader.isEOF,
              let change = try? JSONDecoder().decode(ApplicationPolicyChange.self, from: json),
              let pid = clientPid, let path = clientExecutablePath, let start = clientStartTime,
              peerProcessValidator(pid, path, start) else { return Data([5]) }
        let registry = AuthenticatedApplicationRegistry(
            store: applicationRegistry, authenticator: authenticator,
            invalidateApprovals: {
                guard self.peerProcessValidator(pid, path, start) else { throw ApplicationRegistryError.staleRevision }
                self.gitSigningGraceManager.invalidateAll(broadcast: false)
                self.agentSessions.endAll(reason: .keyChanged)
            }
        )
        do {
            if change == .pause {
                try registry.setPaused(true)
            } else {
                try promptGate.run(requester: .init(executablePath: path, pid: pid), clientSocket: clientSocket) {
                    switch change {
                    case .set(let app): try registry.set(app)
                    case .remove(let identity): try registry.remove(identity: identity)
                    case .pause: break
                    case .resume: try registry.setPaused(false)
                    }
                }
            }
            auditRecorder.record(AuditEvent(type: .policyChange, result: .info,
                sensitive: .init(processChain: AuditProcessChain.build(pid: pid, executablePath: path))))
            return Data([6])
        } catch {
            auditRecorder.record(AuditEvent(type: .policyChange,
                result: AuditEvent.isUserCancellation(error) ? .cancelled : .denied,
                reason: .policyUnavailable,
                sensitive: .init(processChain: AuditProcessChain.build(pid: pid, executablePath: path))))
            return Data([5])
        }
    }
}
