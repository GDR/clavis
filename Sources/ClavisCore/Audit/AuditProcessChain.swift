import Foundation
import Darwin

public enum AuditProcessChain {
    public static func build(
        pid: pid_t,
        executablePath: String,
        maxDepth: Int = 16,
        processInfo: ((pid_t) -> (parent: pid_t, path: String)?)? = nil
    ) -> [AuditProcess] {
        guard maxDepth > 0 else { return [] }
        var chain: [AuditProcess] = [
            AuditProcess(executablePath: AuditEvent.sanitizedPath(executablePath), pid: pid)
        ]
        var currentPid = pid
        var visited: Set<pid_t> = [pid]

        while chain.count < maxDepth && currentPid > 1 {
            let next: (parent: pid_t, path: String)?
            if let lookup = processInfo {
                next = lookup(currentPid)
            } else {
                if let snapshot = SSHAgentServer.processParentSnapshot(pid: currentPid),
                   let path = SSHAgentServer.getProcessPath(pid: snapshot.parentPid) {
                    next = (snapshot.parentPid, path)
                } else {
                    next = nil
                }
            }

            guard let (parentPid, parentPath) = next else { break }
            guard parentPid > 1 else { break }
            guard !visited.contains(parentPid) else { break }

            visited.insert(parentPid)
            chain.append(AuditProcess(executablePath: AuditEvent.sanitizedPath(parentPath), pid: parentPid))
            currentPid = parentPid
        }

        return chain
    }
}
