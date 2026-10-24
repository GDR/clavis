import Foundation
import Security
import CryptoKit
import Darwin

public struct VerifiedApplicationCaller: Equatable, Sendable {
    public let identity: ApplicationIdentity
    public let application: RegisteredApplication
    public let pid: pid_t
    public let startTime: UInt64
    public let path: String
}

/// Returns uncertainty rather than guessing whether an interactive shell is human.
public final class ApplicationCallerResolver {
    public struct Process: Equatable, Sendable {
        public let pid: pid_t
        public let parent: pid_t
        public let start: UInt64
        public let path: String
        public init(pid: pid_t, parent: pid_t, start: UInt64, path: String) {
            self.pid = pid; self.parent = parent; self.start = start; self.path = path
        }
    }

    private let inspect: (pid_t) -> Process?
    private let verify: (ApplicationIdentity, Process) -> Bool
    private let transparentHelper: (Process) -> Bool

    public init(
        inspect: @escaping (pid_t) -> Process? = ApplicationCallerResolver.inspectProcess,
        verify: @escaping (ApplicationIdentity, Process) -> Bool = ApplicationIdentityVerifier.matches,
        transparentHelper: @escaping (Process) -> Bool = ApplicationCallerResolver.isTransportHelper
    ) {
        self.inspect = inspect
        self.verify = verify
        self.transparentHelper = transparentHelper
    }

    public static func inspectProcess(_ pid: pid_t) -> Process? {
        guard let before = ProcessInspector.processParentSnapshot(pid: pid),
              let path = ProcessInspector.getProcessPath(pid: pid),
              let after = ProcessInspector.processParentSnapshot(pid: pid), before == after else { return nil }
        return Process(pid: pid, parent: before.parentPid, start: before.startTime, path: path)
    }

    public static func isTransportHelper(_ process: Process) -> Bool {
        // Only Apple's signed transports are transparent to Personal attribution.
        // Shells, interpreters, and arbitrary executables break that attribution.
        guard ["/usr/bin/ssh", "/usr/bin/git", "/usr/bin/ssh-keygen"].contains(process.path),
              let identity = try? ApplicationIdentity(kind: .designatedRequirement, value: "anchor apple") else { return false }
        return ApplicationIdentityVerifier.matches(identity, process)
    }

    public func resolve(
        peerPID: pid_t, peerPath: String, peerStart: UInt64,
        registry: ApplicationRegistrySnapshot
    ) -> VerifiedApplicationCaller? {
        var pid = peerPID
        var visited = Set<pid_t>()
        var personalAttributionIntact = true
        var chain: [Process] = []
        var candidate: (RegisteredApplication, Process)?
        for _ in 0..<32 {
            if pid <= 1 {
                guard let candidate else { return nil }
                return validated(candidate.0, process: candidate.1, chain: chain)
            }
            guard visited.insert(pid).inserted, let process = inspect(pid) else { return nil }
            if chain.isEmpty && (process.path != peerPath || process.start != peerStart) { return nil }
            chain.append(process)
            // Block and Bot classifications may constrain requests even across an
            // interpreter. Personal authority never crosses an unknown ancestor.
            let matches = registry.applications.filter { verify($0.identity, process) }
            if let blocked = matches.first(where: { $0.classification == .block }) {
                return validated(blocked, process: process, chain: chain)
            }
            if let bot = matches.first(where: { $0.classification == .bot }) {
                candidate = (bot, process)
            } else if candidate == nil, personalAttributionIntact, !transparentHelper(process),
                      let personal = matches.first(where: { $0.classification == .personal }) {
                candidate = (personal, process)
            }
            personalAttributionIntact = personalAttributionIntact && transparentHelper(process)
            pid = process.parent
        }
        return nil
    }

    private func validated(_ app: RegisteredApplication, process: Process, chain: [Process]) -> VerifiedApplicationCaller? {
        // Revalidate every sampled ancestor before returning attribution.
        guard chain.allSatisfy({ inspect($0.pid) == $0 }), verify(app.identity, process) else { return nil }
        return VerifiedApplicationCaller(identity: app.identity, application: app, pid: process.pid, startTime: process.start, path: process.path)
    }
}

public enum ApplicationIdentityVerifier {
    /// Called by the native add flow; selecting a path does not classify it.
    public static func identity(forExecutable url: URL) throws -> ApplicationIdentity {
        let canonical = url.resolvingSymlinksInPath()
        var code: SecStaticCode?
        if SecStaticCodeCreateWithPath(canonical as CFURL, [], &code) == errSecSuccess,
           let code, SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess {
            var requirement: SecRequirement?
            var text: CFString?
            if SecCodeCopyDesignatedRequirement(code, [], &requirement) == errSecSuccess,
               let requirement, SecRequirementCopyString(requirement, [], &text) == errSecSuccess,
               let text {
                return try ApplicationIdentity(kind: .designatedRequirement, value: text as String)
            }
        }
        return try ApplicationIdentity(kind: .executableSHA256, value: digest(canonical))
    }

    public static func matches(_ identity: ApplicationIdentity, _ process: ApplicationCallerResolver.Process) -> Bool {
        guard ProcessInspector.peerProcessUnchanged(pid: process.pid, path: process.path, startTime: process.start) else { return false }
        let result: Bool
        switch identity.kind {
        case .designatedRequirement:
            var requirement: SecRequirement?
            var guest: SecCode?
            let attributes = [kSecGuestAttributePid as String: process.pid] as CFDictionary
            result = SecRequirementCreateWithString(identity.value as CFString, [], &requirement) == errSecSuccess
                && requirement != nil
                && SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess
                && guest != nil
                && SecCodeCheckValidity(guest!, [], requirement) == errSecSuccess
        case .executableSHA256:
            // A file hash alone does not identify the code already executing.
            // Require dynamic code validity as well; truly unsigned processes
            // remain uncertain and can only receive authenticated one-shot access.
            var guest: SecCode?
            let attributes = [kSecGuestAttributePid as String: process.pid] as CFDictionary
            result = SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess
                && guest != nil && SecCodeCheckValidity(guest!, [], nil) == errSecSuccess
                && (try? digest(URL(fileURLWithPath: process.path))) == identity.value
        }
        return result && ProcessInspector.peerProcessUnchanged(pid: process.pid, path: process.path, startTime: process.start)
    }

    private static func digest(_ url: URL) throws -> String {
        // Refuse bundles, devices, huge files, or files changing during hashing.
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey, .fileResourceIdentifierKey]
        let before = try url.resourceValues(forKeys: keys)
        guard before.isRegularFile == true, let size = before.fileSize, size > 0, size <= 268_435_456 else {
            throw ApplicationRegistryError.invalidIdentity
        }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let after = try url.resourceValues(forKeys: keys)
        guard before.fileSize == after.fileSize,
              before.contentModificationDate == after.contentModificationDate,
              String(describing: before.fileResourceIdentifier) == String(describing: after.fileResourceIdentifier) else {
            throw ApplicationRegistryError.invalidIdentity
        }
        return hash
    }
}
