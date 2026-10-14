import Foundation
import Darwin

/// Parent and start time from a single `proc_pidinfo` read.
public struct ProcessParentSnapshot: Equatable, Sendable {
    public var startTime: UInt64
    public var parentPid: pid_t

    public init(startTime: UInt64, parentPid: pid_t) {
        self.startTime = startTime
        self.parentPid = parentPid
    }
}

public enum ProcessInspector {
    public static func getProcessName(pid: pid_t) -> String? {
        guard let fullPath = getProcessPath(pid: pid) else { return nil }
        return (fullPath as NSString).lastPathComponent
    }

    public static func getProcessPath(pid: pid_t) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let ret = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        if ret > 0 {
            return String(cString: pathBuffer)
        }
        return nil
    }

    /// Process start time in microseconds since the epoch; stable across `exec`, changes on PID reuse.
    public static func processStartTime(pid: pid_t) -> UInt64? {
        processParentSnapshot(pid: pid)?.startTime
    }

    /// One `proc_pidinfo` snapshot: start time plus parent pid.
    public static func processParentSnapshot(pid: pid_t) -> ProcessParentSnapshot? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return ProcessParentSnapshot(
            startTime: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
            parentPid: pid_t(info.pbi_ppid)
        )
    }

    public static let trustedGitPaths: Set<String> = [
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
        "/run/current-system/sw/bin/git",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
        "/Library/Developer/CommandLineTools/usr/bin/git"
    ]

    public static let trustedSignerHelperPaths: Set<String> = [
        "/usr/bin/ssh-keygen",
        "/usr/local/bin/ssh-keygen",
        "/opt/homebrew/bin/ssh-keygen",
        "/run/current-system/sw/bin/ssh-keygen"
    ]

    public static func isValidNixStoreBinary(standardizedPath: String, binaryName: String) -> Bool {
        isValidNixStoreBinary(standardizedPath: standardizedPath, binaryName: binaryName, storeRoot: "/nix/store")
    }

    internal static func isValidNixStoreBinary(standardizedPath: String, binaryName: String, storeRoot: String) -> Bool {
        let normalizedRoot = storeRoot.hasSuffix("/") ? String(storeRoot.dropLast()) : storeRoot
        let prefix = normalizedRoot + "/"
        guard standardizedPath.hasPrefix(prefix) else { return false }

        let relative = standardizedPath.dropFirst(prefix.count)
        let parts = relative.split(separator: "/", omittingEmptySubsequences: false)
        // Relative to storeRoot, must be `<store-entry>/bin/<binaryName>`
        guard parts.count == 3,
              parts[1] == "bin",
              parts[2] == Substring(binaryName) else {
            return false
        }

        let storeEntry = parts[0]
        // Nix store entries have format `<32-char-hash>-<name>` (at least 34 chars).
        guard storeEntry.count >= 34 else { return false }
        let dashIndex = storeEntry.index(storeEntry.startIndex, offsetBy: 32)
        guard storeEntry[dashIndex] == "-" else { return false }

        let hashPrefix = storeEntry[..<dashIndex]
        guard hashPrefix.unicodeScalars.allSatisfy({
            ($0.value >= 0x30 && $0.value <= 0x39) ||
            ($0.value >= 0x61 && $0.value <= 0x7A) ||
            ($0.value >= 0x41 && $0.value <= 0x5A)
        }) else {
            return false
        }

        let namePart = storeEntry[storeEntry.index(after: dashIndex)...]
        guard !namePart.isEmpty, namePart != "." && namePart != "..",
              namePart.unicodeScalars.allSatisfy({
                  ($0.value >= 0x30 && $0.value <= 0x39) ||
                  ($0.value >= 0x61 && $0.value <= 0x7A) ||
                  ($0.value >= 0x41 && $0.value <= 0x5A) ||
                  $0 == "+" || $0 == "-" || $0 == "." || $0 == "_" || $0 == "?" || $0 == "="
              }) else {
            return false
        }

        let euid = geteuid()
        var lst = stat()
        if lstat(standardizedPath, &lst) == 0 {
            guard lst.st_uid == 0 || lst.st_uid == euid else { return false }
            if (lst.st_mode & S_IFMT) == S_IFLNK {
                let resolved = URL(fileURLWithPath: standardizedPath).resolvingSymlinksInPath().path
                guard resolved.hasPrefix(prefix) else { return false }
            }
            var st = stat()
            guard stat(standardizedPath, &st) == 0 else { return false }
            guard (st.st_mode & S_IFMT) == S_IFREG else { return false }
            guard (st.st_mode & 0o022) == 0 else { return false }
            guard st.st_uid == 0 || st.st_uid == euid else { return false }
        } else if errno != ENOENT {
            return false
        }

        let storeDirPath = "\(normalizedRoot)/\(storeEntry)"
        var dirSt = stat()
        if stat(storeDirPath, &dirSt) == 0 {
            guard (dirSt.st_mode & 0o022) == 0 else { return false }
            guard dirSt.st_uid == 0 || dirSt.st_uid == euid else { return false }
        }

        return true
    }

    private static func containsParentTraversal(_ path: String) -> Bool {
        path.split(separator: "/", omittingEmptySubsequences: false).contains("..")
    }

    public static func isTrustedGitExecutable(path: String) -> Bool {
        guard !containsParentTraversal(path) else { return false }
        let stdPath = URL(fileURLWithPath: path).standardizedFileURL.path
        if trustedGitPaths.contains(stdPath) { return true }
        if (stdPath.hasPrefix("/Applications/Xcode") || stdPath.hasPrefix("/Library/Developer/CommandLineTools")) && stdPath.hasSuffix("/usr/bin/git") {
            return true
        }
        if isValidNixStoreBinary(standardizedPath: stdPath, binaryName: "git") { return true }
        #if DEBUG
        if (path as NSString).lastPathComponent == "xctest" { return true }
        #endif
        return false
    }

    public static func isGitExecutablePath(_ path: String) -> Bool {
        isTrustedGitExecutable(path: path)
    }

    public static func isTrustedSignerHelperExecutable(path: String) -> Bool {
        guard !containsParentTraversal(path) else { return false }
        let stdPath = URL(fileURLWithPath: path).standardizedFileURL.path
        if trustedSignerHelperPaths.contains(stdPath) { return true }
        if isValidNixStoreBinary(standardizedPath: stdPath, binaryName: "ssh-keygen") { return true }
        return false
    }

    public static func isTrustedSshKeygen(path: String) -> Bool {
        isTrustedSignerHelperExecutable(path: path)
    }

    public static func isSSHKeygenExecutablePath(_ path: String) -> Bool {
        isTrustedSignerHelperExecutable(path: path)
    }

    public static let trustedSshPaths: Set<String> = [
        "/usr/bin/ssh",
        "/usr/local/bin/ssh",
        "/opt/homebrew/bin/ssh",
        "/run/current-system/sw/bin/ssh"
    ]

    public static func isTrustedSshBinary(path: String) -> Bool {
        guard !containsParentTraversal(path) else { return false }
        let std = URL(fileURLWithPath: path).standardizedFileURL.path
        if trustedSshPaths.contains(std) { return true }
        if isValidNixStoreBinary(standardizedPath: std, binaryName: "ssh") { return true }
        #if DEBUG
        if (path as NSString).lastPathComponent == "xctest" { return true }
        #endif
        return false
    }

    /// `true` when `peer` is the approved process instance or a live descendant of it
    /// via a git-only process chain ending in a recognized signer helper.
    /// The walk stops at pid 1, a cycle, or a missing snapshot. A sibling that merely
    /// shares the approved process's parent does not match.
    public static func gitGrantCoversPeer(
        peerPid: pid_t,
        peerStartTime: UInt64,
        peerPath: String? = nil,
        approvedPid: pid_t,
        approvedStartTime: UInt64,
        processInfo: (pid_t) -> ProcessParentSnapshot? = { processParentSnapshot(pid: $0) },
        processPathLookup: (pid_t) -> String? = { getProcessPath(pid: $0) },
        resolvedGpgSSHProgram: () -> String? = { SSHAgentServer.gpgSSHProgramResolver() }
    ) -> Bool {
        guard peerPid > 0, approvedPid > 1 else { return false }

        // Direct match: approved process instance itself (e.g. test runner or direct anchor)
        if peerPid == approvedPid {
            guard let peerSnap = processInfo(peerPid) else { return false }
            return peerSnap.startTime == peerStartTime && peerStartTime == approvedStartTime
        }

        // Descendant match:
        // Peer must be a known signer helper (ssh-keygen or resolved gpg.ssh.program)
        guard let resolvedPeerPath = peerPath ?? processPathLookup(peerPid) else {
            return false
        }
        guard isSignerHelper(path: resolvedPeerPath, resolvedGpgSSHProgram: resolvedGpgSSHProgram) else {
            return false
        }

        guard let peerSnap = processInfo(peerPid), peerSnap.startTime == peerStartTime else {
            return false
        }

        // Ancestor path walk: from peer's parent up to approvedPid.
        // Every process on the ancestor path from peer up to approved git (exclusive) must be a trusted git.
        var current = peerSnap.parentPid
        var seen = Set<pid_t>([peerPid])
        seen.reserveCapacity(8)

        for _ in 0..<64 {
            guard current > 1, seen.insert(current).inserted else { return false }
            guard let info = processInfo(current) else { return false }

            if current == approvedPid {
                return info.startTime == approvedStartTime
            }

            guard let path = processPathLookup(current) else { return false }
            guard isTrustedGitExecutable(path: path) else { return false }

            let parent = info.parentPid
            if parent <= 0 || parent == current {
                return false
            }
            current = parent
        }
        return false
    }

    public static func gitGrantCoversPeer(peer: GitApprovedProcess, approved: GitApprovedProcess) -> Bool {
        gitGrantCoversPeer(
            peerPid: peer.pid,
            peerStartTime: peer.startTime,
            peerPath: peer.path,
            approvedPid: approved.pid,
            approvedStartTime: approved.startTime,
            processInfo: { processParentSnapshot(pid: $0) },
            processPathLookup: { getProcessPath(pid: $0) },
            resolvedGpgSSHProgram: { SSHAgentServer.gpgSSHProgramResolver() }
        )
    }

    public static func resolveGpgSSHProgram(gitExecutablePath: String? = nil, timeout: TimeInterval = 2.0) -> String? {
        let gitPath: String
        if let customPath = gitExecutablePath {
            guard FileManager.default.isExecutableFile(atPath: customPath) else { return nil }
            gitPath = customPath
        } else if FileManager.default.isExecutableFile(atPath: "/usr/bin/git") {
            gitPath = "/usr/bin/git"
        } else if FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/git") {
            gitPath = "/opt/homebrew/bin/git"
        } else if FileManager.default.isExecutableFile(atPath: "/usr/local/bin/git") {
            gitPath = "/usr/local/bin/git"
        } else if FileManager.default.isExecutableFile(atPath: "/Applications/Xcode.app/Contents/Developer/usr/bin/git") {
            gitPath = "/Applications/Xcode.app/Contents/Developer/usr/bin/git"
        } else {
            return nil
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: gitPath)
        process.arguments = ["config", "--get", "gpg.ssh.program"]
        var env = ProcessInfo.processInfo.environment
        for key in Array(env.keys) where key.hasPrefix("GIT_") {
            env.removeValue(forKey: key)
        }
        process.environment = env
        let stdoutPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return nil
        }

        let readHandle = stdoutPipe.fileHandleForReading
        let readFd = readHandle.fileDescriptor
        let maxOutputBytes = 64 * 1024
        var outputData = Data()
        var timedOut = false

        let startUptime = DispatchTime.now().uptimeNanoseconds
        let timeoutNanos = UInt64(max(0, timeout) * 1_000_000_000)
        let deadlineUptime = startUptime + timeoutNanos

        var chunk = [UInt8](repeating: 0, count: 4096)

        // Read stdout on the calling thread with poll(2) to avoid close races with
        // readDataToEndOfFile() which can throw an uncatchable Obj-C exception if closed
        // while blocked on Darwin.
        while true {
            let nowUptime = DispatchTime.now().uptimeNanoseconds
            if nowUptime >= deadlineUptime {
                timedOut = true
                break
            }
            let remainingNanos = deadlineUptime - nowUptime
            let remainingMs = Int32(min(max(1, (remainingNanos + 999_999) / 1_000_000), UInt64(Int32.max)))

            var pfd = pollfd(fd: readFd, events: Int16(POLLIN), revents: 0)
            let pollRet = poll(&pfd, 1, remainingMs)

            if pollRet < 0 {
                if errno == EINTR {
                    continue
                }
                break
            } else if pollRet == 0 {
                timedOut = true
                break
            }

            let bytesRead = read(readFd, &chunk, chunk.count)
            if bytesRead > 0 {
                if outputData.count < maxOutputBytes {
                    let toAppend = min(bytesRead, maxOutputBytes - outputData.count)
                    outputData.append(contentsOf: chunk[0..<toAppend])
                }
            } else if bytesRead == 0 {
                break
            } else {
                if errno == EINTR {
                    continue
                }
                break
            }
        }

        try? readHandle.close()

        if timedOut {
            process.terminate()
            for _ in 0..<10 where process.isRunning {
                usleep(5_000)
            }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            return nil
        }

        while process.isRunning {
            let nowUptime = DispatchTime.now().uptimeNanoseconds
            if nowUptime >= deadlineUptime {
                process.terminate()
                for _ in 0..<10 where process.isRunning {
                    usleep(5_000)
                }
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
                process.waitUntilExit()
                return nil
            }
            usleep(5_000)
        }

        process.waitUntilExit()

        guard process.terminationStatus == 0 else { return nil }
        guard let raw = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return nil
        }
        return raw
    }

    public static func resolveGpgSSHProgram(forGitProcess gitExecutablePath: String? = nil, timeout: TimeInterval = 2.0) -> String? {
        resolveGpgSSHProgram(gitExecutablePath: gitExecutablePath, timeout: timeout)
    }

    public static func isSignerHelper(
        path: String,
        resolvedGpgSSHProgram: () -> String? = { SSHAgentServer.gpgSSHProgramResolver() }
    ) -> Bool {
        if isTrustedSignerHelperExecutable(path: path) {
            return true
        }
        if let custom = resolvedGpgSSHProgram(), !custom.isEmpty {
            let expandedCustom = NSString(string: custom).expandingTildeInPath
            let stdCustom = URL(fileURLWithPath: expandedCustom).standardizedFileURL.path
            let stdPath = URL(fileURLWithPath: path).standardizedFileURL.path
            if stdPath == stdCustom {
                return true
            }
        }
        return false
    }

    public static func isSigningHelperPath(_ path: String, configuredProgram: String? = nil) -> Bool {
        isSignerHelper(path: path, resolvedGpgSSHProgram: { configuredProgram })
    }

    public static func isRefusedAnchor(pid: pid_t, path: String) -> Bool {
        if pid <= 1 { return true }
        let base = (path as NSString).lastPathComponent.lowercased()
        let refusedBases: Set<String> = [
            "launchd",
            "sh", "bash", "zsh", "csh", "tcsh", "fish", "dash", "ksh",
            "terminal", "iterm", "iterm2", "alacritty", "kitty", "wezterm", "wezterm-gui",
            "tmux", "screen", "login"
        ]
        return refusedBases.contains(base)
    }

    /// Resolves the process anchor for a Git signing grant.
    /// If peer executable matches known signer helper (/usr/bin/ssh-keygen, resolved gpg.ssh.program)
    /// and parent executable matches a trusted git binary, anchors the grant on parent git (pid + start time).
    /// Never anchors on shell, terminal, or launchd.
    public static func grantAnchor(
        peerPid: pid_t,
        peerPath: String,
        processInfo: (pid_t) -> ProcessParentSnapshot? = { processParentSnapshot(pid: $0) },
        processPathLookup: (pid_t) -> String? = { getProcessPath(pid: $0) },
        resolvedGpgSSHProgram: () -> String? = { SSHAgentServer.gpgSSHProgramResolver() }
    ) -> GitApprovedProcess? {
        guard peerPid > 1 else { return nil }

        // Fast-path: if peer executable is trusted git (or test runner xctest in DEBUG), anchor on itself
        // without spawning `git config --get gpg.ssh.program`.
        if isTrustedGitExecutable(path: peerPath) {
            guard !isRefusedAnchor(pid: peerPid, path: peerPath) else { return nil }
            guard let peerSnap = processInfo(peerPid), peerSnap.startTime > 0 else { return nil }
            var topGitPid = peerPid
            var topGitSnap = peerSnap
            var topGitPath = peerPath
            var current = peerPid
            var seen = Set<pid_t>([current])
            for _ in 0..<64 {
                guard let currSnap = processInfo(current) else { break }
                let ppid = currSnap.parentPid
                guard ppid > 1, seen.insert(ppid).inserted else { break }
                guard let pSnap = processInfo(ppid), pSnap.startTime > 0 else { break }
                guard let pPath = processPathLookup(ppid) else { break }
                guard isTrustedGitExecutable(path: pPath), !isRefusedAnchor(pid: ppid, path: pPath) else { break }
                topGitPid = ppid
                topGitSnap = pSnap
                topGitPath = pPath
                current = ppid
            }
            return GitApprovedProcess(pid: topGitPid, startTime: topGitSnap.startTime, path: topGitPath)
        }

        // Otherwise, a peer can only anchor on its parent if that parent is a trusted git executable
        // AND the peer itself is a recognized signer helper. Verify the parent first (in-memory)
        // before potentially invoking `resolvedGpgSSHProgram()`.
        guard let peerSnap = processInfo(peerPid) else { return nil }
        let parentPid = peerSnap.parentPid
        guard parentPid > 1 else { return nil }
        guard let parentSnap = processInfo(parentPid), parentSnap.startTime > 0 else { return nil }
        guard let parentPath = processPathLookup(parentPid),
              isTrustedGitExecutable(path: parentPath),
              !isRefusedAnchor(pid: parentPid, path: parentPath) else {
            return nil
        }

        guard isSignerHelper(path: peerPath, resolvedGpgSSHProgram: resolvedGpgSSHProgram) else {
            return nil
        }

        // Walk up contiguous git ancestors to anchor on the root git process (e.g. git rebase)
        var topGitPid = parentPid
        var topGitSnap = parentSnap
        var topGitPath = parentPath
        var current = parentPid
        var seen = Set<pid_t>([peerPid, current])
        for _ in 0..<64 {
            guard let currSnap = processInfo(current) else { break }
            let ppid = currSnap.parentPid
            guard ppid > 1, seen.insert(ppid).inserted else { break }
            guard let pSnap = processInfo(ppid), pSnap.startTime > 0 else { break }
            guard let pPath = processPathLookup(ppid) else { break }
            guard isTrustedGitExecutable(path: pPath), !isRefusedAnchor(pid: ppid, path: pPath) else { break }
            topGitPid = ppid
            topGitSnap = pSnap
            topGitPath = pPath
            current = ppid
        }
        return GitApprovedProcess(pid: topGitPid, startTime: topGitSnap.startTime, path: topGitPath)
    }

    public static func grantAnchor(peerPid: pid_t, peerPath: String) -> GitApprovedProcess? {
        grantAnchor(
            peerPid: peerPid,
            peerPath: peerPath,
            processInfo: { processParentSnapshot(pid: $0) },
            processPathLookup: { getProcessPath(pid: $0) },
            resolvedGpgSSHProgram: { SSHAgentServer.gpgSSHProgramResolver() }
        )
    }

    /// `true` while `pid` is still the same process image that was attributed when the
    /// connection was accepted. A peer that `exec`s a different binary after connecting
    /// (keeping the inherited socket) or a recycled PID would otherwise keep the identity,
    /// and therefore the Git signing grant, of the executable seen at `accept()`.
    public static func peerProcessUnchanged(pid: pid_t, path: String, startTime: UInt64) -> Bool {
        guard let currentPath = getProcessPath(pid: pid),
              let currentStart = processStartTime(pid: pid) else {
            return false
        }
        return currentPath == path && currentStart == startTime
    }

    /// Groups recent Git signatures by executable, parent, and process group.
    /// When `ppid > 1` the string omits the signing process instance, so it must not
    /// authorize a grant: grants are bound to `GitApprovedProcess` and its descendants.
    public static func resolveClientIdentity(pid: pid_t, processPath: String) -> String {
        let stdPath = URL(fileURLWithPath: processPath).standardizedFileURL.path

        var procInfo = proc_bsdinfo()
        let ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard ret == MemoryLayout<proc_bsdinfo>.size else {
            return "\(stdPath):pid:\(pid)"
        }

        let ppid = pid_t(procInfo.pbi_ppid)
        let pgid = procInfo.pbi_pgid
        let startTime = procInfo.pbi_start_tvsec

        if ppid > 1, let parentPath = getProcessPath(pid: ppid) {
            var parentInfo = proc_bsdinfo()
            let pRet = proc_pidinfo(ppid, PROC_PIDTBSDINFO, 0, &parentInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
            if pRet == MemoryLayout<proc_bsdinfo>.size {
                let parentStart = parentInfo.pbi_start_tvsec
                let stdParentPath = URL(fileURLWithPath: parentPath).standardizedFileURL.path
                return "\(stdPath)|parent:\(stdParentPath):\(ppid):\(parentStart)|pgid:\(pgid)"
            }
            let stdParentPath = URL(fileURLWithPath: parentPath).standardizedFileURL.path
            return "\(stdPath)|parent:\(stdParentPath):\(ppid)|pgid:\(pgid)"
        }

        return "\(stdPath)|self:\(pid):\(startTime)|pgid:\(pgid)"
    }
}
