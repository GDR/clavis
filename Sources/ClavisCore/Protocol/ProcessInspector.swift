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

/// Destination parsed from an interactive `ssh` command's argv.
public struct SSHCommandDestination: Equatable, Sendable {
    public let username: String?
    public let host: String

    public init(username: String?, host: String) {
        self.username = username
        self.host = host
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
    /// Falls back to `sysctl(KERN_PROC_PID)` when `proc_pidinfo` fails with `EPERM`
    /// on setuid-root ancestors (e.g. `/usr/bin/login` spawned by Ghostty/Terminal).
    public static func processParentSnapshot(pid: pid_t) -> ProcessParentSnapshot? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size {
            return ProcessParentSnapshot(
                startTime: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
                parentPid: pid_t(info.pbi_ppid)
            )
        }
        return sysctlParentSnapshot(pid: pid)
    }

    internal static func sysctlParentSnapshot(pid: pid_t) -> ProcessParentSnapshot? {
        guard pid > 0 else { return nil }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var kp = kinfo_proc()
        var len = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, UInt32(mib.count), &kp, &len, nil, 0) == 0,
              len == MemoryLayout<kinfo_proc>.size,
              kp.kp_proc.p_pid == pid else {
            return nil
        }
        let sec = kp.kp_proc.p_starttime.tv_sec
        let usec = kp.kp_proc.p_starttime.tv_usec
        guard sec >= 0, usec >= 0 else { return nil }
        return ProcessParentSnapshot(
            startTime: UInt64(sec) * 1_000_000 + UInt64(usec),
            parentPid: kp.kp_eproc.e_ppid
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
        let last = (path as NSString).lastPathComponent
        if last == "xctest" || last == "swiftpm-testing-helper" { return true }
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
        let last = (path as NSString).lastPathComponent
        if last == "xctest" || last == "swiftpm-testing-helper" { return true }
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

    public static func resolveGpgSSHProgram(
        gitExecutablePath: String? = nil,
        environment: [String: String]? = nil,
        timeout: TimeInterval = 2.0
    ) -> String? {
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
        var env = environment ?? TestContextScope.current?.environment ?? ProcessInfo.processInfo.environment
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

    public static func resolveGpgSSHProgram(
        forGitProcess gitExecutablePath: String? = nil,
        environment: [String: String]? = nil,
        timeout: TimeInterval = 2.0
    ) -> String? {
        resolveGpgSSHProgram(
            gitExecutablePath: gitExecutablePath,
            environment: environment,
            timeout: timeout
        )
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

    // MARK: - Process Arguments, Working Directory & Destination Helpers

    private static let maxProcArgsBytes = 1_048_576
    private static let maxProcArgCount: Int32 = 4096

    /// Reads `argv` for `pid` via `sysctl(KERN_PROCARGS2)`. Returns `nil` if unavailable or outside bounds.
    public static func processArguments(pid: pid_t) -> [String]? {
        guard pid > 0 else { return nil }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0,
              size >= MemoryLayout<Int32>.size,
              size <= maxProcArgsBytes else {
            return nil
        }

        var buffer = [UInt8](repeating: 0, count: size)
        var actualSize = size
        guard sysctl(&mib, UInt32(mib.count), &buffer, &actualSize, nil, 0) == 0,
              actualSize >= MemoryLayout<Int32>.size,
              actualSize <= buffer.count else {
            return nil
        }
        return parseProcArgs2Buffer(Array(buffer.prefix(actualSize)))
    }

    internal static func parseProcArgs2Buffer(_ buffer: [UInt8]) -> [String]? {
        guard buffer.count >= MemoryLayout<Int32>.size else { return nil }
        let argc = buffer.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc > 0, argc <= maxProcArgCount else { return nil }

        var offset = MemoryLayout<Int32>.size
        // Skip exec_path up to its terminating NUL.
        while offset < buffer.count && buffer[offset] != 0 {
            offset += 1
        }
        guard offset < buffer.count else { return nil }
        // Skip trailing NUL alignment padding between exec_path and argv[0].
        while offset < buffer.count && buffer[offset] == 0 {
            offset += 1
        }

        var args: [String] = []
        args.reserveCapacity(Int(argc))
        for _ in 0..<Int(argc) {
            guard offset < buffer.count else { return nil }
            let start = offset
            while offset < buffer.count && buffer[offset] != 0 {
                offset += 1
            }
            guard offset < buffer.count,
                  let arg = String(bytes: buffer[start..<offset], encoding: .utf8) else {
                return nil
            }
            args.append(arg)
            offset += 1
        }
        return args
    }

    /// Extracts `(username, host)` from an `ssh` command's `argv` without trusting non-`ssh` executables.
    public static func extractSSHDestination(fromArguments args: [String]) -> SSHCommandDestination? {
        guard let rawArgv0 = args.first, !rawArgv0.isEmpty else { return nil }
        var argv0Base = URL(fileURLWithPath: rawArgv0).lastPathComponent
        if argv0Base.hasPrefix("-") {
            argv0Base.removeFirst()
        }
        guard argv0Base == "ssh" else { return nil }

        let optionsTakingArg: Set<Character> = [
            "B", "b", "c", "D", "E", "e", "F", "I", "i", "J", "L", "l",
            "m", "O", "o", "P", "p", "Q", "R", "S", "W", "w"
        ]

        var explicitLoginUser: String?
        var explicitPort: String?
        var optionConfigUser: String?
        var destinationToken: String?

        func recordSSHOption(_ optionValue: String) {
            let trimmed = optionValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let lower = trimmed.lowercased()
            let rawValue: String
            if lower.hasPrefix("user=") {
                rawValue = String(trimmed.dropFirst(5))
            } else if lower.hasPrefix("user ") || lower.hasPrefix("user\t") {
                rawValue = String(trimmed.dropFirst(4))
            } else {
                return
            }
            var val = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if (val.hasPrefix("\"") && val.hasSuffix("\"")) || (val.hasPrefix("'") && val.hasSuffix("'")), val.count >= 2 {
                val = String(val.dropFirst().dropLast())
            }
            if !val.isEmpty && optionConfigUser == nil {
                optionConfigUser = val
            }
        }

        var index = 1
        while index < args.count {
            let arg = args[index]
            if arg == "--" {
                index += 1
                if index < args.count {
                    destinationToken = args[index]
                }
                break
            }
            if arg.hasPrefix("-") && arg.count > 1 {
                var charIdx = arg.index(after: arg.startIndex)
                while charIdx < arg.endIndex {
                    let flag = arg[charIdx]
                    let nextIdx = arg.index(after: charIdx)
                    if optionsTakingArg.contains(flag) {
                        let optionValue: String
                        if nextIdx < arg.endIndex {
                            optionValue = String(arg[nextIdx...])
                        } else if index + 1 < args.count {
                            index += 1
                            optionValue = args[index]
                        } else {
                            return nil
                        }
                        switch flag {
                        case "l":
                            if !optionValue.isEmpty {
                                explicitLoginUser = optionValue
                            }
                        case "p":
                            if !optionValue.isEmpty {
                                explicitPort = optionValue
                            }
                        case "o":
                            recordSSHOption(optionValue)
                        default:
                            break
                        }
                        break
                    }
                    charIdx = nextIdx
                }
                index += 1
                continue
            }

            destinationToken = arg
            break
        }

        guard let token = destinationToken?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty else {
            return nil
        }

        let argUser: String?
        let rawHost: String
        let uriPort: String?

        if token.lowercased().hasPrefix("ssh://") {
            guard let url = URL(string: token),
                  let host = url.host,
                  !host.isEmpty else {
                return nil
            }
            let path = url.path
            guard path.isEmpty || path == "/" else { return nil }
            argUser = (url.user?.isEmpty == false) ? url.user : nil
            rawHost = host
            uriPort = url.port.map(String.init)
        } else {
            uriPort = nil
            if let atIndex = token.lastIndex(of: "@") {
                let userPart = String(token[..<atIndex])
                let hostPart = String(token[token.index(after: atIndex)...])
                guard !userPart.isEmpty, !hostPart.isEmpty else { return nil }
                argUser = userPart
                rawHost = hostPart
            } else {
                argUser = nil
                rawHost = token
            }
        }

        var bareHost = rawHost
        if bareHost.hasPrefix("[") && bareHost.hasSuffix("]") {
            bareHost = String(bareHost.dropFirst().dropLast())
        }
        guard isValidDestinationHost(bareHost) else { return nil }

        let resolvedUser = argUser ?? explicitLoginUser ?? optionConfigUser
        if let resolvedUser, containsUnsafeControlOrWhitespace(resolvedUser) {
            return nil
        }

        let effectivePort = uriPort ?? explicitPort
        let formattedHost: String
        if let port = effectivePort,
           let portNumber = UInt16(port),
           portNumber > 0,
           portNumber != 22 {
            formattedHost = bareHost.contains(":") ? "[\(bareHost)]:\(portNumber)" : "\(bareHost):\(portNumber)"
        } else {
            formattedHost = bareHost
        }

        return SSHCommandDestination(username: resolvedUser, host: formattedHost)
    }

    private static func isValidDestinationHost(_ host: String) -> Bool {
        guard !host.isEmpty,
              !host.hasPrefix("-"),
              !host.hasPrefix("/"),
              !host.hasPrefix("."),
              !host.contains("/"),
              !containsUnsafeControlOrWhitespace(host) else {
            return false
        }
        return true
    }

    private static func containsUnsafeControlOrWhitespace(_ value: String) -> Bool {
        value.unicodeScalars.contains {
            CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0)
        }
    }

    /// Reads the current working directory of `pid` via `proc_pidinfo(PROC_PIDVNODEPATHINFO)`.
    public static func processWorkingDirectory(pid: pid_t) -> String? {
        guard pid > 0 else { return nil }
        var vpi = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, size) == size else {
            return nil
        }
        return withUnsafeBytes(of: vpi.pvi_cdir.vip_path) { raw -> String? in
            let limit = min(raw.count, Int(MAXPATHLEN))
            let slice = raw.prefix(limit)
            let endIndex = slice.firstIndex(of: 0) ?? limit
            guard let path = String(bytes: slice.prefix(endIndex), encoding: .utf8),
                  !path.isEmpty else {
                return nil
            }
            return path
        }
    }

    /// Walks up at most 16 directories from `cwd` to locate a Git repository and return its directory name.
    public static func gitRepositoryName(forWorkingDirectory cwd: String) -> String? {
        guard cwd.hasPrefix("/") else { return nil }
        let fm = FileManager.default
        var dirURL = URL(fileURLWithPath: cwd).standardizedFileURL

        for _ in 0..<16 {
            let dotGitPath = dirURL.appendingPathComponent(".git").path
            if fm.fileExists(atPath: dotGitPath) {
                let name = dirURL.lastPathComponent
                return (name.isEmpty || name == "/") ? nil : name
            }

            let headPath = dirURL.appendingPathComponent("HEAD").path
            let objectsPath = dirURL.appendingPathComponent("objects").path
            var headIsDir: ObjCBool = false
            var objectsIsDir: ObjCBool = false
            if fm.fileExists(atPath: headPath, isDirectory: &headIsDir),
               !headIsDir.boolValue,
               fm.fileExists(atPath: objectsPath, isDirectory: &objectsIsDir),
               objectsIsDir.boolValue {
                if dirURL.lastPathComponent == ".git" {
                    let parentName = dirURL.deletingLastPathComponent().lastPathComponent
                    return (parentName.isEmpty || parentName == "/") ? nil : parentName
                }
                var name = dirURL.lastPathComponent
                if name.hasSuffix(".git") && name.count > 4 {
                    name = String(name.dropLast(4))
                }
                return (name.isEmpty || name == "/") ? nil : name
            }

            let parent = dirURL.deletingLastPathComponent()
            if parent.path == dirURL.path || dirURL.path == "/" {
                break
            }
            dirURL = parent
        }
        return nil
    }
}
