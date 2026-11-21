import Foundation
import Testing
@testable import ClavisCore

@Suite struct ApplicationCallerResolverTests {
    typealias Process = ApplicationCallerResolver.Process
    private func app(_ classification: ApplicationClassification, path: String) throws -> RegisteredApplication {
        RegisteredApplication(
            identity: try ApplicationIdentity(kind: .designatedRequirement, value: path),
            name: path, path: path, classification: classification
        )
    }
    private func resolver(_ chain: [Process], changed: Bool = false) -> ApplicationCallerResolver {
        ApplicationCallerResolver(
            inspect: { pid in
                guard let process = chain.first(where: { $0.pid == pid }) else { return nil }
                return changed ? Process(pid: pid, parent: process.parent, start: process.start + 1, path: process.path) : process
            },
            verify: { identity, process in identity.value == process.path },
            transparentHelper: { ["/ssh", "/git", "/ssh-keygen"].contains($0.path) }
        )
    }
    private func resolve(_ chain: [Process], apps: [RegisteredApplication]) -> VerifiedApplicationCaller? {
        resolver(chain).resolve(peerPID: 100, peerPath: chain[0].path, peerStart: 7, registry: .init(applications: apps))
    }

    @Test func knownDirectClientResolvesAndRevalidates() throws {
        let client = try app(.personal, path: "/Editor")
        let chain = [Process(pid: 100, parent: 1, start: 7, path: "/Editor")]
        let result = resolve(chain, apps: [client])
        #expect(result?.application == client)
        #expect(result?.pid == 100)
        #expect(result?.startTime == 7)
    }

    @Test func botInPersonalTerminalCannotInheritPersonalAuthority() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh"),
            Process(pid: 101, parent: 102, start: 8, path: "/bot"),
            Process(pid: 102, parent: 103, start: 9, path: "/shell"),
            Process(pid: 103, parent: 1, start: 10, path: "/Terminal")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Terminal")]) == nil)
        #expect(resolve(chain, apps: [try app(.bot, path: "/bot"), try app(.personal, path: "/Terminal")])?.application.classification == .bot)
    }

    @Test func interactiveShellIsAlsoUncertainRatherThanAssumedPersonal() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh"),
            Process(pid: 101, parent: 102, start: 8, path: "/shell"),
            Process(pid: 102, parent: 1, start: 9, path: "/Terminal")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Terminal")]) == nil)
    }

    @Test func verifiedTransportChainCanAttributeGUIClient() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh-keygen"),
            Process(pid: 101, parent: 102, start: 8, path: "/git"),
            Process(pid: 102, parent: 1, start: 9, path: "/Editor")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Editor")])?.application.classification == .personal)
    }

    @Test func transportClassificationCannotReplaceActualCaller() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/ssh"),
            Process(pid: 101, parent: 1, start: 8, path: "/bot")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/ssh")]) == nil)
        #expect(resolve(chain, apps: [try app(.personal, path: "/ssh"), try app(.bot, path: "/bot")])?.application.classification == .bot)
    }

    @Test func blockedAncestorOverridesPersonalOrBotDescendant() throws {
        let chain = [
            Process(pid: 100, parent: 101, start: 7, path: "/Editor"),
            Process(pid: 101, parent: 1, start: 8, path: "/blocked")
        ]
        #expect(resolve(chain, apps: [try app(.personal, path: "/Editor"), try app(.block, path: "/blocked")])?.application.classification == .block)
    }

    @Test func cyclesMissingAncestorsAndPIDReuseReturnUncertainty() throws {
        let app = try app(.personal, path: "/Editor")
        let cycle = [Process(pid: 100, parent: 100, start: 7, path: "/Editor")]
        #expect(resolve(cycle, apps: [app]) == nil)
        let missing = [Process(pid: 100, parent: 101, start: 7, path: "/Editor")]
        #expect(resolve(missing, apps: [app]) == nil)
        #expect(resolver(missing, changed: true).resolve(peerPID: 100, peerPath: "/Editor", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func replacedAncestorDuringResolutionInvalidatesCandidate() throws {
        let app = try app(.personal, path: "/Editor")
        var calls = 0
        let resolver = ApplicationCallerResolver(inspect: { pid in
            calls += 1
            return Process(pid: pid, parent: 1, start: calls == 1 ? 7 : 8, path: "/Editor")
        }, verify: { _, _ in true }, transparentHelper: { _ in false })
        #expect(resolver.resolve(peerPID: 100, peerPath: "/Editor", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func boundedTraversalAndWrongPeerPathFailClosed() throws {
        let app = try app(.personal, path: "/Editor")
        var chain: [Process] = []
        for pid in 100...140 {
            let path = pid == 140 ? "/Editor" : "/ssh"
            let start: UInt64 = pid == 100 ? 7 : 8
            chain.append(Process(pid: Int32(pid), parent: Int32(pid + 1), start: start, path: path))
        }
        #expect(resolve(chain, apps: [app]) == nil)
        let direct = [Process(pid: 100, parent: 1, start: 7, path: "/Editor")]
        #expect(resolver(direct).resolve(peerPID: 100, peerPath: "/imposter", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func failedIdentityVerificationCannotUseRegisteredNameOrPath() throws {
        let app = try app(.personal, path: "/Editor")
        let resolver = ApplicationCallerResolver(inspect: { pid in
            Process(pid: pid, parent: 1, start: 7, path: "/Editor")
        }, verify: { _, _ in false }, transparentHelper: { _ in false })
        #expect(resolver.resolve(peerPID: 100, peerPath: "/Editor", peerStart: 7, registry: .init(applications: [app])) == nil)
    }

    @Test func appleBinaryRegistrationDoesNotMatchUnrelatedRunningProcess() throws {
        let identity = try ApplicationIdentityVerifier.identity(forExecutable: URL(fileURLWithPath: "/usr/bin/ssh"))
        #expect(identity.kind == .designatedRequirement)
        let current = try #require(ApplicationCallerResolver.inspectProcess(getpid()))
        #expect(!ApplicationIdentityVerifier.matches(identity, current))
        let forged = Process(pid: current.pid, parent: current.parent, start: current.start + 1, path: current.path)
        #expect(!ApplicationIdentityVerifier.matches(identity, forged))
    }

    @Test func executableIdentityRequiresRealFileAndRoundTrips() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: (any Error).self) { try ApplicationIdentityVerifier.identity(forExecutable: directory) }
        let file = directory.appendingPathComponent("unsigned")
        try Data("not executable code".utf8).write(to: file)
        let identity = try ApplicationIdentityVerifier.identity(forExecutable: file)
        #expect(identity.kind == .executableSHA256)
        #expect(identity.value.count == 64)
        #expect(try ApplicationIdentityVerifier.identity(forExecutable: file) == identity)
        try Data("changed".utf8).write(to: file)
        #expect(try ApplicationIdentityVerifier.identity(forExecutable: file) != identity)
    }

    @Test func sysctlParentSnapshotMatchesProcPidInfoAndRejectsInvalidPID() throws {
        let pid = getpid()
        let direct = try #require(ProcessInspector.processParentSnapshot(pid: pid))
        let viaSysctl = try #require(ProcessInspector.sysctlParentSnapshot(pid: pid))
        #expect(viaSysctl == direct)
        #expect(ProcessInspector.sysctlParentSnapshot(pid: -1) == nil)
        #expect(ProcessInspector.sysctlParentSnapshot(pid: 0) == nil)
    }

    @Test func parseProcArgs2BufferAndLiveProcessInspectionWork() throws {
        // Construct KERN_PROCARGS2 buffer: Int32 argc, exec_path\0, NUL padding, argv[0]\0, argv[1]\0...
        func makeProcArgs2(argc: Int32, execPath: String, padNuls: Int, args: [String], truncateLastNul: Bool = false) -> [UInt8] {
            var bytes = [UInt8]()
            withUnsafeBytes(of: argc) { bytes.append(contentsOf: $0) }
            bytes.append(contentsOf: execPath.utf8)
            bytes.append(0)
            bytes.append(contentsOf: [UInt8](repeating: 0, count: padNuls))
            for arg in args {
                bytes.append(contentsOf: arg.utf8)
                bytes.append(0)
            }
            if truncateLastNul && !bytes.isEmpty {
                bytes.removeLast()
            }
            return bytes
        }

        let buf = makeProcArgs2(argc: 4, execPath: "/usr/bin/ssh", padNuls: 5, args: ["ssh", "", "-p2222", "git@github.com"])
        #expect(ProcessInspector.parseProcArgs2Buffer(buf) == ["ssh", "", "-p2222", "git@github.com"])

        // Reject invalid argc / truncated buffer
        #expect(ProcessInspector.parseProcArgs2Buffer([0, 0]) == nil)
        #expect(ProcessInspector.parseProcArgs2Buffer(makeProcArgs2(argc: 0, execPath: "/usr/bin/ssh", padNuls: 1, args: [])) == nil)
        #expect(ProcessInspector.parseProcArgs2Buffer(makeProcArgs2(argc: -1, execPath: "/usr/bin/ssh", padNuls: 1, args: [])) == nil)
        #expect(ProcessInspector.parseProcArgs2Buffer(makeProcArgs2(argc: 4097, execPath: "/usr/bin/ssh", padNuls: 1, args: [])) == nil)
        #expect(ProcessInspector.parseProcArgs2Buffer(makeProcArgs2(argc: 2, execPath: "/usr/bin/ssh", padNuls: 1, args: ["ssh", "host"], truncateLastNul: true)) == nil)

        // Live process inspection on current process
        let pid = getpid()
        let liveArgs = try #require(ProcessInspector.processArguments(pid: pid))
        #expect(!liveArgs.isEmpty)
        let liveCwd = try #require(ProcessInspector.processWorkingDirectory(pid: pid))
        #expect(liveCwd.hasPrefix("/"))
        #expect(ProcessInspector.processArguments(pid: -1) == nil)
        #expect(ProcessInspector.processWorkingDirectory(pid: -1) == nil)
    }

    @Test func extractSSHDestinationHandlesFlagsURIsAndRejectsUnsafeInputs() {
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: ["/usr/bin/ssh", "git@github.com"])
                == SSHCommandDestination(username: "git", host: "github.com")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "ssh", "-o", "SendEnv=GIT_PROTOCOL", "--", "git@github.com", "git-receive-pack 'GDR/clavis.git'"
            ]) == SSHCommandDestination(username: "git", host: "github.com")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "/opt/homebrew/bin/ssh", "-vT", "-p", "2222", "-l", "deploy", "prod.internal"
            ]) == SSHCommandDestination(username: "deploy", host: "prod.internal:2222")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "-ssh", "-p22", "-ladmin", "-oUser=ignored", "box.local"
            ]) == SSHCommandDestination(username: "admin", host: "box.local")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "ssh", "-oUser=ops", "box.local"
            ]) == SSHCommandDestination(username: "ops", host: "box.local")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "ssh", "ssh://alice@example.com:2222"
            ]) == SSHCommandDestination(username: "alice", host: "example.com:2222")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "ssh", "ssh://bob@example.com:22"
            ]) == SSHCommandDestination(username: "bob", host: "example.com")
        )
        #expect(
            ProcessInspector.extractSSHDestination(fromArguments: [
                "ssh", "-p", "2222", "[::1]"
            ]) == SSHCommandDestination(username: nil, host: "[::1]:2222")
        )

        // Reject non-ssh argv0, file paths, and option-like hosts
        #expect(ProcessInspector.extractSSHDestination(fromArguments: ["swiftpm-testing-helper", "github.com"]) == nil)
        #expect(ProcessInspector.extractSSHDestination(fromArguments: ["/usr/bin/git", "github.com"]) == nil)
        #expect(ProcessInspector.extractSSHDestination(fromArguments: ["ssh", "/tmp/socket"]) == nil)
        #expect(ProcessInspector.extractSSHDestination(fromArguments: ["ssh", "./localfile"]) == nil)
        #expect(ProcessInspector.extractSSHDestination(fromArguments: ["ssh", "--", "-evil"]) == nil)
        #expect(ProcessInspector.extractSSHDestination(fromArguments: ["ssh", "-l"]) == nil)
    }

    @Test func gitRepositoryNameResolvesStandardWorktreeBareAndDotGitDirs() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }

        // 1. Standard repo + nested subdir + inside .git/
        let repo = root.appendingPathComponent("clavis")
        let sub = repo.appendingPathComponent("Sources/ClavisCore")
        let dotGit = repo.appendingPathComponent(".git")
        let dotGitObjects = dotGit.appendingPathComponent("objects")
        let dotGitRefs = dotGit.appendingPathComponent("refs")
        try fm.createDirectory(at: sub, withIntermediateDirectories: true)
        try fm.createDirectory(at: dotGitObjects, withIntermediateDirectories: true)
        try fm.createDirectory(at: dotGitRefs, withIntermediateDirectories: true)
        try Data("ref: refs/heads/main\n".utf8).write(to: dotGit.appendingPathComponent("HEAD"))

        #expect(ProcessInspector.gitRepositoryName(forWorkingDirectory: repo.path) == "clavis")
        #expect(ProcessInspector.gitRepositoryName(forWorkingDirectory: sub.path) == "clavis")
        #expect(ProcessInspector.gitRepositoryName(forWorkingDirectory: dotGitRefs.path) == "clavis")

        // 2. Worktree (.git file)
        let worktree = root.appendingPathComponent("clavis-wt")
        try fm.createDirectory(at: worktree, withIntermediateDirectories: true)
        try Data("gitdir: ../clavis/.git/worktrees/wt\n".utf8).write(to: worktree.appendingPathComponent(".git"))
        #expect(ProcessInspector.gitRepositoryName(forWorkingDirectory: worktree.path) == "clavis-wt")

        // 3. Bare repo with .git suffix
        let bare = root.appendingPathComponent("upstream.git")
        try fm.createDirectory(at: bare.appendingPathComponent("objects"), withIntermediateDirectories: true)
        try Data("ref: refs/heads/main\n".utf8).write(to: bare.appendingPathComponent("HEAD"))
        #expect(ProcessInspector.gitRepositoryName(forWorkingDirectory: bare.path) == "upstream")

        // 4. Non-repo directory
        let plain = root.appendingPathComponent("plain")
        try fm.createDirectory(at: plain, withIntermediateDirectories: true)
        #expect(ProcessInspector.gitRepositoryName(forWorkingDirectory: plain.path) == nil)
    }
}
