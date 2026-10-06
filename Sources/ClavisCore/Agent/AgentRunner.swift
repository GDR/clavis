import Foundation
import Darwin

public struct AgentRunOptions: Equatable {
    public var keyLabel: String?
    public var leaseMinutes: Int?
    public var setSSHAuthSock = false
    public var keepGitSSHCommand = false
    public var command: [String]

    public init(
        keyLabel: String? = nil,
        leaseMinutes: Int? = nil,
        setSSHAuthSock: Bool = false,
        keepGitSSHCommand: Bool = false,
        command: [String] = []
    ) {
        self.keyLabel = keyLabel
        self.leaseMinutes = leaseMinutes
        self.setSSHAuthSock = setSSHAuthSock
        self.keepGitSSHCommand = keepGitSSHCommand
        self.command = command
    }
}

public enum AgentRunError: Error, Equatable, LocalizedError {
    case missingCommand
    case noAgentKey
    case ambiguousAgentKey([String])
    case unknownKey(String)
    case notAgentKey(String)
    case gitSSHCommandAlreadySet
    case agentNotRunning
    case registrationRefused

    public var errorDescription: String? {
        switch self {
        case .missingCommand:
            return "Missing command to run after '--'."
        case .noAgentKey:
            return "No agent key found. Generate one with: clavis generate <label> --agent"
        case .ambiguousAgentKey(let keys):
            return "Multiple agent keys found (\(keys.joined(separator: ", "))). Specify one with --key <label>."
        case .unknownKey(let label):
            return "Key '\(label)' not found."
        case .notAgentKey(let label):
            return "Key '\(label)' is not an agent key."
        case .gitSSHCommandAlreadySet:
            return "GIT_SSH_COMMAND is already set in environment. Use --keep-git-ssh-command to proceed anyway."
        case .agentNotRunning:
            return "Clavis agent daemon is not running. Start it with: clavis daemon"
        case .registrationRefused:
            return "Agent session registration was refused or cancelled."
        }
    }
}

public enum AgentRunner {
    public static func parse(_ args: [String]) throws -> AgentRunOptions {
        guard let dashDashIndex = args.firstIndex(of: "--") else {
            throw AgentRunError.missingCommand
        }
        let command = Array(args.suffix(from: dashDashIndex + 1))
        guard !command.isEmpty else {
            throw AgentRunError.missingCommand
        }

        var options = AgentRunOptions(command: command)
        let flagArgs = Array(args.prefix(upTo: dashDashIndex))
        var index = 0
        while index < flagArgs.count {
            let arg = flagArgs[index]
            if arg == "--key" {
                index += 1
                guard index < flagArgs.count else { throw AgentRunError.missingCommand }
                options.keyLabel = flagArgs[index]
            } else if arg.hasPrefix("--key=") {
                options.keyLabel = String(arg.dropFirst("--key=".count))
            } else if arg == "--lease" || arg == "--minutes" {
                index += 1
                guard index < flagArgs.count, let minutes = Int(flagArgs[index]) else { throw AgentRunError.missingCommand }
                options.leaseMinutes = minutes
            } else if arg.hasPrefix("--lease=") {
                guard let minutes = Int(arg.dropFirst("--lease=".count)) else { throw AgentRunError.missingCommand }
                options.leaseMinutes = minutes
            } else if arg.hasPrefix("--minutes=") {
                guard let minutes = Int(arg.dropFirst("--minutes=".count)) else { throw AgentRunError.missingCommand }
                options.leaseMinutes = minutes
            } else if arg == "--set-ssh-auth-sock" || arg == "--ssh-auth-sock" {
                options.setSSHAuthSock = true
            } else if arg == "--keep-git-ssh-command" {
                options.keepGitSSHCommand = true
            }
            index += 1
        }
        return options
    }

    public static func chooseKey(_ requested: String?, keys: [Ed25519KeyInfo]) throws -> Ed25519KeyInfo {
        if let requested = requested {
            guard let key = keys.first(where: { $0.label == requested }) else {
                throw AgentRunError.unknownKey(requested)
            }
            guard key.purpose == .agent else {
                throw AgentRunError.notAgentKey(requested)
            }
            return key
        } else {
            let agentKeys = keys.filter { $0.purpose == .agent }
            if agentKeys.isEmpty {
                throw AgentRunError.noAgentKey
            }
            if agentKeys.count > 1 {
                throw AgentRunError.ambiguousAgentKey(agentKeys.map { $0.label })
            }
            return agentKeys[0]
        }
    }

    public static func childEnvironment(
        base: [String: String],
        agentSocket: String,
        sessionID: String,
        options: AgentRunOptions
    ) throws -> [String: String] {
        var env = base
        env["CLAVIS_AGENT_SOCK"] = agentSocket
        env["CLAVIS_AGENT_SESSION"] = sessionID

        if options.setSSHAuthSock {
            env["SSH_AUTH_SOCK"] = agentSocket
        }

        let quotedSocket = "'" + agentSocket.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let gitSSHCommand = "ssh -o IdentityAgent=\(quotedSocket)"

        if let _ = base["GIT_SSH_COMMAND"] {
            if !options.keepGitSSHCommand {
                throw AgentRunError.gitSSHCommandAlreadySet
            }
        } else {
            env["GIT_SSH_COMMAND"] = gitSSHCommand
        }

        return env
    }

    public static func spawnAndWait(_ command: [String], environment: [String: String]) throws -> Int32 {
        guard let exe = command.first, !command.isEmpty else {
            throw AgentRunError.missingCommand
        }

        var cArgs = command.map { strdup($0) }
        cArgs.append(nil)
        defer {
            for ptr in cArgs where ptr != nil {
                free(ptr)
            }
        }

        var cEnv = environment.map { strdup("\($0.key)=\($0.value)") }
        cEnv.append(nil)
        defer {
            for ptr in cEnv where ptr != nil {
                free(ptr)
            }
        }

        var pid: pid_t = 0
        let spawnResult = cArgs.withUnsafeMutableBufferPointer { argv in
            cEnv.withUnsafeMutableBufferPointer { envp in
                posix_spawnp(&pid, exe, nil, nil, argv.baseAddress, envp.baseAddress)
            }
        }

        guard spawnResult == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(spawnResult))
        }

        let oldInt = signal(SIGINT, SIG_IGN)
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        termSource.setEventHandler { kill(pid, SIGTERM) }
        termSource.resume()

        let hupSource = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .global())
        hupSource.setEventHandler { kill(pid, SIGHUP) }
        hupSource.resume()

        defer {
            termSource.cancel()
            hupSource.cancel()
            signal(SIGINT, oldInt)
        }

        var status: Int32 = 0
        while true {
            let res = waitpid(pid, &status, 0)
            if res < 0 {
                if errno == EINTR { continue }
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            break
        }

        if (status & 0x7f) == 0 {
            return (status >> 8) & 0xff
        } else if (status & 0x7f) != 0 {
            return 128 + (status & 0x7f)
        }
        return status
    }
}
