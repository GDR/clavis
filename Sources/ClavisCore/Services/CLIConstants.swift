import Foundation

public enum CLICommand: String, CaseIterable {
    case generate
    case importCmd = "import"
    case list
    case delete
    case exportPub = "export-pub"
    case lock
    case logs
    case help
    case dashH = "-h"
    case dashDashHelp = "--help"

    public static func match(_ argument: String) -> CLICommand? {
        let lower = argument.lowercased()
        if lower == "-h" { return .dashH }
        if lower == "--help" { return .dashDashHelp }
        return CLICommand(rawValue: lower)
    }
}

public enum CLIFlag: String {
    case gitOnly = "--git-only"
    case stdin = "--stdin"
    case dash = "-"
    case daemon = "--daemon"
}

public enum CLIMessages {
    public static func usage(for command: CLICommand) -> String {
        switch command {
        case .generate:
            return "Usage: clavis generate <label>"
        case .importCmd:
            return "Usage: clavis import <label> [--stdin] [--git-only]"
        case .delete:
            return "Usage: clavis delete <label>"
        case .exportPub:
            return "Usage: clavis export-pub <label>"
        default:
            return help
        }
    }

    public static let help = """
    Clavis — Native macOS Ed25519 Keychain & SSH Agent Daemon

    USAGE:
      clavis generate <label> [--git-only]  Generate a new key pair in Keychain
      clavis import <label> [--stdin]       Import a 32-byte hex seed into Keychain
      clavis list                          List all stored keys and OpenSSH public keys
      clavis export-pub <label>            Print the OpenSSH public key for <label>
      clavis delete <label>                Delete key pair from Keychain
      clavis lock                          Lock all session caches and active Git sessions
      clavis logs                          Print live Touch ID and authentication logs
      clavis daemon / --daemon            Run SSH Agent socket daemon in background
      clavis                               Launch SwiftUI Key Manager GUI
    """

    public static let seedFromArgvRejected = "Refusing private seed in command arguments. Use interactive input or --stdin."
    public static let invalidSeedLength = "Invalid hex seed string (must be 64 hex characters / 32 bytes)."
    public static let noValidSeed = "No valid seed provided. Use stdin or the interactive prompt."
    public static let lockedAll = "🔒 All active sessions and caches locked."
    public static let promptSeedTerminal = "Enter 64-character hex seed: "

    public static func noKeysFound() -> String {
        "No Ed25519 keys found in Keychain."
    }

    public static func foundKeysHeader(count: Int) -> String {
        "Found \(count) key(s) in Keychain:"
    }

    public static func keyNotFound(label: String) -> String {
        "Key '\(label)' not found in Keychain."
    }

    public static func noLogFileFound(path: String) -> String {
        "No log file found at \(path)"
    }

    public static func successfullyGenerated(info: Ed25519KeyInfo) -> String {
        "Successfully generated Ed25519 key '\(info.label)' in Keychain.\n" + info.cliSummary
    }

    public static func successfullyImported(info: Ed25519KeyInfo) -> String {
        "Successfully imported Ed25519 seed for '\(info.label)' into Keychain.\n" + info.cliSummary
    }

    public static func successfullyDeleted(label: String) -> String {
        "Successfully deleted key '\(label)' from Keychain."
    }

    public static func failedToGenerate(error: Error) -> String {
        "Failed to generate key: \(error.localizedDescription)"
    }

    public static func failedToImport(error: Error) -> String {
        "Failed to import key: \(error.localizedDescription)"
    }

    public static func failedToList(error: Error) -> String {
        "Failed to list keys: \(error.localizedDescription)"
    }

    public static func failedToDelete(error: Error) -> String {
        "Failed to delete key: \(error.localizedDescription)"
    }

    public static func failedToExport(error: Error) -> String {
        "Failed to export public key: \(error.localizedDescription)"
    }

    public enum Agent {
        public static func active(socketPath: String, pid: pid_t?) -> String {
            let pidStr = pid.map { " (PID \($0))" } ?? ""
            return "🟢 Clavis SSH Agent is active at \(socketPath)\(pidStr)"
        }

        public static let notRunning = "🔴 Clavis SSH Agent is not running."
        public static let stopped = "🛑 Clavis SSH Agent stopped."
        public static let notRunningInfo = "ℹ️ Clavis SSH Agent was not running."

        public static func restarted(socketPath: String) -> String {
            "🔄 Clavis SSH Agent restarted at \(socketPath)"
        }

        public static func alreadyRunning(pid: pid_t) -> String {
            "Another clavis-agent instance is already running (PID: \(pid))."
        }

        public static func daemonStarted(socketPath: String, pid: pid_t) -> String {
            "🔑 Clavis SSH Agent socket daemon started at \(socketPath) (PID: \(pid))"
        }
    }
}
