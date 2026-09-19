import Foundation

public struct CLICommandResult: Equatable {
    public let exitCode: Int32
    public let output: String
    public let error: String?

    public init(exitCode: Int32, output: String, error: String? = nil) {
        self.exitCode = exitCode
        self.output = output
        self.error = error
    }
}

public struct CLIService {
    public static func handle(args: [String]) -> CLICommandResult? {
        guard args.count > 1 else { return nil }

        let subcommand = args[1].lowercased()

        switch subcommand {
        case "generate":
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis generate <label>")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            do {
                let info = try KeychainManager.shared.generateKey(label: label)
                var out = "Successfully generated Ed25519 key '\(info.label)' in Keychain.\n"
                out += "Fingerprint: \(info.fingerprint)\n"
                out += "Public Key:  \(info.publicKeyOpenSSH)"
                return CLICommandResult(exitCode: 0, output: out)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to generate key: \(error.localizedDescription)")
            }

        case "import":
            guard args.count >= 4 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis import <label> <hex_seed>")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            let hexSeed = args[3].trimmingCharacters(in: .whitespaces)
            guard let seedData = Data(hexString: hexSeed), seedData.count == 32 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Invalid hex seed string (must be 64 hex characters / 32 bytes).")
            }
            do {
                let info = try KeychainManager.shared.importKey(label: label, seedData: seedData)
                var out = "Successfully imported Ed25519 seed for '\(info.label)' into Keychain.\n"
                out += "Fingerprint: \(info.fingerprint)\n"
                out += "Public Key:  \(info.publicKeyOpenSSH)"
                return CLICommandResult(exitCode: 0, output: out)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to import key: \(error.localizedDescription)")
            }

        case "list":
            do {
                let keys = try KeychainManager.shared.listKeys()
                if keys.isEmpty {
                    return CLICommandResult(exitCode: 0, output: "No Ed25519 keys found in Keychain.")
                }
                var lines: [String] = ["Found \(keys.count) key(s) in Keychain:"]
                for key in keys {
                    lines.append(" - [\(key.label)]")
                    lines.append("   Fingerprint: \(key.fingerprint)")
                    lines.append("   Public Key:  \(key.publicKeyOpenSSH)")
                }
                return CLICommandResult(exitCode: 0, output: lines.joined(separator: "\n"))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to list keys: \(error.localizedDescription)")
            }

        case "delete":
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis delete <label>")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            do {
                try KeychainManager.shared.deleteKey(label: label)
                return CLICommandResult(exitCode: 0, output: "Successfully deleted key '\(label)' from Keychain.")
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to delete key: \(error.localizedDescription)")
            }

        case "export-pub":
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis export-pub <label>")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            do {
                let keys = try KeychainManager.shared.listKeys()
                guard let match = keys.first(where: { $0.label == label }) else {
                    return CLICommandResult(exitCode: 1, output: "", error: "Key '\(label)' not found in Keychain.")
                }
                return CLICommandResult(exitCode: 0, output: match.publicKeyOpenSSH)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to export public key: \(error.localizedDescription)")
            }

        case "logs":
            let logURL = ClavisLogger.logFileURL
            if let content = try? String(contentsOf: logURL, encoding: .utf8) {
                return CLICommandResult(exitCode: 0, output: content)
            } else {
                return CLICommandResult(exitCode: 0, output: "No log file found at \(logURL.path)")
            }

        case "--help", "-h", "help":
            let helpMsg = """
            Clavis — Native macOS Ed25519 Keychain & SSH Agent Daemon

            USAGE:
              clavis generate <label>         Generate a new Ed25519 key pair in Keychain
              clavis import <label> <hex_seed> Import a 32-byte hex seed into Keychain
              clavis list                     List all stored keys and OpenSSH public keys
              clavis export-pub <label>       Print the OpenSSH public key for <label>
              clavis delete <label>           Delete key pair from Keychain
              clavis logs                     Print live Touch ID and authentication logs
              clavis daemon / --daemon       Run SSH Agent socket daemon in background
              clavis                          Launch SwiftUI Key Manager GUI
            """
            return CLICommandResult(exitCode: 0, output: helpMsg)

        default:
            return nil
        }
    }
}
