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
    public static func handle(
        args: [String],
        inputReader: () -> String? = { readLine() },
        keyManager: KeychainManager = .shared
    ) -> CLICommandResult? {
        guard args.count > 1 else { return nil }

        let subcommand = args[1].lowercased()

        switch subcommand {
        case "generate":
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis generate <label>")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            do {
                let info = try keyManager.generateKey(label: label)
                var out = "Successfully generated Ed25519 key '\(info.label)' in Keychain.\n"
                out += "Fingerprint: \(info.fingerprint)\n"
                out += "Public Key:  \(info.publicKeyOpenSSH)"
                return CLICommandResult(exitCode: 0, output: out)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to generate key: \(error.localizedDescription)")
            }

        case "import":
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis import <label> [--stdin | <hex_seed>]")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            var hexSeed: String? = nil
            var warning: String? = nil

            if args.count >= 4 && args[3] != "--stdin" && args[3] != "-" {
                hexSeed = args[3].trimmingCharacters(in: .whitespaces)
                warning = "⚠️ [SECURITY WARNING] Passing private seed via CLI arguments exposes secrets in process list ('ps') and shell history. Use 'clavis import <label>' (interactive) or 'clavis import <label> --stdin' instead."
                ClavisLogger.log("SECURITY", "Seed passed via argv for key '\(label)'.")
            } else {
                if isatty(STDIN_FILENO) != 0 && (args.count == 3 || args[3] != "--stdin") {
                    var buffer = [CChar](repeating: 0, count: 256)
                    if let pass = readpassphrase("Enter 64-character hex seed: ", &buffer, buffer.count, RPP_REQUIRE_TTY) {
                        hexSeed = String(cString: pass).trimmingCharacters(in: .whitespacesAndNewlines)
                        buffer.withUnsafeMutableBytes { raw in
                            if let base = raw.baseAddress {
                                SecureMemory.zero(base, byteCount: raw.count)
                            }
                        }
                    }
                } else {
                    hexSeed = inputReader()?.trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }

            guard let rawHex = hexSeed, !rawHex.isEmpty else {
                return CLICommandResult(exitCode: 1, output: "", error: "No seed provided. Provide seed via stdin, interactive prompt, or argument.")
            }

            guard let seedData = Data(hexString: rawHex), seedData.count == 32 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Invalid hex seed string (must be 64 hex characters / 32 bytes).")
            }
            do {
                let info = try keyManager.importKey(label: label, seedData: seedData)
                var out = ""
                if let warn = warning {
                    out += "\(warn)\n\n"
                }
                out += "Successfully imported Ed25519 seed for '\(info.label)' into Keychain.\n"
                out += "Fingerprint: \(info.fingerprint)\n"
                out += "Public Key:  \(info.publicKeyOpenSSH)"
                return CLICommandResult(exitCode: 0, output: out)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to import key: \(error.localizedDescription)")
            }

        case "list":
            do {
                let keys = try keyManager.listKeys()
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
                try keyManager.deleteKey(label: label)
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
                let keys = try keyManager.listKeys()
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
