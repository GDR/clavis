import Foundation
import Darwin

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
        seedDataProvider: (() -> Data?)? = nil,
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
                return CLICommandResult(exitCode: 1, output: "", error: "Usage: clavis import <label> [--stdin]")
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            if args.count >= 4 && args[3] != "--stdin" && args[3] != "-" {
                ClavisLogger.log("SECURITY", "Rejected private seed passed via argv for key '\(label)'.")
                return CLICommandResult(
                    exitCode: 1,
                    output: "",
                    error: "Refusing private seed in command arguments. Use interactive input or --stdin."
                )
            }

            var seedData: Data?
            if let seedDataProvider {
                seedData = seedDataProvider()
            } else if isatty(STDIN_FILENO) != 0 && args.count == 3 {
                seedData = readSeedFromTerminal()
            } else {
                seedData = readSeedFromStandardInput()
            }

            guard var seedData else {
                return CLICommandResult(exitCode: 1, output: "", error: "No valid seed provided. Use stdin or the interactive prompt.")
            }
            defer {
                seedData.withUnsafeMutableBytes { raw in
                    if let base = raw.baseAddress {
                        SecureMemory.zero(base, byteCount: raw.count)
                    }
                }
                seedData.removeAll(keepingCapacity: false)
            }
            guard seedData.count == 32 else {
                return CLICommandResult(exitCode: 1, output: "", error: "Invalid hex seed string (must be 64 hex characters / 32 bytes).")
            }
            do {
                let info = try keyManager.importKey(label: label, consuming: &seedData)
                var out = "Successfully imported Ed25519 seed for '\(info.label)' into Keychain.\n"
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
              clavis import <label> [--stdin]    Import a 32-byte hex seed into Keychain
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

    private static func readSeedFromTerminal() -> Data? {
        var buffer = [CChar](repeating: 0, count: 128)
        defer {
            buffer.withUnsafeMutableBytes { raw in
                if let base = raw.baseAddress {
                    SecureMemory.zero(base, byteCount: raw.count)
                }
            }
        }
        guard readpassphrase("Enter 64-character hex seed: ", &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
            return nil
        }
        return buffer.withUnsafeBytes { decodeHexSeed($0) }
    }

    private static func readSeedFromStandardInput() -> Data? {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(65)
        defer {
            bytes.withUnsafeMutableBytes { raw in
                if let base = raw.baseAddress {
                    SecureMemory.zero(base, byteCount: raw.count)
                }
            }
            bytes.removeAll(keepingCapacity: false)
        }

        while bytes.count <= 128 {
            var byte: UInt8 = 0
            let result = Darwin.read(STDIN_FILENO, &byte, 1)
            if result < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if result == 0 || byte == 0x0A { break }
            bytes.append(byte)
        }
        guard bytes.count <= 128 else { return nil }
        return bytes.withUnsafeBytes { decodeHexSeed($0) }
    }

    private static func decodeHexSeed(_ raw: UnsafeRawBufferPointer) -> Data? {
        let bytes = raw.bindMemory(to: UInt8.self)
        var end = bytes.firstIndex(of: 0) ?? bytes.endIndex
        var start = bytes.startIndex
        while start < end, isASCIIWhitespace(bytes[start]) { start += 1 }
        while end > start, isASCIIWhitespace(bytes[end - 1]) { end -= 1 }
        guard end - start == 64 else { return nil }

        var decoded = Data(count: 32)
        var succeeded = false
        defer {
            if !succeeded {
                decoded.withUnsafeMutableBytes { output in
                    if let base = output.baseAddress {
                        SecureMemory.zero(base, byteCount: output.count)
                    }
                }
            }
        }

        let valid = decoded.withUnsafeMutableBytes { output -> Bool in
            guard let destination = output.bindMemory(to: UInt8.self).baseAddress else { return false }
            for index in 0..<32 {
                guard let high = hexNibble(bytes[start + index * 2]),
                      let low = hexNibble(bytes[start + index * 2 + 1]) else {
                    return false
                }
                destination[index] = (high << 4) | low
            }
            return true
        }
        guard valid else { return nil }
        succeeded = true
        return decoded
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48...57: return byte - 48
        case 65...70: return byte - 55
        case 97...102: return byte - 87
        default: return nil
        }
    }

    private static func isASCIIWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }
}
