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

        guard let command = CLICommand.match(args[1]) else { return nil }

        switch command {
        case .generate:
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .generate))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            let isGitOnly = args.contains(CLIFlag.gitOnly.rawValue)
            let purpose: KeyPurpose = isGitOnly ? .gitSigningOnly : .general
            do {
                let info = try keyManager.generateKey(label: label, keyPurpose: purpose)
                return CLICommandResult(exitCode: 0, output: CLIMessages.successfullyGenerated(info: info))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToGenerate(error: error))
            }

        case .importCmd:
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .importCmd))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            let isGitOnly = args.contains(CLIFlag.gitOnly.rawValue)
            let purpose: KeyPurpose = isGitOnly ? .gitSigningOnly : .general
            let nonFlagArgs = args.filter { $0 != CLIFlag.gitOnly.rawValue }
            if nonFlagArgs.count >= 4 && nonFlagArgs[3] != CLIFlag.stdin.rawValue && nonFlagArgs[3] != CLIFlag.dash.rawValue {
                ClavisLogger.log("SECURITY", "Rejected private seed passed via argv for key '\(label)'.")
                return CLICommandResult(
                    exitCode: 1,
                    output: "",
                    error: CLIMessages.seedFromArgvRejected
                )
            }

            var seedData: Data?
            if let seedDataProvider {
                seedData = seedDataProvider()
            } else if isatty(STDIN_FILENO) != 0 && nonFlagArgs.count == 3 {
                seedData = readSeedFromTerminal()
            } else {
                seedData = readSeedFromStandardInput()
            }

            guard var seedData else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.noValidSeed)
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
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.invalidSeedLength)
            }
            do {
                let info = try keyManager.importKey(label: label, consuming: &seedData, keyPurpose: purpose)
                return CLICommandResult(exitCode: 0, output: CLIMessages.successfullyImported(info: info))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToImport(error: error))
            }

        case .list:
            do {
                let keys = try keyManager.listKeys()
                if keys.isEmpty {
                    return CLICommandResult(exitCode: 0, output: CLIMessages.noKeysFound())
                }
                var lines: [String] = [CLIMessages.foundKeysHeader(count: keys.count)]
                for key in keys {
                    let purposeTag = key.purpose == .gitSigningOnly ? " [Git Only]" : ""
                    lines.append(" - [\(key.label)]\(purposeTag)")
                    lines.append("   Fingerprint: \(key.fingerprint)")
                    lines.append("   Public Key:  \(key.publicKeyOpenSSH)")
                }
                return CLICommandResult(exitCode: 0, output: lines.joined(separator: "\n"))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToList(error: error))
            }

        case .lock:
            SessionCacheManager.shared.clearCache()
            GitSigningGraceManager.shared.invalidateAll()
            return CLICommandResult(exitCode: 0, output: CLIMessages.lockedAll)

        case .delete:
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .delete))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            do {
                try keyManager.deleteKey(label: label)
                return CLICommandResult(exitCode: 0, output: CLIMessages.successfullyDeleted(label: label))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToDelete(error: error))
            }

        case .exportPub:
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .exportPub))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            do {
                let keys = try keyManager.listKeys()
                guard let match = keys.first(where: { $0.label == label }) else {
                    return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.keyNotFound(label: label))
                }
                return CLICommandResult(exitCode: 0, output: match.publicKeyOpenSSH)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToExport(error: error))
            }

        case .logs:
            let logURL = ClavisLogger.logFileURL
            if let content = try? String(contentsOf: logURL, encoding: .utf8) {
                return CLICommandResult(exitCode: 0, output: content)
            } else {
                return CLICommandResult(exitCode: 0, output: CLIMessages.noLogFileFound(path: logURL.path))
            }

        case .dashDashHelp, .dashH, .help:
            return CLICommandResult(exitCode: 0, output: CLIMessages.help)
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
        guard readpassphrase(CLIMessages.promptSeedTerminal, &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
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
