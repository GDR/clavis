import Foundation
import Darwin
import CryptoKit

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

public struct HistoryCheckArgs: Equatable {
    public let days: Int
    public let dbPath: String?

    public init(days: Int = 7, dbPath: String? = nil) {
        self.days = days
        self.dbPath = dbPath
    }
}

public enum HistoryCheckArgError: Error, Equatable, LocalizedError {
    case invalidDays(String)
    case missingArgument(String)
    case unknownArgument(String)

    public var errorDescription: String? {
        switch self {
        case .invalidDays(let val):
            return "Invalid value for --days: '\(val)' (must be an integer between 1 and 30)"
        case .missingArgument(let flag):
            return "Missing value for \(flag)"
        case .unknownArgument(let arg):
            return "Unknown argument: \(arg)"
        }
    }
}

public struct CLIService {
    public static func handle(
        args: [String],
        seedDataProvider: (() -> Data?)? = nil,
        keyManager: KeychainManager = .shared,
        agentLifecycle: AgentLifecycleManager = .shared,
        vaultStore: EncryptedVaultStore = .shared,
        isTTY: Bool = (isatty(STDIN_FILENO) != 0),
        confirmationPrompt: (() -> String?)? = nil
    ) -> CLICommandResult? {
        guard args.count > 1 else { return nil }

        guard let command = CLICommand.match(args[1]) else { return nil }

        switch command {
        case .generate:
            guard args.count >= 3 else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .generate))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            let purpose: KeyPurpose
            do {
                purpose = try parseGeneratePurpose(args: args)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: error.localizedDescription)
            }
            let isEnclave = args.contains("--enclave") || args.contains("--secure-enclave")
            let storage: KeyStorageType = isEnclave ? .secureEnclave : .keychain
            let algorithm = isEnclave ? "ECDSA P-256" : "Ed25519"
            let policy: BiometricPolicy? = isEnclave ? .biometryCurrentSet : nil
            do {
                let info = try keyManager.generateKey(
                    label: label,
                    algorithm: algorithm,
                    storageType: storage,
                    biometricPolicy: policy,
                    keyPurpose: purpose
                )
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
                let lines = formatKeyListEntries(keys: keys)
                return CLICommandResult(exitCode: 0, output: lines.joined(separator: "\n"))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToList(error: error))
            }

        case .kind:
            guard args.count >= 4 else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .kind))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            guard let newPurpose = parseKindTarget(argument: args[3]) else {
                return CLICommandResult(exitCode: 1, output: "", error: "Invalid target kind '\(args[3])'. Must be 'agent' or 'personal'.")
            }

            do {
                try keyManager.changeKind(label: label, to: newPurpose)
                return CLICommandResult(exitCode: 0, output: CLIMessages.successfullyChangedKind(label: label, newPurpose: newPurpose))
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.failedToChangeKind(error: error))
            }

        case .lock:
            SessionCacheManager.shared.clearCache()
            GitSigningGraceManager.shared.invalidateAll()
            do {
                try agentLifecycle.sendLockAllToAgent()
                return CLICommandResult(exitCode: 0, output: CLIMessages.lockedAll)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Lock failed: \(error.localizedDescription)")
            }

        case .delete:
            guard args.count >= 3, args.contains(CLIFlag.yes.rawValue) else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .delete))
            }
            let label = args[2].trimmingCharacters(in: .whitespaces)
            ClavisLogger.promptDebug("clavis-cli", "CLIService: delete key '\(label)' requested")
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
                return CLICommandResult(exitCode: 0, output: ClavisLogger.sanitizeLogContent(content))
            } else {
                return CLICommandResult(exitCode: 0, output: CLIMessages.noLogFileFound(path: logURL.path))
            }

        case .vault:
            guard args.count >= 3, args[2] == "repair" else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .vault))
            }
            let replacePin = args.contains(CLIFlag.replacePin.rawValue)
            ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt initiated (replacePin: \(replacePin)).")

            // Refuse before verifyMasterKey(): it triggers a Touch ID prompt, which a script without a
            // terminal must not be able to cause.
            guard isTTY else {
                ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed: non-TTY stdin refuses repair confirmation.")
                return CLICommandResult(
                    exitCode: 1,
                    output: "",
                    error: "Vault repair requires an interactive terminal (TTY) for confirmation."
                )
            }

            let pubKey: P256.KeyAgreement.PublicKey
            let fingerprint: String
            do {
                (pubKey, fingerprint) = try vaultStore.verifyMasterKey()
            } catch {
                ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed during verification: \(error.localizedDescription)")
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to verify vault master key: \(error.localizedDescription)")
            }

            var outputLines: [String] = []
            outputLines.append("Master key fingerprint: \(fingerprint)")
            // The Secure Enclave check in verifyMasterKey proves the key is usable, not that it is the
            // original one. The creation date is a second signal the owner can compare with memory.
            let masterKeyURL = vaultStore.vaultDirectoryURL.appendingPathComponent("master.key")
            if let created = (try? FileManager.default.attributesOfItem(atPath: masterKeyURL.path))?[.creationDate] as? Date {
                outputLines.append("master.key created: \(ISO8601DateFormatter().string(from: created))")
            }

            let expectedPin = Data(SHA256.hash(data: pubKey.rawRepresentation))
            let existingPin: Data?
            do {
                existingPin = try vaultStore.activePinStore.loadPin()
            } catch {
                ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed reading Keychain pin: \(error.localizedDescription)")
                return CLICommandResult(exitCode: 1, output: outputLines.joined(separator: "\n"), error: "Failed to read Keychain pin: \(error.localizedDescription)")
            }

            if let existingPin, existingPin != expectedPin {
                // The pin is SHA-256(master.pub), so it renders in the same format as `fingerprint`
                // and can be compared with it directly.
                let pinnedFingerprint = EncryptedVaultStore.fingerprint(forPin: existingPin)
                outputLines.append("Keychain pinned fingerprint: \(pinnedFingerprint)")
                if !replacePin {
                    ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed: existing pin mismatch requires --replace-pin flag.")
                    return CLICommandResult(
                        exitCode: 1,
                        output: outputLines.joined(separator: "\n"),
                        error: "WARNING: Vault master key pin mismatch detected! Existing Keychain pin does not match vault master key. Use --replace-pin to overwrite."
                    )
                }
                outputLines.append("WARNING: Replacing existing mismatched vault master key pin in Keychain!")
                outputLines.append("If you do not recognize the master key fingerprint above, do not confirm: master.key may have been replaced.")
                ClavisLogger.log("SECURITY_ALERT", "Vault repair replacing pin \(pinnedFingerprint) with \(fingerprint).")
            }

            let confirmed: Bool
            ClavisLogger.promptDebug("clavis-cli", "CLIService: displaying vault repair confirmation prompt (fingerprint: \(fingerprint))")
            if let confirmationPrompt {
                confirmed = confirmationPrompt()?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "yes"
            } else {
                print("Repair vault master key pin for fingerprint \(fingerprint)? Type 'yes' to confirm: ", terminator: "")
                fflush(stdout)
                let input = readLine(strippingNewline: true)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                confirmed = (input == "yes")
            }
            ClavisLogger.promptDebug("clavis-cli", "CLIService: vault repair confirmation result: \(confirmed ? "confirmed" : "cancelled")")

            guard confirmed else {
                ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed: cancelled by user.")
                return CLICommandResult(exitCode: 1, output: outputLines.joined(separator: "\n"), error: "Vault repair cancelled by user.")
            }

            do {
                try vaultStore.activePinStore.savePin(expectedPin)
                ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt succeeded: master key pin restored (fingerprint: \(fingerprint)).")
                outputLines.append("Vault master key pin successfully repaired.")
                return CLICommandResult(exitCode: 0, output: outputLines.joined(separator: "\n"))
            } catch {
                ClavisLogger.log("SECURITY_ALERT", "Vault repair attempt failed saving pin: \(error.localizedDescription)")
                return CLICommandResult(exitCode: 1, output: outputLines.joined(separator: "\n"), error: "Failed to save pin to Keychain: \(error.localizedDescription)")
            }

        case .run:
            return handleRun(
                args: Array(args.dropFirst(2)),
                keyManager: keyManager,
                agentLifecycle: agentLifecycle
            )

        case .history:
            guard args.count >= 3 && args[2].lowercased() == "check" else {
                return CLICommandResult(exitCode: 1, output: "", error: CLIMessages.usage(for: .history))
            }
            let checkArgs: HistoryCheckArgs
            do {
                checkArgs = try parseHistoryCheckArgs(args)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: error.localizedDescription)
            }

            let dbURL: URL
            if let dbPath = checkArgs.dbPath {
                dbURL = URL(fileURLWithPath: dbPath)
            } else {
                dbURL = AuditStore.defaultURL
            }

            guard FileManager.default.fileExists(atPath: dbURL.path) else {
                return CLICommandResult(exitCode: 1, output: "", error: "Database file not found: \(dbURL.path)")
            }

            let store: AuditStore
            do {
                store = try AuditStore(url: dbURL, readOnly: true)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Failed to open audit store: \(error.localizedDescription)")
            }
            defer { store.close() }

            let reader = LogWitnessReader()
            let witness = reader.read(days: checkArgs.days)

            do {
                let report = try AuditIntegrityChecker.check(
                    store: store,
                    witness: witness,
                    now: Date(),
                    days: checkArgs.days
                )
                let (output, exitCode) = formatHistoryCheckReport(report)
                return CLICommandResult(exitCode: exitCode, output: output)
            } catch {
                return CLICommandResult(exitCode: 1, output: "", error: "Integrity check failed: \(error.localizedDescription)")
            }

        case .dashDashHelp, .dashH, .help:
            return CLICommandResult(exitCode: 0, output: CLIMessages.help)
        }
    }

    public static func parseHistoryCheckArgs(_ args: [String]) throws -> HistoryCheckArgs {
        var tokens = args
        if let idx = tokens.firstIndex(of: "history") {
            guard idx + 1 < tokens.count, tokens[idx + 1] == "check" else {
                throw HistoryCheckArgError.unknownArgument(tokens[idx])
            }
            tokens = Array(tokens.suffix(from: idx + 2))
        } else if tokens.first == "check" {
            tokens = Array(tokens.dropFirst())
        }

        var days = 7
        var dbPath: String?

        var i = 0
        while i < tokens.count {
            let token = tokens[i]
            if token == "--days" {
                guard i + 1 < tokens.count else {
                    throw HistoryCheckArgError.missingArgument("--days")
                }
                let valStr = tokens[i + 1]
                guard let val = Int(valStr), val >= 1 && val <= 30 else {
                    throw HistoryCheckArgError.invalidDays(valStr)
                }
                days = val
                i += 2
            } else if token == "--db" {
                guard i + 1 < tokens.count else {
                    throw HistoryCheckArgError.missingArgument("--db")
                }
                dbPath = tokens[i + 1]
                i += 2
            } else {
                throw HistoryCheckArgError.unknownArgument(token)
            }
        }

        return HistoryCheckArgs(days: days, dbPath: dbPath)
    }

    public static func formatHistoryCheckReport(_ report: AuditIntegrityReport) -> (output: String, exitCode: Int32) {
        let isoFormatter = ISO8601DateFormatter()
        let checkedFromStr = isoFormatter.string(from: report.checkedFrom)
        var lines: [String] = []

        switch report.status {
        case .ok:
            lines.append("History integrity check: OK")
            lines.append("Checked rows: \(report.checkedRows) (since \(checkedFromStr))")
            lines.append("No problems detected.")
            if !report.unwitnessedRows.isEmpty {
                let unwitnessedPreview = report.unwitnessedRows.prefix(5).map(String.init).joined(separator: ", ")
                let suffix = report.unwitnessedRows.count > 5 ? "..." : ""
                lines.append("Warning: \(report.unwitnessedRows.count) unwitnessed row(s) in window (seq: \(unwitnessedPreview)\(suffix))")
            }
            if !report.gapsOutsideWindow.isEmpty {
                let gapsSummary = report.gapsOutsideWindow.map { "\($0.lowerBound)...\($0.upperBound)" }.joined(separator: ", ")
                lines.append("Notice: \(report.gapsOutsideWindow.count) gap(s) before log retention window: \(gapsSummary)")
            }
            return (lines.joined(separator: "\n"), 0)

        case .problems:
            lines.append("History integrity check: PROBLEMS DETECTED")
            lines.append("Checked rows: \(report.checkedRows) (since \(checkedFromStr))")
            lines.append("Missing rows: \(report.missingRows.count)")
            lines.append("Inconsistent rows: \(report.inconsistentRows.count)")
            lines.append("Tail truncated: \(report.truncatedTail ? "yes" : "no")")
            lines.append("")
            lines.append("Problems:")

            var problemCount = 0
            for item in report.missingRows {
                if problemCount >= 20 { break }
                let timeStr = item.loggedAt.map { isoFormatter.string(from: $0) } ?? "unknown time"
                lines.append("  - Missing: seq \(item.seq) (witnessed at \(timeStr))")
                problemCount += 1
            }

            for seq in report.inconsistentRows {
                if problemCount >= 20 { break }
                lines.append("  - Inconsistent: seq \(seq)")
                problemCount += 1
            }

            if report.truncatedTail && problemCount < 20 {
                lines.append("  - Truncated tail detected (max witnessed seq exceeds database)")
                problemCount += 1
            }

            let totalProblems = report.missingRows.count + report.inconsistentRows.count + (report.truncatedTail ? 1 : 0)
            if totalProblems > 20 {
                lines.append("  ... and \(totalProblems - 20) more problem(s)")
            }

            return (lines.joined(separator: "\n"), 2)

        case .unavailable(let reason):
            lines.append("History integrity check: UNAVAILABLE (\(reason))")
            lines.append("Checked from: \(checkedFromStr)")
            lines.append("Unified log witness stream is unavailable.")
            return (lines.joined(separator: "\n"), 1)
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
        ClavisLogger.promptDebug("clavis-cli", "CLIService: prompting for seed via terminal passphrase prompt")
        guard readpassphrase(CLIMessages.promptSeedTerminal, &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
            return nil
        }
        return buffer.withUnsafeBytes { decodeHexSeed($0) }
    }

    private static func readSeedFromStandardInput() -> Data? {
        ClavisLogger.promptDebug("clavis-cli", "CLIService: reading seed from standard input")
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

    // MARK: - Pure CLI Helpers

    public static func parseGeneratePurpose(args: [String]) throws -> KeyPurpose {
        let isGitOnly = args.contains(CLIFlag.gitOnly.rawValue)
        let isAgent = args.contains(CLIFlag.agent.rawValue)
        if isGitOnly && isAgent {
            throw NSError(
                domain: "ClavisCLI",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: CLIMessages.agentAndGitOnlyExclusive]
            )
        }
        if isGitOnly { return .gitSigningOnly }
        if isAgent { return .agent }
        return .general
    }

    public static func parseKindTarget(argument: String) -> KeyPurpose? {
        let lower = argument.trimmingCharacters(in: .whitespaces).lowercased()
        if lower == "agent" { return .agent }
        if lower == "personal" { return .general }
        return nil
    }

    public static func formatKeyHeader(label: String, purpose: KeyPurpose) -> String {
        let tag: String
        switch purpose {
        case .general:
            tag = ""
        case .gitSigningOnly:
            tag = " [Git Only]"
        case .agent:
            tag = " [Agent]"
        }
        return " - [\(label)]\(tag)"
    }

    public static func formatKeyListEntries(keys: [Ed25519KeyInfo]) -> [String] {
        if keys.isEmpty {
            return [CLIMessages.noKeysFound()]
        }
        var lines: [String] = [CLIMessages.foundKeysHeader(count: keys.count)]
        for key in keys {
            lines.append(formatKeyHeader(label: key.label, purpose: key.purpose))
            lines.append("   Fingerprint: \(key.fingerprint)")
            lines.append("   Public Key:  \(key.publicKeyOpenSSH)")
        }
        return lines
    }

    private static func handleRun(
        args: [String],
        keyManager: KeychainManager,
        agentLifecycle: AgentLifecycleManager
    ) -> CLICommandResult {
        let options: AgentRunOptions
        do {
            options = try AgentRunner.parse(args)
        } catch {
            return CLICommandResult(exitCode: 1, output: "", error: error.localizedDescription)
        }

        guard SSHAgentServer.isSocketListening(atPath: SSHAgentServer.defaultSocketPath) &&
              SSHAgentServer.isSocketListening(atPath: SSHAgentServer.defaultAgentSocketPath) else {
            return CLICommandResult(exitCode: 1, output: "", error: AgentRunError.agentNotRunning.localizedDescription)
        }

        let keys = (try? keyManager.listKeys()) ?? []
        let key: Ed25519KeyInfo
        do {
            key = try AgentRunner.chooseKey(options.keyLabel, keys: keys)
        } catch {
            return CLICommandResult(exitCode: 1, output: "", error: error.localizedDescription)
        }

        let toolName = (options.command[0] as NSString).lastPathComponent
        let leaseMinutes = options.leaseMinutes ?? 0

        let session: (id: String, leaseSeconds: Int)
        do {
            session = try agentLifecycle.registerAgentSession(
                keyLabel: key.label,
                toolName: toolName,
                leaseMinutes: leaseMinutes
            )
        } catch {
            return CLICommandResult(exitCode: 1, output: "", error: AgentRunError.registrationRefused.localizedDescription)
        }

        let childEnv: [String: String]
        do {
            childEnv = try AgentRunner.childEnvironment(
                base: ProcessInfo.processInfo.environment,
                agentSocket: SSHAgentServer.defaultAgentSocketPath,
                sessionID: session.id,
                options: options
            )
        } catch {
            _ = agentLifecycle.endAgentSession(id: session.id)
            return CLICommandResult(exitCode: 1, output: "", error: error.localizedDescription)
        }

        let exitCode: Int32
        do {
            exitCode = try AgentRunner.spawnAndWait(options.command, environment: childEnv)
        } catch {
            _ = agentLifecycle.endAgentSession(id: session.id)
            return CLICommandResult(exitCode: 1, output: "", error: "Failed to spawn command: \(error.localizedDescription)")
        }

        _ = agentLifecycle.endAgentSession(id: session.id)
        return CLICommandResult(exitCode: exitCode, output: "")
    }
}
