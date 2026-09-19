import Foundation
import CryptoKit
import ClavisCore
import Darwin

private final class BoundedStdinLineReader {
    private let maximumLineBytes: Int
    private var pending = Data()
    private var reachedEOF = false
    private(set) var exceededLimit = false

    init(maximumLineBytes: Int) {
        self.maximumLineBytes = maximumLineBytes
    }

    func readLine() -> String? {
        while true {
            if let newline = pending.firstIndex(of: 0x0A) {
                let line = Data(pending[..<newline])
                pending.removeSubrange(...newline)
                guard line.count <= maximumLineBytes else {
                    exceededLimit = true
                    pending.removeAll(keepingCapacity: false)
                    return nil
                }
                return String(decoding: line, as: UTF8.self)
            }

            if reachedEOF {
                guard !pending.isEmpty else { return nil }
                guard pending.count <= maximumLineBytes else {
                    exceededLimit = true
                    pending.removeAll(keepingCapacity: false)
                    return nil
                }
                let line = String(decoding: pending, as: UTF8.self)
                pending.removeAll(keepingCapacity: false)
                return line
            }

            var chunk = [UInt8](repeating: 0, count: 4096)
            let bytesRead = chunk.withUnsafeMutableBytes { raw -> Int in
                while true {
                    let result = Darwin.read(STDIN_FILENO, raw.baseAddress, raw.count)
                    if result < 0 && errno == EINTR { continue }
                    return result
                }
            }
            guard bytesRead >= 0 else {
                reachedEOF = true
                return nil
            }
            guard bytesRead > 0 else {
                reachedEOF = true
                continue
            }
            pending.append(contentsOf: chunk.prefix(bytesRead))

            if pending.firstIndex(of: 0x0A) == nil && pending.count > maximumLineBytes {
                exceededLimit = true
                pending.removeAll(keepingCapacity: false)
                return nil
            }
        }
    }
}

@main
public struct AgePluginClavis {
    static let maximumIPCLineBytes = 8 * 1024
    static let maximumIPCBodyBytes = 64 * 1024
    static let maximumIPCLines = 4_096
    static let maximumIPCItems = 256
    static let maximumCryptoOperations = 1_024

    public static func main() {
        let args = CommandLine.arguments

        if args.contains("--age-plugin=recipient-V1") {
            handleRecipientV1()
        } else if args.contains("--age-plugin=identity-V1") {
            handleIdentityV1()
        } else {
            print("age-plugin-clavis v0.1.0")
            print("Usage: age-plugin-clavis --age-plugin=identity-V1 | --age-plugin=recipient-V1")
        }
    }

    public static func handleRecipientV1(
        inputProvider: (() -> String?)? = nil,
        outputHandler: (String) -> Void = { print($0) }
    ) {
        let stdinReader = inputProvider == nil
            ? BoundedStdinLineReader(maximumLineBytes: maximumIPCLineBytes)
            : nil
        let source = inputProvider ?? { stdinReader?.readLine() }
        var inputLineCount = 0
        var inputRejected = false

        func nextInputLine() -> String? {
            guard let line = source() else {
                if stdinReader?.exceededLimit == true { inputRejected = true }
                return nil
            }
            inputLineCount += 1
            guard inputLineCount <= maximumIPCLines,
                  line.utf8.count <= maximumIPCLineBytes else {
                inputRejected = true
                return nil
            }
            return line
        }

        func rejectOversizedInput() {
            outputHandler("-> error protocol IPC input limit exceeded")
            fflush(stdout)
        }

        var recipients: [String] = []
        var fileKeys: [Data] = []
        var pendingLine: String? = nil

        while true {
            let line: String?
            if let pending = pendingLine {
                line = pending
                pendingLine = nil
            } else {
                line = nextInputLine()
            }
            guard let currentLine = line else {
                if inputRejected { rejectOversizedInput() }
                break
            }

            let trimmed = currentLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }

            let parts = trimmed.split(separator: " ")
            guard !parts.isEmpty else { continue }

            if parts[0] == "->" {
                guard parts.count >= 2 else { continue }
                let action = parts[1]

                if action == "add-recipient", parts.count >= 3 {
                    guard recipients.count < maximumIPCItems else {
                        rejectOversizedInput()
                        return
                    }
                    recipients.append(String(parts[2]))
                } else if action == "wrap-file-key" {
                    var b64String = ""
                    var bodyByteCount = 0
                    while let bodyLine = nextInputLine() {
                        let cleanLine = bodyLine.trimmingCharacters(in: .whitespacesAndNewlines)
                        if cleanLine.hasPrefix("->") {
                            pendingLine = cleanLine
                            break
                        }
                        if cleanLine.isEmpty {
                            continue
                        }
                        let lineBytes = cleanLine.utf8.count
                        guard lineBytes <= maximumIPCBodyBytes - bodyByteCount else {
                            rejectOversizedInput()
                            return
                        }
                        bodyByteCount += lineBytes
                        b64String += cleanLine
                    }
                    if inputRejected {
                        rejectOversizedInput()
                        return
                    }
                    if let keyData = Data(base64Encoded: b64String), !keyData.isEmpty {
                        guard fileKeys.count < maximumIPCItems else {
                            rejectOversizedInput()
                            return
                        }
                        fileKeys.append(keyData)
                    }
                } else if action == "done" {
                    let (operationCount, overflow) = recipients.count.multipliedReportingOverflow(by: fileKeys.count)
                    guard !overflow, operationCount <= maximumCryptoOperations else {
                        rejectOversizedInput()
                        return
                    }
                    for (fileKeyIndex, fileKey) in fileKeys.enumerated() {
                        for recipientStr in recipients {
                            do {
                                let (epkB64, wrappedKeyPayload) = try AgePluginCrypto.wrapFileKey(fileKey: fileKey, recipientString: recipientStr)
                                outputHandler("-> recipient-stanza \(fileKeyIndex) clavis \(epkB64)")
                                formatBase64(wrappedKeyPayload, outputHandler: outputHandler)
                            } catch {
                                outputHandler("-> error Failed to wrap file key for recipient \(recipientStr)")
                            }
                        }
                    }
                    outputHandler("-> ok")
                    fflush(stdout)
                    break
                }
            }
        }
    }

    public static func handleIdentityV1(
        inputProvider: (() -> String?)? = nil,
        outputHandler: (String) -> Void = { print($0) },
        fetchKeys: () throws -> [Ed25519KeyInfo] = { try KeychainManager.shared.listKeys() },
        unwrapKey: (String, String, Data, String) throws -> Data = { label, prompt, wrappedKey, epkB64 in
            try KeychainManager.shared.unwrapAgeFileKey(label: label, prompt: prompt, wrappedKey: wrappedKey, epkB64: epkB64)
        }
    ) {
        let stdinReader = inputProvider == nil
            ? BoundedStdinLineReader(maximumLineBytes: maximumIPCLineBytes)
            : nil
        let source = inputProvider ?? { stdinReader?.readLine() }
        var inputLineCount = 0
        var inputRejected = false

        func nextInputLine() -> String? {
            guard let line = source() else {
                if stdinReader?.exceededLimit == true { inputRejected = true }
                return nil
            }
            inputLineCount += 1
            guard inputLineCount <= maximumIPCLines,
                  line.utf8.count <= maximumIPCLineBytes else {
                inputRejected = true
                return nil
            }
            return line
        }

        func rejectOversizedInput() {
            outputHandler("-> error protocol IPC input limit exceeded")
            fflush(stdout)
        }

        var identities: [String] = []
        var stanzas: [(index: Int, epkB64: String, wrappedKey: Data)] = []
        var pendingLine: String? = nil
        var isDone = false

        while true {
            let line: String?
            if let pending = pendingLine {
                line = pending
                pendingLine = nil
            } else {
                line = nextInputLine()
            }
            guard let currentLine = line else {
                if inputRejected { rejectOversizedInput() }
                break
            }

            let trimmed = currentLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }

            let parts = trimmed.split(separator: " ")
            guard !parts.isEmpty else { continue }

            if parts[0] == "->" {
                guard parts.count >= 2 else { continue }
                let action = parts[1]

                if action == "add-identity", parts.count >= 3 {
                    guard identities.count < maximumIPCItems else {
                        rejectOversizedInput()
                        return
                    }
                    identities.append(String(parts[2]))
                } else if action == "recipient-stanza", parts.count >= 4 {
                    let fileKeyIndex = Int(parts[2]) ?? 0
                    let stanzaType = String(parts[3])
                    let epkB64 = parts.count >= 5 ? String(parts[4]) : ""

                    var b64String = ""
                    var bodyByteCount = 0
                    while let bodyLine = nextInputLine() {
                        let cleanLine = bodyLine.trimmingCharacters(in: .whitespacesAndNewlines)
                        if cleanLine.hasPrefix("->") {
                            pendingLine = cleanLine
                            break
                        }
                        if cleanLine.isEmpty {
                            continue
                        }
                        let lineBytes = cleanLine.utf8.count
                        guard lineBytes <= maximumIPCBodyBytes - bodyByteCount else {
                            rejectOversizedInput()
                            return
                        }
                        bodyByteCount += lineBytes
                        b64String += cleanLine
                    }

                    if inputRejected {
                        rejectOversizedInput()
                        return
                    }

                    if stanzaType == "clavis", let wrappedData = Data(base64Lenient: b64String) {
                        guard stanzas.count < maximumIPCItems else {
                            rejectOversizedInput()
                            return
                        }
                        stanzas.append((index: fileKeyIndex, epkB64: epkB64, wrappedKey: wrappedData))
                    }
                } else if (action == "unwrap-file-key" || action == "done") && !isDone {
                    isDone = true
                    unwrapStanzas(
                        stanzas: stanzas,
                        identities: identities,
                        outputHandler: outputHandler,
                        fetchKeys: fetchKeys,
                        unwrapKey: unwrapKey
                    )
                    outputHandler("-> ok")
                    fflush(stdout)
                    break
                }
            }
        }
    }

    public static func parseRecipientPublicKey(_ recipientStr: String) -> Data? {
        if let decoded = try? Bech32.decode(bech32String: recipientStr) {
            if decoded.data.count == 32 {
                return decoded.data
            }
        }
        if let hexData = Data(hexString: recipientStr), hexData.count == 32 {
            return hexData
        }
        return nil
    }

    public static func formatBase64(_ data: Data, width: Int = 64, outputHandler: (String) -> Void) {
        let b64 = data.base64EncodedString()
        var index = b64.startIndex
        while index < b64.endIndex {
            let nextIndex = b64.index(index, offsetBy: width, limitedBy: b64.endIndex) ?? b64.endIndex
            outputHandler(String(b64[index..<nextIndex]))
            index = nextIndex
        }
    }

    private static func unwrapStanzas(
        stanzas: [(index: Int, epkB64: String, wrappedKey: Data)],
        identities: [String],
        outputHandler: (String) -> Void,
        fetchKeys: () throws -> [Ed25519KeyInfo],
        unwrapKey: (String, String, Data, String) throws -> Data
    ) {
        guard !stanzas.isEmpty else { return }

        let allKeys: [Ed25519KeyInfo]
        do {
            allKeys = try fetchKeys()
        } catch {
            outputHandler("-> error identity Failed to list Keychain keys")
            return
        }

        // Only consider age-compatible (Ed25519) keys
        let ageCompatibleKeys = allKeys.filter { $0.isAgeCompatible }
        guard ageCompatibleKeys.count <= maximumIPCItems else {
            outputHandler("-> error protocol IPC input limit exceeded")
            return
        }

        // If specific identities were supplied by caller (age -i identity.txt), filter strictly by them
        let candidateKeys: [Ed25519KeyInfo]
        if !identities.isEmpty {
            candidateKeys = ageCompatibleKeys.filter { key in
                identities.contains { id in
                    id.caseInsensitiveCompare(key.label) == .orderedSame ||
                    id == key.ageRecipient ||
                    id.contains(key.label)
                }
            }
        } else {
            candidateKeys = ageCompatibleKeys
        }

        if candidateKeys.isEmpty {
            outputHandler("-> error identity No matching age-compatible keys found in Clavis")
            return
        }

        let (operationCount, overflow) = candidateKeys.count.multipliedReportingOverflow(by: stanzas.count)
        guard !overflow, operationCount <= maximumCryptoOperations else {
            outputHandler("-> error protocol IPC input limit exceeded")
            return
        }

        for stanza in stanzas {
            var unwrapped = false

            for keyInfo in candidateKeys {
                do {
                    let fileKey = try unwrapKey(
                        keyInfo.label,
                        "Touch ID to unwrap age file key using '\(keyInfo.label)'",
                        stanza.wrappedKey,
                        stanza.epkB64
                    )

                    outputHandler("-> file-key \(stanza.index)")
                    formatBase64(fileKey, outputHandler: outputHandler)
                    unwrapped = true
                    break
                } catch {
                    continue
                }
            }

            if !unwrapped {
                outputHandler("-> error identity Failed to unwrap stanza \(stanza.index)")
            }
        }
    }
}
