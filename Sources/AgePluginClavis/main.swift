import Foundation
import CryptoKit
import ClavisCore

@main
public struct AgePluginClavis {
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
        inputProvider: () -> String? = { readLine() },
        outputHandler: (String) -> Void = { print($0) }
    ) {
        var recipients: [String] = []
        var fileKeys: [Data] = []
        var pendingLine: String? = nil

        while true {
            let line: String?
            if let pending = pendingLine {
                line = pending
                pendingLine = nil
            } else {
                line = inputProvider()
            }
            guard let currentLine = line else { break }

            let trimmed = currentLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }

            let parts = trimmed.split(separator: " ")
            guard !parts.isEmpty else { continue }

            if parts[0] == "->" {
                guard parts.count >= 2 else { continue }
                let action = parts[1]

                if action == "add-recipient", parts.count >= 3 {
                    recipients.append(String(parts[2]))
                } else if action == "wrap-file-key" {
                    var b64String = ""
                    while let bodyLine = inputProvider() {
                        let cleanLine = bodyLine.trimmingCharacters(in: .whitespacesAndNewlines)
                        if cleanLine.hasPrefix("->") {
                            pendingLine = cleanLine
                            break
                        }
                        if cleanLine.isEmpty {
                            continue
                        }
                        b64String += cleanLine
                    }
                    if let keyData = Data(base64Encoded: b64String), !keyData.isEmpty {
                        fileKeys.append(keyData)
                    }
                } else if action == "done" {
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
        inputProvider: () -> String? = { readLine() },
        outputHandler: (String) -> Void = { print($0) },
        fetchKeys: () throws -> [Ed25519KeyInfo] = { try KeychainManager.shared.listKeys() },
        fetchPrivateKey: (String, String) throws -> Curve25519.Signing.PrivateKey = { label, prompt in
            try KeychainManager.shared.fetchPrivateKey(label: label, prompt: prompt)
        }
    ) {
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
                line = inputProvider()
            }
            guard let currentLine = line else { break }

            let trimmed = currentLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }

            let parts = trimmed.split(separator: " ")
            guard !parts.isEmpty else { continue }

            if parts[0] == "->" {
                guard parts.count >= 2 else { continue }
                let action = parts[1]

                if action == "add-identity", parts.count >= 3 {
                    identities.append(String(parts[2]))
                } else if action == "recipient-stanza", parts.count >= 4 {
                    let fileKeyIndex = Int(parts[2]) ?? 0
                    let stanzaType = String(parts[3])
                    let epkB64 = parts.count >= 5 ? String(parts[4]) : ""

                    var b64String = ""
                    while let bodyLine = inputProvider() {
                        let cleanLine = bodyLine.trimmingCharacters(in: .whitespacesAndNewlines)
                        if cleanLine.hasPrefix("->") {
                            pendingLine = cleanLine
                            break
                        }
                        if cleanLine.isEmpty {
                            continue
                        }
                        b64String += cleanLine
                    }

                    if stanzaType == "clavis", let wrappedData = Data(base64Lenient: b64String) {
                        stanzas.append((index: fileKeyIndex, epkB64: epkB64, wrappedKey: wrappedData))
                    }
                } else if (action == "unwrap-file-key" || action == "done") && !isDone {
                    isDone = true
                    unwrapStanzas(
                        stanzas: stanzas,
                        identities: identities,
                        outputHandler: outputHandler,
                        fetchKeys: fetchKeys,
                        fetchPrivateKey: fetchPrivateKey
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
        fetchPrivateKey: (String, String) throws -> Curve25519.Signing.PrivateKey
    ) {
        guard !stanzas.isEmpty else { return }

        let keyInfos: [Ed25519KeyInfo]
        do {
            keyInfos = try fetchKeys()
        } catch {
            outputHandler("-> error identity Failed to list Keychain keys")
            return
        }

        if keyInfos.isEmpty {
            outputHandler("-> error identity No keys found in Keychain")
            return
        }

        for stanza in stanzas {
            var unwrapped = false

            for keyInfo in keyInfos {
                do {
                    let edPrivateKey = try fetchPrivateKey(
                        keyInfo.label,
                        "Touch ID to unwrap age file key"
                    )
                    let fileKey = try AgePluginCrypto.unwrapFileKey(
                        wrappedKey: stanza.wrappedKey,
                        epkB64: stanza.epkB64,
                        ed25519Seed: edPrivateKey.rawRepresentation
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

