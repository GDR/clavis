import Foundation
import ClavisCore

@main
struct AgePluginClavis {
    static func main() {
        let args = CommandLine.arguments

        if args.contains("--age-plugin=recipient-V1") {
            handleRecipientV1()
        } else if args.contains("--age-plugin=identity-V1") {
            handleIdentityV1()
        } else {
            print("age-plugin-clavis v0.1.0")
            print("Usage: age-plugin-clavis --age-plugin=identity-V1")
        }
    }

    static func handleRecipientV1() {
        var recipients: [String] = []
        var fileKeys: [Data] = []
        
        while let line = readLine() {
            let parts = line.split(separator: " ")
            guard !parts.isEmpty else { continue }
            
            let command = parts[0]
            if command == "->", parts.count >= 2 {
                let action = parts[1]
                if action == "add-recipient", parts.count >= 3 {
                    recipients.append(String(parts[2]))
                } else if action == "wrap-file-key" {
                    // Read line of base64 key
                    if let keyLine = readLine() {
                        let clean = keyLine.trimmingCharacters(in: .whitespacesAndNewlines)
                        if let keyData = Data(base64Encoded: clean) {
                            fileKeys.append(keyData)
                        }
                    }
                } else if action == "done" {
                    // Respond with recipient stanzas
                    for (index, _) in recipients.enumerated() {
                        let epk = Data(repeating: 0x01, count: 32).base64EncodedString()
                        let wrappedKey = (fileKeys.indices.contains(index) ? fileKeys[index] : Data(repeating: 0x42, count: 16)).base64EncodedString()
                        print("-> recipient-stanza \(index) clavis \(epk)")
                        print(wrappedKey)
                    }
                    print("-> ok")
                    fflush(stdout)
                    break
                }
            }
        }
    }

    static func handleIdentityV1() {
        var identities: [String] = []
        var stanzas: [(index: Int, epk: String, wrappedKey: Data)] = []
        var currentStanzaIndex = 0

        while let line = readLine() {
            let parts = line.split(separator: " ")
            guard !parts.isEmpty else { continue }

            let command = parts[0]
            if command == "->", parts.count >= 2 {
                let action = parts[1]
                if action == "add-identity", parts.count >= 3 {
                    identities.append(String(parts[2]))
                } else if action == "recipient-stanza", parts.count >= 4 {
                    let epk = String(parts[3])
                    if let keyLine = readLine() {
                        let clean = keyLine.trimmingCharacters(in: .whitespacesAndNewlines)
                        if let wrappedData = Data(base64Encoded: clean) {
                            stanzas.append((currentStanzaIndex, epk, wrappedData))
                            currentStanzaIndex += 1
                        }
                    }
                } else if action == "done" {
                    let keys = (try? KeychainManager.shared.listKeys()) ?? []
                    if let firstKey = keys.first, let stanza = stanzas.first {
                        do {
                            let _ = try KeychainManager.shared.fetchPrivateKey(
                                label: firstKey.label,
                                prompt: "Touch ID to unwrap age file key"
                            )
                            let fileKeyB64 = stanza.wrappedKey.base64EncodedString()
                            print("-> file-key \(stanza.index)")
                            print(fileKeyB64)
                        } catch {
                            print("-> error identity Keychain authentication failed")
                        }
                    }
                    print("-> ok")
                    fflush(stdout)
                    break
                }
            }
        }
    }
}
