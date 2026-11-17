import Testing
import Foundation
@testable import ClavisCore

@Suite("AgentKeyCLITests")
struct AgentKeyCLITests {

    @Test
    func test_005_T6_parseGeneratePurpose() throws {
        // Default to general
        let defaultPurpose = try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key1"])
        #expect(defaultPurpose == .general)

        // --git-only flag
        let gitPurpose = try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key2", "--git-only"])
        #expect(gitPurpose == .gitSigningOnly)

        // --agent flag
        let agentPurpose = try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key3", "--agent"])
        #expect(agentPurpose == .agent)

        // Mutually exclusive: --git-only and --agent together must throw
        #expect {
            try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key4", "--git-only", "--agent"])
        } throws: { error in
            let nsError = error as NSError
            return nsError.localizedDescription == CLIMessages.agentAndGitOnlyExclusive
        }
    }

    @Test
    func test_005_T6_parseKindTarget() {
        #expect(CLIService.parseKindTarget(argument: "agent") == .agent)
        #expect(CLIService.parseKindTarget(argument: "Agent") == .agent)
        #expect(CLIService.parseKindTarget(argument: "AGENT") == .agent)
        #expect(CLIService.parseKindTarget(argument: " agent ") == .agent)

        #expect(CLIService.parseKindTarget(argument: "personal") == .general)
        #expect(CLIService.parseKindTarget(argument: "Personal") == .general)
        #expect(CLIService.parseKindTarget(argument: "PERSONAL") == .general)
        #expect(CLIService.parseKindTarget(argument: " personal ") == .general)

        #expect(CLIService.parseKindTarget(argument: "invalid") == nil)
        #expect(CLIService.parseKindTarget(argument: "git-only") == nil)
        #expect(CLIService.parseKindTarget(argument: "") == nil)
    }

    @Test
    func test_005_T6_formatKeyHeader() {
        #expect(CLIService.formatKeyHeader(label: "my-general", purpose: .general) == " - [my-general]")
        #expect(CLIService.formatKeyHeader(label: "my-git", purpose: .gitSigningOnly) == " - [my-git] [Git Only]")
        #expect(CLIService.formatKeyHeader(label: "my-agent", purpose: .agent) == " - [my-agent] [Agent]")
    }

    @Test
    func test_005_T6_formatKeyListEntries() {
        // Empty list
        let emptyEntries = CLIService.formatKeyListEntries(keys: [])
        #expect(emptyEntries == [CLIMessages.noKeysFound()])

        // Multiple keys
        let k1 = SSHKeyInfo(
            label: "work-key",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneral work-key",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:generalFingerprint",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .general
        )
        let k2 = SSHKeyInfo(
            label: "commit-signer",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB Commit commit-signer",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:gitFingerprint",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .gitSigningOnly
        )
        let k3 = SSHKeyInfo(
            label: "agent-claude",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB Agent agent-claude",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:agentFingerprint",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: nil,
            keyPurpose: .agent
        )

        let entries = CLIService.formatKeyListEntries(keys: [k1, k2, k3])
        #expect(entries[0] == CLIMessages.foundKeysHeader(count: 3))
        #expect(entries[1] == " - [work-key]")
        #expect(entries[4] == " - [commit-signer] [Git Only]")
        #expect(entries[7] == " - [agent-claude] [Agent]")
    }

    @Test
    func test_SSHKeyInfo_promotionAndBackwardCompatibilityTypealias() {
        // Verify type identity between SSHKeyInfo and backward-compatible Ed25519KeyInfo typealias
        #expect(SSHKeyInfo.self == Ed25519KeyInfo.self)

        // Verify strict invariant: Keychain publicServiceName must remain unchanged
        #expect(KeychainManager.publicServiceName == "com.clavis.ed25519.pub")
        #expect(KeychainManager.privateServiceName == "com.clavis.private-record.v2")

        // Verify accurate CLI strings
        #expect(CLIMessages.noKeysFound() == "No keys found in Keychain.")
        #expect(CLIMessages.help.contains("Clavis — Native macOS Secure Enclave SSH Agent & Key Manager"))
        #expect(!CLIMessages.help.contains("Ed25519"))

        let sampleKey = SSHKeyInfo(
            label: "p256-key",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA...",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:test",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )
        let generatedMsg = CLIMessages.successfullyGenerated(info: sampleKey)
        #expect(generatedMsg.contains("Successfully generated key 'p256-key' in Keychain."))
        #expect(!generatedMsg.contains("Ed25519"))
    }
}
