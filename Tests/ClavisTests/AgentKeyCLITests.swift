import XCTest
@testable import ClavisCore

final class AgentKeyCLITests: XCTestCase {

    func test_005_T6_parseGeneratePurpose() throws {
        // Default to general
        let defaultPurpose = try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key1"])
        XCTAssertEqual(defaultPurpose, .general)

        // --git-only flag
        let gitPurpose = try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key2", "--git-only"])
        XCTAssertEqual(gitPurpose, .gitSigningOnly)

        // --agent flag
        let agentPurpose = try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key3", "--agent"])
        XCTAssertEqual(agentPurpose, .agent)

        // Mutually exclusive: --git-only and --agent together must throw
        XCTAssertThrowsError(
            try CLIService.parseGeneratePurpose(args: ["clavis", "generate", "key4", "--git-only", "--agent"])
        ) { error in
            let nsError = error as NSError
            XCTAssertEqual(nsError.localizedDescription, CLIMessages.agentAndGitOnlyExclusive)
        }
    }

    func test_005_T6_parseKindTarget() {
        XCTAssertEqual(CLIService.parseKindTarget(argument: "agent"), .agent)
        XCTAssertEqual(CLIService.parseKindTarget(argument: "Agent"), .agent)
        XCTAssertEqual(CLIService.parseKindTarget(argument: "AGENT"), .agent)
        XCTAssertEqual(CLIService.parseKindTarget(argument: " agent "), .agent)

        XCTAssertEqual(CLIService.parseKindTarget(argument: "personal"), .general)
        XCTAssertEqual(CLIService.parseKindTarget(argument: "Personal"), .general)
        XCTAssertEqual(CLIService.parseKindTarget(argument: "PERSONAL"), .general)
        XCTAssertEqual(CLIService.parseKindTarget(argument: " personal "), .general)

        XCTAssertNil(CLIService.parseKindTarget(argument: "invalid"))
        XCTAssertNil(CLIService.parseKindTarget(argument: "git-only"))
        XCTAssertNil(CLIService.parseKindTarget(argument: ""))
    }

    func test_005_T6_formatKeyHeader() {
        XCTAssertEqual(CLIService.formatKeyHeader(label: "my-general", purpose: .general), " - [my-general]")
        XCTAssertEqual(CLIService.formatKeyHeader(label: "my-git", purpose: .gitSigningOnly), " - [my-git] [Git Only]")
        XCTAssertEqual(CLIService.formatKeyHeader(label: "my-agent", purpose: .agent), " - [my-agent] [Agent]")
    }

    func test_005_T6_formatKeyListEntries() {
        // Empty list
        let emptyEntries = CLIService.formatKeyListEntries(keys: [])
        XCTAssertEqual(emptyEntries, [CLIMessages.noKeysFound()])

        // Multiple keys
        let k1 = Ed25519KeyInfo(
            label: "work-key",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeneral work-key",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:generalFingerprint",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain,
            biometricPolicy: nil,
            keyPurpose: .general
        )
        let k2 = Ed25519KeyInfo(
            label: "commit-signer",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGit commit-signer",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:gitFingerprint",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain,
            biometricPolicy: nil,
            keyPurpose: .gitSigningOnly
        )
        let k3 = Ed25519KeyInfo(
            label: "agent-claude",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAgent agent-claude",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:agentFingerprint",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .keychain,
            biometricPolicy: nil,
            keyPurpose: .agent
        )

        let entries = CLIService.formatKeyListEntries(keys: [k1, k2, k3])
        XCTAssertEqual(entries[0], CLIMessages.foundKeysHeader(count: 3))
        XCTAssertEqual(entries[1], " - [work-key]")
        XCTAssertEqual(entries[4], " - [commit-signer] [Git Only]")
        XCTAssertEqual(entries[7], " - [agent-claude] [Agent]")
    }
}
