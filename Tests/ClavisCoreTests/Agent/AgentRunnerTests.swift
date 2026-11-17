import Testing
import Foundation
@testable import ClavisCore

@Suite("AgentRunnerTests", .serialized)
struct AgentRunnerTests {
    private func makeKey(label: String, purpose: KeyPurpose) -> SSHKeyInfo {
        SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAA",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:\(label)",
            algorithmName: "ECDSA P-256",
            keyPurpose: purpose
        )
    }

    @Test
    func test_001_T5_parseRequiresDoubleDashAndCommand() throws {
        #expect {
            try AgentRunner.parse(["--key", "foo"])
        } throws: { error in
            (error as? AgentRunError) == .missingCommand
        }

        #expect {
            try AgentRunner.parse(["--key", "foo", "--"])
        } throws: { error in
            (error as? AgentRunError) == .missingCommand
        }

        let opts1 = try AgentRunner.parse(["--", "echo", "hi"])
        #expect(opts1.command == ["echo", "hi"])
        #expect(opts1.keyLabel == nil)
        #expect(opts1.leaseMinutes == nil)
        #expect(!opts1.setSSHAuthSock)
        #expect(!opts1.keepGitSSHCommand)

        let opts2 = try AgentRunner.parse([
            "--key", "my-key",
            "--minutes", "30",
            "--set-ssh-auth-sock",
            "--keep-git-ssh-command",
            "--", "git", "push"
        ])
        #expect(opts2.command == ["git", "push"])
        #expect(opts2.keyLabel == "my-key")
        #expect(opts2.leaseMinutes == 30)
        #expect(opts2.setSSHAuthSock)
        #expect(opts2.keepGitSSHCommand)

        let opts3 = try AgentRunner.parse([
            "--key=key2",
            "--lease=45",
            "--ssh-auth-sock",
            "--", "ls"
        ])
        #expect(opts3.command == ["ls"])
        #expect(opts3.keyLabel == "key2")
        #expect(opts3.leaseMinutes == 45)
        #expect(opts3.setSSHAuthSock)
    }

    @Test
    func test_001_T5_chooseKeySingleAgentKeyDefault() throws {
        let agentKey = makeKey(label: "agent-1", purpose: .agent)
        let personalKey = makeKey(label: "personal-1", purpose: .general)

        let chosen = try AgentRunner.chooseKey(nil, keys: [agentKey, personalKey])
        #expect(chosen.label == "agent-1")

        #expect {
            try AgentRunner.chooseKey(nil, keys: [personalKey])
        } throws: { error in
            (error as? AgentRunError) == .noAgentKey
        }
    }

    @Test
    func test_001_T5_chooseKeyAmbiguousErrors() throws {
        let agentKey1 = makeKey(label: "agent-1", purpose: .agent)
        let agentKey2 = makeKey(label: "agent-2", purpose: .agent)

        #expect {
            try AgentRunner.chooseKey(nil, keys: [agentKey1, agentKey2])
        } throws: { error in
            (error as? AgentRunError) == .ambiguousAgentKey(["agent-1", "agent-2"])
        }

        let explicit = try AgentRunner.chooseKey("agent-2", keys: [agentKey1, agentKey2])
        #expect(explicit.label == "agent-2")
    }

    @Test
    func test_001_T5_chooseKeyRefusesPersonalKey() throws {
        let personalKey = makeKey(label: "personal-1", purpose: .general)

        #expect {
            try AgentRunner.chooseKey("personal-1", keys: [personalKey])
        } throws: { error in
            (error as? AgentRunError) == .notAgentKey("personal-1")
        }

        #expect {
            try AgentRunner.chooseKey("unknown", keys: [personalKey])
        } throws: { error in
            (error as? AgentRunError) == .unknownKey("unknown")
        }
    }

    @Test
    func test_001_T5_envSetsGitSSHCommandAndKeepsSSHAuthSock() throws {
        let base = ["SSH_AUTH_SOCK": "/tmp/personal.sock"]
        let opts = AgentRunOptions(setSSHAuthSock: false, command: ["git", "push"])
        let env = try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: opts
        )

        #expect(env["SSH_AUTH_SOCK"] == "/tmp/personal.sock")
        #expect(env["GIT_SSH_COMMAND"] == "ssh -o IdentityAgent='/tmp/agent.sock'")
        #expect(env["CLAVIS_AGENT_SOCK"] == "/tmp/agent.sock")
        #expect(env["CLAVIS_AGENT_SESSION"] == "sess-123")

        let optsWithSock = AgentRunOptions(setSSHAuthSock: true, command: ["git", "push"])
        let envWithSock = try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: optsWithSock
        )
        #expect(envWithSock["SSH_AUTH_SOCK"] == "/tmp/agent.sock")
    }

    @Test
    func test_001_T5_envRefusesExistingGitSSHCommand() throws {
        let base = ["GIT_SSH_COMMAND": "ssh -i /path/key"]
        let opts = AgentRunOptions(keepGitSSHCommand: false, command: ["git", "push"])

        #expect {
            try AgentRunner.childEnvironment(
                base: base,
                agentSocket: "/tmp/agent.sock",
                sessionID: "sess-123",
                options: opts
            )
        } throws: { error in
            (error as? AgentRunError) == .gitSSHCommandAlreadySet
        }
    }

    @Test
    func test_001_T5_envKeepFlagLeavesIt() throws {
        let base = ["GIT_SSH_COMMAND": "ssh -i /path/key"]
        let opts = AgentRunOptions(keepGitSSHCommand: true, command: ["git", "push"])

        let env = try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: opts
        )
        #expect(env["GIT_SSH_COMMAND"] == "ssh -i /path/key")
    }

    @Test
    func test_001_T5_envQuotesSocketPathWithSpaces() throws {
        let socketPath = "/tmp/path with spaces and 'quote'/agent.sock"
        let opts = AgentRunOptions(command: ["git", "push"])
        let env = try AgentRunner.childEnvironment(
            base: [:],
            agentSocket: socketPath,
            sessionID: "sess-123",
            options: opts
        )
        let expectedCmd = "ssh -o IdentityAgent='/tmp/path with spaces and '\\''quote'\\''/agent.sock'"
        #expect(env["GIT_SSH_COMMAND"] == expectedCmd)
    }

    @Test
    func test_001_T5_spawnReturnsChildExitCode() throws {
        let code = try AgentRunner.spawnAndWait(["/bin/sh", "-c", "exit 7"], environment: [:])
        #expect(code == 7)
    }

    @Test
    func test_001_T5_spawnReportsSignal() throws {
        let code = try AgentRunner.spawnAndWait(["/bin/sh", "-c", "kill -TERM $$"], environment: [:])
        #expect(code == 143)
    }
}
