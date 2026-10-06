import XCTest
@testable import ClavisCore

final class AgentRunnerTests: XCTestCase {
    private func makeKey(label: String, purpose: KeyPurpose) -> Ed25519KeyInfo {
        Ed25519KeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAA",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:\(label)",
            algorithmName: "Ed25519",
            keyPurpose: purpose
        )
    }

    func test_001_T5_parseRequiresDoubleDashAndCommand() throws {
        XCTAssertThrowsError(try AgentRunner.parse(["--key", "foo"])) { error in
            XCTAssertEqual(error as? AgentRunError, .missingCommand)
        }

        XCTAssertThrowsError(try AgentRunner.parse(["--key", "foo", "--"])) { error in
            XCTAssertEqual(error as? AgentRunError, .missingCommand)
        }

        let opts1 = try AgentRunner.parse(["--", "echo", "hi"])
        XCTAssertEqual(opts1.command, ["echo", "hi"])
        XCTAssertNil(opts1.keyLabel)
        XCTAssertNil(opts1.leaseMinutes)
        XCTAssertFalse(opts1.setSSHAuthSock)
        XCTAssertFalse(opts1.keepGitSSHCommand)

        let opts2 = try AgentRunner.parse([
            "--key", "my-key",
            "--minutes", "30",
            "--set-ssh-auth-sock",
            "--keep-git-ssh-command",
            "--", "git", "push"
        ])
        XCTAssertEqual(opts2.command, ["git", "push"])
        XCTAssertEqual(opts2.keyLabel, "my-key")
        XCTAssertEqual(opts2.leaseMinutes, 30)
        XCTAssertTrue(opts2.setSSHAuthSock)
        XCTAssertTrue(opts2.keepGitSSHCommand)

        let opts3 = try AgentRunner.parse([
            "--key=key2",
            "--lease=45",
            "--ssh-auth-sock",
            "--", "ls"
        ])
        XCTAssertEqual(opts3.command, ["ls"])
        XCTAssertEqual(opts3.keyLabel, "key2")
        XCTAssertEqual(opts3.leaseMinutes, 45)
        XCTAssertTrue(opts3.setSSHAuthSock)
    }

    func test_001_T5_chooseKeySingleAgentKeyDefault() throws {
        let agentKey = makeKey(label: "agent-1", purpose: .agent)
        let personalKey = makeKey(label: "personal-1", purpose: .general)

        let chosen = try AgentRunner.chooseKey(nil, keys: [agentKey, personalKey])
        XCTAssertEqual(chosen.label, "agent-1")

        XCTAssertThrowsError(try AgentRunner.chooseKey(nil, keys: [personalKey])) { error in
            XCTAssertEqual(error as? AgentRunError, .noAgentKey)
        }
    }

    func test_001_T5_chooseKeyAmbiguousErrors() throws {
        let agentKey1 = makeKey(label: "agent-1", purpose: .agent)
        let agentKey2 = makeKey(label: "agent-2", purpose: .agent)

        XCTAssertThrowsError(try AgentRunner.chooseKey(nil, keys: [agentKey1, agentKey2])) { error in
            XCTAssertEqual(error as? AgentRunError, .ambiguousAgentKey(["agent-1", "agent-2"]))
        }

        let explicit = try AgentRunner.chooseKey("agent-2", keys: [agentKey1, agentKey2])
        XCTAssertEqual(explicit.label, "agent-2")
    }

    func test_001_T5_chooseKeyRefusesPersonalKey() throws {
        let personalKey = makeKey(label: "personal-1", purpose: .general)

        XCTAssertThrowsError(try AgentRunner.chooseKey("personal-1", keys: [personalKey])) { error in
            XCTAssertEqual(error as? AgentRunError, .notAgentKey("personal-1"))
        }

        XCTAssertThrowsError(try AgentRunner.chooseKey("unknown", keys: [personalKey])) { error in
            XCTAssertEqual(error as? AgentRunError, .unknownKey("unknown"))
        }
    }

    func test_001_T5_envSetsGitSSHCommandAndKeepsSSHAuthSock() throws {
        let base = ["SSH_AUTH_SOCK": "/tmp/personal.sock"]
        let opts = AgentRunOptions(setSSHAuthSock: false, command: ["git", "push"])
        let env = try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: opts
        )

        XCTAssertEqual(env["SSH_AUTH_SOCK"], "/tmp/personal.sock")
        XCTAssertEqual(env["GIT_SSH_COMMAND"], "ssh -o IdentityAgent='/tmp/agent.sock'")
        XCTAssertEqual(env["CLAVIS_AGENT_SOCK"], "/tmp/agent.sock")
        XCTAssertEqual(env["CLAVIS_AGENT_SESSION"], "sess-123")

        let optsWithSock = AgentRunOptions(setSSHAuthSock: true, command: ["git", "push"])
        let envWithSock = try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: optsWithSock
        )
        XCTAssertEqual(envWithSock["SSH_AUTH_SOCK"], "/tmp/agent.sock")
    }

    func test_001_T5_envRefusesExistingGitSSHCommand() throws {
        let base = ["GIT_SSH_COMMAND": "ssh -i /path/key"]
        let opts = AgentRunOptions(keepGitSSHCommand: false, command: ["git", "push"])

        XCTAssertThrowsError(try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: opts
        )) { error in
            XCTAssertEqual(error as? AgentRunError, .gitSSHCommandAlreadySet)
        }
    }

    func test_001_T5_envKeepFlagLeavesIt() throws {
        let base = ["GIT_SSH_COMMAND": "ssh -i /path/key"]
        let opts = AgentRunOptions(keepGitSSHCommand: true, command: ["git", "push"])

        let env = try AgentRunner.childEnvironment(
            base: base,
            agentSocket: "/tmp/agent.sock",
            sessionID: "sess-123",
            options: opts
        )
        XCTAssertEqual(env["GIT_SSH_COMMAND"], "ssh -i /path/key")
    }

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
        XCTAssertEqual(env["GIT_SSH_COMMAND"], expectedCmd)
    }

    func test_001_T5_spawnReturnsChildExitCode() throws {
        let code = try AgentRunner.spawnAndWait(["/bin/sh", "-c", "exit 7"], environment: [:])
        XCTAssertEqual(code, 7)
    }

    func test_001_T5_spawnReportsSignal() throws {
        let code = try AgentRunner.spawnAndWait(["/bin/sh", "-c", "kill -TERM $$"], environment: [:])
        XCTAssertEqual(code, 143)
    }
}
