import Foundation
import Testing
@testable import Clavis
@testable import ClavisCore

@Suite
struct MenuBarSessionTests {
    private let now = Date(timeIntervalSince1970: 1000)

    private func key(_ label: String, purpose: KeyPurpose) -> SSHKeyInfo {
        SSHKeyInfo(label: label, publicKeyOpenSSH: "", publicKeyBlob: Data(), fingerprint: label, keyPurpose: purpose)
    }

    private func agent(_ id: String, key: String = "Agent key", seconds: TimeInterval = 60) -> AgentSessionSummary {
        AgentSessionSummary(id: id, keyLabel: key, keyFingerprint: key, toolName: "Tool", rootPid: 123,
                            startedAt: now, expiresAt: now.addingTimeInterval(seconds))
    }

    @Test func includesAllGitKeysAndPreservesIndividualAgentTargets() {
        let graces = ["Git 1", "Git 2"].map {
            ActiveGitGraceInfo(keyLabel: $0, remainingSeconds: 300, remainingOperations: 5, observedAt: now)
        }
        let rows = MenuBarSession.active(gitGraces: graces, agentSessions: [agent("a"), agent("b")], keys: [], at: now)
        #expect(rows.count == 4)
        #expect(Set(rows.map(\.id)) == [.git(keyLabel: "Git 1"), .git(keyLabel: "Git 2"), .agent(sessionID: "a"), .agent(sessionID: "b")])
    }

    @Test func usesKeyPurposeInsteadOfAlgorithmOrClientName() {
        let rows = MenuBarSession.active(
            gitGraces: [ActiveGitGraceInfo(keyLabel: "Git", remainingSeconds: 30, remainingOperations: 1, observedAt: now)],
            agentSessions: [agent("agent")],
            keys: [key("Git", purpose: .gitSigningOnly), key("Agent key", purpose: .agent)], at: now)
        #expect(rows.first { $0.keyLabel == "Git" }?.purpose == .gitSigningOnly)
        #expect(rows.first { $0.keyLabel == "Agent key" }?.purpose == .agent)
        #expect(rows.first { $0.keyLabel == "Agent key" }?.toolName == "Tool")
    }

    @Test func excludesExpiredAndExhaustedAuthorizations() {
        let rows = MenuBarSession.active(gitGraces: [
            ActiveGitGraceInfo(keyLabel: "Expired", remainingSeconds: 0, remainingOperations: 1, observedAt: now),
            ActiveGitGraceInfo(keyLabel: "Exhausted", remainingSeconds: 60, remainingOperations: 0, observedAt: now)
        ], agentSessions: [agent("expired", seconds: 0), agent("past", seconds: -1)], keys: [], at: now)
        #expect(rows.isEmpty)
    }

    @Test func countdownAdvancesWithoutRenewingTheSnapshot() {
        let rows = MenuBarSession.active(gitGraces: [
            ActiveGitGraceInfo(keyLabel: "General", remainingSeconds: 65, remainingOperations: 3, observedAt: now)
        ], agentSessions: [], keys: [], at: now)
        #expect(rows[0].purpose == .general)
        #expect(rows[0].remainingTime(at: now) == "1:05")
        #expect(rows[0].remainingTime(at: now.addingTimeInterval(6)) == "0:59")
        #expect(rows[0].remainingTime(at: now.addingTimeInterval(66)) == "0:00")
        #expect(MenuBarSession.active(gitGraces: [], agentSessions: [agent("a")], keys: [], at: now.addingTimeInterval(61)).isEmpty)
    }
}
