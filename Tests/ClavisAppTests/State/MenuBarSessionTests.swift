import Foundation
import Testing
@testable import Clavis
@testable import ClavisCore

@Suite
struct MenuBarSessionTests {
    private let now = Date(timeIntervalSince1970: 1_000_000)

    private func key(
        _ label: String,
        purpose: KeyPurpose = .general,
        fingerprint: String? = nil,
        publicKeyOpenSSH: String = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@clavis"
    ) -> SSHKeyInfo {
        SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: publicKeyOpenSSH,
            publicKeyBlob: Data(),
            fingerprint: fingerprint ?? "SHA256:\(label)",
            keyPurpose: purpose
        )
    }

    private func agent(_ id: String, key: String = "Agent key", seconds: TimeInterval = 60, tool: String = "Claude Code") -> AgentSessionSummary {
        AgentSessionSummary(
            id: id,
            keyLabel: key,
            keyFingerprint: "SHA256:\(key)",
            toolName: tool,
            rootPid: 123,
            startedAt: now,
            expiresAt: now.addingTimeInterval(seconds)
        )
    }

    @Test func deduplicatesPersonalGrantsPerKeyWhilePreservingIndividualAgentTargets() {
        let graces = [
            ActiveGitGraceInfo(keyLabel: "Git 1", remainingSeconds: 120, remainingOperations: 5, observedAt: now, callerName: "Terminal"),
            ActiveGitGraceInfo(keyLabel: "Git 1", remainingSeconds: 300, remainingOperations: 5, observedAt: now, endsAtLock: true, callerName: "git"),
            ActiveGitGraceInfo(keyLabel: "Git 2", remainingSeconds: 300, remainingOperations: 5, observedAt: now)
        ]
        let rows = MenuBarSession.active(
            gitGraces: graces,
            agentSessions: [agent("a"), agent("b")],
            keys: [],
            at: now
        )
        #expect(rows.count == 4)
        #expect(Set(rows.map(\.id)) == [.git(keyLabel: "Git 1"), .git(keyLabel: "Git 2"), .agent(sessionID: "a"), .agent(sessionID: "b")])

        let mergedGit1 = rows.first { $0.id == .git(keyLabel: "Git 1") }
        #expect(mergedGit1?.endsAtLock == true)
        #expect(mergedGit1?.callerName == "Terminal")
        #expect(mergedGit1?.expiresAt == now.addingTimeInterval(300))
    }

    @Test func usesKeyPurposeIconsAndSubtitlesWithCallerFallback() {
        let keys = [
            key("Git", purpose: .gitSigningOnly),
            key("Agent key", purpose: .agent)
        ]
        let rows = MenuBarSession.active(
            gitGraces: [
                ActiveGitGraceInfo(keyLabel: "Git", remainingSeconds: 30, remainingOperations: 1, observedAt: now)
            ],
            agentSessions: [agent("agent", tool: "Claude Code")],
            keys: keys,
            at: now
        )
        let gitRow = rows.first { $0.keyLabel == "Git" }
        let agentRow = rows.first { $0.keyLabel == "Agent key" }
        #expect(gitRow?.purpose == .gitSigningOnly)
        #expect(gitRow?.isAgentKey == false)
        #expect(gitRow?.iconSystemName == "person.fill")
        #expect(gitRow?.subtitle == "Git signing")

        #expect(agentRow?.purpose == .agent)
        #expect(agentRow?.isAgentKey == true)
        #expect(agentRow?.iconSystemName == "cpu")
        #expect(agentRow?.callerName == "Claude Code")
        #expect(agentRow?.subtitle == "Claude Code")
    }

    @Test func excludesExpiredAndExhaustedAuthorizations() {
        let rows = MenuBarSession.active(
            gitGraces: [
                ActiveGitGraceInfo(keyLabel: "Expired", remainingSeconds: 0, remainingOperations: 1, observedAt: now),
                ActiveGitGraceInfo(keyLabel: "Exhausted", remainingSeconds: 60, remainingOperations: 0, observedAt: now)
            ],
            agentSessions: [agent("expired", seconds: 0), agent("past", seconds: -1)],
            keys: [],
            at: now
        )
        #expect(rows.isEmpty)
    }

    @Test func formatsRoundedUnitsMinutesHoursDaysYearsAndEndsOnLock() {
        #expect(MenuBarSession.formatRemaining(0) == "1m left")
        #expect(MenuBarSession.formatRemaining(1) == "1m left")
        #expect(MenuBarSession.formatRemaining(59) == "1m left")
        #expect(MenuBarSession.formatRemaining(65) == "2m left")
        #expect(MenuBarSession.formatRemaining(272) == "5m left")
        #expect(MenuBarSession.formatRemaining(3580) == "1h left")
        #expect(MenuBarSession.formatRemaining(5400) == "2h left")
        #expect(MenuBarSession.formatRemaining(86_400) == "1d left")
        #expect(MenuBarSession.formatRemaining(365 * 86_400) == "1y left")

        let rows = MenuBarSession.active(
            gitGraces: [
                ActiveGitGraceInfo(keyLabel: "Timed", remainingSeconds: 65, remainingOperations: 3, observedAt: now),
                ActiveGitGraceInfo(keyLabel: "Session", remainingSeconds: 86_400, remainingOperations: 3, observedAt: now, endsAtLock: true)
            ],
            agentSessions: [],
            keys: [],
            at: now
        )

        let timed = rows.first { $0.keyLabel == "Timed" }
        #expect(timed?.remainingTime(at: now) == "2m left")
        #expect(timed?.isExpiringSoon(at: now) == false)
        #expect(timed?.remainingTime(at: now.addingTimeInterval(5)) == "1m left")
        #expect(timed?.isExpiringSoon(at: now.addingTimeInterval(5)) == true)
        #expect(timed?.remainingTime(at: now.addingTimeInterval(64)) == "1m left")
        #expect(timed?.isExpiringSoon(at: now.addingTimeInterval(64)) == true)

        let untilLock = rows.first { $0.keyLabel == "Session" }
        #expect(untilLock?.endsAtLock == true)
        #expect(untilLock?.remainingTime(at: now) == "Ends on lock")
        #expect(untilLock?.isExpiringSoon(at: now) == false)
    }

    @Test func inactiveKeysExcludesActiveByLabelAndFingerprintAndSorts() {
        let allKeys = [
            key("Zeta", purpose: .agent, fingerprint: "fp-zeta"),
            key("Alpha", purpose: .general, fingerprint: "fp-alpha"),
            key("Beta", purpose: .gitSigningOnly, fingerprint: "fp-beta"),
            key("Agent Active", purpose: .agent, fingerprint: "fp-agent")
        ]
        let active = MenuBarSession.active(
            gitGraces: [ActiveGitGraceInfo(keyLabel: "Alpha", remainingSeconds: 300, remainingOperations: 5, observedAt: now)],
            agentSessions: [AgentSessionSummary(id: "s1", keyLabel: "Agent Active", keyFingerprint: "fp-agent", toolName: "Claude", rootPid: 10, startedAt: now, expiresAt: now.addingTimeInterval(600))],
            keys: allKeys,
            at: now
        )
        let inactive = MenuBarSession.inactiveKeys(from: allKeys, active: active)
        #expect(inactive.map(\.label) == ["Beta", "Zeta"])
    }
}
