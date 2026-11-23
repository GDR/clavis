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

    @Test func groupedByKeyGroupsMultiSessionAgentAndPersonalKeys() {
        let keys = [
            key("GitHub", purpose: .general, fingerprint: "fp-gh"),
            key("Agent Deploy", purpose: .agent, fingerprint: "fp-ag")
        ]
        let rows = MenuBarSession.active(
            gitGraces: [
                ActiveGitGraceInfo(keyLabel: "GitHub", remainingSeconds: 180, remainingOperations: 5, observedAt: now, callerName: "Terminal")
            ],
            agentSessions: [
                AgentSessionSummary(id: "s1", keyLabel: "Agent Deploy", keyFingerprint: "fp-ag", toolName: "Claude Code", rootPid: 11, startedAt: now, expiresAt: now.addingTimeInterval(600)),
                AgentSessionSummary(id: "s2", keyLabel: "Agent Deploy", keyFingerprint: "fp-ag", toolName: "Cursor", rootPid: 12, startedAt: now, expiresAt: now.addingTimeInterval(900))
            ],
            keys: keys,
            at: now,
            shareAcrossSSHHosts: { $0?.label == "Agent Deploy" }
        )

        let groups = MenuBarSession.groupedByKey(rows)
        #expect(groups.count == 2)

        let agentGroup = groups.first { $0.keyLabel == "Agent Deploy" }
        #expect(agentGroup?.sessions.count == 2)
        #expect(agentGroup?.isAgentKey == true)
        #expect(agentGroup?.sessions.allSatisfy(\.isBroadScope) == true)
        #expect(agentGroup?.sessions.allSatisfy { $0.effectiveScopeLabel == ClavisUIStrings.MenuBar.anyHost } == true)

        let personalGroup = groups.first { $0.keyLabel == "GitHub" }
        #expect(personalGroup?.sessions.count == 1)
        #expect(personalGroup?.sessions.first?.isBroadScope == false)
        #expect(personalGroup?.sessions.first?.effectiveScopeLabel == "Git signing")
    }

    @Test func broadScopeAppliesToPersonalSSHAndDualCapabilityAgentKeys() {
        let sshOnlyKey = SSHKeyInfo(
            label: "Bastion",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3 Bastion",
            publicKeyBlob: Data(),
            fingerprint: "fp-bastion",
            accessProfile: KeyAccessProfile(type: .personal, capabilities: .init(ssh: true, signature: false))
        )
        let dualAgentKey = SSHKeyInfo(
            label: "Dual Agent",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3 DualAgent",
            publicKeyBlob: Data(),
            fingerprint: "fp-dual",
            accessProfile: KeyAccessProfile(type: .bot, capabilities: .init(ssh: true, signature: true))
        )
        let sessions = MenuBarSession.active(
            gitGraces: [
                ActiveGitGraceInfo(keyLabel: "Bastion", remainingSeconds: 300, remainingOperations: 5, observedAt: now, callerName: "iTerm2")
            ],
            agentSessions: [
                AgentSessionSummary(id: "d1", keyLabel: "Dual Agent", keyFingerprint: "fp-dual", toolName: "Claude Code", rootPid: 21, startedAt: now, expiresAt: now.addingTimeInterval(900))
            ],
            keys: [sshOnlyKey, dualAgentKey],
            at: now,
            shareAcrossSSHHosts: { _ in true }
        )

        let bastion = sessions.first { $0.keyLabel == "Bastion" }
        #expect(bastion?.isBroadScope == true)
        #expect(bastion?.effectiveScopeLabel == "Any host")

        let dual = sessions.first { $0.keyLabel == "Dual Agent" }
        #expect(dual?.isBroadScope == true)
        #expect(dual?.effectiveScopeLabel == "Any host & Git")
    }
}
