import Foundation
import Testing
@testable import ClavisCore

@Suite struct LocalizationTests {

    @Test func testInspectorLocalizedStrings() {
        #expect(!ClavisUIStrings.Inspector.usedBySection.isEmpty)
        #expect(ClavisUIStrings.Inspector.statusReady == "Ready")
        #expect(ClavisUIStrings.Inspector.statusUnsupported == "Unsupported")
        #expect(ClavisUIStrings.Inspector.statusConfigured == "Configured")
        #expect(ClavisUIStrings.Inspector.statusIncompatible == "Incompatible")

        #expect(!ClavisUIStrings.Inspector.securitySection.isEmpty)
        #expect(ClavisUIStrings.Inspector.storageHardwareEnclave == "Apple Secure Enclave (Hardware Chip)")
        #expect(ClavisUIStrings.Inspector.storageSoftwareKeychain == "macOS Login Keychain (Software)")
    }

    @Test func testFeedbackStrings() {
        #expect(ClavisUIStrings.Inspector.feedbackLockedKey("id_rsa") == "Locked 'id_rsa'")
    }

    @Test func testKeyListLocalizedStrings() {
        #expect(ClavisUIStrings.KeyList.title == "Keys")
        #expect(ClavisUIStrings.KeyList.identitiesAvailable(count: 1) == "1 identity available")
        #expect(ClavisUIStrings.KeyList.identitiesAvailable(count: 3) == "3 identities available")
        #expect(ClavisUIStrings.KeyList.noKeySelectedTitle == "No Key Selected")
        #expect(ClavisUIStrings.KeyList.deletedKey(label: "my-key") == "Deleted key 'my-key'.")
        #expect(ClavisUIStrings.KeyList.allCachedKeysLocked == "All cached keys locked.")
    }

    @Test func testMenuBarQuitAlertStrings() {
        #expect(ClavisUIStrings.MenuBar.quitConfirmationTitle == "Quit Clavis?")
        #expect(!ClavisUIStrings.MenuBar.quitConfirmationDetailsWithAgent.isEmpty)
        #expect(!ClavisUIStrings.MenuBar.quitConfirmationDetailsSimple.isEmpty)
    }

    @Test func testCommonMinRemaining() {
        #expect(ClavisUIStrings.Common.minRemaining(5) == "5 min remaining")
        #expect(ClavisUIStrings.Common.appName == "Clavis")
        #expect(ClavisUIStrings.Common.cancel == "Cancel")
        #expect(ClavisUIStrings.Common.delete == "Delete")
        #expect(ClavisUIStrings.Common.copy == "Copy")
        #expect(ClavisUIStrings.Common.copied == "Copied")
        #expect(ClavisUIStrings.Common.error == "Error")
        #expect(ClavisUIStrings.Common.ok == "OK")
    }

    @Test func testBadges() {
        #expect(ClavisUIStrings.Badges.hardware == "Hardware")
        #expect(ClavisUIStrings.Badges.software == "Software")
        #expect(ClavisUIStrings.Badges.gitOnly == "Git Only")
    }

    @Test func testAddKeyPopoverStrings() {
        #expect(ClavisUIStrings.AddKeyPopover.header == "ADD KEY")
        #expect(ClavisUIStrings.AddKeyPopover.newKeyTitle == "New Key…")
        #expect(ClavisUIStrings.AddKeyPopover.newKeySubtitle == "Generate a new cryptographic identity")
    }

    @Test func testCreateKeyStrings() {
        #expect(ClavisUIStrings.CreateKey.title == "Create New Key")
        #expect(ClavisUIStrings.CreateKey.nameLabel == "Key Name")
        #expect(ClavisUIStrings.CreateKey.typeLabel == "Key Type")
        #expect(ClavisUIStrings.CreateKey.biometricPolicyLabel == "Biometric Authentication Policy")
        #expect(ClavisUIStrings.CreateKey.purposeLabel == "Key Purpose & Scope")
        #expect(ClavisUIStrings.CreateKey.generateButton == "Generate Key")
        #expect(ClavisUIStrings.CreateKey.enclaveUnavailable == "Apple Secure Enclave is not available on this device.")
        #expect(ClavisUIStrings.CreateKey.tagSSH == "SSH")
        #expect(ClavisUIStrings.CreateKey.tagGitSigning == "Git Signing")
    }

    @Test func testBiometricPolicyAndKeyPurpose() {
        #expect(BiometricPolicy.userPresence.title == "User Presence")
        #expect(BiometricPolicy.biometryCurrentSet.title == "Strict Biometrics")
        #expect(KeyPurpose.general.title == "General (SSH & Git)")
        #expect(KeyPurpose.gitSigningOnly.title == "Git Signing Only")
        #expect(KeyPurpose.agent.title == "Agent")
    }

    @Test func testPromptStrings() {
        #expect(ClavisUIStrings.Prompt.sshAuthentication(keyLabel: "my-key") == "use “my-key” for SSH authentication")
        #expect(ClavisUIStrings.Prompt.gitCommitSigning(keyLabel: "my-key") == "sign a Git commit with “my-key”")
        #expect(ClavisUIStrings.Prompt.gitSigningSession(keyLabel: "my-key") == "authorize a 5-minute Git signing session with “my-key”")
        #expect(
            ClavisUIStrings.AgentSession.approvePrompt(tool: "/usr/bin/claude", keyLabel: "my-key", minutes: 30)
            == "Start agent session for “claude” with key “my-key” for 30 minutes"
        )
    }

    @Test func testMenuBarFormatting() {
        #expect(ClavisUIStrings.MenuBar.activeWithPID(1234) == "Active (PID 1234)")
        #expect(ClavisUIStrings.MenuBar.identitiesReady(count: 1) == "1 identity ready")
        #expect(ClavisUIStrings.MenuBar.identitiesReady(count: 5) == "5 identities ready")
        #expect(ClavisUIStrings.MenuBar.gitSessionTitle(label: "deploy") == "Git Session: deploy")
        #expect(ClavisUIStrings.MenuBar.gitSessionDetails(timeRemaining: "4:32", opsLeft: 3) == "4:32 remaining • 3 ops left")
    }

    @Test func testAppSettingsAndAuth() {
        #expect(ClavisUIStrings.Settings.windowTitle == "Settings")
        #expect(ClavisUIStrings.App.unsupportedTitle == "Clavis cannot run on this Mac")
        #expect(ClavisUIStrings.App.unsupportedMessage == "Clavis requires a Mac with Secure Enclave support.")
        #expect(ClavisUIStrings.Auth.errorTimedOut == "User authentication timed out")
        #expect(ClavisUIStrings.Auth.errorRejected == "User authentication failed or was cancelled")
    }

    @Test func testXCStringsTranslationsIntegrity() throws {
        // Find Localizable.xcstrings in the repository
        let thisFile = URL(fileURLWithPath: #filePath)
        let repoRoot = thisFile.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let xcstringsURL = repoRoot.appendingPathComponent("Sources/ClavisCore/Resources/Localizable.xcstrings")

        let data = try Data(contentsOf: xcstringsURL)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let unwrappedJson = try #require(json)

        let strings = unwrappedJson["strings"] as? [String: [String: Any]]
        let unwrappedStrings = try #require(strings)
        #expect(unwrappedStrings.count > 100)

        // Verify every entry has non-empty en and ru translations
        for (key, entry) in unwrappedStrings {
            guard let localizations = entry["localizations"] as? [String: [String: Any]] else {
                Issue.record("Missing localizations dict for key: \(key)")
                continue
            }
            guard let enUnit = localizations["en"]?["stringUnit"] as? [String: Any],
                  let enVal = enUnit["value"] as? String, !enVal.isEmpty else {
                Issue.record("Missing or empty 'en' localization for key: \(key)")
                continue
            }
            guard let ruUnit = localizations["ru"]?["stringUnit"] as? [String: Any],
                  let ruVal = ruUnit["value"] as? String, !ruVal.isEmpty else {
                Issue.record("Missing or empty 'ru' localization for key: \(key)")
                continue
            }
        }
    }

    @Test func testGitSigningPromptStringsEnglishDefaults() {
        let strings = GitSigningPromptStrings.localized
        #expect(strings.header == "Clavis — Git Signing Session")
        #expect(strings.allowFiveMinutesButton == "Grant 5 Minutes")
        #expect(strings.cancelButton == "Cancel")
        #expect(strings.singleShotButton == "Sign Once")

        let msg = strings.messageTemplate("test-key", "git (PID 100)")
        #expect(msg.contains("Detected a series of Git commits"))
        #expect(msg.contains("Grant automatic Git signing for 5 minutes"))
        // Must contain no Cyrillic characters
        #expect(!msg.unicodeScalars.contains(where: { ("\u{0400}"..."\u{04FF}").contains($0) }))
    }

    @Test func testEveryKeyHasEnglishDefaultInXCStrings() throws {
        let thisFile = URL(fileURLWithPath: #filePath)
        let repoRoot = thisFile.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let xcstringsURL = repoRoot.appendingPathComponent("Sources/ClavisCore/Resources/Localizable.xcstrings")

        let data = try Data(contentsOf: xcstringsURL)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let strings = json?["strings"] as? [String: [String: Any]] ?? [:]

        #expect(!strings.isEmpty)
        for (key, entry) in strings {
            let localizations = entry["localizations"] as? [String: [String: Any]]
            let enUnit = localizations?["en"]?["stringUnit"] as? [String: Any]
            let enVal = enUnit?["value"] as? String
            #expect(enVal != nil, "Key '\(key)' is missing English default translation")
            #expect(!(enVal?.isEmpty ?? true), "Key '\(key)' has empty English default translation")
        }
    }

    @Test func testHistoryLocalizedStrings() {
        let expectedStrings: [(String, String)] = [
            (ClavisUIStrings.History.windowTitle, "Signing History"),
            (ClavisUIStrings.History.showHistory, "Show History"),
            (ClavisUIStrings.History.filterAllKeys, "All Keys"),
            (ClavisUIStrings.History.filterAllKinds, "All Types"),
            (ClavisUIStrings.History.filterKindPersonal, "Personal"),
            (ClavisUIStrings.History.filterKindAgent, "Agent"),
            (ClavisUIStrings.History.filterAllResult, "All Results"),
            (ClavisUIStrings.History.filterRangeHour, "Last Hour"),
            (ClavisUIStrings.History.filterRangeDay, "Last 24 Hours"),
            (ClavisUIStrings.History.filterRangeWeek, "Last 7 Days"),
            (ClavisUIStrings.History.filterRangeAll, "All Time"),
            (ClavisUIStrings.History.resultAllowed, "Allowed"),
            (ClavisUIStrings.History.resultDenied, "Denied"),
            (ClavisUIStrings.History.resultCancelled, "Cancelled"),
            (ClavisUIStrings.History.resultFailed, "Failed"),
            (ClavisUIStrings.History.resultInfo, "Info"),
            (ClavisUIStrings.History.empty, "No audit events recorded"),
            (ClavisUIStrings.History.export, "Export…"),
            (ClavisUIStrings.History.suppressedCount(5), "5 similar events suppressed"),
            (ClavisUIStrings.History.unreadable, "Unreadable (history key changed)"),
            (ClavisUIStrings.History.omitted, "—"),
            (ClavisUIStrings.History.omittedTooltip, "Details were not recorded"),
            (ClavisUIStrings.History.checkIntegrity, "Check Integrity"),
            (ClavisUIStrings.History.checkIntegrityTitle, "Audit History Integrity"),
            (ClavisUIStrings.History.checkingIntegrity, "Checking history integrity…"),
            (ClavisUIStrings.History.checkStatusOk, "History is intact"),
            (ClavisUIStrings.History.checkStatusOkDesc, "No missing or altered records detected within the verification window."),
            (ClavisUIStrings.History.checkStatusProblems, "Potential tampering detected"),
            (ClavisUIStrings.History.checkStatusProblemsDesc, "Discrepancies found between local database and system witness records."),
            (ClavisUIStrings.History.checkStatusUnavailable, "Integrity check unavailable"),
            (ClavisUIStrings.History.checkCheckedRows(10), "Checked rows: 10"),
            (ClavisUIStrings.History.checkMissingRows(2), "Missing rows: 2"),
            (ClavisUIStrings.History.checkInconsistentRows(1), "Inconsistent rows: 1"),
            (ClavisUIStrings.History.checkTruncatedTail, "History tail truncated: Yes"),
            (ClavisUIStrings.History.checkProblemsHeader, "Detected Problems"),
            (ClavisUIStrings.History.checkMissingRowFormat(seq: 5, witnessedAt: "2026-10-06"), "Missing sequence 5 (witnessed 2026-10-06)"),
            (ClavisUIStrings.History.checkInconsistentRowFormat(seq: 3), "Inconsistent row sequence 3"),
            (ClavisUIStrings.History.checkLearnMore, "Learn more"),
            (ClavisUIStrings.History.gapBanner(count: 3), "3 entries missing (gap detected)"),
        ]
        for (actual, expected) in expectedStrings {
            #expect(actual == expected)
        }
        #expect(!ClavisUIStrings.History.checkRetentionExplanation.isEmpty)
    }

    @Test func testPanelLockLocalizedStrings() {
        let expectedStrings: [(String, String)] = [
            (ClavisUIStrings.PanelLock.title, "Clavis is locked"),
            (ClavisUIStrings.PanelLock.unlock, "Unlock"),
            (ClavisUIStrings.PanelLock.unlockMenu, "Unlock Clavis…"),
            (ClavisUIStrings.PanelLock.reason, "unlock Clavis"),
            (ClavisUIStrings.PanelLock.disableReason, "Modify control panel lock settings"),
            (ClavisUIStrings.PanelLock.settingsSection, "Control Panel Lock"),
            (ClavisUIStrings.PanelLock.settingsToggle, "Require authentication to open Clavis"),
            (ClavisUIStrings.PanelLock.settingsIdle, "Lock after inactivity"),
            (ClavisUIStrings.PanelLock.minutesFormat(5), "5 min"),
            (ClavisUIStrings.PanelLock.agentSessionsCount(2), "2 agent sessions running"),
        ]
        for (actual, expected) in expectedStrings {
            #expect(actual == expected)
        }
    }

    @Test func testAgentKeyLocalizedStrings() {
        let expectedStrings: [(String, String)] = [
            (ClavisUIStrings.KeyPurposeStrings.agentTitle, "Agent"),
            (ClavisUIStrings.KeyPurposeStrings.agentSubtitle, "Only usable by agents you start through Clavis. Never offered to your terminal."),
            (ClavisUIStrings.KeyList.filterAll, "All"),
            (ClavisUIStrings.KeyList.filterPersonal, "Personal"),
            (ClavisUIStrings.KeyList.filterAgent, "Agent"),
            (ClavisUIStrings.Badges.agent, "Agent"),
            (ClavisUIStrings.KeyDetail.copyDeployKey, "Copy Deploy Key"),
            (ClavisUIStrings.KeyDetail.changeKind, "Change Kind…"),
            (ClavisUIStrings.KeyDetail.changeKindConfirm, "Change Kind"),
        ]
        for (actual, expected) in expectedStrings {
            #expect(actual == expected)
        }
        #expect(!ClavisUIStrings.KeyDetail.changeKindAlertMessage(label: "test-key", newPurpose: .agent).isEmpty)
    }

    @Test func testAgentSessionLocalizedStrings() {
        let expectedStrings: [(String, String)] = [
            (ClavisUIStrings.AgentSession.menuSection, "Agent Sessions"),
            (ClavisUIStrings.AgentSession.end, "End"),
            (ClavisUIStrings.AgentSession.remainingFormat(minutes: 12), "12 min remaining"),
            (ClavisUIStrings.AgentSession.historyShowSession, "Show session"),
            (ClavisUIStrings.AgentSession.historyEndSession, "End session"),
            (ClavisUIStrings.AgentSession.extend, "Extend…"),
            (ClavisUIStrings.AgentSession.extend30m, "+30 min"),
            (ClavisUIStrings.AgentSession.extend1h, "+1 hour"),
            (ClavisUIStrings.AgentSession.extend4h, "+4 hours"),
            (ClavisUIStrings.AgentSession.extendPrompt, "Extend agent session"),
            (ClavisUIStrings.AgentSession.askPrompt, "Approve agent signature"),
            (ClavisUIStrings.AgentSession.revokeAll, "Revoke all agent sessions"),
            (ClavisUIStrings.AgentSession.notificationSignedTitle, "Agent signed"),
            (ClavisUIStrings.AgentSession.notificationRateLimitedTitle, "Agent rate limited"),
        ]
        for (actual, expected) in expectedStrings {
            #expect(actual == expected)
        }
    }

    @Test func testAgentPolicyLocalizedStrings() {
        let expectedStrings: [(String, String)] = [
            (ClavisUIStrings.AgentPolicy.sectionTitle, "Agent Session Policy"),
            (ClavisUIStrings.AgentPolicy.modeTitle, "Approval Mode"),
            (ClavisUIStrings.AgentPolicy.modeNone, "None (Silent)"),
            (ClavisUIStrings.AgentPolicy.modeNotify, "Notify"),
            (ClavisUIStrings.AgentPolicy.modeAsk, "Ask every time"),
            (ClavisUIStrings.AgentPolicy.leaseTitle, "Session Length"),
            (ClavisUIStrings.AgentPolicy.allowedHostsTitle, "Allowed Hosts"),
            (ClavisUIStrings.AgentPolicy.allowedHostsAny, "Any host"),
            (ClavisUIStrings.AgentPolicy.addHost, "Add host…"),
            (ClavisUIStrings.AgentPolicy.addHostButton, "Add"),
            (ClavisUIStrings.AgentPolicy.hostNotFound, "Host not found in known_hosts — connect once with ssh first"),
            (ClavisUIStrings.AgentPolicy.rateLimitTitle, "Rate Limit"),
            (ClavisUIStrings.AgentPolicy.burstTitle, "Burst"),
            (ClavisUIStrings.AgentPolicy.refillTitle, "Refill per minute"),
            (ClavisUIStrings.AgentPolicy.saveButton, "Save Policy"),
            (ClavisUIStrings.AgentPolicy.savedFeedback, "Policy saved"),
            (ClavisUIStrings.AgentPolicy.globalMaxLease, "Maximum agent session length"),
            (ClavisUIStrings.AgentPolicy.changePrompt, "Change agent session policy"),
        ]
        for (actual, expected) in expectedStrings {
            #expect(actual == expected)
        }
    }

    @Test func testPinUnlockLocalizedStrings() {
        let expectedStrings: [(String, String)] = [
            (ClavisUIStrings.PinUnlock.pinLabel, "PIN"),
            (ClavisUIStrings.PinUnlock.pinPlaceholder, "Enter PIN"),
            (ClavisUIStrings.PinUnlock.confirmPinPlaceholder, "Confirm PIN"),
            (ClavisUIStrings.PinUnlock.unlock, "Unlock"),
            (ClavisUIStrings.PinUnlock.useTouchID, "Use Touch ID"),
            (ClavisUIStrings.PinUnlock.usePassword, "Use login password…"),
            (ClavisUIStrings.PinUnlock.wrongPIN, "Incorrect PIN"),
            (ClavisUIStrings.PinUnlock.waitFormat(30), "Try again in 30 s"),
            (ClavisUIStrings.PinUnlock.passwordRequired, "PIN is disabled. Login password required."),
            (ClavisUIStrings.PinUnlock.historyBanner, "Enter PIN to read details"),
            (ClavisUIStrings.PinUnlock.tooShort, "PIN must be at least 6 characters."),
            (ClavisUIStrings.PinUnlock.pinMismatch, "PINs do not match."),
            (ClavisUIStrings.PinUnlock.changePIN, "Change PIN…"),
            (ClavisUIStrings.PinUnlock.forgotPIN, "Forgot PIN…"),
            (ClavisUIStrings.PinUnlock.settingsSection, "Unlock Method"),
            (ClavisUIStrings.PinUnlock.modePasswordOrBiometry, "Touch ID or password"),
            (ClavisUIStrings.PinUnlock.modeBiometryOrPIN, "Touch ID or PIN"),
            (ClavisUIStrings.PinUnlock.modeBiometryAndPIN, "Touch ID and PIN"),
            (ClavisUIStrings.PinUnlock.setPinTitle, "Set PIN"),
        ]
        for (actual, expected) in expectedStrings {
            #expect(actual == expected)
        }
        #expect(!ClavisUIStrings.PinUnlock.warningOrMode.isEmpty)
        #expect(!ClavisUIStrings.PinUnlock.resetWarning.isEmpty)
    }
}
