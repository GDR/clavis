@testable import ClavisTestSupport
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
        #expect(ClavisUIStrings.Inspector.postureGeneral == "Prompts Touch ID for each SSH authentication or Git signing request.")
        #expect(ClavisUIStrings.Inspector.socketStatusActive == "Active")
        #expect(ClavisUIStrings.Inspector.socketStatusOffline == "Offline")
        #expect(ClavisUIStrings.Inspector.changeKeyPurpose == "Change Key Purpose…")
        #expect(ClavisUIStrings.Inspector.revokeGitSession == "Revoke Session")
        #expect(ClavisUIStrings.Inspector.gitSessionOperationsLeft(5) == "5 operations remaining")
        #expect(ClavisUIStrings.Inspector.deleteAlertMessage(label: "test", fingerprint: "SHA256:abc") == "Are you sure you want to delete 'test' (SHA256:abc)? This action cannot be undone.")
    }

    @Test func testInspectorNewLocalizationStrings() {
        // Section headers & buttons
        #expect(ClavisUIStrings.Inspector.activeGitSessionSection == "ACTIVE GIT SIGNING SESSION")
        #expect(ClavisUIStrings.Inspector.revokeGitSessionButton == "Revoke")

        // Purpose change feedback toasts
        #expect(ClavisUIStrings.Inspector.feedbackChangedPurposeToAgent == "Changed purpose to Agent")
        #expect(ClavisUIStrings.Inspector.feedbackChangedPurposeToGeneral == "Changed purpose to General")
        #expect(ClavisUIStrings.Inspector.feedbackChangedPurpose(to: .agent) == "Changed purpose to Agent")
        #expect(ClavisUIStrings.Inspector.feedbackChangedPurpose(to: .general) == "Changed purpose to General")

        // Destructive description
        #expect(
            ClavisUIStrings.Inspector.deleteKeyDescription(label: "prod-key", fingerprint: "SHA256:abc")
            == "Permanently remove 'prod-key' (SHA256:abc) from the Secure Enclave."
        )

        // Socket names
        #expect(ClavisUIStrings.Inspector.socketNameSSHAgent == "ssh-agent socket")
        #expect(ClavisUIStrings.Inspector.socketNameAgent == "agent socket")

        // Security badges
        #expect(ClavisUIStrings.Inspector.badgeSilent == "Silent")
        #expect(ClavisUIStrings.Inspector.badgeNotify == "Notify")
        #expect(ClavisUIStrings.Inspector.badgeGraceActive == "Grace Active")

        // Dynamic subtitles
        #expect(ClavisUIStrings.Inspector.subtitleGitGraceActive == "Hardware Isolated · Git signing grace active")
        #expect(ClavisUIStrings.Inspector.subtitleAgentSilent == "Hardware Isolated · Silent agent lease")
        #expect(ClavisUIStrings.Inspector.subtitleAgentNotify == "Hardware Isolated · Agent lease with notification")
        #expect(ClavisUIStrings.Inspector.subtitleAgentAsk == "Hardware Isolated · Touch ID prompt per agent signature")
        #expect(ClavisUIStrings.Inspector.subtitleGitSigningOnly == "Hardware Isolated · Git commit signing only")

        // Posture titles & descriptions
        #expect(ClavisUIStrings.Inspector.postureAgentTitle == "Hardware Isolation (Agent Policy)")
        #expect(ClavisUIStrings.Inspector.postureAgentSilentDesc(lease: "8h").contains("operate silently without prompts"))
        #expect(ClavisUIStrings.Inspector.postureAgentNotifyDesc(lease: "2h").contains("post a notification on each signature"))
        #expect(ClavisUIStrings.Inspector.postureAgentAskDesc.contains("explicit Touch ID user confirmation"))
        #expect(ClavisUIStrings.Inspector.postureGitSigningOnlyTitle == "Hardware Isolation (Git Signing Only)")
        #expect(ClavisUIStrings.Inspector.postureGitSigningOnlyDesc.contains("Restricted strictly to local Git commit"))
        #expect(ClavisUIStrings.Inspector.postureGitGraceActiveSuffix.contains("5-minute Git signing grace session is currently active"))
        #expect(ClavisUIStrings.Inspector.postureGeneralStrictDesc.contains("Secure Enclave strictly requires Touch ID"))
        #expect(ClavisUIStrings.Inspector.postureGeneralPresenceDesc.contains("Signatures require Touch ID user presence"))
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
        #expect(ClavisUIStrings.KeyList.searchHelp == "Search keys (⌘F)")
        #expect(ClavisUIStrings.KeyList.addKeyHelp == "Create New Key (⌘N)")
        #expect(ClavisUIStrings.KeyList.onboardingTitle == "Welcome to Clavis")
        #expect(ClavisUIStrings.KeyList.onboardingSubtitle == "Generate your first hardware-bound SSH key to get started.")
        #expect(ClavisUIStrings.KeyList.contextMenuCopyPublicKey == "Copy Public Key")
        #expect(ClavisUIStrings.KeyList.contextMenuCopyFingerprint == "Copy Fingerprint")
        #expect(ClavisUIStrings.KeyList.contextMenuDeleteKey == "Delete Key…")
    }

    @Test func testMenuBarQuitAlertStrings() {
        #expect(ClavisUIStrings.MenuBar.quitConfirmationTitle == "Quit Clavis?")
        #expect(!ClavisUIStrings.MenuBar.quitConfirmationDetailsWithAgent.isEmpty)
        #expect(!ClavisUIStrings.MenuBar.quitConfirmationDetailsSimple.isEmpty)
        #expect(ClavisUIStrings.MenuBar.noKeysHint == "Create an SSH key to start")
        #expect(ClavisUIStrings.MenuBar.showAllKeys(count: 6) == "Show all 6 keys…")
        #expect(ClavisUIStrings.MenuBar.showAllKeysSimple == "Show all keys…")
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
        #expect(ClavisUIStrings.Common.retry == "Retry")
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
        #expect(ClavisUIStrings.CreateKey.hardwareEnclaveCardTitle == "Apple Secure Enclave")
        #expect(ClavisUIStrings.CreateKey.hardwareEnclaveCardSubtitle == "Hardware-bound NIST P-256 identity protected by biometric authentication.")
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
        #expect(ClavisUIStrings.Settings.vaultSection == "VAULT INTEGRITY")
        #expect(ClavisUIStrings.Settings.vaultHealthy == "Hardware vault cache is synchronized and healthy.")
        #expect(ClavisUIStrings.Settings.vaultDesyncWarning == "Vault desynchronization detected")
        #expect(ClavisUIStrings.Settings.vaultDesyncDetails(3) == "3 anomalies detected between keychain and public key store.")
        #expect(ClavisUIStrings.Settings.vaultRepairButton == "Repair Vault")
        #expect(ClavisUIStrings.Settings.aboutSection == "ABOUT CLAVIS")
        #expect(ClavisUIStrings.Settings.versionLabel == "Version")
        #expect(ClavisUIStrings.Settings.commitShaLabel == "Commit SHA")
        #expect(ClavisUIStrings.Settings.codeSigningLabel == "Code Signing Identity")
        #expect(ClavisUIStrings.Settings.daemonParityLabel == "Daemon Version Parity")
        #expect(ClavisUIStrings.App.unsupportedTitle == "Clavis cannot run on this Mac")
        #expect(ClavisUIStrings.App.unsupportedMessage == "Clavis requires a Mac with Secure Enclave support.")
        #expect(ClavisUIStrings.Auth.errorTimedOut == "User authentication timed out")
        #expect(ClavisUIStrings.Auth.errorRejected == "User authentication failed or was cancelled")
    }

    @Test func test_009_historySearchTokenStrings() {
        #expect(ClavisUIStrings.History.searchField == "Search history")
        #expect(ClavisUIStrings.History.newestFirst == "Newest first")
        #expect(ClavisUIStrings.History.oldestFirst == "Oldest first")
        #expect(ClavisUIStrings.History.matchingCount("72") == "72 matching events")
        #expect(ClavisUIStrings.History.matchingCountOne == "1 matching event")
        #expect(ClavisUIStrings.History.removeBadge("Host: github.com") == "Remove Host: github.com")
        #expect(ClavisUIStrings.History.clearDate("from") == "Clear from date")
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
        #expect(ClavisUIStrings.History.windowTitle == "Signing History")
        #expect(ClavisUIStrings.History.showHistory == "Show History")
        #expect(ClavisUIStrings.History.retry == "Retry")
        #expect(ClavisUIStrings.History.refresh == "Refresh")
        #expect(ClavisUIStrings.History.refreshHelp == "Refresh History (⌘R)")
        #expect(ClavisUIStrings.History.searchPlaceholder == "Search by key, host, or process...")
        #expect(ClavisUIStrings.History.filterHost == "Host")
        #expect(ClavisUIStrings.History.filterProcess == "Process")
        #expect(ClavisUIStrings.History.loadMore == "Load More Events")
        #expect(ClavisUIStrings.History.loading == "Loading…")
        #expect(ClavisUIStrings.History.showingEvents(count: 5, total: 20) == "Showing 5 of 20 events")
        #expect(ClavisUIStrings.History.eventDetails == "Event Details")
        #expect(ClavisUIStrings.History.processChain == "Process Chain")
        #expect(ClavisUIStrings.History.processId == "Process ID")
        #expect(ClavisUIStrings.History.recordHash == "Record SHA-256 Hash")
        #expect(ClavisUIStrings.History.sessionId == "Session ID")
        #expect(ClavisUIStrings.History.copyDetails == "Copy Event Details")
        #expect(ClavisUIStrings.History.copyHash == "Copy SHA-256 Hash")
        #expect(ClavisUIStrings.History.filterAllKeys == "All Keys")
        #expect(ClavisUIStrings.History.filterAllKinds == "All Types")
        #expect(ClavisUIStrings.History.filterKindPersonal == "Personal")
        #expect(ClavisUIStrings.History.filterKindAgent == "Agent")
        #expect(ClavisUIStrings.History.filterAllResult == "All Results")
        #expect(ClavisUIStrings.History.filterRangeHour == "Last Hour")
        #expect(ClavisUIStrings.History.filterRangeDay == "Last 24 Hours")
        #expect(ClavisUIStrings.History.filterRangeWeek == "Last 7 Days")
        #expect(ClavisUIStrings.History.filterRangeAll == "All Time")
        #expect(ClavisUIStrings.History.resultAllowed == "Allowed")
        #expect(ClavisUIStrings.History.resultDenied == "Denied")
        #expect(ClavisUIStrings.History.resultCancelled == "Cancelled")
        #expect(ClavisUIStrings.History.resultFailed == "Failed")
        #expect(ClavisUIStrings.History.resultInfo == "Info")
        #expect(ClavisUIStrings.History.empty == "No audit events recorded")
        #expect(ClavisUIStrings.History.export == "Export…")
        #expect(ClavisUIStrings.History.suppressedCount(5) == "5 similar events suppressed")
        #expect(ClavisUIStrings.History.unreadable == "Unreadable (history key changed)")
        #expect(ClavisUIStrings.History.omitted == "—")
        #expect(ClavisUIStrings.History.omittedTooltip == "Details were not recorded")
        #expect(ClavisUIStrings.History.checkIntegrity == "Check Integrity")
        #expect(ClavisUIStrings.History.checkIntegrityTitle == "Audit History Integrity")
        #expect(ClavisUIStrings.History.checkingIntegrity == "Checking history integrity…")
        #expect(ClavisUIStrings.History.checkStatusOk == "History is intact")
        #expect(ClavisUIStrings.History.checkStatusOkDesc == "No missing or altered records detected within the verification window.")
        #expect(ClavisUIStrings.History.checkStatusProblems == "Potential tampering detected")
        #expect(ClavisUIStrings.History.checkStatusProblemsDesc == "Discrepancies found between local database and system witness records.")
        #expect(ClavisUIStrings.History.checkStatusUnavailable == "Integrity check unavailable")
        #expect(ClavisUIStrings.History.checkCheckedRows(10) == "Checked rows: 10")
        #expect(ClavisUIStrings.History.checkMissingRows(2) == "Missing rows: 2")
        #expect(ClavisUIStrings.History.checkInconsistentRows(1) == "Inconsistent rows: 1")
        #expect(ClavisUIStrings.History.checkTruncatedTail == "History tail truncated: Yes")
        #expect(ClavisUIStrings.History.checkProblemsHeader == "Detected Problems")
        #expect(ClavisUIStrings.History.checkMissingRowFormat(seq: 5, witnessedAt: "2026-10-06") == "Missing sequence 5 (witnessed 2026-10-06)")
        #expect(ClavisUIStrings.History.checkInconsistentRowFormat(seq: 3) == "Inconsistent row sequence 3")
        #expect(!ClavisUIStrings.History.checkRetentionExplanation.isEmpty)
        #expect(ClavisUIStrings.History.checkLearnMore == "Learn more")
        #expect(ClavisUIStrings.History.gapBanner(count: 3) == "3 entries missing (gap detected)")
    }

    @Test func testPanelLockLocalizedStrings() {
        #expect(ClavisUIStrings.PanelLock.title == "Clavis is locked")
        #expect(ClavisUIStrings.PanelLock.clarification == "Locking the control panel does not disable background SSH authentication or agent signing.")
        #expect(ClavisUIStrings.PanelLock.unlock == "Unlock")
        #expect(ClavisUIStrings.PanelLock.enterPinToUnlock == "Press Return to unlock")
        #expect(ClavisUIStrings.PanelLock.unlockMenu == "Unlock Clavis…")
        #expect(ClavisUIStrings.PanelLock.reason == "unlock Clavis")
        #expect(ClavisUIStrings.PanelLock.disableReason == "Modify control panel lock settings")
        #expect(ClavisUIStrings.PanelLock.settingsSection == "Control Panel Lock")
        #expect(ClavisUIStrings.PanelLock.settingsToggle == "Require authentication to open Clavis")
        #expect(ClavisUIStrings.PanelLock.settingsIdle == "Lock after inactivity")
        #expect(ClavisUIStrings.PanelLock.minutesFormat(5) == "5 min")
        #expect(ClavisUIStrings.PanelLock.agentSessionsCount(2) == "2 agent sessions running")
    }

    @Test func testAgentKeyLocalizedStrings() {
        #expect(ClavisUIStrings.KeyPurposeStrings.agentTitle == "Agent")
        #expect(ClavisUIStrings.KeyPurposeStrings.agentSubtitle == "Only usable by agents you start through Clavis. Never offered to your terminal.")
        #expect(ClavisUIStrings.KeyList.filterAll == "All")
        #expect(ClavisUIStrings.KeyList.filterPersonal == "Personal")
        #expect(ClavisUIStrings.KeyList.filterAgent == "Agent")
        #expect(ClavisUIStrings.Badges.agent == "Agent")
        #expect(ClavisUIStrings.KeyDetail.copyDeployKey == "Copy Deploy Key")
        #expect(ClavisUIStrings.KeyDetail.changePurpose == "Change Purpose…")
        #expect(ClavisUIStrings.KeyDetail.changeKind == "Change Purpose…")
        #expect(ClavisUIStrings.KeyDetail.changePurposeConfirm == "Change Purpose")
        #expect(ClavisUIStrings.KeyDetail.changeKindConfirm == "Change Purpose")
        #expect(ClavisUIStrings.Inspector.changePurpose == "Change Purpose…")
        #expect(ClavisUIStrings.Inspector.changeKind == "Change Purpose…")
        #expect(ClavisUIStrings.Inspector.changePurposeConfirm == "Change Purpose")
        #expect(ClavisUIStrings.Inspector.changeKindConfirm == "Change Purpose")
        #expect(!ClavisUIStrings.KeyDetail.changePurposeAlertMessage(label: "test-key", newPurpose: .agent).isEmpty)
        #expect(!ClavisUIStrings.KeyDetail.changeKindAlertMessage(label: "test-key", newPurpose: .agent).isEmpty)
    }

    @Test func testAgentSessionLocalizedStrings() {
        #expect(ClavisUIStrings.AgentSession.menuSection == "Agent Sessions")
        #expect(ClavisUIStrings.AgentSession.end == "End")
        #expect(ClavisUIStrings.AgentSession.remainingFormat(minutes: 12) == "12 min remaining")
        #expect(ClavisUIStrings.AgentSession.historyShowSession == "Show session")
        #expect(ClavisUIStrings.AgentSession.historyEndSession == "End session")
        #expect(ClavisUIStrings.AgentSession.extend == "Extend…")
        #expect(ClavisUIStrings.AgentSession.extend30m == "+30 min")
        #expect(ClavisUIStrings.AgentSession.extend1h == "+1 hour")
        #expect(ClavisUIStrings.AgentSession.extend4h == "+4 hours")
        #expect(ClavisUIStrings.AgentSession.extendPrompt == "Extend agent session")
        #expect(ClavisUIStrings.AgentSession.askPrompt == "Approve agent signature")
        #expect(ClavisUIStrings.AgentSession.revokeAll == "Revoke all agent sessions")
        #expect(ClavisUIStrings.AgentSession.notificationSignedTitle == "Agent signed")
        #expect(ClavisUIStrings.AgentSession.notificationRateLimitedTitle == "Agent rate limited")
    }

    @Test func testAgentPolicyLocalizedStrings() {
        #expect(ClavisUIStrings.AgentPolicy.sectionTitle == "Agent Session Policy")
        #expect(ClavisUIStrings.AgentPolicy.modeTitle == "Approval Mode")
        #expect(ClavisUIStrings.AgentPolicy.modeNone == "None (Silent)")
        #expect(ClavisUIStrings.AgentPolicy.modeNotify == "Notify")
        #expect(ClavisUIStrings.AgentPolicy.modeAsk == "Ask every time")
        #expect(ClavisUIStrings.AgentPolicy.leaseTitle == "Session Length")
        #expect(ClavisUIStrings.AgentPolicy.allowedHostsTitle == "Allowed Hosts")
        #expect(ClavisUIStrings.AgentPolicy.allowedHostsAny == "Any host")
        #expect(ClavisUIStrings.AgentPolicy.addHost == "Add host…")
        #expect(ClavisUIStrings.AgentPolicy.addHostButton == "Add")
        #expect(ClavisUIStrings.AgentPolicy.hostNotFound == "Host not found in known_hosts — connect once with ssh first")
        #expect(ClavisUIStrings.AgentPolicy.rateLimitTitle == "Rate Limit")
        #expect(ClavisUIStrings.AgentPolicy.burstTitle == "Burst")
        #expect(ClavisUIStrings.AgentPolicy.refillTitle == "Refill per minute")
        #expect(ClavisUIStrings.AgentPolicy.saveButton == "Save Policy")
        #expect(ClavisUIStrings.AgentPolicy.savedFeedback == "Policy saved")
        #expect(ClavisUIStrings.AgentPolicy.unsavedChanges == "Unsaved changes")
        #expect(ClavisUIStrings.AgentPolicy.discardChanges == "Discard Changes")
        #expect(ClavisUIStrings.AgentPolicy.notificationPermissionDenied == "Notifications are disabled in macOS System Settings. Notification banners will not be displayed.")
        #expect(ClavisUIStrings.AgentPolicy.invalidRateLimit == "Max signatures per minute must be a positive integer greater than 0.")
        #expect(ClavisUIStrings.AgentPolicy.invalidHostPattern == "Invalid host pattern. Enter a valid hostname, IP, or wildcard pattern.")
        #expect(ClavisUIStrings.AgentPolicy.globalMaxLease == "Maximum agent session length")
        #expect(ClavisUIStrings.AgentPolicy.changePrompt == "Change agent session policy")
    }

    @Test func testPinUnlockLocalizedStrings() {
        #expect(ClavisUIStrings.PinUnlock.pinLabel == "PIN")
        #expect(ClavisUIStrings.PinUnlock.pinPlaceholder == "Enter PIN")
        #expect(ClavisUIStrings.PinUnlock.confirmPinPlaceholder == "Confirm PIN")
        #expect(ClavisUIStrings.PinUnlock.unlock == "Unlock")
        #expect(ClavisUIStrings.PinUnlock.useTouchID == "Use Touch ID")
        #expect(ClavisUIStrings.PinUnlock.usePassword == "Use login password…")
        #expect(ClavisUIStrings.PinUnlock.wrongPIN == "Incorrect PIN")
        #expect(ClavisUIStrings.PinUnlock.waitFormat(30) == "Try again in 30 s")
        #expect(ClavisUIStrings.PinUnlock.passwordRequired == "PIN is disabled. Login password required.")
        #expect(ClavisUIStrings.PinUnlock.historyBanner == "Enter PIN to read details")
        #expect(!ClavisUIStrings.PinUnlock.warningOrMode.isEmpty)
        #expect(!ClavisUIStrings.PinUnlock.resetWarning.isEmpty)
        #expect(ClavisUIStrings.PinUnlock.tooShort == "PIN must be at least 6 characters.")
        #expect(ClavisUIStrings.PinUnlock.pinMismatch == "PINs do not match.")
        #expect(ClavisUIStrings.PinUnlock.changePIN == "Change PIN…")
        #expect(ClavisUIStrings.PinUnlock.forgotPIN == "Forgot PIN…")
        #expect(ClavisUIStrings.PinUnlock.settingsSection == "Unlock Method")
        #expect(ClavisUIStrings.PinUnlock.modePasswordOrBiometry == "Touch ID or password")
        #expect(ClavisUIStrings.PinUnlock.modeBiometryOrPIN == "Touch ID or PIN")
        #expect(ClavisUIStrings.PinUnlock.modeBiometryAndPIN == "Touch ID and PIN")
        #expect(ClavisUIStrings.PinUnlock.setPinTitle == "Set PIN")
    }

    @Test func testAccessibilityLocalizedStrings() {
        #expect(ClavisUIStrings.Accessibility.addKey == "Create new SSH key")
        #expect(ClavisUIStrings.Accessibility.lockAll == "Lock all active keys")
        #expect(ClavisUIStrings.Accessibility.settings == "Settings")
        #expect(ClavisUIStrings.Accessibility.history == "Signing history")
        #expect(ClavisUIStrings.Accessibility.statusActive == "Status: active")
        #expect(ClavisUIStrings.Accessibility.statusOffline == "Status: offline")
        #expect(ClavisUIStrings.Accessibility.pinDigit == "PIN digit entry")
        #expect(ClavisUIStrings.Accessibility.copyPublicKey == "Copy public key")
        #expect(ClavisUIStrings.Accessibility.copyFingerprint == "Copy SHA-256 fingerprint")
        #expect(ClavisUIStrings.Accessibility.agentStatus == "Agent status")
        #expect(ClavisUIStrings.Accessibility.moreActions == "More actions")
        #expect(ClavisUIStrings.Accessibility.deleteHost == "Remove allowed host")
        #expect(ClavisUIStrings.Accessibility.expandDetails == "Expand details")
        #expect(ClavisUIStrings.Accessibility.collapseDetails == "Collapse details")
        #expect(ClavisUIStrings.Accessibility.expanded == "Expanded")
        #expect(ClavisUIStrings.Accessibility.collapsed == "Collapsed")
        #expect(ClavisUIStrings.Accessibility.copyProcessInfo == "Copy process path and PID")
        #expect(ClavisUIStrings.Accessibility.copyItem(label: "Host") == "Copy Host")
    }
}
