import XCTest
@testable import ClavisCore

final class LocalizationTests: XCTestCase {

    func testInspectorLocalizedStrings() {
        XCTAssertFalse(ClavisUIStrings.Inspector.usedBySection.isEmpty)
        XCTAssertEqual(ClavisUIStrings.Inspector.agePluginRegistered, "Registered CLI plugin")
        XCTAssertEqual(ClavisUIStrings.Inspector.agePluginIncompatible("Ed25519"), "Incompatible (Ed25519 not supported by age)")
        XCTAssertEqual(ClavisUIStrings.Inspector.statusReady, "Ready")
        XCTAssertEqual(ClavisUIStrings.Inspector.statusUnsupported, "Unsupported")
        XCTAssertEqual(ClavisUIStrings.Inspector.agenixWorkflow, "NixOS secret workflow")
        XCTAssertEqual(ClavisUIStrings.Inspector.agenixHardwareIncompatible, "Hardware key incompatible with agenix")
        XCTAssertEqual(ClavisUIStrings.Inspector.agenixAlgorithmIncompatible("ECDSA"), "Incompatible with ECDSA")
        XCTAssertEqual(ClavisUIStrings.Inspector.statusConfigured, "Configured")
        XCTAssertEqual(ClavisUIStrings.Inspector.statusIncompatible, "Incompatible")

        XCTAssertFalse(ClavisUIStrings.Inspector.securitySection.isEmpty)
        XCTAssertEqual(ClavisUIStrings.Inspector.storageHardwareEnclave, "Apple Secure Enclave (Hardware Chip)")
        XCTAssertEqual(ClavisUIStrings.Inspector.storageSoftwareKeychain, "macOS Login Keychain (Software)")
        XCTAssertEqual(ClavisUIStrings.Inspector.sessionCacheHardwarePrompt, "Disabled (Prompt on each signature)")
        XCTAssertEqual(ClavisUIStrings.Inspector.sessionCacheAlwaysPrompt, "Disabled (Always Prompt)")
        XCTAssertEqual(ClavisUIStrings.Inspector.sessionCacheActiveTimeout("5 Minutes"), "Active (5 Minutes)")
    }

    func testSessionTimeoutLocalizedTitles() {
        XCTAssertEqual(SessionTimeout.never.localizedTitle, "Off (Always Prompt)")
        XCTAssertEqual(SessionTimeout.fiveMinutes.localizedTitle, "5 Minutes")
        XCTAssertEqual(SessionTimeout.fifteenMinutes.localizedTitle, "15 Minutes")
        XCTAssertEqual(SessionTimeout.oneHour.localizedTitle, "1 Hour")
    }

    func testFeedbackStrings() {
        XCTAssertEqual(ClavisUIStrings.Inspector.feedbackLockedKey("id_rsa"), "Locked 'id_rsa'")
        XCTAssertEqual(ClavisUIStrings.Inspector.feedbackUnlockedKey("id_rsa"), "Unlocked 'id_rsa'")
    }

    func testKeyListLocalizedStrings() {
        XCTAssertEqual(ClavisUIStrings.KeyList.title, "Keys")
        XCTAssertEqual(ClavisUIStrings.KeyList.identitiesAvailable(count: 1), "1 identity available")
        XCTAssertEqual(ClavisUIStrings.KeyList.identitiesAvailable(count: 3), "3 identities available")
        XCTAssertEqual(ClavisUIStrings.KeyList.noKeySelectedTitle, "No Key Selected")
        XCTAssertEqual(ClavisUIStrings.KeyList.deletedKey(label: "my-key"), "Deleted key 'my-key'.")
        XCTAssertEqual(ClavisUIStrings.KeyList.allCachedKeysLocked, "All cached keys locked.")
    }

    func testMenuBarQuitAlertStrings() {
        XCTAssertEqual(ClavisUIStrings.MenuBar.quitConfirmationTitle, "Quit Clavis?")
        XCTAssertFalse(ClavisUIStrings.MenuBar.quitConfirmationDetailsWithAgent.isEmpty)
        XCTAssertFalse(ClavisUIStrings.MenuBar.quitConfirmationDetailsSimple.isEmpty)
    }

    func testCommonMinRemaining() {
        XCTAssertEqual(ClavisUIStrings.Common.minRemaining(5), "5 min remaining")
        XCTAssertEqual(ClavisUIStrings.Common.appName, "Clavis")
        XCTAssertEqual(ClavisUIStrings.Common.cancel, "Cancel")
        XCTAssertEqual(ClavisUIStrings.Common.delete, "Delete")
        XCTAssertEqual(ClavisUIStrings.Common.copy, "Copy")
        XCTAssertEqual(ClavisUIStrings.Common.copied, "Copied")
        XCTAssertEqual(ClavisUIStrings.Common.error, "Error")
        XCTAssertEqual(ClavisUIStrings.Common.ok, "OK")
    }

    func testBadges() {
        XCTAssertEqual(ClavisUIStrings.Badges.hardware, "Hardware")
        XCTAssertEqual(ClavisUIStrings.Badges.software, "Software")
        XCTAssertEqual(ClavisUIStrings.Badges.gitOnly, "Git Only")
    }

    func testAddKeyPopoverStrings() {
        XCTAssertEqual(ClavisUIStrings.AddKeyPopover.header, "ADD KEY")
        XCTAssertEqual(ClavisUIStrings.AddKeyPopover.newKeyTitle, "New Key…")
        XCTAssertEqual(ClavisUIStrings.AddKeyPopover.newKeySubtitle, "Generate a new cryptographic identity")
        XCTAssertEqual(ClavisUIStrings.AddKeyPopover.importKeyTitle, "Import Key…")
        XCTAssertEqual(ClavisUIStrings.AddKeyPopover.importKeySubtitle, "Store an existing private key securely")
    }

    func testCreateKeyStrings() {
        XCTAssertEqual(ClavisUIStrings.CreateKey.title, "Create New Key")
        XCTAssertEqual(ClavisUIStrings.CreateKey.nameLabel, "Key Name")
        XCTAssertEqual(ClavisUIStrings.CreateKey.typeLabel, "Key Type")
        XCTAssertEqual(ClavisUIStrings.CreateKey.biometricPolicyLabel, "Biometric Authentication Policy")
        XCTAssertEqual(ClavisUIStrings.CreateKey.purposeLabel, "Key Purpose & Scope")
        XCTAssertEqual(ClavisUIStrings.CreateKey.generateButton, "Generate Key")
        XCTAssertEqual(ClavisUIStrings.CreateKey.enclaveUnavailable, "Apple Secure Enclave is not available on this device.")
        XCTAssertEqual(ClavisUIStrings.CreateKey.tagSSH, "SSH")
        XCTAssertEqual(ClavisUIStrings.CreateKey.tagGitSigning, "Git Signing")
        XCTAssertEqual(ClavisUIStrings.CreateKey.tagAge, "age / agenix")
        XCTAssertEqual(ClavisUIStrings.CreateKey.tagAgeIncompatible, "Incompatible with age")
    }

    func testImportKeyStrings() {
        XCTAssertEqual(ClavisUIStrings.ImportKey.title, "Import Existing Key")
        XCTAssertEqual(ClavisUIStrings.ImportKey.nameLabel, "Key Name / Label")
        XCTAssertEqual(ClavisUIStrings.ImportKey.seedLabel, "32-Byte Raw Seed (Hex)")
        XCTAssertEqual(ClavisUIStrings.ImportKey.seedHint, "64 hex characters")
        XCTAssertEqual(ClavisUIStrings.ImportKey.seedValid, "Valid Ed25519 Seed Detected")
        XCTAssertEqual(ClavisUIStrings.ImportKey.seedWaiting, "Waiting for valid 64-char hex seed...")
        XCTAssertEqual(ClavisUIStrings.ImportKey.storageTitle, "Destination: Login Keychain")
        XCTAssertEqual(ClavisUIStrings.ImportKey.button, "Import Key")
        XCTAssertEqual(ClavisUIStrings.ImportKey.errorInvalidInput, "Please enter a valid label and 64-character hex seed.")
    }

    func testBiometricPolicyAndKeyPurpose() {
        XCTAssertEqual(BiometricPolicy.userPresence.title, "User Presence")
        XCTAssertEqual(BiometricPolicy.biometryCurrentSet.title, "Strict Biometrics")
        XCTAssertEqual(KeyPurpose.general.title, "General (SSH & Git)")
        XCTAssertEqual(KeyPurpose.gitSigningOnly.title, "Git Signing Only")
        XCTAssertEqual(KeyPurpose.agent.title, "Agent")
    }

    func testPromptStrings() {
        XCTAssertEqual(ClavisUIStrings.Prompt.sshAuthentication(keyLabel: "my-key"), "use “my-key” for SSH authentication")
        XCTAssertEqual(ClavisUIStrings.Prompt.gitCommitSigning(keyLabel: "my-key"), "sign a Git commit with “my-key”")
        XCTAssertEqual(ClavisUIStrings.Prompt.gitSigningSession(keyLabel: "my-key"), "authorize a 5-minute Git signing session with “my-key”")
        XCTAssertEqual(
            ClavisUIStrings.AgentSession.approvePrompt(tool: "/usr/bin/claude", keyLabel: "my-key", minutes: 30),
            "Start agent session for “claude” with key “my-key” for 30 minutes"
        )
    }

    func testMenuBarFormatting() {
        XCTAssertEqual(ClavisUIStrings.MenuBar.activeWithPID(1234), "Active (PID 1234)")
        XCTAssertEqual(ClavisUIStrings.MenuBar.identitiesReady(count: 1), "1 identity ready")
        XCTAssertEqual(ClavisUIStrings.MenuBar.identitiesReady(count: 5), "5 identities ready")
        XCTAssertEqual(ClavisUIStrings.MenuBar.gitSessionTitle(label: "deploy"), "Git Session: deploy")
        XCTAssertEqual(ClavisUIStrings.MenuBar.gitSessionDetails(timeRemaining: "4:32", opsLeft: 3), "4:32 remaining • 3 ops left")
    }

    func testAppSettingsAndAuth() {
        XCTAssertEqual(ClavisUIStrings.Settings.windowTitle, "Settings")
        XCTAssertEqual(ClavisUIStrings.App.unsupportedTitle, "Clavis cannot run on this Mac")
        XCTAssertEqual(ClavisUIStrings.App.unsupportedMessage, "Clavis requires a Mac with Secure Enclave support.")
        XCTAssertEqual(ClavisUIStrings.Auth.errorTimedOut, "User authentication timed out")
        XCTAssertEqual(ClavisUIStrings.Auth.errorRejected, "User authentication failed or was cancelled")
    }

    func testXCStringsTranslationsIntegrity() throws {
        // Find Localizable.xcstrings in the repository
        let thisFile = URL(fileURLWithPath: #file)
        let repoRoot = thisFile.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let xcstringsURL = repoRoot.appendingPathComponent("Sources/ClavisCore/Resources/Localizable.xcstrings")

        let data = try Data(contentsOf: xcstringsURL)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertNotNil(json)

        let strings = json?["strings"] as? [String: [String: Any]]
        XCTAssertNotNil(strings)
        XCTAssertGreaterThan(strings?.count ?? 0, 100)

        // Verify every entry has non-empty en and ru translations
        for (key, entry) in strings ?? [:] {
            guard let localizations = entry["localizations"] as? [String: [String: Any]] else {
                XCTFail("Missing localizations dict for key: \(key)")
                continue
            }
            guard let enUnit = localizations["en"]?["stringUnit"] as? [String: Any],
                  let enVal = enUnit["value"] as? String, !enVal.isEmpty else {
                XCTFail("Missing or empty 'en' localization for key: \(key)")
                continue
            }
            guard let ruUnit = localizations["ru"]?["stringUnit"] as? [String: Any],
                  let ruVal = ruUnit["value"] as? String, !ruVal.isEmpty else {
                XCTFail("Missing or empty 'ru' localization for key: \(key)")
                continue
            }
        }
    }

    func testGitSigningPromptStringsEnglishDefaults() {
        let strings = GitSigningPromptStrings.localized
        XCTAssertEqual(strings.header, "Clavis — Git Signing Session")
        XCTAssertEqual(strings.allowFiveMinutesButton, "Grant 5 Minutes")
        XCTAssertEqual(strings.cancelButton, "Cancel")
        XCTAssertEqual(strings.singleShotButton, "Sign Once")

        let msg = strings.messageTemplate("test-key", "git (PID 100)")
        XCTAssertTrue(msg.contains("Detected a series of Git commits"))
        XCTAssertTrue(msg.contains("Grant automatic Git signing for 5 minutes"))
        // Must contain no Cyrillic characters
        XCTAssertFalse(msg.unicodeScalars.contains(where: { ("\u{0400}"..."\u{04FF}").contains($0) }))
    }

    func testEveryKeyHasEnglishDefaultInXCStrings() throws {
        let thisFile = URL(fileURLWithPath: #file)
        let repoRoot = thisFile.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let xcstringsURL = repoRoot.appendingPathComponent("Sources/ClavisCore/Resources/Localizable.xcstrings")

        let data = try Data(contentsOf: xcstringsURL)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let strings = json?["strings"] as? [String: [String: Any]] ?? [:]

        XCTAssertFalse(strings.isEmpty)
        for (key, entry) in strings {
            let localizations = entry["localizations"] as? [String: [String: Any]]
            let enUnit = localizations?["en"]?["stringUnit"] as? [String: Any]
            let enVal = enUnit?["value"] as? String
            XCTAssertNotNil(enVal, "Key '\(key)' is missing English default translation")
            XCTAssertFalse(enVal?.isEmpty ?? true, "Key '\(key)' has empty English default translation")
        }
    }

    func testHistoryLocalizedStrings() {
        XCTAssertEqual(ClavisUIStrings.History.windowTitle, "Signing History")
        XCTAssertEqual(ClavisUIStrings.History.showHistory, "Show History")
        XCTAssertEqual(ClavisUIStrings.History.filterAllKeys, "All Keys")
        XCTAssertEqual(ClavisUIStrings.History.filterAllKinds, "All Types")
        XCTAssertEqual(ClavisUIStrings.History.filterKindPersonal, "Personal")
        XCTAssertEqual(ClavisUIStrings.History.filterKindAgent, "Agent")
        XCTAssertEqual(ClavisUIStrings.History.filterAllResult, "All Results")
        XCTAssertEqual(ClavisUIStrings.History.filterRangeHour, "Last Hour")
        XCTAssertEqual(ClavisUIStrings.History.filterRangeDay, "Last 24 Hours")
        XCTAssertEqual(ClavisUIStrings.History.filterRangeWeek, "Last 7 Days")
        XCTAssertEqual(ClavisUIStrings.History.filterRangeAll, "All Time")
        XCTAssertEqual(ClavisUIStrings.History.resultAllowed, "Allowed")
        XCTAssertEqual(ClavisUIStrings.History.resultDenied, "Denied")
        XCTAssertEqual(ClavisUIStrings.History.resultCancelled, "Cancelled")
        XCTAssertEqual(ClavisUIStrings.History.resultFailed, "Failed")
        XCTAssertEqual(ClavisUIStrings.History.resultInfo, "Info")
        XCTAssertEqual(ClavisUIStrings.History.empty, "No audit events recorded")
        XCTAssertEqual(ClavisUIStrings.History.export, "Export…")
        XCTAssertEqual(ClavisUIStrings.History.suppressedCount(5), "5 similar events suppressed")
        XCTAssertEqual(ClavisUIStrings.History.unreadable, "Unreadable (history key changed)")
        XCTAssertEqual(ClavisUIStrings.History.omitted, "—")
        XCTAssertEqual(ClavisUIStrings.History.omittedTooltip, "Details were not recorded")
        XCTAssertEqual(ClavisUIStrings.History.checkIntegrity, "Check Integrity")
        XCTAssertEqual(ClavisUIStrings.History.checkIntegrityTitle, "Audit History Integrity")
        XCTAssertEqual(ClavisUIStrings.History.checkingIntegrity, "Checking history integrity…")
        XCTAssertEqual(ClavisUIStrings.History.checkStatusOk, "History is intact")
        XCTAssertEqual(ClavisUIStrings.History.checkStatusOkDesc, "No missing or altered records detected within the verification window.")
        XCTAssertEqual(ClavisUIStrings.History.checkStatusProblems, "Potential tampering detected")
        XCTAssertEqual(ClavisUIStrings.History.checkStatusProblemsDesc, "Discrepancies found between local database and system witness records.")
        XCTAssertEqual(ClavisUIStrings.History.checkStatusUnavailable, "Integrity check unavailable")
        XCTAssertEqual(ClavisUIStrings.History.checkCheckedRows(10), "Checked rows: 10")
        XCTAssertEqual(ClavisUIStrings.History.checkMissingRows(2), "Missing rows: 2")
        XCTAssertEqual(ClavisUIStrings.History.checkInconsistentRows(1), "Inconsistent rows: 1")
        XCTAssertEqual(ClavisUIStrings.History.checkTruncatedTail, "History tail truncated: Yes")
        XCTAssertEqual(ClavisUIStrings.History.checkProblemsHeader, "Detected Problems")
        XCTAssertEqual(ClavisUIStrings.History.checkMissingRowFormat(seq: 5, witnessedAt: "2026-10-06"), "Missing sequence 5 (witnessed 2026-10-06)")
        XCTAssertEqual(ClavisUIStrings.History.checkInconsistentRowFormat(seq: 3), "Inconsistent row sequence 3")
        XCTAssertFalse(ClavisUIStrings.History.checkRetentionExplanation.isEmpty)
        XCTAssertEqual(ClavisUIStrings.History.checkLearnMore, "Learn more")
        XCTAssertEqual(ClavisUIStrings.History.gapBanner(count: 3), "3 entries missing (gap detected)")
    }

    func testPanelLockLocalizedStrings() {
        XCTAssertEqual(ClavisUIStrings.PanelLock.title, "Clavis is locked")
        XCTAssertEqual(ClavisUIStrings.PanelLock.unlock, "Unlock")
        XCTAssertEqual(ClavisUIStrings.PanelLock.unlockMenu, "Unlock Clavis…")
        XCTAssertEqual(ClavisUIStrings.PanelLock.reason, "unlock Clavis")
        XCTAssertEqual(ClavisUIStrings.PanelLock.disableReason, "Modify control panel lock settings")
        XCTAssertEqual(ClavisUIStrings.PanelLock.settingsSection, "Control Panel Lock")
        XCTAssertEqual(ClavisUIStrings.PanelLock.settingsToggle, "Require authentication to open Clavis")
        XCTAssertEqual(ClavisUIStrings.PanelLock.settingsIdle, "Lock after inactivity")
        XCTAssertEqual(ClavisUIStrings.PanelLock.minutesFormat(5), "5 min")
        XCTAssertEqual(ClavisUIStrings.PanelLock.agentSessionsCount(2), "2 agent sessions running")
    }

    func testAgentKeyLocalizedStrings() {
        XCTAssertEqual(ClavisUIStrings.KeyPurposeStrings.agentTitle, "Agent")
        XCTAssertEqual(ClavisUIStrings.KeyPurposeStrings.agentSubtitle, "Only usable by agents you start through Clavis. Never offered to your terminal.")
        XCTAssertEqual(ClavisUIStrings.KeyList.filterAll, "All")
        XCTAssertEqual(ClavisUIStrings.KeyList.filterPersonal, "Personal")
        XCTAssertEqual(ClavisUIStrings.KeyList.filterAgent, "Agent")
        XCTAssertEqual(ClavisUIStrings.Badges.agent, "Agent")
        XCTAssertEqual(ClavisUIStrings.KeyDetail.copyDeployKey, "Copy Deploy Key")
        XCTAssertEqual(ClavisUIStrings.KeyDetail.changeKind, "Change Kind…")
        XCTAssertEqual(ClavisUIStrings.KeyDetail.changeKindConfirm, "Change Kind")
        XCTAssertFalse(ClavisUIStrings.KeyDetail.changeKindAlertMessage(label: "test-key", newPurpose: .agent).isEmpty)
    }

    func testAgentSessionLocalizedStrings() {
        XCTAssertEqual(ClavisUIStrings.AgentSession.menuSection, "Agent Sessions")
        XCTAssertEqual(ClavisUIStrings.AgentSession.end, "End")
        XCTAssertEqual(ClavisUIStrings.AgentSession.remainingFormat(minutes: 12), "12 min remaining")
        XCTAssertEqual(ClavisUIStrings.AgentSession.historyShowSession, "Show session")
        XCTAssertEqual(ClavisUIStrings.AgentSession.historyEndSession, "End session")
    }

    func testPinUnlockLocalizedStrings() {
        XCTAssertEqual(ClavisUIStrings.PinUnlock.pinLabel, "PIN")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.pinPlaceholder, "Enter PIN")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.unlock, "Unlock")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.useTouchID, "Use Touch ID")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.usePassword, "Use login password…")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.wrongPIN, "Incorrect PIN")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.waitFormat(30), "Try again in 30 s")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.passwordRequired, "PIN is disabled. Login password required.")
        XCTAssertEqual(ClavisUIStrings.PinUnlock.historyBanner, "Enter PIN to read details")
    }
}

