@testable import ClavisTestSupport
import Foundation
import Testing
import SwiftUI
@testable import ClavisCore
@testable import Clavis

@Suite(.serialized)
final class SheetsErgonomicsTests {
    private let fixture: ClavisTestFixture

    init() throws {
        self.fixture = try ClavisTestFixture()
    }

    deinit {
        fixture.cleanup()
    }

    @Test func testCreateKeySheetPresets() {
        let preset = KeyTypePreset.hardware
        #expect(preset.rawValue == "hardware")
        #expect(preset.storageType == .secureEnclave)
        #expect(preset.algorithm == .ecdsaP256)
        #expect(!preset.title.isEmpty)
        #expect(!preset.badge.isEmpty)
        #expect(!preset.subtitle.isEmpty)
        #expect(preset.icon == "cpu")
    }

    @MainActor
    @Test func testCreateKeySheetInitialization() {
        let keyManager = fixture.makeKeyManager()
        let appState = AppState(keyManager: keyManager)
        let sheet = CreateKeySheet(appState: appState)
        #expect(sheet.appState === appState)
        #expect(sheet.isGenerateDisabled)
        // D-40 / E2: User Presence is the creation default; legacy biometryCurrentSet
        // remains a model case but is not offered on new keys.
        #expect(CreateKeySheet.defaultBiometricPolicy == .userPresence)
        #expect(CreateKeySheet.defaultPurpose == .general)
        #expect(BiometricPolicy.allCases == [.biometryCurrentSet, .userPresence, .biometryOrPasscode, .devicePasscode])
        #expect(CreateKeySheet.creationPolicies == [.biometryOrPasscode, .userPresence, .devicePasscode])
        #expect(CreateKeySheet.sheetTitle == "New Key")
        #expect(CreateKeySheet.storageFootnoteText.contains("Apple Secure Enclave (P-256)"))
        #expect(CreateKeySheet.namePlaceholderText == "GitHub SSH")
        #expect(CreateKeySheet.typeFootnote(for: .personal) == "Personal keys never appear on the agent socket.")
        #expect(CreateKeySheet.typeFootnote(for: .bot) == "For AI agents. Each app is approved on first use.")
        #expect(CreateKeySheet.confirmationFootnote(policy: .userPresence, timeout: .fifteenMinutes) == "Touch ID, Apple Watch, or password. Unlocks 15 min per app.")
        #expect(CreateKeySheet.confirmationFootnote(policy: .biometryOrPasscode, timeout: .always) == "Touch ID (invalidated if fingerprints change). Prompts on every request.")
        #expect(CreateKeySheet.confirmationFootnote(policy: .devicePasscode, timeout: .untilLock) == "Mac login password only. Stays unlocked until lock per app.")
    }

    @Test func testCreateKeyGenerateGating() {
        // Disabled until name non-empty AND at least one capability on.
        #expect(CreateKeySheet.isGenerateDisabled(name: "", sshEnabled: true, signatureEnabled: true, isCreating: false))
        #expect(CreateKeySheet.isGenerateDisabled(name: "   ", sshEnabled: true, signatureEnabled: true, isCreating: false))
        #expect(CreateKeySheet.isGenerateDisabled(name: "Work GitHub", sshEnabled: false, signatureEnabled: false, isCreating: false))
        #expect(CreateKeySheet.isGenerateDisabled(name: "Work GitHub", sshEnabled: true, signatureEnabled: true, isCreating: true))
        #expect(!CreateKeySheet.isGenerateDisabled(name: "Work GitHub", sshEnabled: true, signatureEnabled: false, isCreating: false))
        #expect(!CreateKeySheet.isGenerateDisabled(name: "Work GitHub", sshEnabled: false, signatureEnabled: true, isCreating: false))
    }

    @Test func testCreateKeyUnlockedTimeoutOptions() {
        // D-40: Once · 15 min · 8 hours · Until Lock · 1 Day, default 15 min.
        #expect(CreateKeySheet.unlockedTimeoutOptions.map(\.title) == ["Once", "15 min", "8 hours", "Until Lock", "1 Day"])
        #expect(CreateKeySheet.unlockedTimeoutOptions.map(\.period) == [.always, .fifteenMinutes, .session, .untilLock, .oneDay])
        #expect(CreateKeySheet.defaultUnlockedTimeout == .fifteenMinutes)
        #expect(KeyGracePeriod.defaultPeriod(for: .general) == .fifteenMinutes)
        #expect(KeyGracePeriod.defaultPeriod(for: .agent) == .fifteenMinutes)
    }

    @Test func testCreateKeyLearnPopoverContent() {
        #expect(CreateKeyReferenceContent.title == "New Key Reference")
        #expect(CreateKeyReferenceContent.rows.map(\.label) == [
            "Type", "Strict Biometrics", "User Presence", "Password", "Timeout", "Storage"
        ])
    }

    @Test func testAboutProvenanceVersionAndCommit() {
        let version = AboutProvenance.appVersion
        #expect(!version.isEmpty)
        #expect(version.hasPrefix("v"))

        let rawVersion = AboutProvenance.rawVersion
        #expect(!rawVersion.isEmpty)

        let commit = AboutProvenance.gitCommitSHA
        #expect(!commit.isEmpty)
        #expect(commit.count >= 7)

        let identity = AboutProvenance.codeSigningIdentity
        #expect(!identity.isEmpty)
    }

    @Test func testAboutProvenanceDaemonParity() {
        // When socket is inactive, parity must be offline
        let offlineStatus = AboutProvenance.daemonParity(isSocketActive: false, agentPID: nil)
        #expect(offlineStatus == .offline)

        let offlineWithPid = AboutProvenance.daemonParity(isSocketActive: false, agentPID: 1234)
        #expect(offlineWithPid == .offline)

        // When socket is active with no PID, parity defaults to matching
        let activeNoPid = AboutProvenance.daemonParity(isSocketActive: true, agentPID: nil)
        #expect(activeNoPid == .matching)

        // When socket is active with our current process PID (not in a foreign bundle)
        let currentPid = ProcessInfo.processInfo.processIdentifier
        let activeCurrentPid = AboutProvenance.daemonParity(isSocketActive: true, agentPID: currentPid)
        #expect(activeCurrentPid == .matching)
    }

    @Test func testVaultSyncReportAnomalyBehavior() {
        let cleanReport = VaultSyncReport(missingPublicCache: [], orphanedPublicCache: [], repairedCount: 0)
        #expect(!cleanReport.isDesynchronized)
        #expect(cleanReport.detectedAnomalies.isEmpty)

        let desyncedMissing = VaultSyncReport(missingPublicCache: ["key-1"], orphanedPublicCache: [], repairedCount: 0)
        #expect(desyncedMissing.isDesynchronized)
        #expect(desyncedMissing.detectedAnomalies.count == 1)
        #expect(desyncedMissing.detectedAnomalies.first == .missingPublicCache(label: "key-1"))

        let desyncedOrphaned = VaultSyncReport(missingPublicCache: [], orphanedPublicCache: ["key-2"], repairedCount: 0)
        #expect(desyncedOrphaned.isDesynchronized)
        #expect(desyncedOrphaned.detectedAnomalies.count == 1)
        #expect(desyncedOrphaned.detectedAnomalies.first == .orphanedPublicCache(label: "key-2"))
    }

    @Test func testKeychainManagerSyncVaultIntegration() throws {
        let keyManager = fixture.makeKeyManager()
        let report = try keyManager.syncVault(repair: false)
        #expect(!report.isDesynchronized)

        let repairReport = try keyManager.syncVault(repair: true)
        #expect(!repairReport.isDesynchronized)
        #expect(repairReport.repairedCount == 0)
    }

    @MainActor
    @Test func testSettingsSheetInitialization() {
        let keyManager = fixture.makeKeyManager()
        let appState = AppState(keyManager: keyManager)
        let settingsSheet = SettingsSheet(appState: appState)
        let settingsView = SettingsView()
        _ = settingsSheet.body
        _ = settingsView.body
        #expect(PanelLockController.idleOptions == [1, 5, 15, 30, 60])
        #expect(SettingsView.inactivityGraceNote(minutes: 1) == "Lock the Clavis window after 1 minute of inactivity.")
        #expect(SettingsView.inactivityGraceNote(minutes: 15) == "Lock the Clavis window after 15 minutes of inactivity.")
        #expect(SettingsView.inactivityOptionLabel(minutes: 1) == "1 minute")
        #expect(SettingsView.inactivityOptionLabel(minutes: 30) == "30 minutes")
    }
}
