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
    }
}
