@testable import ClavisTestSupport
import Testing
import Foundation
import SwiftUI
@testable import ClavisCore
@testable import Clavis

@Suite
@MainActor
struct KeyListViewTests {

    private func makeSampleKeys() -> [SSHKeyInfo] {
        let key1 = SSHKeyInfo(
            label: "work-laptop",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGithubKeyWork work@laptop",
            publicKeyBlob: Data([0x01, 0x02, 0x03]),
            fingerprint: "SHA256:abc123workfingerprint",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )

        let key2 = SSHKeyInfo(
            label: "deploy-agent-key",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= agent@server",
            publicKeyBlob: Data([0x04, 0x05, 0x06]),
            fingerprint: "SHA256:xyz789agentfingerprint",
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .agent
        )

        let key3 = SSHKeyInfo(
            label: "personal-git-signing",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersonalSigning git@personal",
            publicKeyBlob: Data([0x07, 0x08, 0x09]),
            fingerprint: "SHA256:qwe456gitfingerprint",
            createdAt: Date(),
            algorithmName: "Ed25519",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .gitSigningOnly
        )

        return [key1, key2, key3]
    }

    // MARK: - Search Filtering Tests (#103)

    @Test
    func testSearchFilterMatchesLabelCaseInsensitively() {
        let keys = makeSampleKeys()

        let resultUpper = KeyListView.filterKeys(keys, query: "WORK", kind: .all)
        #expect(resultUpper.count == 1)
        #expect(resultUpper.first?.label == "work-laptop")

        let resultLower = KeyListView.filterKeys(keys, query: "work", kind: .all)
        #expect(resultLower.count == 1)
        #expect(resultLower.first?.label == "work-laptop")

        let resultPartial = KeyListView.filterKeys(keys, query: "laptop", kind: .all)
        #expect(resultPartial.count == 1)
        #expect(resultPartial.first?.label == "work-laptop")
    }

    @Test
    func testSearchFilterMatchesAlgorithm() {
        let keys = makeSampleKeys()

        let edResults = KeyListView.filterKeys(keys, query: "Ed25519", kind: .all)
        #expect(edResults.count == 2)
        #expect(edResults.map(\.label).contains("work-laptop"))
        #expect(edResults.map(\.label).contains("personal-git-signing"))

        let ecdsaResults = KeyListView.filterKeys(keys, query: "ECDSA", kind: .all)
        #expect(ecdsaResults.count == 1)
        #expect(ecdsaResults.first?.label == "deploy-agent-key")
    }

    @Test
    func testSearchFilterMatchesFingerprint() {
        let keys = makeSampleKeys()

        let result = KeyListView.filterKeys(keys, query: "xyz789agent", kind: .all)
        #expect(result.count == 1)
        #expect(result.first?.label == "deploy-agent-key")
    }

    @Test
    func testSearchFilterEmptyOrWhitespaceReturnsAll() {
        let keys = makeSampleKeys()

        let emptyResult = KeyListView.filterKeys(keys, query: "", kind: .all)
        #expect(emptyResult.count == 3)

        let whitespaceResult = KeyListView.filterKeys(keys, query: "   \t\n  ", kind: .all)
        #expect(whitespaceResult.count == 3)
    }

    @Test
    func testSearchFilterNoMatchReturnsEmpty() {
        let keys = makeSampleKeys()

        let result = KeyListView.filterKeys(keys, query: "nonexistent-query-12345", kind: .all)
        #expect(result.isEmpty)
    }

    @Test
    func testSearchFilterCombinedWithKindFilter() {
        let keys = makeSampleKeys()

        // "Ed25519" matches work-laptop (general) and personal-git-signing (gitSigningOnly).
        // Under personal filter: both are personal (general and gitSigningOnly).
        let personalEd = KeyListView.filterKeys(keys, query: "Ed25519", kind: .personal)
        #expect(personalEd.count == 2)

        // Under agent filter: only agent keys. None of the Ed25519 keys are agent.
        let agentEd = KeyListView.filterKeys(keys, query: "Ed25519", kind: .agent)
        #expect(agentEd.isEmpty)

        // "deploy" under agent filter returns the deploy key
        let agentDeploy = KeyListView.filterKeys(keys, query: "deploy", kind: .agent)
        #expect(agentDeploy.count == 1)
        #expect(agentDeploy.first?.label == "deploy-agent-key")
    }

    // MARK: - Direct CreateKeySheet Opening Tests (#87, #90)

    @Test
    func testCreateKeyButtonDirectlySetsActiveSheet() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        await fixture.run {
            let km = fixture.makeKeyManager()
            let mockAgent = MockAgentController()
            let appState = AppState(keyManager: km, agentLifecycle: mockAgent)

            #expect(appState.activeSheet == nil)

            // Direct sheet presentation without AddKeyPopoverView
            appState.activeSheet = .create
            #expect(appState.activeSheet == .create)
        }
    }

    // MARK: - Context Menu Actions on KeySidebarRowView (#103)

    @Test
    func testKeySidebarRowViewCallbacks() {
        let keys = makeSampleKeys()
        let key = keys[0]

        var copyPublicCalled = false
        var copyFingerprintCalled = false
        var deleteCalled = false
        var selectCalled = false

        let rowView = KeySidebarRowView(
            key: key,
            isSelected: true,
            onSelect: { selectCalled = true },
            onCopyPublicKey: { copyPublicCalled = true },
            onCopyFingerprint: { copyFingerprintCalled = true },
            onDelete: { deleteCalled = true }
        )

        #expect(rowView.key.label == "work-laptop")
        #expect(rowView.isSelected == true)

        rowView.onSelect()
        #expect(selectCalled)

        rowView.onCopyPublicKey?()
        #expect(copyPublicCalled)

        rowView.onCopyFingerprint?()
        #expect(copyFingerprintCalled)

        rowView.onDelete?()
        #expect(deleteCalled)
    }

    // MARK: - Tooltips & Strings (#93, #92 Part 2)

    @Test
    func testToolbarTooltipsAreNonEmpty() {
        let createHelp = ClavisUIStrings.CreateKey.title
        #expect(!createHelp.isEmpty)

        let lockAllHelp = ClavisUIStrings.KeyList.lockAllKeysHelp
        #expect(!lockAllHelp.isEmpty)

        let noUnlockedHelp = ClavisUIStrings.KeyList.noUnlockedKeysHelp
        #expect(!noUnlockedHelp.isEmpty)

        let settingsHelp = ClavisUIStrings.KeyList.settingsHelp
        #expect(!settingsHelp.isEmpty)
    }

    @Test
    func testStatusFeedbackStringsAreNonEmpty() {
        let deleted = ClavisUIStrings.KeyList.deletedKey(label: "test-key")
        #expect(deleted.contains("test-key"))

        let allLocked = ClavisUIStrings.KeyList.allCachedKeysLocked
        #expect(!allLocked.isEmpty)

        let copiedSSH = ClavisUIStrings.Inspector.feedbackCopiedOpenSSH
        #expect(!copiedSSH.isEmpty)

        let copiedFP = ClavisUIStrings.Inspector.feedbackCopiedFingerprint
        #expect(!copiedFP.isEmpty)
    }

    @Test
    func testContextMenuStringsAreNonEmpty() {
        let copyPK = ClavisUIStrings.Inspector.copyPublicKey
        #expect(!copyPK.isEmpty)

        let copyFP = ClavisUIStrings.Inspector.copyFingerprintMenu
        #expect(!copyFP.isEmpty)

        let deleteMenu = ClavisUIStrings.Inspector.deleteKeyMenu
        #expect(!deleteMenu.isEmpty)
    }

    // MARK: - Keyboard Selection Navigation & Accessibility (#82)

    @Test
    func testKeyboardSelectionArrowNavigation() {
        let keys = makeSampleKeys()
        #expect(keys.count == 3)

        // Starting with no selection -> moves to first key
        let initialNext = KeyListView.nextSelectedKeyId(keys: keys, currentId: nil)
        #expect(initialNext == keys[0].id)

        let initialPrev = KeyListView.previousSelectedKeyId(keys: keys, currentId: nil)
        #expect(initialPrev == keys[0].id)

        // Forward arrow navigation (Down Arrow)
        let step1 = KeyListView.nextSelectedKeyId(keys: keys, currentId: keys[0].id)
        #expect(step1 == keys[1].id)

        let step2 = KeyListView.nextSelectedKeyId(keys: keys, currentId: keys[1].id)
        #expect(step2 == keys[2].id)

        // Backward arrow navigation (Up Arrow)
        let back1 = KeyListView.previousSelectedKeyId(keys: keys, currentId: keys[2].id)
        #expect(back1 == keys[1].id)

        let back2 = KeyListView.previousSelectedKeyId(keys: keys, currentId: keys[1].id)
        #expect(back2 == keys[0].id)
    }

    @Test
    func testKeyboardSelectionClampsAtBoundaries() {
        let keys = makeSampleKeys()

        // Down arrow at the end of the list stays on the last key
        let atEnd = KeyListView.nextSelectedKeyId(keys: keys, currentId: keys[2].id)
        #expect(atEnd == keys[2].id)

        // Up arrow at the beginning stays on the first key
        let atStart = KeyListView.previousSelectedKeyId(keys: keys, currentId: keys[0].id)
        #expect(atStart == keys[0].id)
    }

    @Test
    func testKeyboardSelectionEmptyListReturnsNil() {
        let empty: [SSHKeyInfo] = []
        #expect(KeyListView.nextSelectedKeyId(keys: empty, currentId: nil) == nil)
        #expect(KeyListView.previousSelectedKeyId(keys: empty, currentId: nil) == nil)
        #expect(KeyListView.nextSelectedKeyId(keys: empty, currentId: "some-id") == nil)
        #expect(KeyListView.previousSelectedKeyId(keys: empty, currentId: "some-id") == nil)
    }

    @Test
    func testStatusDotAccessibilityValues() {
        let activeDot = StatusDot(isActive: true)
        #expect(activeDot.isActive == true)

        let inactiveDot = StatusDot(isActive: false)
        #expect(inactiveDot.isActive == false)

        #expect(ClavisUIStrings.Accessibility.agentStatus == "Agent status")
        #expect(ClavisUIStrings.Accessibility.statusActive == "Status: active")
        #expect(ClavisUIStrings.Accessibility.statusOffline == "Status: offline")
    }

    @Test
    func testToolbarButtonAccessibilityStrings() {
        #expect(ClavisUIStrings.Accessibility.addKey == "Create new SSH key")
        #expect(ClavisUIStrings.Accessibility.lockAll == "Lock all active keys")
        #expect(ClavisUIStrings.Accessibility.settings == "Settings")
    }

    @Test
    func testContactsSidebarAndEmptyStateConstants() {
        #expect(KeyListView.sidebarWidth == 260)
        #expect(KeyListView.toolbarHeight == 52)
        #expect(KeyListView.searchCapsuleHeight == 36)
        #expect(KeyListView.emptyStateTitle == "A key that stays on your Mac.")
        #expect(KeyListView.emptyStateSubtitle.contains("Secure Enclave"))
        #expect(KeyListView.emptyStateCreateButtonTitle == "Create your first key")
        #expect(KeyListView.historyVerifiedTooltip.contains("linked hashes"))
    }

    @Test
    func testKeySidebarRowSubtitleAndDividerState() {
        let keys = makeSampleKeys()
        let generalKey = keys[0]
        let agentKey = keys[1]
        let gitKey = keys[2]

        let lockedGeneralRow = KeySidebarRowView(
            key: generalKey,
            isSelected: false,
            isUnlocked: false,
            showDivider: true,
            onSelect: {}
        )
        #expect(lockedGeneralRow.subtitleText == "SSH & Git · Locked")
        #expect(lockedGeneralRow.showDivider == true)

        let unlockedAgentRow = KeySidebarRowView(
            key: agentKey,
            isSelected: true,
            isUnlocked: true,
            showDivider: false,
            onSelect: {}
        )
        #expect(unlockedAgentRow.subtitleText == "Agent · Unlocked")
        #expect(unlockedAgentRow.showDivider == false)

        let lockedGitRow = KeySidebarRowView(
            key: gitKey,
            isSelected: false,
            isUnlocked: false,
            showDivider: true,
            onSelect: {}
        )
        #expect(lockedGitRow.subtitleText == "Git signing · Locked")
    }
}

