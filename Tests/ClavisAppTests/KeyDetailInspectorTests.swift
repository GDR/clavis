@testable import ClavisTestSupport
import Testing
import Foundation
import SwiftUI
@testable import ClavisCore
@testable import Clavis

@Suite("KeyDetailInspectorTests")
struct KeyDetailInspectorTests {

    private func makeTestKey(
        label: String = "test-key",
        purpose: KeyPurpose = .general,
        biometricPolicy: BiometricPolicy = .userPresence,
        fingerprint: String = "SHA256:abc1234567890defghijklmnopqrstuvwxyz123456"
    ) -> SSHKeyInfo {
        SSHKeyInfo(
            label: label,
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... \(label)",
            publicKeyBlob: Data(repeating: 0x42, count: 32),
            fingerprint: fingerprint,
            createdAt: Date(),
            algorithmName: "ECDSA P-256",
            storage: .secureEnclave,
            biometricPolicy: biometricPolicy,
            keyPurpose: purpose
        )
    }

    // MARK: - #102: Delete Key Confirmation UX & shortFingerprint

    @Test
    func testShortFingerprintFormatting() {
        let fullFingerprint = "SHA256:abc1234567890defghijklmnopqrstuvwxyz123456"
        let key = makeTestKey(fingerprint: fullFingerprint)

        #expect(key.shortFingerprint == "SHA256:abc123456")
        #expect(key.shortFingerprint.count == 16)
        #expect(fullFingerprint.hasPrefix(key.shortFingerprint))

        // Short or exact 16-char fingerprint returned as-is
        let exact16 = makeTestKey(fingerprint: "SHA256:123456789")
        #expect(exact16.shortFingerprint == "SHA256:123456789")
    }

    @Test
    func testDeleteConfirmationAlertIncludesLabelAndShortFingerprint() {
        let key = makeTestKey(
            label: "production-deploy",
            fingerprint: "SHA256:uD734VbKz8x91011121314151617181920212223242"
        )

        let title = KeyDetailInspectorView.deleteConfirmationTitle(label: key.label)
        #expect(title.contains("production-deploy"))

        let message = KeyDetailInspectorView.deleteConfirmationMessage(
            label: key.label,
            shortFingerprint: key.shortFingerprint
        )

        #expect(message.contains("production-deploy"), "Message must contain key label")
        #expect(message.contains(key.shortFingerprint), "Message must contain key shortFingerprint")
        #expect(message.contains("cannot be undone") || message.contains("невозможно отменить"))
    }

    // MARK: - #83: Dynamic Security Posture Copy

    @Test
    func testDynamicSecurityPostureForGeneralKey() {
        let generalKey = makeTestKey(purpose: .general, biometricPolicy: .userPresence)

        // Without Git grace
        let badgeDefault = KeyDetailInspectorView.securityBadgeText(for: generalKey)
        #expect(badgeDefault == ClavisUIStrings.Inspector.alwaysPromptBadge)

        let subtitleDefault = KeyDetailInspectorView.dynamicSecuritySubtitle(for: generalKey)
        #expect(subtitleDefault == ClavisUIStrings.Inspector.hardwareIsolated)

        let postureDefault = KeyDetailInspectorView.securityPostureInfo(for: generalKey)
        #expect(postureDefault.title == ClavisUIStrings.Inspector.hardwareIsolationPresenceTitle)
        #expect(postureDefault.description.contains("Touch ID user presence per operation"))
        #expect(postureDefault.description.contains("5-minute process-scoped Git signing grace"))

        // With Git grace active
        let badgeGrace = KeyDetailInspectorView.securityBadgeText(for: generalKey, hasActiveGitGrace: true)
        #expect(badgeGrace == "Grace Active")

        let subtitleGrace = KeyDetailInspectorView.dynamicSecuritySubtitle(for: generalKey, hasActiveGitGrace: true)
        #expect(subtitleGrace.contains("Git signing grace active"))

        let postureGrace = KeyDetailInspectorView.securityPostureInfo(for: generalKey, hasActiveGitGrace: true)
        #expect(postureGrace.description.contains("Git signing grace session is currently active"))
    }

    @Test
    func testDynamicSecurityPostureForStrictBiometricsGeneralKey() {
        let strictKey = makeTestKey(purpose: .general, biometricPolicy: .biometryCurrentSet)

        let posture = KeyDetailInspectorView.securityPostureInfo(for: strictKey)
        #expect(posture.title == ClavisUIStrings.Inspector.hardwareIsolationStrictTitle)
        #expect(posture.description.contains("current biometric enrollment"))
        #expect(posture.description.contains("Device password fallback is disabled"))
        #expect(posture.description.contains("5-minute process-scoped Git signing grace"))
    }

    @Test
    func testDynamicSecurityPostureForGitSigningOnlyKey() {
        let gitKey = makeTestKey(purpose: .gitSigningOnly)

        let badge = KeyDetailInspectorView.securityBadgeText(for: gitKey)
        #expect(badge == "Git Only")

        let subtitle = KeyDetailInspectorView.dynamicSecuritySubtitle(for: gitKey)
        #expect(subtitle.contains("Git commit signing only"))

        let posture = KeyDetailInspectorView.securityPostureInfo(for: gitKey)
        #expect(posture.title.contains("Git Signing Only"))
        #expect(posture.description.contains("Restricted strictly to local Git commit and tag signing"))
        #expect(posture.description.contains("Forwarded agent requests are blocked"))
        #expect(posture.description.contains("5-minute process-scoped Git signing grace"))
    }

    @Test
    func testDynamicSecurityPostureForAgentKeyModes() {
        let agentKey = makeTestKey(purpose: .agent)

        // Mode: .none (Silent lease)
        let silentPolicy = AgentKeyPolicy(mode: .none, leaseMinutes: 480)
        let silentBadge = KeyDetailInspectorView.securityBadgeText(for: agentKey, agentPolicy: silentPolicy)
        #expect(silentBadge == "Silent")

        let silentSubtitle = KeyDetailInspectorView.dynamicSecuritySubtitle(for: agentKey, agentPolicy: silentPolicy)
        #expect(silentSubtitle.contains("Silent agent lease"))

        let silentPosture = KeyDetailInspectorView.securityPostureInfo(for: agentKey, agentPolicy: silentPolicy)
        #expect(silentPosture.title.contains("Agent Policy"))
        #expect(silentPosture.description.contains("silently without prompts"))
        #expect(silentPosture.description.contains("8h"))
        #expect(silentPosture.description.contains("Apple Secure Enclave"))

        // Mode: .notify (Lease with notification)
        let notifyPolicy = AgentKeyPolicy(mode: .notify, leaseMinutes: 120)
        let notifyBadge = KeyDetailInspectorView.securityBadgeText(for: agentKey, agentPolicy: notifyPolicy)
        #expect(notifyBadge == "Notify")

        let notifySubtitle = KeyDetailInspectorView.dynamicSecuritySubtitle(for: agentKey, agentPolicy: notifyPolicy)
        #expect(notifySubtitle.contains("Agent lease with notification"))

        let notifyPosture = KeyDetailInspectorView.securityPostureInfo(for: agentKey, agentPolicy: notifyPolicy)
        #expect(notifyPosture.description.contains("post a notification on each signature"))
        #expect(notifyPosture.description.contains("2h"))
        #expect(notifyPosture.description.contains("Apple Secure Enclave"))

        // Mode: .ask (Prompt per signature)
        let askPolicy = AgentKeyPolicy(mode: .ask, leaseMinutes: 60)
        let askBadge = KeyDetailInspectorView.securityBadgeText(for: agentKey, agentPolicy: askPolicy)
        #expect(askBadge == ClavisUIStrings.Inspector.alwaysPromptBadge)

        let askSubtitle = KeyDetailInspectorView.dynamicSecuritySubtitle(for: agentKey, agentPolicy: askPolicy)
        #expect(askSubtitle.contains("Touch ID prompt per agent signature"))

        let askPosture = KeyDetailInspectorView.securityPostureInfo(for: agentKey, agentPolicy: askPolicy)
        #expect(askPosture.description.contains("explicit Touch ID user confirmation"))
        #expect(askPosture.description.contains("Apple Secure Enclave"))
    }

    // MARK: - #83: Live Socket Status and Path Separation

    @Test
    func testSocketStatusReflectsLiveDaemonStateAndPathRole() {
        let personalKey = makeTestKey(purpose: .general)
        let agentKey = makeTestKey(purpose: .agent)

        // Personal key socket info when active
        let activePersonal = KeyDetailInspectorView.socketStatusInfo(for: personalKey, isSocketActive: true)
        #expect(activePersonal.name == "ssh-agent socket")
        #expect(activePersonal.socketPath == "~/.ssh/clavis.sock")
        #expect(activePersonal.status == ClavisUIStrings.Inspector.statusActive)
        #expect(activePersonal.isActive == true)

        // Personal key socket info when offline/stopped
        let offlinePersonal = KeyDetailInspectorView.socketStatusInfo(for: personalKey, isSocketActive: false)
        #expect(offlinePersonal.status == ClavisUIStrings.Inspector.statusOffline)
        #expect(offlinePersonal.isActive == false)

        // Agent key socket info
        let activeAgent = KeyDetailInspectorView.socketStatusInfo(for: agentKey, isSocketActive: true)
        #expect(activeAgent.name == "agent socket")
        #expect(activeAgent.socketPath == "~/.ssh/clavis-agent.sock")
        #expect(activeAgent.status == ClavisUIStrings.Inspector.statusActive)
        #expect(activeAgent.isActive == true)

        let offlineAgent = KeyDetailInspectorView.socketStatusInfo(for: agentKey, isSocketActive: false)
        #expect(offlineAgent.status == ClavisUIStrings.Inspector.statusOffline)
        #expect(offlineAgent.isActive == false)
    }

    // MARK: - #88: Change Key Purpose

    @Test
    @MainActor
    func testChangeKeyKindBetweenGeneralAndAgent() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        try await fixture.run {
            let keyManager = fixture.makeKeyManager(authenticator: AllowingAuthenticator())
            let appState = AppState(keyManager: keyManager)

            // Generate initial general key
            let initialKey = try appState.generateKey(label: "toggle-purpose-test", keyPurpose: .general)
            #expect(initialKey.purpose == .general)

            // Change general -> agent
            try appState.changeKeyKind(label: initialKey.label, to: .agent)
            let agentKey = try #require(appState.keys.first(where: { $0.label == initialKey.label }))
            #expect(agentKey.purpose == .agent)

            // Change agent -> general
            try appState.changeKeyKind(label: initialKey.label, to: .general)
            let restoredKey = try #require(appState.keys.first(where: { $0.label == initialKey.label }))
            #expect(restoredKey.purpose == .general)
        }
    }

    @Test
    @MainActor
    func testGitSigningOnlyKeyDisallowsPurposeChange() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        try await fixture.run {
            let keyManager = fixture.makeKeyManager(authenticator: AllowingAuthenticator())
            let appState = AppState(keyManager: keyManager)

            let gitKey = try appState.generateKey(label: "git-immutable-test", keyPurpose: .gitSigningOnly)
            #expect(gitKey.purpose == .gitSigningOnly)

            #expect(throws: (any Error).self) {
                try appState.changeKeyKind(label: gitKey.label, to: .agent)
            }
            #expect(throws: (any Error).self) {
                try appState.changeKeyKind(label: gitKey.label, to: .general)
            }
        }
    }

    // MARK: - #94 (UI): Git Signing Grace Sessions & Revoke

    @Test
    @MainActor
    func testPerKeyGitGraceSessionStateAndRevocation() async throws {
        let fixture = try ClavisTestFixture()
        defer { fixture.cleanup() }

        try await fixture.run {
            let keyManager = fixture.makeKeyManager(authenticator: AllowingAuthenticator())
            let settingsVM = SettingsViewModel(agentLifecycle: MockAgentController())
            let appState = AppState(keyManager: keyManager, settingsViewModel: settingsVM)

            let keyA = try appState.generateKey(label: "key-a", keyPurpose: .general)
            let keyB = try appState.generateKey(label: "key-b", keyPurpose: .general)

            // Populate active grace for keyA in appState
            let graceA = ActiveGitGraceInfo(keyLabel: keyA.label, remainingSeconds: 245, remainingOperations: 180)
            let graceB = ActiveGitGraceInfo(keyLabel: keyB.label, remainingSeconds: 150, remainingOperations: 95)
            appState.activeGitGraces = [graceA, graceB]

            #expect(graceA.formattedRemainingTime == "4:05")
            #expect(graceB.formattedRemainingTime == "2:30")

            // Revoking keyA only removes keyA's grace
            appState.revokeGitGrace(keyLabel: keyA.label)
            #expect(appState.activeGitGraces.contains(where: { $0.keyLabel == keyA.label }) == false)
            #expect(appState.activeGitGraces.contains(where: { $0.keyLabel == keyB.label }) == true)
        }
    }

    // MARK: - Milestone M1 (PR 1): Header Title Stack & Overflow Menu Deduplication

    @Test
    func testHeaderTwoLineTitleStackFormatting() {
        let generalKey = makeTestKey(label: "deploy-key", purpose: .general)
        let stack = KeyDetailInspectorView.headerTitleStack(for: generalKey)
        #expect(stack.title == "deploy-key")
        #expect(stack.subtitle == "ECDSA P-256 · Hardware Key")

        let customAlgoKey = SSHKeyInfo(
            label: "ed25519-key",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@sk",
            publicKeyBlob: Data(repeating: 0x42, count: 32),
            fingerprint: "SHA256:soft1234567890defghijklmnopqrstuvwxyz123456",
            createdAt: Date(),
            algorithmName: "Ed25519-SK",
            storage: .secureEnclave,
            biometricPolicy: .userPresence,
            keyPurpose: .general
        )
        let customStack = KeyDetailInspectorView.headerTitleStack(for: customAlgoKey)
        #expect(customStack.title == "ed25519-key")
        #expect(customStack.subtitle == "Ed25519-SK · Hardware Key")

        // Also verify underlying subtitle formatter handles software fallback correctly
        #expect(ClavisUIStrings.Inspector.keySubtitle(algorithm: "RSA-4096", isHardware: false) == "RSA-4096 · Software Key")
    }

    @Test
    func testOverflowMenuDeduplicationAcrossKeyPurposes() {
        // Agent keys contain deploy key, openSSH, fingerprint, change purpose, delete
        let agentKey = makeTestKey(purpose: .agent)
        let agentActions = KeyDetailInspectorView.overflowMenuActions(for: agentKey)
        #expect(agentActions == [.copyDeployKey, .copyOpenSSH, .copyFingerprint, .changePurpose, .deleteKey])

        // General keys contain openSSH, fingerprint, change purpose, delete
        let generalKey = makeTestKey(purpose: .general)
        let generalActions = KeyDetailInspectorView.overflowMenuActions(for: generalKey)
        #expect(generalActions == [.copyOpenSSH, .copyFingerprint, .changePurpose, .deleteKey])

        // Git signing keys contain openSSH, fingerprint, delete (immutable purpose)
        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        let gitActions = KeyDetailInspectorView.overflowMenuActions(for: gitKey)
        #expect(gitActions == [.copyOpenSSH, .copyFingerprint, .deleteKey])

        // Assert Show History is NEVER present in the overflow menu for any key purpose
        for purpose in [KeyPurpose.general, KeyPurpose.agent, KeyPurpose.gitSigningOnly] {
            let key = makeTestKey(purpose: purpose)
            let actions = KeyDetailInspectorView.overflowMenuActions(for: key)
            #expect(!actions.contains(where: { "\($0)".lowercased().contains("history") }))
        }
    }

    @Test
    func testPrimaryHeaderShowHistoryStringAndIcon() {
        #expect(ClavisUIStrings.History.showHistory == "Show History")
        #expect(ClavisUIStrings.Accessibility.moreActions == "More actions")
    }

    // MARK: - Milestone M2 (PR 2): Consistent Public Identity Bordered Copy Controls (Refs clavis-m46)

    @Test
    func testPublicIdentityCopyStringsAndAccessibility() {
        #expect(ClavisUIStrings.Common.copy == "Copy")
        #expect(ClavisUIStrings.Inspector.copySSHKeyButton == "Copy SSH Key")
        #expect(ClavisUIStrings.KeyDetail.copyDeployKey == "Copy Deploy Key")
        #expect(ClavisUIStrings.Accessibility.copyFingerprint == "Copy SHA-256 fingerprint")
        #expect(ClavisUIStrings.Inspector.copyFingerprintHelp == "Copy SHA-256 Fingerprint")
    }

    @Test
    func testFingerprintCopyButtonAttributes() {
        let attrs = KeyDetailInspectorView.fingerprintCopyButtonAttributes()

        // 1. Button label string matching ClavisUIStrings.Common.copy ("Copy")
        #expect(attrs.label == ClavisUIStrings.Common.copy)
        #expect(attrs.label == "Copy")

        // 2. Accessibility label matching ClavisUIStrings.Accessibility.copyFingerprint ("Copy SHA-256 fingerprint")
        #expect(attrs.accessibilityLabel == ClavisUIStrings.Accessibility.copyFingerprint)
        #expect(attrs.accessibilityLabel == "Copy SHA-256 fingerprint")

        // 3. Tooltip help string matching ClavisUIStrings.Inspector.copyFingerprintHelp ("Copy SHA-256 Fingerprint")
        #expect(attrs.help == ClavisUIStrings.Inspector.copyFingerprintHelp)
        #expect(attrs.help == "Copy SHA-256 Fingerprint")

        // 4. Assert distinctions between control attributes
        #expect(!attrs.label.isEmpty)
        #expect(!attrs.accessibilityLabel.isEmpty)
        #expect(!attrs.help.isEmpty)
        #expect(attrs.label != attrs.accessibilityLabel)
        #expect(attrs.label != attrs.help)
    }

    @Test
    func testPublicKeyCopyButtonTitleForDifferentKeyPurposes() {
        // General SSH key: "Copy SSH Key"
        let generalKey = makeTestKey(label: "personal-laptop", purpose: .general)
        #expect(KeyDetailInspectorView.publicKeyCopyButtonTitle(for: generalKey) == ClavisUIStrings.Inspector.copySSHKeyButton)
        #expect(KeyDetailInspectorView.publicKeyCopyButtonTitle(for: generalKey) == "Copy SSH Key")

        // Git signing only key: "Copy SSH Key"
        let gitKey = makeTestKey(label: "git-commit-signer", purpose: .gitSigningOnly)
        #expect(KeyDetailInspectorView.publicKeyCopyButtonTitle(for: gitKey) == ClavisUIStrings.Inspector.copySSHKeyButton)
        #expect(KeyDetailInspectorView.publicKeyCopyButtonTitle(for: gitKey) == "Copy SSH Key")

        // Agent key: "Copy Deploy Key"
        let agentKey = makeTestKey(label: "agent-session-key", purpose: .agent)
        #expect(KeyDetailInspectorView.publicKeyCopyButtonTitle(for: agentKey) == ClavisUIStrings.KeyDetail.copyDeployKey)
        #expect(KeyDetailInspectorView.publicKeyCopyButtonTitle(for: agentKey) == "Copy Deploy Key")
    }

    @Test
    func testCopyActionFeedbackStrings() {
        // Assert exact localized values and non-empty feedback strings
        #expect(ClavisUIStrings.Inspector.feedbackCopiedFingerprint == "Copied fingerprint to clipboard")
        #expect(ClavisUIStrings.Inspector.feedbackCopiedOpenSSH == "Copied OpenSSH public key to clipboard")

        #expect(!ClavisUIStrings.Inspector.feedbackCopiedFingerprint.isEmpty)
        #expect(!ClavisUIStrings.Inspector.feedbackCopiedOpenSSH.isEmpty)
        #expect(ClavisUIStrings.Inspector.feedbackCopiedFingerprint != ClavisUIStrings.Inspector.feedbackCopiedOpenSSH)
    }

    @Test
    func testPublicIdentityCopyControlsComposite() {
        let generalKey = makeTestKey(purpose: .general)
        let generalControls = KeyDetailInspectorView.publicIdentityCopyControls(for: generalKey)
        #expect(generalControls.publicKeyButtonTitle == ClavisUIStrings.Inspector.copySSHKeyButton)
        #expect(generalControls.publicKeyFeedback == ClavisUIStrings.Inspector.feedbackCopiedOpenSSH)
        #expect(generalControls.fingerprintButtonLabel == ClavisUIStrings.Common.copy)
        #expect(generalControls.fingerprintAccessibilityLabel == ClavisUIStrings.Accessibility.copyFingerprint)
        #expect(generalControls.fingerprintHelp == ClavisUIStrings.Inspector.copyFingerprintHelp)
        #expect(generalControls.fingerprintFeedback == ClavisUIStrings.Inspector.feedbackCopiedFingerprint)

        let agentKey = makeTestKey(purpose: .agent)
        let agentControls = KeyDetailInspectorView.publicIdentityCopyControls(for: agentKey)
        #expect(agentControls.publicKeyButtonTitle == ClavisUIStrings.KeyDetail.copyDeployKey)
        #expect(agentControls.publicKeyFeedback == ClavisUIStrings.Inspector.feedbackCopiedOpenSSH)
    }

    // MARK: - Milestone M3 (PR 3): Consolidate Socket Status & Security Posture into SECURITY Card (Refs clavis-cc3)

    @Test
    func testConsolidatedSecurityInfoForGeneralKey() {
        let generalKey = makeTestKey(purpose: .general, biometricPolicy: .userPresence)
        let info = KeyDetailInspectorView.consolidatedSecurityInfo(for: generalKey, isSocketActive: true)

        #expect(info.storageValue == ClavisUIStrings.Inspector.storageHardwareEnclave)
        #expect(info.authenticationValue == ClavisUIStrings.Inspector.authUserPresence)
        #expect(info.socketName == "ssh-agent socket")
        #expect(info.socketPath == "~/.ssh/clavis.sock")
        #expect(info.socketStatus == ClavisUIStrings.Inspector.statusActive)
        #expect(info.isSocketActive == true)
        #expect(info.postureIcon == "lock.shield.fill")
        #expect(info.postureDescription.contains("Touch ID user presence per operation"))
    }

    @Test
    func testConsolidatedSecurityInfoForStrictBiometricsGeneralKey() {
        let strictKey = makeTestKey(purpose: .general, biometricPolicy: .biometryCurrentSet)
        let info = KeyDetailInspectorView.consolidatedSecurityInfo(for: strictKey, isSocketActive: false)

        #expect(info.authenticationValue == ClavisUIStrings.Inspector.authTouchIdOnlyStrict)
        #expect(info.socketStatus == ClavisUIStrings.Inspector.statusOffline)
        #expect(info.isSocketActive == false)
        #expect(info.postureIcon == "touchid")
        #expect(info.postureDescription.contains("current biometric enrollment"))
    }

    @Test
    func testConsolidatedSecurityInfoForGitSigningOnlyKey() {
        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        let info = KeyDetailInspectorView.consolidatedSecurityInfo(for: gitKey, isSocketActive: true)

        #expect(info.socketName == "ssh-agent socket")
        #expect(info.socketPath == "~/.ssh/clavis.sock")
        #expect(info.postureIcon == "arrow.triangle.branch")
        #expect(info.postureDescription.contains("Restricted strictly to local Git commit and tag signing"))
    }

    @Test
    func testConsolidatedSecurityInfoForAgentKey() {
        let agentKey = makeTestKey(purpose: .agent)
        let policy = AgentKeyPolicy(mode: .notify, leaseMinutes: 120)
        let info = KeyDetailInspectorView.consolidatedSecurityInfo(
            for: agentKey,
            isSocketActive: true,
            agentPolicy: policy
        )

        #expect(info.socketName == "agent socket")
        #expect(info.socketPath == "~/.ssh/clavis-agent.sock")
        #expect(info.postureIcon == "cpu")
        #expect(info.postureDescription.contains("post a notification on each signature"))
        #expect(info.postureDescription.contains("2h"))
    }

    @Test
    func testPostureIconMappingAcrossKeyPurposes() {
        let generalKey = makeTestKey(purpose: .general, biometricPolicy: .userPresence)
        #expect(KeyDetailInspectorView.postureIcon(for: generalKey) == "lock.shield.fill")
        #expect(KeyDetailInspectorView.securityPostureIcon(for: generalKey) == "lock.shield.fill")

        let strictKey = makeTestKey(purpose: .general, biometricPolicy: .biometryCurrentSet)
        #expect(KeyDetailInspectorView.postureIcon(for: strictKey) == "touchid")
        #expect(KeyDetailInspectorView.securityPostureIcon(for: strictKey) == "touchid")

        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        #expect(KeyDetailInspectorView.postureIcon(for: gitKey) == "arrow.triangle.branch")
        #expect(KeyDetailInspectorView.securityPostureIcon(for: gitKey) == "arrow.triangle.branch")

        let agentKey = makeTestKey(purpose: .agent)
        #expect(KeyDetailInspectorView.postureIcon(for: agentKey) == "cpu")
        #expect(KeyDetailInspectorView.securityPostureIcon(for: agentKey) == "cpu")
    }

    @Test
    func testSecurityCardSocketRowConsolidationAcrossKeyPurposes() {
        let generalKey = makeTestKey(purpose: .general)
        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        let agentKey = makeTestKey(purpose: .agent)

        // General key active & offline
        let generalActive = KeyDetailInspectorView.securityCardSocketRow(for: generalKey, isSocketActive: true)
        #expect(generalActive.name == "ssh-agent socket")
        #expect(generalActive.socketPath == "~/.ssh/clavis.sock")
        #expect(generalActive.status == ClavisUIStrings.Inspector.statusActive)
        #expect(generalActive.isActive == true)

        let generalOffline = KeyDetailInspectorView.securityCardSocketRow(for: generalKey, isSocketActive: false)
        #expect(generalOffline.status == ClavisUIStrings.Inspector.statusOffline)
        #expect(generalOffline.isActive == false)

        // Git signing only key active & offline
        let gitActive = KeyDetailInspectorView.securityCardSocketRow(for: gitKey, isSocketActive: true)
        #expect(gitActive.name == "ssh-agent socket")
        #expect(gitActive.socketPath == "~/.ssh/clavis.sock")
        #expect(gitActive.status == ClavisUIStrings.Inspector.statusActive)
        #expect(gitActive.isActive == true)

        // Agent key active & offline
        let agentActive = KeyDetailInspectorView.securityCardSocketRow(for: agentKey, isSocketActive: true)
        #expect(agentActive.name == "agent socket")
        #expect(agentActive.socketPath == "~/.ssh/clavis-agent.sock")
        #expect(agentActive.status == ClavisUIStrings.Inspector.statusActive)
        #expect(agentActive.isActive == true)

        let agentOffline = KeyDetailInspectorView.securityCardSocketRow(for: agentKey, isSocketActive: false)
        #expect(agentOffline.name == "agent socket")
        #expect(agentOffline.socketPath == "~/.ssh/clavis-agent.sock")
        #expect(agentOffline.status == ClavisUIStrings.Inspector.statusOffline)
        #expect(agentOffline.isActive == false)
    }

    @Test
    func testSecurityPostureFootnoteFormattingAcrossKeyPurposes() {
        // 1. General Key (User Presence)
        let generalPresenceKey = makeTestKey(purpose: .general, biometricPolicy: .userPresence)
        let presenceFootnote = KeyDetailInspectorView.securityPostureFootnote(for: generalPresenceKey)
        #expect(presenceFootnote.contains("Touch ID user presence per operation"))
        #expect(presenceFootnote.contains("5-minute process-scoped Git signing grace window"))
        #expect(presenceFootnote.contains("Keys cannot be cached"))

        // 2. General Key (Strict Biometrics)
        let generalStrictKey = makeTestKey(purpose: .general, biometricPolicy: .biometryCurrentSet)
        let strictFootnote = KeyDetailInspectorView.securityPostureFootnote(for: generalStrictKey)
        #expect(strictFootnote.contains("current biometric enrollment"))
        #expect(strictFootnote.contains("Device password fallback is disabled"))

        // 3. Git Signing Only Key
        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        let gitFootnote = KeyDetailInspectorView.securityPostureFootnote(for: gitKey)
        #expect(gitFootnote.contains("Restricted strictly to local Git commit and tag signing"))
        #expect(gitFootnote.contains("Forwarded agent requests are blocked"))

        // 4. Agent Key Modes
        let agentKey = makeTestKey(purpose: .agent)
        let silentPolicy = AgentKeyPolicy(mode: .none, leaseMinutes: 480)
        let silentFootnote = KeyDetailInspectorView.securityPostureFootnote(for: agentKey, agentPolicy: silentPolicy)
        #expect(silentFootnote.contains("silently without prompts"))
        #expect(silentFootnote.contains("Apple Secure Enclave"))

        let notifyPolicy = AgentKeyPolicy(mode: .notify, leaseMinutes: 120)
        let notifyFootnote = KeyDetailInspectorView.securityPostureFootnote(for: agentKey, agentPolicy: notifyPolicy)
        #expect(notifyFootnote.contains("post a notification on each signature"))
        #expect(notifyFootnote.contains("Apple Secure Enclave"))

        let askPolicy = AgentKeyPolicy(mode: .ask, leaseMinutes: 60)
        let askFootnote = KeyDetailInspectorView.securityPostureFootnote(for: agentKey, agentPolicy: askPolicy)
        #expect(askFootnote.contains("explicit Touch ID user confirmation"))
        #expect(askFootnote.contains("Apple Secure Enclave"))
    }

    @Test
    func testSecurityPostureFootnoteActiveGitGraceIntegration() {
        let generalKey = makeTestKey(purpose: .general)
        let footnoteWithGrace = KeyDetailInspectorView.securityPostureFootnote(for: generalKey, hasActiveGitGrace: true)
        #expect(footnoteWithGrace.contains("A 5-minute Git signing grace session is currently active for this key."))

        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        let gitFootnoteWithGrace = KeyDetailInspectorView.securityPostureFootnote(for: gitKey, hasActiveGitGrace: true)
        #expect(gitFootnoteWithGrace.contains("A 5-minute Git signing grace session is currently active for this key."))
    }

    @Test
    func testPreservedLocalizationInvariantsForUsedBySection() {
        #expect(!ClavisUIStrings.Inspector.usedBySection.isEmpty)
        #expect(ClavisUIStrings.Inspector.usedBySection == "USED BY")
        #expect(ClavisUIStrings.Inspector.socketStatusActive == "Active")
        #expect(ClavisUIStrings.Inspector.socketStatusOffline == "Offline")
        #expect(!ClavisUIStrings.Inspector.securitySection.isEmpty)
    }

    // MARK: - Key Purpose Actions & Localization Invariants (M4 / clavis-t53)

    @Test
    func testKeyPurposeActionStringsAndInvariants() {
        let strings = KeyDetailInspectorView.purposeActionStrings
        #expect(strings.actionLabel == "Change Purpose…")
        #expect(strings.confirmButton == "Change Purpose")
        #expect(strings.alertTitle == "Change Purpose…")

        #expect(ClavisUIStrings.Inspector.changeKind == strings.actionLabel)
        #expect(ClavisUIStrings.Inspector.changeKindConfirm == strings.confirmButton)
        #expect(ClavisUIStrings.KeyDetail.changeKind == strings.actionLabel)
        #expect(ClavisUIStrings.KeyDetail.changeKindConfirm == strings.confirmButton)

        let msg = strings.alertMessage(label: "my-key", targetPurpose: .agent)
        #expect(msg.contains("my-key"))
        #expect(msg.contains("Agent"))
        #expect(msg.contains("purpose") || msg.contains("назначение"))
    }

    // MARK: - Destructive Delete Footer Control & Inspector Localization (M5 / clavis-uta)

    @Test
    func testDeleteFooterAttributes() {
        let key = makeTestKey(label: "deploy-key", fingerprint: "SHA256:abc1234567890def")
        let footer = KeyDetailInspectorView.deleteFooterAttributes(for: key)

        #expect(footer.buttonTitle == ClavisUIStrings.Inspector.deleteKey)
        #expect(footer.buttonTitle == "Delete Key")
        #expect(footer.iconSystemName == "trash")
        #expect(footer.alertTitle == "\(ClavisUIStrings.Inspector.deleteAlertTitle) (deploy-key)")
        #expect(footer.confirmButtonTitle == ClavisUIStrings.Common.delete)
        #expect(footer.confirmButtonTitle == "Delete")
        #expect(footer.cancelButtonTitle == ClavisUIStrings.Common.cancel)
        #expect(footer.cancelButtonTitle == "Cancel")
    }

    @Test
    func testDeleteConfirmationAlertMessageExactFormatting() {
        let key = makeTestKey(
            label: "production-deploy",
            fingerprint: "SHA256:uD734VbKz8x91011121314151617181920212223242"
        )

        let message = KeyDetailInspectorView.deleteConfirmationMessage(
            label: key.label,
            shortFingerprint: key.shortFingerprint
        )

        #expect(message == "Are you sure you want to delete 'production-deploy' (SHA256:uD734VbKz)? This action cannot be undone.")
    }

    @Test
    func testActiveGitSessionStringsAndRevocation() {
        #expect(ClavisUIStrings.Inspector.activeGitSessionSection == "ACTIVE GIT SIGNING SESSION")
        #expect(ClavisUIStrings.Inspector.revokeGitSessionButton == "Revoke")
        #expect(ClavisUIStrings.Inspector.revokeGitSession == "Revoke Session")
    }

    @Test
    func testSecurityBadgeTextLocalization() {
        let agentKey = makeTestKey(purpose: .agent)
        #expect(KeyDetailInspectorView.securityBadgeText(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .none)) == "Silent")
        #expect(KeyDetailInspectorView.securityBadgeText(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .notify)) == "Notify")
        #expect(KeyDetailInspectorView.securityBadgeText(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .ask)) == "Always Prompt")

        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        #expect(KeyDetailInspectorView.securityBadgeText(for: gitKey, hasActiveGitGrace: false) == "Git Only")
        #expect(KeyDetailInspectorView.securityBadgeText(for: gitKey, hasActiveGitGrace: true) == "Grace Active")

        let generalKey = makeTestKey(purpose: .general)
        #expect(KeyDetailInspectorView.securityBadgeText(for: generalKey, hasActiveGitGrace: false) == "Always Prompt")
        #expect(KeyDetailInspectorView.securityBadgeText(for: generalKey, hasActiveGitGrace: true) == "Grace Active")
    }

    @Test
    func testDynamicSecuritySubtitleLocalization() {
        let agentKey = makeTestKey(purpose: .agent)
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .none)) == "Hardware Isolated · Silent agent lease")
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .notify)) == "Hardware Isolated · Agent lease with notification")
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .ask)) == "Hardware Isolated · Touch ID prompt per agent signature")

        let gitKey = makeTestKey(purpose: .gitSigningOnly)
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: gitKey, hasActiveGitGrace: false) == "Hardware Isolated · Git commit signing only")
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: gitKey, hasActiveGitGrace: true) == "Hardware Isolated · Git signing grace active")

        let generalKey = makeTestKey(purpose: .general)
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: generalKey, hasActiveGitGrace: false) == "Hardware Isolated · Touch ID per operation")
        #expect(KeyDetailInspectorView.dynamicSecuritySubtitle(for: generalKey, hasActiveGitGrace: true) == "Hardware Isolated · Git signing grace active")
    }

    @Test
    func testSocketStatusInfoLocalization() {
        let agentKey = makeTestKey(purpose: .agent)
        let agentSocket = KeyDetailInspectorView.socketStatusInfo(for: agentKey, isSocketActive: true)
        #expect(agentSocket.name == "agent socket")
        #expect(agentSocket.socketPath == "~/.ssh/clavis-agent.sock")
        #expect(agentSocket.status == "Active")

        let generalKey = makeTestKey(purpose: .general)
        let generalSocket = KeyDetailInspectorView.socketStatusInfo(for: generalKey, isSocketActive: false)
        #expect(generalSocket.name == "ssh-agent socket")
        #expect(generalSocket.socketPath == "~/.ssh/clavis.sock")
        #expect(generalSocket.status == "Offline")
    }

    @Test
    func testTrimIdentityMiddleTruncation() {
        let short = "SHA256:short"
        #expect(KeyDetailInspectorView.trimIdentity(short) == short)

        let longKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ8s9Ak7mD4Kx2vUqW5fYh3nPb6gRz0eLcVt1oHiE8wQjN7yM5Sa2x6bF4kU9dC0rThG3vP1eZ8s5QlN6nY= test"
        let trimmed = KeyDetailInspectorView.trimIdentity(longKey)
        #expect(trimmed.hasPrefix(String(longKey.prefix(32))))
        #expect(trimmed.hasSuffix(String(longKey.suffix(14))))
        #expect(trimmed.contains("…"))
        #expect(trimmed.count == 32 + 1 + 14)
    }

    @Test
    func testApprovalSummaryAndDescriptionTexts() {
        let strictGeneral = makeTestKey(purpose: .general, biometricPolicy: .biometryCurrentSet)
        #expect(KeyDetailInspectorView.approvalSummaryText(for: strictGeneral) == "Strict biometrics")
        #expect(KeyDetailInspectorView.approvalDescriptionText(for: strictGeneral).contains("Touch ID only"))

        let presenceGeneral = makeTestKey(purpose: .general, biometricPolicy: .userPresence)
        #expect(KeyDetailInspectorView.approvalSummaryText(for: presenceGeneral) == "User presence")
        #expect(KeyDetailInspectorView.approvalDescriptionText(for: presenceGeneral).contains("Apple Watch"))

        let agentKey = makeTestKey(purpose: .agent, biometricPolicy: .userPresence)
        #expect(KeyDetailInspectorView.approvalSummaryText(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .none)) == "Autonomous")
        #expect(KeyDetailInspectorView.approvalSummaryText(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .notify)) == "Notify only")
        #expect(KeyDetailInspectorView.approvalSummaryText(for: agentKey, agentPolicy: AgentKeyPolicy(mode: .ask)) == "User presence")
    }

    @Test
    @MainActor
    func testInlineRenameFieldPreserves28ptHeight() {
        var draft = "test 2"
        let field = InlineKeyRenameField(
            text: Binding(get: { draft }, set: { draft = $0 }),
            onCommit: {},
            onCancel: {}
        )
        let hosting = NSHostingView(
            rootView: field
                .frame(height: 28, alignment: .leading)
                .overlay(alignment: .bottom) {
                    Rectangle().frame(height: 1)
                }
        )
        #expect(hosting.fittingSize.height == 28)
    }

    @Test
    @MainActor
    func testInlineRenameFieldClickOutsideCommitsAndLosesFocus() {
        var draft = "initial-name"
        var commitCount = 0
        var cancelCount = 0

        let field = InlineKeyRenameField(
            text: Binding(get: { draft }, set: { draft = $0 }),
            onCommit: { commitCount += 1 },
            onCancel: { cancelCount += 1 }
        )
        let coordinator = field.makeCoordinator()

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 300),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 300))
        window.contentView = container

        let textField = NSTextField(frame: NSRect(x: 20, y: 240, width: 180, height: 28))
        textField.stringValue = draft
        textField.delegate = coordinator
        container.addSubview(textField)
        coordinator.textField = textField

        window.makeFirstResponder(textField)
        textField.stringValue = "renamed-key"

        // Clicking inside the text field bounds must not commit
        let insideClickHandled = coordinator.handleMouseDown(
            in: window,
            locationInWindow: NSPoint(x: 50, y: 250)
        )
        #expect(insideClickHandled == false)
        #expect(commitCount == 0)

        // Clicking outside the text field bounds resigns focus and commits once
        let outsideClickHandled = coordinator.handleMouseDown(
            in: window,
            locationInWindow: NSPoint(x: 200, y: 100)
        )
        #expect(outsideClickHandled == true)
        #expect(commitCount == 1)
        #expect(cancelCount == 0)
        #expect(draft == "renamed-key")

        // Subsequent outside clicks after finish must be ignored
        let secondOutsideClick = coordinator.handleMouseDown(
            in: window,
            locationInWindow: NSPoint(x: 200, y: 100)
        )
        #expect(secondOutsideClick == false)
        #expect(commitCount == 1)
    }

    @Test
    @MainActor
    func testSettingsSheetModalAndOutsideClickDismissal() {
        #expect(KeyManagerSheet.settings.id == "settings")
        #expect(KeyManagerSheet.create.id == "create")

        var dismissCount = 0
        let bridge = SheetOutsideClickDismissBridge(onDismiss: { dismissCount += 1 })
        let coordinator = bridge.makeCoordinator()

        let parentWindow = NSWindow(
            contentRect: NSRect(x: 100, y: 100, width: 600, height: 500),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        let sheetWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 300, height: 200),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        let probeView = NSView(frame: NSRect(x: 0, y: 0, width: 1, height: 1))
        sheetWindow.contentView?.addSubview(probeView)
        coordinator.probeView = probeView

        parentWindow.beginSheet(sheetWindow)
        defer { parentWindow.endSheet(sheetWindow) }

        let sheetCenter = NSPoint(x: sheetWindow.frame.midX, y: sheetWindow.frame.midY)
        #expect(coordinator.handleMouseDown(in: sheetWindow, screenLocation: sheetCenter) == false)
        #expect(dismissCount == 0)

        let outsideInParent = NSPoint(x: parentWindow.frame.minX + 12, y: parentWindow.frame.minY + 12)
        #expect(coordinator.handleMouseDown(in: parentWindow, screenLocation: outsideInParent) == true)
        #expect(dismissCount == 1)
    }

    @Test
    @MainActor
    func testCircularGlassIconButtonDoesNotTakeSheetInitialFocus() {
        let parentWindow = NSWindow(
            contentRect: NSRect(x: 100, y: 100, width: 600, height: 500),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        let sheetWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 300, height: 200),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        let hostingView = NSHostingView(
            rootView: VStack {
                CircularGlassIconButton(
                    icon: "xmark",
                    size: 28,
                    iconSize: 11,
                    helpText: "Cancel",
                    accessibilityLabel: "Cancel",
                    action: {}
                )
            }
            .frame(width: 300, height: 200)
        )
        sheetWindow.contentView = hostingView
        hostingView.layoutSubtreeIfNeeded()

        parentWindow.beginSheet(sheetWindow)
        defer { parentWindow.endSheet(sheetWindow) }

        sheetWindow.recalculateKeyViewLoop()
        sheetWindow.selectNextKeyView(nil)

        #expect(sheetWindow.firstResponder === sheetWindow)
    }

    @Test
    @MainActor
    func testSidebarAndMainPaneUseFullHeightScrollViewsWithTopGlassBars() throws {
        let appState = AppState()
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 911, height: 400),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden

        let hostingView = NSHostingView(rootView: KeyListView().environmentObject(appState))
        window.contentView = hostingView
        window.makeKeyAndOrderFront(nil)
        defer { window.orderOut(nil) }
        hostingView.layoutSubtreeIfNeeded()
        appState.keys = (1...10).map { makeTestKey(label: "Test \($0)", fingerprint: "SHA256:abc1234567890def\($0)") }
        RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        hostingView.layoutSubtreeIfNeeded()

        func collectScrollViews(in view: NSView) -> [NSScrollView] {
            var result: [NSScrollView] = []
            if let sv = view as? NSScrollView {
                result.append(sv)
            }
            for sub in view.subviews {
                result.append(contentsOf: collectScrollViews(in: sub))
            }
            return result
        }

        let scrollViews = collectScrollViews(in: hostingView)
        #expect(scrollViews.count == 2)
        let leftSV = try #require(scrollViews.first { abs($0.frame.width - 222) < 1 && abs($0.frame.height - 400) < 1 })
        let rightSV = try #require(scrollViews.first { abs($0.frame.width - 689) < 1 && abs($0.frame.height - 400) < 1 })
        #expect(leftSV.contentInsets.top >= KeyListView.toolbarHeight)
        #expect(rightSV.contentInsets.top >= KeyListView.toolbarHeight)

        func pocketSubviews(in sv: NSScrollView) -> [NSView] {
            sv.subviews.filter {
                let name = String(describing: type(of: $0))
                return name.contains("Pocket") || name.contains("BackdropView")
            }
        }

        // At rest, scroll pocket and backdrop views are hidden so the header matches the pane surface.
        #expect(!pocketSubviews(in: leftSV).isEmpty)
        #expect(pocketSubviews(in: leftSV).allSatisfy { $0.isHidden })
        #expect(!pocketSubviews(in: rightSV).isEmpty)
        #expect(pocketSubviews(in: rightSV).allSatisfy { $0.isHidden })

        // Scrolling reveals the liquid glass pocket.
        leftSV.contentView.setBoundsOrigin(NSPoint(x: 0, y: -60))
        NotificationCenter.default.post(name: NSView.boundsDidChangeNotification, object: leftSV.contentView)
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        #expect(pocketSubviews(in: leftSV).allSatisfy { !$0.isHidden })

        // Returning to the top fades out the pocket smoothly (stays unhidden during transition, then hides on completion).
        leftSV.contentView.setBoundsOrigin(NSPoint(x: 0, y: -leftSV.contentInsets.top))
        NotificationCenter.default.post(name: NSView.boundsDidChangeNotification, object: leftSV.contentView)
        let leftPocket = try #require(leftSV.subviews.first { String(describing: type(of: $0)) == "NSScrollPocket" })
        let rightPocket = try #require(rightSV.subviews.first { String(describing: type(of: $0)) == "NSScrollPocket" })
        #expect(!leftPocket.isHidden)
        #expect(leftPocket.alphaValue == 0.0)
        #expect(leftPocket.layer?.allowsGroupOpacity == false)

        // Left and right scroll pockets must use distinct backdropGroupNames so scrolling one pane
        // never alters the other pane's CABackdropLayer capture in WindowServer.
        let leftGroup = leftPocket.identifier?.rawValue
        let rightGroup = rightPocket.identifier?.rawValue
        #expect(leftGroup != nil)
        #expect(rightGroup != nil)
        #expect(leftGroup != rightGroup)

        let fadeOutDeadline = Date().addingTimeInterval(2.0)
        while !pocketSubviews(in: leftSV).allSatisfy(\.isHidden) && Date() < fadeOutDeadline {
            _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }
        #expect(pocketSubviews(in: leftSV).allSatisfy { $0.isHidden })

        appState.activeMainPane = .history
        RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        hostingView.layoutSubtreeIfNeeded()
        let historyScrollViews = collectScrollViews(in: hostingView)
        let historyRightSV = try #require(historyScrollViews.first { abs($0.frame.width - 689) < 1 && abs($0.frame.height - 400) < 1 })
        #expect(historyRightSV.contentInsets.top >= KeyListView.toolbarHeight)
        #expect(!pocketSubviews(in: historyRightSV).isEmpty)
        #expect(pocketSubviews(in: historyRightSV).allSatisfy { $0.isHidden })

        historyRightSV.documentView?.setFrameSize(NSSize(width: 689, height: 800))
        historyRightSV.contentView.setBoundsOrigin(NSPoint(x: 0, y: -60))
        NotificationCenter.default.post(name: NSView.boundsDidChangeNotification, object: historyRightSV.contentView)
        #expect(pocketSubviews(in: historyRightSV).allSatisfy { !$0.isHidden })

        let historyPocket = try #require(historyRightSV.subviews.first { String(describing: type(of: $0)) == "NSScrollPocket" })
        let historyGroup = historyPocket.identifier?.rawValue
        #expect(historyGroup != nil)
        #expect(historyGroup != leftGroup)
    }
}
