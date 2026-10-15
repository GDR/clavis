@testable import ClavisTestSupport
import Testing
import Foundation
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
            let appState = AppState(keyManager: keyManager)

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
}
