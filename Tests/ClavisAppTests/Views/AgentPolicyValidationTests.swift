@testable import ClavisTestSupport
import Testing
import Foundation
import SwiftUI
@testable import ClavisCore
@testable import Clavis

@Suite("AgentPolicyValidationTests")
struct AgentPolicyValidationTests {

    // MARK: - #97 Rate Limit Validation ("Max Signatures / Min")

    @Test("Non-numeric rate limit triggers inline validation error")
    func testNonNumericRateLimitReturnsError() {
        let invalidInputs = [
            "10/min",
            "abc",
            "5.5",
            "10.0",
            "12a",
            "ten",
            "--5",
            "one",
            "5,5"
        ]

        for input in invalidInputs {
            let error = AgentPolicyValidator.validateMaxSignaturesPerMinute(input)
            #expect(error != nil, "Expected validation error for non-numeric input: '\(input)'")
            #expect(error == "Max Signatures / Min must be a valid positive integer")
        }
    }

    @Test("Zero or negative rate limit triggers inline validation error")
    func testZeroOrNegativeRateLimitReturnsError() {
        let zeroAndNegativeInputs = ["0", "-1", "-5", "-100"]

        for input in zeroAndNegativeInputs {
            let error = AgentPolicyValidator.validateMaxSignaturesPerMinute(input)
            #expect(error != nil, "Expected validation error for zero/negative input: '\(input)'")
            #expect(error == "Max Signatures / Min must be greater than 0")
        }
    }

    @Test("Empty or whitespace-only rate limit triggers inline validation error")
    func testEmptyRateLimitReturnsError() {
        let emptyInputs = ["", "   ", "\t", "\n"]

        for input in emptyInputs {
            let error = AgentPolicyValidator.validateMaxSignaturesPerMinute(input)
            #expect(error != nil, "Expected validation error for empty input")
            #expect(error == "Max Signatures / Min cannot be empty")
        }
    }

    @Test("Out of range rate limit (> 600) triggers inline validation error")
    func testOutOfRangeRateLimitReturnsError() {
        let outOfRangeInputs = ["601", "1000", "50000"]

        for input in outOfRangeInputs {
            let error = AgentPolicyValidator.validateMaxSignaturesPerMinute(input)
            #expect(error != nil, "Expected validation error for out-of-range input: '\(input)'")
            #expect(error == "Max Signatures / Min must be between 1 and 600")
        }
    }

    @Test("Valid positive integer rate limits return no error")
    func testValidRateLimitsSucceed() {
        let validInputs = ["1", "6", "10", "30", "60", "600", "  15  "]

        for input in validInputs {
            let error = AgentPolicyValidator.validateMaxSignaturesPerMinute(input)
            #expect(error == nil, "Expected valid rate limit for '\(input)', got error: \(String(describing: error))")
        }
    }

    // MARK: - #97 Allowed Hosts Pattern Validation

    @Test("Allowed hosts rejects URL schemes (e.g. ssh://, https://)")
    func testHostPatternRejectsURLSchemes() {
        let schemeInputs = [
            "ssh://github.com",
            "https://gitlab.com",
            "http://192.168.1.1",
            "git://github.com",
            "custom://myhost"
        ]

        for input in schemeInputs {
            let error = AgentPolicyValidator.validateHostPattern(input)
            #expect(error != nil, "Expected validation error for scheme in: '\(input)'")
            #expect(error?.contains("URL schemes") == true, "Expected scheme warning for '\(input)'")
        }
    }

    @Test("Allowed hosts rejects port numbers (e.g. :22)")
    func testHostPatternRejectsPorts() {
        let portInputs = [
            "github.com:22",
            "gitlab.com:2222",
            "192.168.1.1:22",
            "[2001:db8::1]:22",
            "host.internal:8080"
        ]

        for input in portInputs {
            let error = AgentPolicyValidator.validateHostPattern(input)
            #expect(error != nil, "Expected validation error for port in: '\(input)'")
            #expect(error?.contains("Port numbers") == true, "Expected port warning for '\(input)'")
        }
    }

    @Test("Allowed hosts rejects usernames and paths")
    func testHostPatternRejectsUsernamesAndPaths() {
        let invalidInputs = [
            "git@github.com",
            "user@server.local",
            "github.com/repo",
            "host.example.com/path"
        ]

        for input in invalidInputs {
            let error = AgentPolicyValidator.validateHostPattern(input)
            #expect(error != nil, "Expected validation error for: '\(input)'")
        }
    }

    @Test("Allowed hosts rejects empty or invalid syntax patterns")
    func testHostPatternRejectsInvalidSyntax() {
        let invalidSyntax = [
            "",
            "   ",
            "host name",
            "host;evil",
            "host$var",
            "host!name"
        ]

        for input in invalidSyntax {
            let error = AgentPolicyValidator.validateHostPattern(input)
            #expect(error != nil, "Expected validation error for invalid syntax: '\(input)'")
        }
    }

    @Test("Allowed hosts rejects patterns exceeding 255 characters")
    func testHostPatternRejectsExcessiveLength() {
        let tooLong = String(repeating: "a", count: 256)
        let error = AgentPolicyValidator.validateHostPattern(tooLong)
        #expect(error != nil)
        #expect(error?.contains("must not exceed 255 characters") == true)
    }

    @Test("Allowed hosts accepts valid hostnames, wildcards, and IPs")
    func testHostPatternAcceptsValidPatterns() {
        let validPatterns = [
            "github.com",
            "gitlab.internal.corp",
            "bastion-01.infra.aws.com",
            "*.github.com",
            "*.corp.example.internal",
            "192.168.1.1",
            "10.0.*.*",
            "[2001:db8::1]",
            "my-host_name.domain"
        ]

        for pattern in validPatterns {
            let error = AgentPolicyValidator.validateHostPattern(pattern)
            #expect(error == nil, "Expected valid host pattern for '\(pattern)', got error: \(String(describing: error))")
        }
    }

    // MARK: - #89 Dirty State Tracking & Save Button Disablement

    @Test("Initial form state matching baseline is not dirty and save is disabled")
    func testInitialFormStateIsNotDirty() {
        let baseline = AgentKeyPolicy(
            mode: .none,
            leaseMinutes: 480,
            allowedHosts: [],
            burst: 30,
            refillPerMinute: 6
        )
        let form = AgentPolicyFormState(baseline: baseline)

        #expect(!form.isModeDirty)
        #expect(!form.isLeaseDirty)
        #expect(!form.isAllowedHostsDirty)
        #expect(!form.isBurstDirty)
        #expect(!form.isRefillDirty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    @Test("Modifying approval mode marks dirty and enables save")
    func testModeChangeMarksDirty() {
        let baseline = AgentKeyPolicy(mode: .none)
        var form = AgentPolicyFormState(baseline: baseline)

        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)

        form.mode = .notify
        #expect(form.isModeDirty)
        #expect(form.hasUnsavedChanges)
        #expect(!form.isSaveDisabled)

        form.mode = .ask
        #expect(form.isModeDirty)
        #expect(form.hasUnsavedChanges)

        form.mode = .none
        #expect(!form.isModeDirty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    @Test("Modifying lease minutes marks dirty and enables save")
    func testLeaseMinutesChangeMarksDirty() {
        let baseline = AgentKeyPolicy(leaseMinutes: 480)
        var form = AgentPolicyFormState(baseline: baseline)

        form.leaseMinutes = 60
        #expect(form.isLeaseDirty)
        #expect(form.hasUnsavedChanges)
        #expect(!form.isSaveDisabled)

        form.leaseMinutes = 480
        #expect(!form.isLeaseDirty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    @Test("Modifying allowed hosts marks dirty and enables save")
    func testAllowedHostsChangeMarksDirty() {
        let baseline = AgentKeyPolicy(allowedHosts: [])
        var form = AgentPolicyFormState(baseline: baseline)

        let sampleHost = AgentAllowedHost(name: "github.com", hostKeyBlob: Data([0x01, 0x02]))
        form.allowedHosts.append(sampleHost)

        #expect(form.isAllowedHostsDirty)
        #expect(form.hasUnsavedChanges)
        #expect(!form.isSaveDisabled)

        form.allowedHosts.removeAll()
        #expect(!form.isAllowedHostsDirty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    @Test("Modifying burst marks dirty and enables save")
    func testBurstChangeMarksDirty() {
        let baseline = AgentKeyPolicy(burst: 30)
        var form = AgentPolicyFormState(baseline: baseline)

        form.burst = 50
        #expect(form.isBurstDirty)
        #expect(form.hasUnsavedChanges)
        #expect(!form.isSaveDisabled)

        form.burst = 30
        #expect(!form.isBurstDirty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    @Test("Modifying rate limit text marks dirty and validates properly")
    func testRateLimitTextChangeMarksDirtyAndValidates() {
        let baseline = AgentKeyPolicy(refillPerMinute: 6)
        var form = AgentPolicyFormState(baseline: baseline)

        // Valid change
        form.maxSignaturesPerMinuteText = "12"
        #expect(form.isRefillDirty)
        #expect(form.hasUnsavedChanges)
        #expect(form.rateLimitValidationError == nil)
        #expect(!form.isSaveDisabled)

        // Invalid change: non-numeric string
        form.maxSignaturesPerMinuteText = "10/min"
        #expect(form.isRefillDirty)
        #expect(form.hasUnsavedChanges)
        #expect(form.rateLimitValidationError != nil)
        #expect(form.isSaveDisabled, "Save must be disabled when rate limit is invalid")

        // Invalid change: 0
        form.maxSignaturesPerMinuteText = "0"
        #expect(form.rateLimitValidationError != nil)
        #expect(form.isSaveDisabled)

        // Restored to baseline
        form.maxSignaturesPerMinuteText = "6"
        #expect(!form.isRefillDirty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    @Test("Reverting form restores baseline and disables save")
    func testRevertingChangesRestoresBaseline() {
        let baseline = AgentKeyPolicy(
            mode: .none,
            leaseMinutes: 480,
            allowedHosts: [],
            burst: 30,
            refillPerMinute: 6
        )
        var form = AgentPolicyFormState(baseline: baseline)

        form.mode = .ask
        form.leaseMinutes = 15
        form.burst = 100
        form.maxSignaturesPerMinuteText = "20"
        form.allowedHosts.append(AgentAllowedHost(name: "test.com", hostKeyBlob: Data([0xAA])))

        #expect(form.hasUnsavedChanges)
        #expect(!form.isSaveDisabled)

        form.revert()

        #expect(form.mode == .none)
        #expect(form.leaseMinutes == 480)
        #expect(form.burst == 30)
        #expect(form.refillPerMinute == 6)
        #expect(form.maxSignaturesPerMinuteText == "6")
        #expect(form.allowedHosts.isEmpty)
        #expect(!form.hasUnsavedChanges)
        #expect(form.isSaveDisabled)
    }

    // MARK: - Notification Warning Banner (#98)

    @Test("Notification warning banner shows only when notify mode is selected and permissions are denied")
    func testNotificationWarningBannerVisibility() {
        // 1. None mode with denied permissions -> no warning
        var form = AgentPolicyFormState(
            mode: AgentKeyPolicy.Mode.none,
            isNotificationPermissionDenied: true
        )
        #expect(!form.showNotificationWarning)

        // 2. Ask mode with denied permissions -> no warning
        form.mode = .ask
        #expect(!form.showNotificationWarning)

        // 3. Notify mode with granted permissions -> no warning
        form.mode = .notify
        form.isNotificationPermissionDenied = false
        #expect(!form.showNotificationWarning)

        // 4. Notify mode with denied permissions -> warning IS visible!
        form.isNotificationPermissionDenied = true
        #expect(form.showNotificationWarning)
    }

    // MARK: - AgentPolicyView Component & Action Integration

    @Test @MainActor
    func testAgentPolicyViewValidationAndDirtyTracking() {
        let dummyKey = SSHKeyInfo(
            label: "test-agent-key",
            publicKeyOpenSSH: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
            publicKeyBlob: Data(),
            fingerprint: "SHA256:agent-test-policy",
            keyPurpose: .agent
        )
        let appState = AppState()
        let view = AgentPolicyView(
            key: dummyKey,
            appState: appState,
            notificationPermissionDeniedOverride: true
        )

        #expect(view.rateLimitValidationError == nil)
        #expect(view.notificationPermissionDeniedOverride == true)
        #expect(view.isNotificationPermissionDenied == true)

        // Host validation via AgentPolicyView action
        let schemeError = view.addHost("ssh://bad-host.com")
        #expect(schemeError != nil)
        #expect(schemeError?.contains("URL schemes") == true)

        let portError = view.addHost("bad-port.com:22")
        #expect(portError != nil)
        #expect(portError?.contains("Port numbers") == true)

        // Host validation via AgentPolicyFormState
        var form = AgentPolicyFormState()
        let formSchemeError = form.addHost("https://bad.com")
        #expect(formSchemeError != nil)
        #expect(form.hostError?.contains("URL schemes") == true)

        let formPortError = form.addHost("host.com:2222")
        #expect(formPortError != nil)
        #expect(form.hostError?.contains("Port numbers") == true)
    }
}
