import AppKit
import SwiftUI
import LocalAuthentication
import Testing
@testable import Clavis
@testable import ClavisCore

@Suite @MainActor
struct NotchTouchIDPromptTests {

    @Test
    func sessionScopeTitlesDurationsAndGraceMapping() {
        let all = NotchSessionScope.allCases
        #expect(all == [.once, .fifteenMinutes, .untilLock, .oneDay])
        #expect(NotchSessionScope.once.title == "Once")
        #expect(NotchSessionScope.fifteenMinutes.title == "15 min")
        #expect(NotchSessionScope.untilLock.title == "Until Lock")
        #expect(NotchSessionScope.oneDay.title == "1 Day")

        #expect(NotchSessionScope.once.approvalSummaryText == "Approve this request only")
        #expect(NotchSessionScope.fifteenMinutes.approvalSummaryText == "Approve for 15 minutes")
        #expect(NotchSessionScope.untilLock.approvalSummaryText == "Approve until lock")
        #expect(NotchSessionScope.oneDay.approvalSummaryText == "Approve for up to 24 hours")

        #expect(NotchSessionScope.once.durationSeconds == nil)
        #expect(NotchSessionScope.fifteenMinutes.durationSeconds == 900)
        #expect(NotchSessionScope.untilLock.durationSeconds == 28_800)
        #expect(NotchSessionScope.oneDay.durationSeconds == 86_400)

        #expect(NotchSessionScope.once.gitSigningPromptChoice == .singleShot)
        #expect(NotchSessionScope.fifteenMinutes.gitSigningPromptChoice == .grantSession(duration: 900))
        #expect(NotchSessionScope.untilLock.gitSigningPromptChoice == .grantSession(duration: 28_800))
        #expect(NotchSessionScope.oneDay.gitSigningPromptChoice == .grantSession(duration: 86_400))
    }

    @Test
    func reviewStageDoesNotArmBiometricsAndAllowsScopeChangesAfterContinue() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes,
            showsScopeSelector: true
        )

        var biometricCallCount = 0
        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .idle,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: {
                biometricCallCount += 1
                return true
            },
            onComplete: { result in
                capturedResult = result
            }
        )

        #expect(viewModel.phase == .idle)
        #expect(viewModel.selectedScope == .fifteenMinutes)
        #expect(!viewModel.isScopeLocked)

        // Step 1: Expand into reviewing. Biometrics must NOT be armed or invoked in .reviewing.
        viewModel.expand()
        #expect(viewModel.phase == .reviewing)
        #expect(!viewModel.phase.isAuthenticationArmed)
        #expect(!viewModel.isScopeLocked)
        #expect(viewModel.embeddedAuthContext == nil)
        #expect(biometricCallCount == 0)
        #expect(capturedResult == nil)

        // Scope can be changed freely during review
        for scope in NotchSessionScope.allCases {
            viewModel.selectScope(scope)
            #expect(viewModel.selectedScope == scope)
        }

        // Keyboard arrow navigation works during review
        viewModel.selectScope(.fifteenMinutes)
        viewModel.selectAdjacentScope(direction: 1)
        #expect(viewModel.selectedScope == .untilLock)

        // Step 2: Continue captures and locks the chosen scope and enters awaitingAuthentication
        viewModel.continueToAuthentication()
        #expect(viewModel.phase == .awaitingAuthentication)
        #expect(viewModel.phase.isAuthenticationArmed)
        #expect(!viewModel.isScopeLocked)
        #expect(viewModel.selectedScope == .untilLock)
        #expect(capturedResult == nil)

        // The duration remains editable after Continue; approval uses the new choice.
        viewModel.selectScope(.once)
        viewModel.selectAdjacentScope(direction: 1)
        #expect(viewModel.selectedScope == .fifteenMinutes)

        // Now biometric authentication can authorize the request with the locked scope
        await viewModel.approveWithBiometrics()
        #expect(biometricCallCount == 1)
        #expect(viewModel.phase == .approved)
        #expect(capturedResult == .approved(scope: .fifteenMinutes, method: .biometrics))
    }

    @Test
    func changingScopeCancelsContextAndClearsPassword() {
        let request = NotchPromptRequest(callerName: "Terminal", processChain: "git", keyLabel: "Test", keyType: .personal, operation: "Sign")
        let model = NotchPromptViewModel(request: request, initialPhase: .awaitingAuthentication)
        model.injectEmbeddedAuthContextForTesting(LAContext())
        model.selectScope(.oneDay)
        #expect(model.selectedScope == .oneDay)
        #expect(model.embeddedAuthContext == nil)
        #expect(model.phase == .awaitingAuthentication)
        model.openPasswordDrawer()
        model.passwordText = "discard-me"
        model.selectScope(.once)
        #expect(model.passwordText.isEmpty)
        #expect(model.phase == .passwordEntry)
        model.phase = .verifying
        model.selectScope(.oneDay)
        #expect(model.selectedScope == .once)
    }

    @Test
    func permittedScopesConstraintIsEnforced() {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Strict Key",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .oneDay,
            permittedScopes: [.once, .fifteenMinutes],
            showsScopeSelector: true
        )

        // Initial scope is clamped to permittedScopes
        #expect(request.initialScope == .once)
        let viewModel = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        #expect(viewModel.selectedScope == .once)

        // Permitted scope can be selected
        viewModel.selectScope(.fifteenMinutes)
        #expect(viewModel.selectedScope == .fifteenMinutes)

        // Disallowed scope is ignored
        viewModel.selectScope(.oneDay)
        #expect(viewModel.selectedScope == .fifteenMinutes)
    }

    @Test
    func biometricApprovalAutoCollapsesToIdle() async {
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "Deploy Bot",
            keyType: .bot,
            operation: "Authenticate with SSH",
            initialScope: .once
        )

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 1_000_000,
            signedDisplayNanoseconds: 1_000_000,
            autoCollapseAfterSigned: true,
            biometricAuthenticator: { true },
            onComplete: { result in
                capturedResult = result
            }
        )

        await viewModel.approveWithBiometrics()
        #expect(viewModel.phase == .idle)
        #expect(capturedResult == .approved(scope: .once, method: .biometrics))
    }

    @Test
    func passwordDrawerLifecycleAndVerification() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .untilLock,
            showsScopeSelector: true,
            allowsPasswordFallback: true
        )

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            passwordVerifier: { candidate in
                candidate == "correct-horse-battery-staple"
            }
        ) { result in
            capturedResult = result
        }

        // Advance to authentication and open password drawer
        viewModel.continueToAuthentication()
        #expect(viewModel.phase == .awaitingAuthentication)

        viewModel.openPasswordDrawer()
        #expect(viewModel.phase == .passwordEntry)
        #expect(!viewModel.isScopeLocked)

        // Typing and closing password drawer clears entry and returns to awaitingAuthentication (not reviewing)
        viewModel.passwordText = "partial-secret"
        viewModel.closePasswordDrawer()
        #expect(viewModel.phase == .awaitingAuthentication)
        #expect(viewModel.passwordText.isEmpty)
        #expect(!viewModel.isScopeLocked)

        // Re-open password drawer
        viewModel.openPasswordDrawer()
        #expect(viewModel.phase == .passwordEntry)

        // Empty password fails with prompt error
        viewModel.passwordText = "   "
        let emptyOk = await viewModel.submitPassword()
        #expect(!emptyOk)
        #expect(viewModel.passwordError == "Enter your Mac login password.")
        #expect(viewModel.phase == .passwordEntry)
        #expect(capturedResult == nil)

        // Wrong password fails with error message and clears passwordText
        viewModel.passwordText = "wrong-password"
        let wrongOk = await viewModel.submitPassword()
        #expect(!wrongOk)
        #expect(viewModel.passwordText.isEmpty)
        #expect(viewModel.passwordError == "Incorrect password. Try again or use Touch ID.")
        #expect(viewModel.phase == .passwordEntry)
        #expect(capturedResult == nil)

        // Correct password transitions to .approved and completes
        viewModel.passwordText = "correct-horse-battery-staple"
        let validOk = await viewModel.submitPassword()
        #expect(validOk)
        #expect(viewModel.passwordText.isEmpty)
        #expect(viewModel.passwordError == nil)
        #expect(viewModel.phase == .approved)
        #expect(capturedResult == .approved(scope: .untilLock, method: .password))
    }

    @Test
    func defaultVerifiersFailClosedAndPolicyDisablesPasswordFallback() async {
        // Default verifiers in test mode must fail closed rather than accepting non-empty strings or `{ true }`.
        let defaultBio = await NotchPromptWindowController.defaultBiometricAuthenticator()
        let defaultPwd = await NotchPromptWindowController.defaultPasswordVerifier("any-non-empty-password")
        #expect(!defaultBio)
        #expect(!defaultPwd)

        // Key policy that forbids password fallback (.biometryCurrentSet) prevents opening drawer
        let biometricOnlyRequest = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Strict Biometric Key",
            keyType: .personal,
            operation: "Sign a Git commit",
            allowsPasswordFallback: false
        )
        let vm = NotchPromptViewModel(request: biometricOnlyRequest, initialPhase: .awaitingAuthentication)
        vm.openPasswordDrawer()
        #expect(vm.phase == .awaitingAuthentication)
        vm.passwordText = "some-password"
        let submitted = await vm.submitPassword()
        #expect(!submitted)
    }

    @Test
    func failedBiometricAttemptDistinguishesNotRecognizedFromCancelAndLockout() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes
        )

        var shouldSucceed = false
        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { shouldSucceed },
            onComplete: { result in
                capturedResult = result
            }
        )

        // 1. Failed biometric match keeps panel open in .awaitingAuthentication and records .notRecognized
        await viewModel.approveWithBiometrics()
        #expect(viewModel.phase == .awaitingAuthentication)
        #expect(viewModel.biometricFailure == .notRecognized)
        #expect(viewModel.biometricFailure?.title == "Fingerprint not recognized")
        #expect(
            viewModel.biometricFailure?.subtitle(allowsPasswordFallback: true, scope: .fifteenMinutes)
                == "Try again or use your Mac password"
        )
        #expect(viewModel.failureShakeTrigger == 1)
        #expect(capturedResult == nil)

        // 2. LAError mapping distinguishes failed match vs cancellation vs lockout vs unavailable hardware
        #expect(NotchBiometricFailure.from(error: LAError(.authenticationFailed)) == .notRecognized)
        #expect(NotchBiometricFailure.from(error: LAError(.biometryLockout)) == .lockout)
        #expect(NotchBiometricFailure.from(error: LAError(.userCancel)) == .cancelled)
        #expect(NotchBiometricFailure.from(error: LAError(.systemCancel)) == .cancelled)
        if case .unavailable = NotchBiometricFailure.from(error: LAError(.biometryNotAvailable)) {
            // Expected unavailable classification
        } else {
            Issue.record("Expected .unavailable for .biometryNotAvailable")
        }

        // Recording a cancellation does not fabricate a failed match
        viewModel.recordBiometricFailure(.cancelled)
        #expect(viewModel.failureShakeTrigger == 1)

        // 3. Retry succeeds when biometric sensor matches on next attempt
        shouldSucceed = true
        await viewModel.approveWithBiometrics()
        #expect(viewModel.biometricFailure == nil)
        #expect(viewModel.phase == .approved)
        #expect(capturedResult == .approved(scope: .fifteenMinutes, method: .biometrics))
    }

    @Test
    func focusLossAndRestorationPreserveStateAndDimensions() {
        let ordinaryRequest = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .untilLock
        )

        var capturedResult: NotchPromptResult?
        let vm = NotchPromptViewModel(
            request: ordinaryRequest,
            initialPhase: .reviewing,
            autoCollapseAfterSigned: false,
            onComplete: { result in
                capturedResult = result
            }
        )
        let view = NotchTouchIDPromptView(viewModel: vm)

        // Focused in .reviewing: 540 x 214
        #expect(vm.isPromptFocused)
        #expect(view.islandWidth == 540)
        #expect(view.islandHeight == 214)

        // Unfocused in .reviewing: collapses controls, height shrinks to 112, scope preserved
        vm.setPromptFocused(false)
        #expect(!vm.isPromptFocused)
        #expect(vm.phase == .reviewing)
        #expect(vm.selectedScope == .untilLock)
        #expect(view.islandHeight == 112)
        #expect(capturedResult == nil)

        // Restoring focus restores height 214
        vm.setPromptFocused(true)
        #expect(vm.isPromptFocused)
        #expect(view.islandHeight == 214)

        // Continue -> awaitingAuthentication (540 x 214) -> open password drawer (540 x 278)
        vm.continueToAuthentication()
        #expect(vm.phase == .awaitingAuthentication)
        #expect(view.islandHeight == 214)

        vm.openPasswordDrawer()
        vm.passwordText = "secret"
        #expect(vm.phase == .passwordEntry)
        #expect(view.islandHeight == 278)

        // Losing focus while password drawer is open hides drawer, clears password, and shrinks to 166
        vm.setPromptFocused(false)
        #expect(!vm.isPromptFocused)
        #expect(vm.phase == .awaitingAuthentication)
        #expect(vm.passwordText.isEmpty)
        #expect(view.islandHeight == 166)
        #expect(capturedResult == nil)

        // Agent warning request adds 64pt height (214 -> 278, unfocused 112 -> 176 and 166 -> 230, password 278 -> 342)
        let warningRequest = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "zsh → claude → git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            agentWarning: NotchAgentWarning(
                title: "Agent requests your Personal key",
                detail: "Detected by: process tree (claude)"
            ),
            initialScope: .once
        )
        let warnVM = NotchPromptViewModel(request: warningRequest, initialPhase: .reviewing)
        let warnView = NotchTouchIDPromptView(viewModel: warnVM)
        #expect(warnView.islandHeight == 278)
        warnVM.setPromptFocused(false)
        #expect(warnView.islandHeight == 176)
        warnVM.setPromptFocused(true)
        warnVM.continueToAuthentication()
        warnVM.openPasswordDrawer()
        #expect(warnView.islandHeight == 342)
        warnVM.setPromptFocused(false)
        #expect(warnView.islandHeight == 230)
    }

    @Test
    func focusDependentLiquidGlassBackgroundAndAccessibilityFallback() {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes
        )

        let vm = NotchPromptViewModel(request: request, initialPhase: .awaitingAuthentication)
        let view = NotchTouchIDPromptView(viewModel: vm)

        // 1. Focused: translucent Liquid Glass background + 15px radial black around the notch; full-brightness content (1.0)
        #expect(vm.isPromptFocused)
        #expect(NotchTouchIDPromptView.notchRadialFeatherRadius == 15.0)
        #expect(view.usesLiquidGlassBackground(reduceTransparency: false))
        #expect(view.foregroundContentOpacity == 1.0)
        #expect(abs(view.backgroundGlassTintOpacity - 0.16) < 1e-6)
        #expect(abs(view.backgroundDarkOverlayOpacity - 0.20) < 1e-6)
        #expect(abs(view.notchRadialBlackOpacity(atDistance: 0) - 1.0) < 1e-6)
        #expect(view.notchRadialBlackOpacity(atDistance: 7.5) > 0.25 && view.notchRadialBlackOpacity(atDistance: 7.5) < 0.75)
        #expect(abs(view.notchRadialBlackOpacity(atDistance: 15.0) - 0.0) < 1e-6)

        var prevOpacity = view.notchRadialBlackOpacity(atDistance: 0)
        for step in 1...15 {
            let currOpacity = view.notchRadialBlackOpacity(atDistance: CGFloat(step))
            #expect(currOpacity < prevOpacity)
            prevOpacity = currOpacity
        }

        // 2. Unfocused: same translucent Liquid Glass background + 15px radial black around the notch; dimmed content (0.52);
        //    no zoom on focus transition (scale stays 1.0, controls only slide vertically by -8pt)
        vm.setPromptFocused(false)
        #expect(!vm.isPromptFocused)
        #expect(view.usesLiquidGlassBackground(reduceTransparency: false))
        #expect(abs(view.foregroundContentOpacity - 0.52) < 1e-6)
        #expect(abs(view.backgroundGlassTintOpacity - 0.16) < 1e-6)
        #expect(abs(view.backgroundDarkOverlayOpacity - 0.20) < 1e-6)
        #expect(view.identityRowScale(reduceMotion: false) == 1.0)
        #expect(view.bottomControlsSlideOffsetY(reduceMotion: false) == -8.0)

        // 3. Reduce Transparency: forces opaque fallback
        #expect(!view.usesLiquidGlassBackground(reduceTransparency: true))
        #expect(abs(view.notchRadialBlackOpacity(atDistance: 15.0, reduceTransparency: true) - 1.0) < 1e-6)

        // 4. Returning focus restores full content brightness (1.0) with same translucent background
        vm.setPromptFocused(true)
        #expect(view.foregroundContentOpacity == 1.0)
        #expect(view.expandCollapseContentOpacity == 1.0)
        #expect(abs(view.backgroundDarkOverlayOpacity - 0.20) < 1e-6)
        #expect(view.identityRowScale(reduceMotion: false) == 1.0)
        #expect(view.bottomControlsSlideOffsetY(reduceMotion: false) == 0.0)
        #expect(view.bottomElementRadialOffset(isLeading: true, rowTop: 169, reduceMotion: false) == .zero)
        #expect(view.bottomElementRadialOffset(isLeading: false, rowTop: 160, reduceMotion: false) == .zero)

        // 5. The shell collapses to the notch; content fades at full size with a six-point reveal.
        vm.deny()
        #expect(vm.phase == .idle)
        #expect(view.islandWidth == 184)
        #expect(view.openStageWidth == 540)
        #expect(abs(view.expandCollapseContentOpacity - 0.0) < 1e-6)
        #expect(view.identityRowScale(reduceMotion: false) == 1.0)
        #expect(view.bottomControlsSlideOffsetY(reduceMotion: false) == 0.0)
        #expect(view.bottomControlsSlideOffsetY(reduceMotion: true) == 0)
        #expect(view.bottomElementRadialOffset(isLeading: true, rowTop: 169, reduceMotion: true) == .zero)
        #expect(view.bottomElementRadialOffset(isLeading: true, rowTop: 169, reduceMotion: false) == CGSize.zero)
        #expect(view.bottomElementRadialOffset(isLeading: false, rowTop: 160, reduceMotion: false) == CGSize.zero)
    }

    @Test(arguments: [false, true])
    func rendersFocusedAndUnfocusedLiquidGlassAgainstLightAndDarkDesktops(isLightDesktop: Bool) async throws {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            callerPath: "/System/Applications/Utilities/Terminal.app",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes,
            showsScopeSelector: true
        )

        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false
        )

        let desktopBackdrop = isLightDesktop
            ? Color(red: 0.92, green: 0.95, blue: 0.99) // bright light desktop
            : Color(red: 0.12, green: 0.18, blue: 0.28) // deep dark desktop

        let rootView = NotchTouchIDPromptView(viewModel: viewModel)
            .environment(\.colorScheme, .dark)
            .frame(width: 640, height: 320, alignment: .top)
            .background(desktopBackdrop)

        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: 640, height: 320)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 320),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = hostingView
        window.orderFront(nil)
        defer { window.orderOut(nil) }

        // Render 1: Focused state (Liquid Glass + 15px radial black around notch + full content)
        viewModel.setPromptFocused(true)
        hostingView.layoutSubtreeIfNeeded()
        try await Task.sleep(nanoseconds: 50_000_000)
        hostingView.layoutSubtreeIfNeeded()

        let focusedBitmap = try #require(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: focusedBitmap)
        let focusedPng = try #require(focusedBitmap.representation(using: .png, properties: [:]))
        #expect(focusedPng.count > 2_000)

        // Render 2: Unfocused state (Liquid Glass + 15px radial black around notch + dimmed content)
        viewModel.setPromptFocused(false)
        hostingView.layoutSubtreeIfNeeded()
        try await Task.sleep(nanoseconds: 50_000_000)
        hostingView.layoutSubtreeIfNeeded()

        let unfocusedBitmap = try #require(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: unfocusedBitmap)
        let unfocusedPng = try #require(unfocusedBitmap.representation(using: .png, properties: [:]))
        #expect(unfocusedPng.count > 2_000)

        // Sample center-x (x = 320) inside the physical notch cutout (y = 14) and in the Liquid Glass body (y = 146).
        let scale = Double(unfocusedBitmap.pixelsHigh) / 320.0
        let sampleX = Int(320.0 * scale)
        let topNotchY = Int(14.0 * scale)
        let lowerGlassY = Int(146.0 * scale)

        let focusedTopLuma = Self.pixelLuminance(in: focusedBitmap, x: sampleX, y: topNotchY)
        let focusedGlassLuma = Self.pixelLuminance(in: focusedBitmap, x: sampleX, y: lowerGlassY)
        let unfocusedTopLuma = Self.pixelLuminance(in: unfocusedBitmap, x: sampleX, y: topNotchY)
        let unfocusedGlassLuma = Self.pixelLuminance(in: unfocusedBitmap, x: sampleX, y: lowerGlassY)

        // Physical notch cutout stays near-black (< 0.06 luminance) in both focused and unfocused states
        #expect(focusedTopLuma < 0.06)
        #expect(unfocusedTopLuma < 0.06)
        // Panel body outside the 15px notch halo is translucent Liquid Glass in both focused and unfocused states
        #expect(focusedGlassLuma > focusedTopLuma + (isLightDesktop ? 0.12 : 0.015))
        #expect(unfocusedGlassLuma > unfocusedTopLuma + (isLightDesktop ? 0.12 : 0.015))

        if ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW"] == "1" {
            let directory = URL(fileURLWithPath: "/private/tmp/clavis-notch-review")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let desktopTag = isLightDesktop ? "light-desktop" : "dark-desktop"
            try focusedPng.write(to: directory.appendingPathComponent("notch-focused-\(desktopTag).png"))
            try unfocusedPng.write(to: directory.appendingPathComponent("notch-unfocused-glass-\(desktopTag).png"))
        }
    }

    private static func pixelLuminance(in bitmap: NSBitmapImageRep, x: Int, y: Int) -> Double {
        let clampedX = min(max(0, x), bitmap.pixelsWide - 1)
        let clampedY = min(max(0, y), bitmap.pixelsHigh - 1)
        guard let color = bitmap.colorAt(x: clampedX, y: clampedY)?.usingColorSpace(.sRGB) else {
            return 0.0
        }
        return 0.2126 * Double(color.redComponent)
            + 0.7152 * Double(color.greenComponent)
            + 0.0722 * Double(color.blueComponent)
    }

    @Test
    func denyAndRequestReplacementPreventStaleCallbacksFromApproving() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Authenticate with SSH"
        )

        var completions: [NotchPromptResult] = []
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 50_000_000,
            signedDisplayNanoseconds: 0,
            biometricAuthenticator: { true },
            onComplete: { result in
                completions.append(result)
            }
        )

        // Start an async biometric approval, then immediately deny before it finishes
        let approvalTask = Task { @MainActor in
            await viewModel.approveWithBiometrics()
        }
        viewModel.deny()
        await approvalTask.value

        // Must have completed exactly once with .denied; stale biometric callback must not approve
        #expect(completions == [.denied])
        #expect(viewModel.phase == .idle)
    }

    @Test
    func agentWarningDerivedOnlyFromRealAgentRequests() {
        let ordinary = AppKitGitSigningGracePresenter.makePromptRequest(
            keyLabel: "Personal MacBook",
            clientDesc: "/usr/bin/git (PID 1)",
            keyType: .personal,
            operation: "Sign a Git commit"
        )
        #expect(ordinary.effectiveWarning == nil)
        #expect(ordinary.keyTypeSubtitle == "Personal key")

        let agentOnPersonal = AppKitGitSigningGracePresenter.makePromptRequest(
            keyLabel: "Personal MacBook",
            clientDesc: "claude",
            keyType: .personal,
            operation: "Sign a Git commit"
        )
        #expect(agentOnPersonal.callerName == "Claude Code")
        #expect(agentOnPersonal.effectiveWarning?.title == "Agent requests your Personal key")
        #expect(agentOnPersonal.effectiveWarning?.detail.contains("Claude Code") == true)

        let agentOnBotKey = AppKitGitSigningGracePresenter.makePromptRequest(
            keyLabel: "Deploy Bot",
            clientDesc: "claude",
            keyType: .bot,
            operation: "Authenticate with SSH"
        )
        #expect(agentOnBotKey.callerName == "Claude Code")
        #expect(agentOnBotKey.keyTypeSubtitle == "Agent key")
        #expect(agentOnBotKey.effectiveWarning == nil)
    }

    @Test
    func windowControllerPositioningAndPresentationLifecycle() async {
        let screenFrame = NSRect(x: 0, y: 0, width: 1512, height: 982)
        let panelSize = NotchPromptWindowController.defaultPanelSize
        let frame = NotchPromptWindowController.topCenterFrame(for: screenFrame, panelSize: panelSize)

        #expect(frame.origin.x == screenFrame.midX - panelSize.width / 2.0)
        #expect(frame.origin.y == screenFrame.maxY - panelSize.height)
        #expect(frame.maxY == screenFrame.maxY)

        let controller = NotchPromptWindowController()
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .untilLock
        )

        let result = await controller.present(
            request: request,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            biometricAuthenticator: { true },
            onPresented: { viewModel in
                #expect(viewModel.phase == .reviewing)
                viewModel.selectScope(.once)
                viewModel.continueToAuthentication()
                #expect(viewModel.phase == .awaitingAuthentication)
                Task { @MainActor in
                    await viewModel.approveWithBiometrics()
                }
            }
        )

        #expect(result == .approved(scope: .once, method: .biometrics))
        #expect(controller.panel?.styleMask.contains(.borderless) == true)
        #expect(controller.panel?.styleMask.contains(.nonactivatingPanel) == true)
        #expect(controller.panel?.isOpaque == false)
        #expect(controller.panel?.hasShadow == false)
    }

    @Test
    func hardwareRelativePlacementValidatesNotchedNonNotchedNegativeOriginsAndHeightChanges() {
        // 1. Notched display with negative global origin and asymmetric auxiliary areas:
        //    Screen frame at (-1728, -240, 1728, 1117) -> hardware top edge maxY = 877 (NOT visibleFrame.maxY = 840).
        //    Left auxiliary width = 740 (minX = -1728, maxX = -988), right auxiliary width = 772 (minX = -772, maxX = 0).
        //    Gap between auxiliary areas is [-988, -772] -> width = 216, center = -880 (distinct from screen.midX = -864).
        let negativeNotchedDisplay = NotchDisplayDescriptor(
            displayID: 42,
            frame: NSRect(x: -1728, y: -240, width: 1728, height: 1117),
            visibleFrame: NSRect(x: -1728, y: -190, width: 1728, height: 1030), // maxY = 840 (excludes 37pt notch/menu bar)
            safeAreaTop: 37,
            auxiliaryTopLeftArea: NSRect(x: -1728, y: 840, width: 740, height: 37),
            auxiliaryTopRightArea: NSRect(x: -772, y: 840, width: 772, height: 37),
            backingScaleFactor: 2.0
        )

        let notchedPlacement = NotchPlacementCalculator.calculatePlacement(
            for: negativeNotchedDisplay,
            panelSize: NSSize(width: 540, height: 214)
        )
        #expect(notchedPlacement.displayID == 42)
        #expect(notchedPlacement.mode.hasHardwareNotch)
        if case .hardwareNotch(let cutoutRect) = notchedPlacement.mode {
            #expect(cutoutRect == NSRect(x: -988, y: 840, width: 216, height: 37))
        } else {
            Issue.record("Expected .hardwareNotch mode for notched display")
        }
        // Must attach to screen.frame.maxY (877), NEVER visibleFrame.maxY (840), and center on gapCenterX (-880)
        #expect(notchedPlacement.topEdgeY == 877)
        #expect(notchedPlacement.horizontalCenterX == -880)
        #expect(notchedPlacement.panelFrame.maxY == 877)
        #expect(notchedPlacement.panelFrame.midX == -880)
        #expect(notchedPlacement.screenGeometry.cutoutWidth == 216)
        #expect(notchedPlacement.screenGeometry.cutoutHeight == 37)
        #expect(notchedPlacement.screenGeometry.hasHardwareNotch)

        // 2. As panel height changes (collapsed -> reviewing -> warning -> password drawer), topEdgeY (maxY) stays fixed:
        for height in [CGFloat(37), 112, 166, 214, 278, 342] {
            let resized = notchedPlacement.frame(forPanelSize: NSSize(width: 540, height: height))
            #expect(resized.maxY == 877)
            #expect(resized.minY == 877 - height)
            #expect(resized.midX == -880)
        }

        // 3. Non-notched external display fallback:
        //    No auxiliary areas, safeAreaTop = 0, menu bar = 25pt (frame.maxY = 1440, visibleFrame.maxY = 1415).
        let externalDisplay = NotchDisplayDescriptor(
            displayID: 77,
            frame: NSRect(x: 1512, y: 0, width: 2560, height: 1440),
            visibleFrame: NSRect(x: 1512, y: 60, width: 2560, height: 1355), // maxY = 1415 (25pt menu bar)
            safeAreaTop: 0,
            auxiliaryTopLeftArea: nil,
            auxiliaryTopRightArea: nil,
            backingScaleFactor: 2.0
        )

        let fallbackPlacement = NotchPlacementCalculator.calculatePlacement(
            for: externalDisplay,
            panelSize: NSSize(width: 540, height: 214)
        )
        #expect(fallbackPlacement.displayID == 77)
        #expect(!fallbackPlacement.mode.hasHardwareNotch)
        #expect(fallbackPlacement.mode == .topCenterFallback(menuBarHeight: 25))
        #expect(fallbackPlacement.topEdgeY == 1440)
        #expect(fallbackPlacement.horizontalCenterX == externalDisplay.frame.midX)
        #expect(fallbackPlacement.panelFrame.maxY == 1440)
        #expect(fallbackPlacement.panelFrame.midX == externalDisplay.frame.midX)
        #expect(!fallbackPlacement.screenGeometry.hasHardwareNotch)
        #expect(fallbackPlacement.screenGeometry.cutoutWidth == 0)
        #expect(fallbackPlacement.screenGeometry.menuBarHeight == 25)
    }

    @Test
    func targetDisplayRetentionAcrossFocusSpaceChangesScalingAndMonitorRemoval() async {
        let builtInNotched = NotchDisplayDescriptor(
            displayID: 101,
            frame: NSRect(x: 0, y: 0, width: 1512, height: 982),
            visibleFrame: NSRect(x: 0, y: 50, width: 1512, height: 900),
            safeAreaTop: 32,
            auxiliaryTopLeftArea: NSRect(x: 0, y: 950, width: 664, height: 32),
            auxiliaryTopRightArea: NSRect(x: 848, y: 950, width: 664, height: 32),
            backingScaleFactor: 2.0
        )
        let externalMonitor = NotchDisplayDescriptor(
            displayID: 202,
            frame: NSRect(x: -2560, y: -120, width: 2560, height: 1440),
            visibleFrame: NSRect(x: -2560, y: -70, width: 2560, height: 1365),
            safeAreaTop: 0,
            auxiliaryTopLeftArea: nil,
            auxiliaryTopRightArea: nil,
            backingScaleFactor: 1.0
        )

        var currentDisplays: [NotchDisplayDescriptor] = [builtInNotched, externalMonitor]
        var simulatedMainDisplayID: CGDirectDisplayID = 101

        let controller = NotchPromptWindowController()
        controller.displaySnapshotsProvider = { currentDisplays }
        controller.initialPreferredDisplayIDProvider = { simulatedMainDisplayID }

        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "zsh → claude → git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes
        )

        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false
        )

        // 1. Configure & present on Display 101 (built-in notched MacBook screen)
        let panel = controller.configurePanel(for: viewModel, preferredDisplayID: 101)
        #expect(controller.targetDisplayID == 101)
        #expect(controller.currentPlacement?.displayID == 101)
        #expect(controller.currentPlacement?.topEdgeY == 982)
        #expect(controller.currentIslandScreenFrame()?.maxY == 982)
        #expect(panel.collectionBehavior.contains(.canJoinAllSpaces))
        #expect(panel.collectionBehavior.contains(.fullScreenAuxiliary))
        #expect(panel.collectionBehavior.contains(.stationary))

        // Advance to awaitingAuthentication, lock scope to .oneDay, open password drawer, and capture auth context identity
        viewModel.selectScope(.oneDay)
        viewModel.continueToAuthentication()
        viewModel.openPasswordDrawer()
        let testAuthContext = LAContext()
        viewModel.injectEmbeddedAuthContextForTesting(testAuthContext)
        viewModel.passwordText = "in-progress-password"
        let originalAuthContextID = viewModel.embeddedAuthContext.map { ObjectIdentifier($0) }
        let originalContentViewID = panel.contentView.map { ObjectIdentifier($0) }
        #expect(originalAuthContextID == ObjectIdentifier(testAuthContext))
        #expect(viewModel.phase == .passwordEntry)
        #expect(!viewModel.isScopeLocked)
        #expect(controller.currentIslandScreenFrame()?.maxY == 982)

        // 2. Simulate user switching app focus or active Space to the external monitor (NSScreen.main becomes Display 202):
        //    Target display and panel frame MUST remain pinned to Display 101 and never jump to Display 202.
        let initialPanelFrame = panel.frame
        simulatedMainDisplayID = 202
        NotificationCenter.default.post(name: NSWindow.didResignKeyNotification, object: panel)
        NotificationCenter.default.post(name: NSApplication.didResignActiveNotification, object: NSApp)
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.activeSpaceDidChangeNotification, object: NSWorkspace.shared)
        await Task.yield()

        #expect(!viewModel.isPromptFocused)
        #expect(controller.targetDisplayID == 101)
        #expect(panel.frame == initialPanelFrame)
        #expect(controller.currentIslandScreenFrame()?.maxY == 982)
        #expect(controller.currentIslandScreenFrame()?.midX == 756)

        NotificationCenter.default.post(name: NSWindow.didBecomeKeyNotification, object: panel)
        await Task.yield()
        controller.focusPromptWindow()
        #expect(viewModel.isPromptFocused)
        #expect(controller.targetDisplayID == 101)
        #expect(panel.frame == initialPanelFrame)
        #expect(panel.frame.midX == 756)

        // Re-open password entry and re-attach testAuthContext to verify state preservation across display scaling change
        viewModel.openPasswordDrawer()
        viewModel.injectEmbeddedAuthContextForTesting(testAuthContext)
        viewModel.passwordText = "preserved-secret"

        // 3. Simulate display scaling / resolution change on Display 101 (e.g. scaled to 1800 x 1169 with 210 x 38 notch)
        //    and post NSApplication.didChangeScreenParametersNotification:
        let scaledBuiltIn = NotchDisplayDescriptor(
            displayID: 101,
            frame: NSRect(x: 0, y: 0, width: 1800, height: 1169),
            visibleFrame: NSRect(x: 0, y: 60, width: 1800, height: 1071),
            safeAreaTop: 38,
            auxiliaryTopLeftArea: NSRect(x: 0, y: 1131, width: 795, height: 38),
            auxiliaryTopRightArea: NSRect(x: 1005, y: 1131, width: 795, height: 38),
            backingScaleFactor: 2.0
        )
        currentDisplays = [scaledBuiltIn, externalMonitor]
        NotificationCenter.default.post(name: NSApplication.didChangeScreenParametersNotification, object: NSApp)
        await Task.yield()

        #expect(controller.targetDisplayID == 101)
        #expect(controller.currentPlacement?.topEdgeY == 1169)
        #expect(controller.currentPlacement?.horizontalCenterX == 900)
        #expect(panel.frame.maxY == 1169)
        #expect(panel.frame.midX == 900)
        #expect(viewModel.screenGeometry.cutoutWidth == 210)
        #expect(viewModel.screenGeometry.cutoutHeight == 38)
        // Verify request, scope, phase, focus, password text, hosting view, and LAContext were preserved in-place
        #expect(viewModel.request == request)
        #expect(viewModel.selectedScope == .oneDay)
        #expect(!viewModel.isScopeLocked)
        #expect(viewModel.phase == .passwordEntry)
        #expect(viewModel.isPromptFocused)
        #expect(viewModel.passwordText == "preserved-secret")
        #expect(viewModel.embeddedAuthContext.map { ObjectIdentifier($0) } == originalAuthContextID)
        #expect(panel.contentView.map { ObjectIdentifier($0) } == originalContentViewID)

        // 4. Simulate clamshell close / target display removal (Display 101 disappears; only Display 202 remains):
        //    Controller must deterministically fall back to Display 202, update targetDisplayID, and preserve auth state.
        currentDisplays = [externalMonitor]
        let fallbackPlacement = controller.handleScreenParametersChanged()
        #expect(fallbackPlacement?.displayID == 202)
        #expect(controller.targetDisplayID == 202)
        #expect(controller.currentPlacement?.mode == .topCenterFallback(menuBarHeight: 25))
        #expect(panel.frame.maxY == externalMonitor.frame.maxY)
        #expect(panel.frame.midX == externalMonitor.frame.midX)
        #expect(!viewModel.screenGeometry.hasHardwareNotch)
        #expect(viewModel.selectedScope == .oneDay)
        #expect(viewModel.phase == .passwordEntry)
        #expect(viewModel.passwordText == "preserved-secret")
        #expect(viewModel.embeddedAuthContext.map { ObjectIdentifier($0) } == originalAuthContextID)
        #expect(panel.contentView.map { ObjectIdentifier($0) } == originalContentViewID)

        controller.dismiss()
        #expect(controller.targetDisplayID == nil)
        #expect(controller.currentPlacement == nil)
    }

    @Test(
        arguments: [false, true],
        [NotchPromptPhase.reviewing, NotchPromptPhase.awaitingAuthentication, NotchPromptPhase.passwordEntry, NotchPromptPhase.approved]
    )
    func rendersNotchTouchIDPromptInStandardAndAgentWarningModes(hasAgentWarning: Bool, phase: NotchPromptPhase) async throws {
        let request = NotchPromptRequest(
            callerName: hasAgentWarning ? "Claude Code" : "Terminal",
            callerPath: hasAgentWarning ? nil : "/System/Applications/Utilities/Terminal.app",
            processChain: hasAgentWarning ? "zsh → claude → git → ssh-keygen" : "git → ssh-keygen",
            keyLabel: hasAgentWarning ? "GitHub Personal" : "Personal MacBook",
            keyType: .personal,
            operation: hasAgentWarning ? "Authenticate with SSH" : "Sign a Git commit",
            agentWarning: hasAgentWarning ? NotchAgentWarning(
                title: "Agent requests your Personal key",
                detail: "Detected by: process tree (claude) and CLAUDECODE=1"
            ) : nil,
            initialScope: .untilLock,
            showsScopeSelector: true
        )

        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: phase,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false
        )

        let rootView = NotchTouchIDPromptView(viewModel: viewModel)
            .environment(\.colorScheme, .dark)
            .frame(width: 640, height: 380, alignment: .top)
            .background(Color(red: 0.14, green: 0.22, blue: 0.34))

        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: 640, height: 380)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 380),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = hostingView
        window.orderFront(nil)
        defer { window.orderOut(nil) }

        hostingView.layoutSubtreeIfNeeded()
        try await Task.sleep(nanoseconds: 50_000_000)
        hostingView.layoutSubtreeIfNeeded()

        let bitmap = try #require(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(png.count > 2_000)

        if ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW"] == "1" {
            let directory = URL(fileURLWithPath: "/private/tmp/clavis-notch-review")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let prefix = hasAgentWarning ? "agent-warning" : "personal"
            try png.write(to: directory.appendingPathComponent("\(prefix)-\(phase.rawValue).png"))

            if !hasAgentWarning && phase == .awaitingAuthentication {
                viewModel.setPromptFocused(false)
                hostingView.layoutSubtreeIfNeeded()
                try await Task.sleep(nanoseconds: 50_000_000)
                hostingView.layoutSubtreeIfNeeded()
                if let unfocusBitmap = hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds) {
                    hostingView.cacheDisplay(in: hostingView.bounds, to: unfocusBitmap)
                    if let unfocusPng = unfocusBitmap.representation(using: .png, properties: [:]) {
                        try unfocusPng.write(to: directory.appendingPathComponent("personal-unfocused-armed.png"))
                    }
                }

                viewModel.setPromptFocused(true)
                viewModel.recordBiometricFailure(.notRecognized)
                hostingView.layoutSubtreeIfNeeded()
                try await Task.sleep(nanoseconds: 50_000_000)
                hostingView.layoutSubtreeIfNeeded()
                if let failBitmap = hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds) {
                    hostingView.cacheDisplay(in: hostingView.bounds, to: failBitmap)
                    if let failPng = failBitmap.representation(using: .png, properties: [:]) {
                        try failPng.write(to: directory.appendingPathComponent("personal-failedBiometrics.png"))
                    }
                }
            }
        }
    }
}
