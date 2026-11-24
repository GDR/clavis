import AppKit
import SwiftUI
import LocalAuthentication
import Testing
@testable import Clavis
@testable import ClavisPromptUI
@testable import ClavisCore

@Suite @MainActor
struct NotchTouchIDPromptTests {

    @Test
    func sessionScopeTitlesDurationsAndGraceMapping() {
        let all = NotchSessionScope.allCases
        #expect(all == [.once, .fifteenMinutes, .eightHours, .untilLock, .oneDay])
        #expect(NotchSessionScope.once.title == "Once")
        #expect(NotchSessionScope.fifteenMinutes.title == "15 min")
        #expect(NotchSessionScope.eightHours.title == "8 hours")
        #expect(NotchSessionScope.untilLock.title == "Until Lock")
        #expect(NotchSessionScope.oneDay.title == "1 Day")

        // D-40 / N_SCOPES sub-copy shown under the Touch ID title.
        #expect(NotchSessionScope.once.approvalSummaryText == "This single request only")
        #expect(NotchSessionScope.fifteenMinutes.approvalSummaryText == "Reuse for 15 minutes")
        #expect(NotchSessionScope.eightHours.approvalSummaryText == "Reuse for 8 hours")
        #expect(NotchSessionScope.untilLock.approvalSummaryText == "Reuse until Mac sleeps or locks")
        #expect(NotchSessionScope.oneDay.approvalSummaryText == "Reuse for 24 hours")

        #expect(NotchSessionScope.once.durationSeconds == nil)
        #expect(NotchSessionScope.fifteenMinutes.durationSeconds == 900)
        #expect(NotchSessionScope.eightHours.durationSeconds == 28_800)
        #expect(NotchSessionScope.untilLock.durationSeconds == 28_800)
        #expect(NotchSessionScope.oneDay.durationSeconds == 86_400)

        // D-40 mapping onto KeyGracePeriod (Once → always, 8 hours → session).
        #expect(NotchSessionScope.once.keyGracePeriod == .always)
        #expect(NotchSessionScope.fifteenMinutes.keyGracePeriod == .fifteenMinutes)
        #expect(NotchSessionScope.eightHours.keyGracePeriod == .session)
        #expect(NotchSessionScope.untilLock.keyGracePeriod == .untilLock)
        #expect(NotchSessionScope.oneDay.keyGracePeriod == .oneDay)
        for scope in NotchSessionScope.allCases {
            #expect(NotchSessionScope.from(gracePeriod: scope.keyGracePeriod) == scope)
        }
        #expect(NotchSessionScope.from(gracePeriod: .fiveMinutes) == nil)

        // D-40 session copy and post-approval toast copy.
        #expect(NotchSessionScope.fifteenMinutes.sessionReuseText
            == "One confirmation is reused for 15 min per requesting app; inside that window, signing is silent.")
        #expect(NotchSessionScope.eightHours.sessionReuseText
            == "One confirmation is reused for 8 hours per requesting app; inside that window, signing is silent.")
        #expect(NotchSessionScope.once.sessionReuseText == "Every request asks again.")
        #expect(NotchSessionScope.fifteenMinutes.nextRequestsToastText(callerName: "Terminal")
            == "Next requests from Terminal won't ask for 15 min")
        #expect(NotchSessionScope.untilLock.nextRequestsToastText(callerName: "Terminal")
            == "Next requests from Terminal won't ask for until lock")
        #expect(NotchSessionScope.once.nextRequestsToastText(callerName: "Terminal")
            == "Next requests from Terminal will ask again")

        #expect(NotchSessionScope.once.gitSigningPromptChoice == .singleShot)
        #expect(NotchSessionScope.fifteenMinutes.gitSigningPromptChoice == .grantSession(duration: 900))
        #expect(NotchSessionScope.eightHours.gitSigningPromptChoice == .grantSession(duration: 28_800))
        #expect(NotchSessionScope.untilLock.gitSigningPromptChoice == .grantSession(duration: 28_800))
        #expect(NotchSessionScope.oneDay.gitSigningPromptChoice == .grantSession(duration: 86_400))
    }

    @Test
    func signingOpensDirectlyInOneStepAndScopeChangesStayLive() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "Sign a Git commit",
            initialScope: .fifteenMinutes,
            showsScopeSelector: true,
            confirmationMode: .presenceOrPassword
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
        #expect(request.opensDirectlyToAuthentication)
        #expect(request.initialExpandedPhase == .awaitingAuthentication)

        // 1-step signing expands directly into .awaitingAuthentication with no Continue step.
        viewModel.expand()
        #expect(viewModel.phase == .awaitingAuthentication)
        #expect(viewModel.phase.isAuthenticationArmed)
        #expect(!viewModel.isScopeLocked)
        #expect(viewModel.authTitleText == "Touch ID or Apple Watch")
        #expect(biometricCallCount == 0)
        #expect(capturedResult == nil)

        // Scope remains editable while armed.
        for scope in NotchSessionScope.allCases {
            viewModel.selectScope(scope)
            #expect(viewModel.selectedScope == scope)
        }

        // Keyboard arrow navigation works cleanly while armed.
        viewModel.selectScope(.fifteenMinutes)
        viewModel.selectAdjacentScope(direction: 1)
        #expect(viewModel.selectedScope == .eightHours)

        // Biometric approval completes with the selected scope.
        await viewModel.approveWithBiometrics()
        #expect(biometricCallCount == 1)
        #expect(viewModel.phase == .approved)
        #expect(capturedResult == .approved(scope: .eightHours, method: .biometrics))
    }

    @Test
    func changingScopeCancelsContextAndClearsPassword() async {
        var now: TimeInterval = 10.0
        let request = NotchPromptRequest(callerName: "Terminal", processChain: "git", keyLabel: "Test", keyType: .personal, operation: "Sign")
        var capturedResult: NotchPromptResult?
        let model = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            onComplete: { result in
                capturedResult = result
            },
            uptimeProvider: { now }
        )

        let embeddedCtx = TrackingContext()
        let evaluatedCtx = TrackingContext()
        model.injectEmbeddedAuthContextForTesting(embeddedCtx)
        model.injectAuthenticatedContextForTesting(evaluatedCtx)

        model.selectScope(.oneDay)
        #expect(model.selectedScope == .oneDay)
        // Unevaluated embedded sensor stays mounted across scope selection to avoid fingerprint flicker and Picker interruption.
        #expect(model.embeddedAuthContext === embeddedCtx)
        #expect(!embeddedCtx.isInvalidated)
        // Any previously evaluated context is still invalidated immediately.
        #expect(evaluatedCtx.isInvalidated)
        #expect(model.takeAuthenticatedContext() == nil)
        #expect(model.phase == .awaitingAuthentication)

        // Biometric completion within the 400 ms post-change settle window fails closed (TOCTOU guard).
        now = 10.20
        let racingCtx = TrackingContext()
        let racingAccepted = await model.handleEmbeddedBiometricCompletion(
            context: racingCtx,
            succeeded: true,
            generation: model.currentAttemptGenerationForTesting
        )
        #expect(!racingAccepted)
        #expect(racingCtx.isInvalidated)
        #expect(model.phase == .awaitingAuthentication)
        #expect(capturedResult == nil)
        #expect(model.biometricFailure == .unavailable("Duration changed — confirm again with Touch ID"))

        model.openPasswordDrawer()
        model.passwordText = "discard-me"
        model.selectScope(.once)
        #expect(model.passwordText.isEmpty)
        #expect(model.phase == .passwordEntry)
        model.phase = .verifying
        model.selectScope(.oneDay)
        #expect(model.selectedScope == .once)

        // After the 400 ms settle window elapses, biometric completion approves with the latest scope.
        var settleNow: TimeInterval = 20.0
        var settledResult: NotchPromptResult?
        let settleModel = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            onComplete: { result in
                settledResult = result
            },
            uptimeProvider: { settleNow }
        )
        settleModel.selectScope(.oneDay)
        settleNow = 20.45
        let validCtx = TrackingContext()
        let settledAccepted = await settleModel.handleEmbeddedBiometricCompletion(
            context: validCtx,
            succeeded: true,
            generation: settleModel.currentAttemptGenerationForTesting
        )
        #expect(settledAccepted)
        #expect(!validCtx.isInvalidated)
        #expect(settleModel.phase == .approved)
        #expect(settledResult == .approved(scope: .oneDay, method: .biometrics))
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
            keyLabel: "Deploy Agent",
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
            },
            onComplete: { result in
                capturedResult = result
            }
        )

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

        // Focused in .reviewing: 540 x 198 (unified recessed auth bar)
        #expect(vm.isPromptFocused)
        #expect(view.islandWidth == 540)
        #expect(view.islandHeight == 198)

        // Unfocused in .reviewing (.passwordOnly note collapses controls): height shrinks to 126, scope preserved
        vm.setPromptFocused(false)
        #expect(!vm.isPromptFocused)
        #expect(vm.phase == .reviewing)
        #expect(vm.selectedScope == .untilLock)
        #expect(view.islandHeight == 126)
        #expect(capturedResult == nil)

        // Restoring focus restores height 198
        vm.setPromptFocused(true)
        #expect(vm.isPromptFocused)
        #expect(view.islandHeight == 198)

        // Continue -> awaitingAuthentication (540 x 198) -> open passwordEntry (same 540 x 198 unified auth bar)
        vm.continueToAuthentication()
        #expect(view.islandHeight == 198)
        #expect(vm.phase == .awaitingAuthentication)

        vm.openPasswordDrawer()
        vm.passwordText = "secret"
        #expect(vm.phase == .passwordEntry)
        #expect(view.islandHeight == 198)

        // Losing focus while password entry is active hides controls, clears password, and shrinks to 152 (armed biometrics)
        vm.setPromptFocused(false)
        #expect(!vm.isPromptFocused)
        #expect(vm.phase == .awaitingAuthentication)
        #expect(vm.passwordText.isEmpty)
        #expect(view.islandHeight == 152)
        #expect(capturedResult == nil)

        // Agent warning request (signing + warning) adds 64pt height (198 -> 262, unfocused 126 -> 190 and 152 -> 216)
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
        #expect(warnView.islandHeight == 262)
        warnVM.setPromptFocused(false)
        #expect(warnView.islandHeight == 190)
        warnVM.setPromptFocused(true)
        warnVM.continueToAuthentication()
        warnVM.openPasswordDrawer()
        #expect(warnView.islandHeight == 262)
        warnVM.setPromptFocused(false)
        #expect(warnView.islandHeight == 216)
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
        window.ignoresMouseEvents = true
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
            let desktopTag = isLightDesktop ? "light-desktop" : "dark-desktop"
            try Self.writeRenderReviewPNG(focusedPng, filename: "notch-focused-\(desktopTag).png")
            try Self.writeRenderReviewPNG(unfocusedPng, filename: "notch-unfocused-glass-\(desktopTag).png")
        }
    }

    private static var renderReviewDirectory: URL {
        let path = ProcessInfo.processInfo.environment["CLAVIS_RENDER_REVIEW_DIR"] ?? "/private/tmp/clavis-notch-review"
        return URL(fileURLWithPath: path)
    }

    private static func writeRenderReviewPNG(_ pngData: Data, filename: String) throws {
        let directory = renderReviewDirectory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try pngData.write(to: directory.appendingPathComponent(filename))
    }

    private static func captureAndSaveRenderReview(hostingView: NSHostingView<some View>, filename: String) async throws {
        hostingView.layoutSubtreeIfNeeded()
        try await Task.sleep(nanoseconds: 50_000_000)
        hostingView.layoutSubtreeIfNeeded()
        if let bitmap = hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds) {
            hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
            if let png = bitmap.representation(using: .png, properties: [:]) {
                try writeRenderReviewPNG(png, filename: filename)
            }
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

        let agentOnAgentKey = AppKitGitSigningGracePresenter.makePromptRequest(
            keyLabel: "Deploy Agent",
            clientDesc: "claude",
            keyType: .bot,
            operation: "Authenticate with SSH"
        )
        #expect(agentOnAgentKey.callerName == "Claude Code")
        #expect(agentOnAgentKey.keyTypeSubtitle == "Agent key")
        #expect(agentOnAgentKey.effectiveWarning == nil)
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
                #expect(viewModel.phase == .awaitingAuthentication)
                viewModel.selectScope(.once)
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
        window.ignoresMouseEvents = true
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
            let prefix = hasAgentWarning ? "agent-warning" : "personal"
            try Self.writeRenderReviewPNG(png, filename: "\(prefix)-\(phase.rawValue).png")

            if !hasAgentWarning && phase == .awaitingAuthentication {
                viewModel.isHoveringCloseButton = true
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "personal-hover-close.png")
                viewModel.isHoveringCloseButton = false

                viewModel.setPromptFocused(false)
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "personal-unfocused-armed.png")

                viewModel.setPromptFocused(true)
                viewModel.recordBiometricFailure(.notRecognized)
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "personal-failedBiometrics.png")
            }
        }
    }

    // MARK: - D-36 Unified Approval Variants

    private static func makeFirstUseRequest(isBroad: Bool = false) -> NotchPromptRequest {
        NotchPromptRequest(
            callerName: "Codex",
            processChain: "codex → agent → git → ssh",
            keyLabel: "Agent SSH",
            keyType: .bot,
            operation: "Authenticate with SSH",
            kind: .agentFirstUse,
            firstUseInfo: NotchFirstUseInfo(
                identity: "ad-hoc · cdhash c07d…12",
                via: "Codex › agent › git › ssh",
                trustDescription: "Codex and everything it launches",
                isBroadApp: isBroad
            )
        )
    }

    @Test
    func agentFirstUseVariantArmsTouchIDWithGrantSubCopy() async {
        let request = Self.makeFirstUseRequest()
        #expect(request.showsScopeSelector == false)
        #expect(request.permittedScopes == [.once])
        #expect(request.hasInfoStrip)
        #expect(request.stepHintText == "1 of 2 · Review the request")

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true },
            onComplete: { capturedResult = $0 }
        )
        let view = NotchTouchIDPromptView(viewModel: viewModel)
        // Stage 1: base (100) + alert (64) + decision capsule (50) = 214pt; no scope picker.
        #expect(view.openHeight == 214)
        #expect(view.islandHeight == 214)

        // Always Allow… arms Stage 2 in place below the decision capsule (+52pt = 266pt).
        viewModel.armAuthentication(mode: .always)
        #expect(viewModel.phase == .awaitingAuthentication)
        #expect(viewModel.allowMode == .always)
        #expect(viewModel.authTitleText == "Touch ID to Always Allow")
        #expect(viewModel.authSubtitleText == "Permanent grant · Codex and everything it launches")
        #expect(view.islandHeight == 266)

        await viewModel.approveWithBiometrics()
        #expect(viewModel.approvalDecision == .alwaysAllow(method: .biometrics))
        #expect(viewModel.approvedResultLabel == "Always Allow")
        #expect(capturedResult == .approved(scope: .once, method: .biometrics))

        // Allow Once arms the single-request sub-copy instead.
        let onceVM = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true }
        )
        onceVM.armAuthentication(mode: .once)
        #expect(onceVM.authTitleText == "Touch ID to Allow Once")
        #expect(onceVM.authSubtitleText == "This single request only")
        await onceVM.approveWithBiometrics()
        #expect(onceVM.approvalDecision == .allowOnce(method: .biometrics))
        #expect(onceVM.approvedResultLabel == "Allow Once")
    }

    @Test
    func broadAppFirstUseShowsWarningAndAlwaysDenyLinkNeverAllows() {
        let request = Self.makeFirstUseRequest(isBroad: true)
        #expect(request.effectiveWarning == nil)
        #expect(request.alertTone == .info)
        let view = NotchTouchIDPromptView(viewModel: NotchPromptViewModel(request: request, initialPhase: .reviewing))
        #expect(view.openHeight == 214)
        #expect(view.islandHeight == 214)

        let viewModel = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        viewModel.neverAllow()
        #expect(viewModel.approvalDecision == .neverAllow)
        #expect(viewModel.phase == .idle)
    }

    @Test
    func keepAccessVariantReviewDenyKeep() async {
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "Agent SSH",
            keyType: .bot,
            operation: "updated 2.1.303 → 2.2.0",
            kind: .keepAccess,
            keepAccessInfo: NotchKeepAccessInfo(
                affectedKeys: ["Agent SSH", "Agent Git Signing"],
                lineage: "claude-code (Nix)",
                fromVersion: "2.1.303",
                toVersion: "2.2.0"
            )
        )
        #expect(request.showsScopeSelector == false)
        #expect(request.stepHintText == "1 of 2 · Review the update")
        #expect(request.keepAccessInfo?.affectedKeysText == "Keeps access to 2 keys: Agent SSH, Agent Git Signing.")
        #expect(request.keepAccessInfo?.lineageNote
            == "Same lineage (claude-code (Nix)), new identity (cdhash). Access moves to the new version after you approve.")

        // Review… closes the prompt so the caller can open the affected key.
        let reviewVM = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        reviewVM.reviewAccess()
        #expect(reviewVM.approvalDecision == .reviewAccess)
        #expect(reviewVM.phase == .idle)

        // Keep… arms Touch ID with the version-move sub-copy.
        let keepVM = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true }
        )
        keepVM.armAuthentication(mode: .once)
        #expect(keepVM.authTitleText == "Touch ID to Keep")
        #expect(keepVM.authSubtitleText == "Access moves to version 2.2.0")
        await keepVM.approveWithBiometrics()
        #expect(keepVM.approvalDecision == .keepAccess(method: .biometrics))
        #expect(keepVM.approvedResultLabel == "Access kept")
    }

    @Test
    func signatureChangedDenyKeepsDefaultFocusAndReviewConvertsToFirstUse() {
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "Agent SSH",
            keyType: .bot,
            operation: "Authenticate with SSH",
            kind: .signatureChanged,
            signatureChangeInfo: NotchSignatureChangeInfo(
                oldIdentity: "Team ID A1B2C3D4E5",
                newTeamID: "Z9Y8X7W6V5"
            )
        )
        #expect(request.showsScopeSelector == false)
        #expect(request.stepHintText == "Review the signer change")
        #expect(request.effectiveWarning?.detail
            == "Same app lineage, different Team ID (Team ID A1B2C3D4E5 → Team ID Z9Y8X7W6V5). It's treated as a new app and has no access.")

        // Deny keeps the default focus: Return denies instead of arming authentication.
        let viewModel = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        viewModel.handleReturnKey()
        #expect(viewModel.approvalDecision == .denied)
        #expect(viewModel.phase == .idle)

        // Review as new app converts the request into an agent first-use prompt.
        let reviewVM = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        reviewVM.reviewAsNewApp()
        #expect(reviewVM.approvalDecision == .reviewAsNewApp)
        let converted = request.convertedToFirstUse(via: "claude › git › ssh")
        #expect(converted.kind == .agentFirstUse)
        #expect(converted.firstUseInfo?.identity == "Team ID Z9Y8X7W6V5")
        #expect(converted.firstUseInfo?.via == "claude › git › ssh")
        #expect(converted.effectiveWarning == nil)
    }

    @Test
    func agentOnPersonalVariantNeverAllowRouteAndContinue() async {
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "GitHub SSH",
            keyType: .personal,
            operation: "Authenticate with SSH",
            agentWarning: .agentOnPersonal(),
            initialScope: .fifteenMinutes,
            kind: .agentOnPersonal
        )
        #expect(request.showsScopeSelector)
        #expect(request.effectiveWarning?.title == "Agent requests your Personal key")
        #expect(request.effectiveWarning?.detail == "Detected by: agent marker + process chain")
        #expect(request.stepHintText == "1 of 2 · Review the session scope")

        let neverVM = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        neverVM.neverAllow()
        #expect(neverVM.approvalDecision == .neverAllow)

        let routeVM = NotchPromptViewModel(request: request, initialPhase: .reviewing)
        routeVM.routeToAgentSocket()
        #expect(routeVM.approvalDecision == .routeToAgentSocket)

        // Continue arms Touch ID; approval carries the chosen session scope.
        let continueVM = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true }
        )
        continueVM.continueToAuthentication()
        #expect(continueVM.phase == .awaitingAuthentication)
        #expect(continueVM.authTitleText == "Touch ID or Apple Watch")
        #expect(continueVM.authSubtitleText == "Reuse for 15 minutes")
        await continueVM.approveWithBiometrics()
        #expect(continueVM.approvalDecision == .approved(scope: .fifteenMinutes, method: .biometrics))
        #expect(continueVM.approvedResultLabel == "15 min")
    }

    @Test
    func queueIndicatorPrefixesStepHint() {
        let first = Self.makeFirstUseRequest()
        #expect(first.withQueue(position: 1, count: 1).stepHintText == "1 of 2 · Review the request")
        // Queue prefix concatenates with the two-step hint, exactly as `showQ` does in the prototype.
        #expect(first.withQueue(position: 1, count: 3).stepHintText == "1 of 3 · 1 of 2 · Review the request")
        #expect(first.withQueue(position: 2, count: 3).stepHintText == "2 of 3 · 1 of 2 · Review the request")

        let signing = NotchPromptRequest(
            callerName: "Terminal", processChain: "git", keyLabel: "GitHub SSH",
            keyType: .personal, operation: "Sign a Git commit"
        )
        #expect(signing.withQueue(position: 1, count: 2).stepHintText == "1 of 2 · 1 of 2 · Review the session scope")
    }

    @Test
    func approvalVariantFocusCollapseKeepsInfoStripVisible() {
        let viewModel = NotchPromptViewModel(request: Self.makeFirstUseRequest(), initialPhase: .reviewing)
        let view = NotchTouchIDPromptView(viewModel: viewModel)
        #expect(view.islandHeight == 214)
        viewModel.setPromptFocused(false)
        // Identity + alert notice + unfocused action note (100 + 64 + 26 = 190).
        #expect(view.islandHeight == 190)
        viewModel.setPromptFocused(true)
        viewModel.armAuthentication(mode: .once)
        #expect(view.islandHeight == 266)
        viewModel.setPromptFocused(false)
        // Stage 2 unfocused keeps identity + alert notice + armed biometric auth bar (100 + 64 + 52 = 216).
        #expect(view.islandHeight == 216)
        viewModel.setPromptFocused(true)
        viewModel.openPasswordDrawer()
        #expect(view.islandHeight == 266)
    }

    @Test
    func windowControllerQueueOpensNextRequestAfterDecision() async {
        let controller = NotchPromptWindowController()
        var presentedRequests: [NotchPromptRequest] = []

        // Occupy the notch with a signing prompt so both approval requests queue behind it.
        let signing = NotchPromptRequest(
            callerName: "Terminal", processChain: "git → ssh-keygen",
            keyLabel: "GitHub SSH", keyType: .personal, operation: "Sign a Git commit"
        )
        var signingVM: NotchPromptViewModel?
        let signingTask = Task { @MainActor in
            await controller.present(
                request: signing,
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 0,
                biometricAuthenticator: { true },
                onPresented: { viewModel in signingVM = viewModel }
            )
        }
        while signingVM == nil { await Task.yield() }

        let first = Task { @MainActor in
            await controller.submitApprovalRequest(
                Self.makeFirstUseRequest(),
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 0,
                biometricAuthenticator: { true },
                onPresented: { viewModel in
                    presentedRequests.append(viewModel.request)
                    viewModel.armAuthentication(mode: .once)
                    Task { @MainActor in await viewModel.approveWithBiometrics() }
                }
            )
        }
        let second = Task { @MainActor in
            await controller.submitApprovalRequest(
                Self.makeFirstUseRequest(),
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 0,
                biometricAuthenticator: { true },
                onPresented: { viewModel in
                    presentedRequests.append(viewModel.request)
                    viewModel.armAuthentication(mode: .always)
                    Task { @MainActor in await viewModel.approveWithBiometrics() }
                }
            )
        }
        while controller.pendingApprovalCount < 3 { await Task.yield() }
        #expect(controller.pendingApprovalCount == 3)

        // Deciding the signing prompt opens the first queued approval with a "1 of 2" queue indicator.
        signingVM?.deny()
        _ = await signingTask.value
        let firstDecision = await first.value
        let secondDecision = await second.value
        #expect(firstDecision == .allowOnce(method: .biometrics))
        #expect(secondDecision == .alwaysAllow(method: .biometrics))
        #expect(presentedRequests.count == 2)
        #expect(presentedRequests[0].stepHintText == "1 of 2 · 1 of 2 · Review the request")
        // After the first decision the next queued request opens; the last one has no queue prefix.
        #expect(presentedRequests[1].queueCount == 1)
        #expect(presentedRequests[1].stepHintText == "1 of 2 · Review the request")
        #expect(controller.pendingApprovalCount == 0)
    }

    @Test
    func presentApprovalDeliversVariantDecisionAndDismissDenies() async {
        let controller = NotchPromptWindowController()
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "Agent SSH",
            keyType: .bot,
            operation: "Authenticate with SSH",
            kind: .signatureChanged,
            signatureChangeInfo: NotchSignatureChangeInfo(oldIdentity: "Team ID A1B2C3D4E5", newTeamID: "Z9Y8X7W6V5")
        )
        let decision = await controller.presentApproval(
            request: request,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            onPresented: { viewModel in
                viewModel.reviewAsNewApp()
            }
        )
        #expect(decision == .reviewAsNewApp)

        // Dismissing an open approval prompt denies it; queued requests are denied too.
        let pending = Task { @MainActor in
            await controller.submitApprovalRequest(
                Self.makeFirstUseRequest(),
                verifyingDelayNanoseconds: 0,
                signedDisplayNanoseconds: 0,
                biometricAuthenticator: { true }
            )
        }
        while controller.activeViewModel == nil { await Task.yield() }
        controller.dismiss()
        #expect(await pending.value == .denied)
        #expect(controller.pendingApprovalCount == 0)
    }

    @Test(arguments: [NotchPromptKind.agentFirstUse, .keepAccess, .signatureChanged, .agentOnPersonal])
    func rendersApprovalVariantsInNotchWindow(kind: NotchPromptKind) async throws {
        let request: NotchPromptRequest
        switch kind {
        case .agentFirstUse:
            request = Self.makeFirstUseRequest(isBroad: true)
        case .keepAccess:
            request = NotchPromptRequest(
                callerName: "Claude Code",
                processChain: "claude → git → ssh",
                keyLabel: "Agent SSH",
                keyType: .bot,
                operation: "updated 2.1.303 → 2.2.0",
                kind: .keepAccess,
                keepAccessInfo: NotchKeepAccessInfo(
                    affectedKeys: ["Agent SSH", "Agent Git Signing"],
                    lineage: "claude-code (Nix)",
                    fromVersion: "2.1.303",
                    toVersion: "2.2.0"
                )
            )
        case .signatureChanged:
            request = NotchPromptRequest(
                callerName: "Claude Code",
                processChain: "claude → git → ssh",
                keyLabel: "Agent SSH",
                keyType: .bot,
                operation: "Authenticate with SSH",
                kind: .signatureChanged,
                signatureChangeInfo: NotchSignatureChangeInfo(oldIdentity: "Team ID A1B2C3D4E5", newTeamID: "Z9Y8X7W6V5")
            )
        case .agentOnPersonal:
            request = NotchPromptRequest(
                callerName: "Claude Code",
                processChain: "claude → git → ssh",
                keyLabel: "GitHub SSH",
                keyType: .personal,
                operation: "Authenticate with SSH",
                agentWarning: .agentOnPersonal(),
                initialScope: .fifteenMinutes,
                kind: .agentOnPersonal
            )
        case .signing:
            request = NotchPromptRequest(
                callerName: "Terminal", processChain: "git → ssh-keygen",
                keyLabel: "GitHub SSH", keyType: .personal, operation: "Sign a Git commit"
            )
        }

        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false
        )
        let rootView = NotchTouchIDPromptView(viewModel: viewModel)
            .environment(\.colorScheme, .dark)
            .frame(width: 640, height: 520, alignment: .top)
            .background(Color(red: 0.14, green: 0.22, blue: 0.34))
        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: 640, height: 520)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 520),
            styleMask: [.borderless], backing: .buffered, defer: false
        )
        window.appearance = NSAppearance(named: .darkAqua)
        window.ignoresMouseEvents = true
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
            try Self.writeRenderReviewPNG(png, filename: "approval-\(kind.rawValue).png")

            switch kind {
            case .agentOnPersonal:
                viewModel.toggleStage2Authentication()
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "approval-agentOnPersonal-stage2.png")
            case .agentFirstUse:
                viewModel.selectFirstUseAllow(mode: .always)
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "approval-agentFirstUse-stage2-always.png")
            case .keepAccess:
                viewModel.toggleIdentityDetails()
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "approval-keepAccess-details.png")
                viewModel.toggleIdentityDetails()
                viewModel.toggleStage2Authentication()
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "approval-keepAccess-stage2.png")
            case .signatureChanged, .signing:
                break
            }
        }
    }

    @Test
    func confirmationModesMapPoliciesAndDriveOneStepBehavior() async {
        // Policy -> confirmation mode + fallback flag mapping (D-40)
        #expect(NotchConfirmationMode(biometricPolicy: .biometryOrPasscode) == .touchIDOrPassword)
        #expect(NotchConfirmationMode.allowsPasswordFallback(for: .biometryOrPasscode))
        #expect(NotchConfirmationMode(biometricPolicy: .userPresence) == .presenceOrPassword)
        #expect(NotchConfirmationMode.allowsPasswordFallback(for: .userPresence))
        #expect(NotchConfirmationMode(biometricPolicy: .devicePasscode) == .passwordOnly)
        #expect(NotchConfirmationMode.allowsPasswordFallback(for: .devicePasscode))
        #expect(NotchConfirmationMode(biometricPolicy: .biometryCurrentSet) == .touchIDOrPassword)
        #expect(!NotchConfirmationMode.allowsPasswordFallback(for: .biometryCurrentSet))

        // Password-only expands straight to .passwordEntry (198pt unified bar focused height),
        // and clears + collapses to 126pt when unfocused without reverting to .awaitingAuthentication.
        let pwRequest = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh",
            keyLabel: "Password Key",
            keyType: .personal,
            operation: "Authenticate with SSH",
            initialScope: .fifteenMinutes,
            confirmationMode: .passwordOnly
        )
        #expect(pwRequest.initialExpandedPhase == .passwordEntry)
        let pwVM = NotchPromptViewModel(
            request: pwRequest,
            initialPhase: .idle,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            passwordVerifier: { $0 == "secret" }
        )
        let pwView = NotchTouchIDPromptView(viewModel: pwVM)
        pwVM.expand()
        #expect(pwVM.phase == .passwordEntry)
        #expect(pwVM.authTitleText == "Mac login password")
        #expect(pwView.islandHeight == 198)

        pwVM.passwordText = "partial"
        pwVM.setPromptFocused(false)
        #expect(pwVM.phase == .passwordEntry)
        #expect(pwVM.passwordText.isEmpty)
        #expect(pwView.islandHeight == 126)

        pwVM.setPromptFocused(true)
        #expect(pwVM.phase == .passwordEntry)
        #expect(pwView.islandHeight == 198)

        // Wrong password shows error subline below auth bar & expands height by 32pt.
        pwVM.passwordText = "bad"
        #expect(await pwVM.submitPassword() == false)
        #expect(pwVM.passwordError == "Incorrect password. Try again.")
        #expect(pwView.islandHeight == 230)

        pwVM.passwordText = "secret"
        #expect(await pwVM.submitPassword() == true)
        #expect(pwVM.phase == .approved)

        // Strict Touch ID mode disables companion Apple Watch.
        let strictRequest = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh",
            keyLabel: "Strict Key",
            keyType: .personal,
            operation: "Sign a Git commit",
            confirmationMode: .touchIDOrPassword
        )
        #expect(!strictRequest.confirmationMode.allowsCompanionWatch)
        #expect(strictRequest.initialExpandedPhase == .awaitingAuthentication)
        let strictVM = NotchPromptViewModel(request: strictRequest, initialPhase: .idle)
        strictVM.expand()
        #expect(strictVM.phase == .awaitingAuthentication)
        #expect(strictVM.authTitleText == "Touch ID to sign")
    }

    @Test(arguments: NotchConfirmationMode.allCases)
    func rendersAllThreeConfirmationModesInVariant01(mode: NotchConfirmationMode) async throws {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            callerPath: "/System/Applications/Utilities/Terminal.app",
            processChain: "Terminal › zsh › ssh",
            keyLabel: "GitHub SSH",
            keyType: .personal,
            operation: "Authenticate with SSH",
            initialScope: .fifteenMinutes,
            allowsPasswordFallback: true,
            confirmationMode: mode
        )
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: request.initialExpandedPhase,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false
        )
        let rootView = NotchTouchIDPromptView(viewModel: viewModel)
            .environment(\.colorScheme, .dark)
            .frame(width: 640, height: 320, alignment: .top)
            .background(Color(red: 0.14, green: 0.22, blue: 0.34))
        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: 640, height: 320)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 320),
            styleMask: [.borderless], backing: .buffered, defer: false
        )
        window.appearance = NSAppearance(named: .darkAqua)
        window.ignoresMouseEvents = true
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
            let name = mode == .touchIDOrPassword ? "notch-strict" : (mode == .presenceOrPassword ? "notch-presence" : "notch-password")
            try Self.writeRenderReviewPNG(png, filename: "\(name).png")
            if mode == .touchIDOrPassword {
                let bioRequest = NotchPromptRequest(
                    callerName: "Ghostty",
                    processChain: "zsh → git → ssh",
                    keyLabel: "Github.com",
                    keyType: .personal,
                    destination: "git@github.com",
                    operation: "Authenticate with SSH",
                    initialScope: .untilLock,
                    allowsPasswordFallback: false,
                    confirmationMode: .touchIDOrPassword
                )
                let bioViewModel = NotchPromptViewModel(
                    request: bioRequest,
                    initialPhase: bioRequest.initialExpandedPhase,
                    verifyingDelayNanoseconds: 0,
                    signedDisplayNanoseconds: 0,
                    autoCollapseAfterSigned: false
                )
                let bioHost = NSHostingView(
                    rootView: NotchTouchIDPromptView(viewModel: bioViewModel)
                        .environment(\.colorScheme, .dark)
                        .frame(width: 640, height: 320, alignment: .top)
                        .background(Color(red: 0.14, green: 0.22, blue: 0.34))
                )
                bioHost.frame = NSRect(x: 0, y: 0, width: 640, height: 320)
                window.contentView = bioHost
                try await Self.captureAndSaveRenderReview(hostingView: bioHost, filename: "personal-biometric-only.png")

                let sysPwdViewModel = NotchPromptViewModel(
                    request: request,
                    initialPhase: request.initialExpandedPhase,
                    verifyingDelayNanoseconds: 0,
                    signedDisplayNanoseconds: 0,
                    autoCollapseAfterSigned: false,
                    hardwarePasswordAuthenticator: { nil }
                )
                let sysPwdHost = NSHostingView(
                    rootView: NotchTouchIDPromptView(viewModel: sysPwdViewModel)
                        .environment(\.colorScheme, .dark)
                        .frame(width: 640, height: 320, alignment: .top)
                        .background(Color(red: 0.14, green: 0.22, blue: 0.34))
                )
                sysPwdHost.frame = NSRect(x: 0, y: 0, width: 640, height: 320)
                window.contentView = sysPwdHost
                try await Self.captureAndSaveRenderReview(hostingView: sysPwdHost, filename: "personal-system-password-button.png")
            } else if mode == .passwordOnly {
                viewModel.setPromptFocused(false)
                try await Self.captureAndSaveRenderReview(hostingView: hostingView, filename: "notch-password-unfocused.png")
            }
        }
    }

    private final class TrackingContext: LAContext {
        private(set) var isInvalidated = false
        override func invalidate() {
            isInvalidated = true
            super.invalidate()
        }
    }

    @Test
    func notchSigningPromptAuthenticatorMapsSSHAndGitBurstRequests() {
        let sshKey = SSHKeyInfo(
            label: "Github.com",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA Github.com",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:test",
            biometricPolicy: .userPresence
        )
        let sshRequest = SigningAuthenticationRequest(
            key: sshKey,
            operation: .ssh,
            operationLabel: "Authenticate with SSH",
            callerName: nil,
            peerPid: 1,
            peerPath: "/usr/bin/ssh",
            allowsSessionScope: false,
            defaultScope: .always,
            reason: "Allow SSH",
            isUncertainCaller: true,
            isForwardedAgent: false
        )
        let mappedSSH = NotchSigningPromptAuthenticator.makeNotchRequest(from: sshRequest)
        #expect(mappedSSH.displayOperation == "Authenticate with SSH")
        #expect(mappedSSH.showsScopeSelector == false)
        #expect(mappedSSH.processChain != "git → ssh-keygen")
        #expect(mappedSSH.processChain == "ssh")
        #expect(mappedSSH.effectiveWarning == nil)

        let forwardedRequest = SigningAuthenticationRequest(
            key: sshKey,
            operation: .ssh,
            operationLabel: "Authenticate with SSH",
            callerName: nil,
            peerPid: 1,
            peerPath: "/usr/bin/ssh",
            allowsSessionScope: false,
            defaultScope: .always,
            reason: "Allow SSH",
            isUncertainCaller: true,
            isForwardedAgent: true
        )
        let mappedForwarded = NotchSigningPromptAuthenticator.makeNotchRequest(from: forwardedRequest)
        #expect(mappedForwarded.effectiveWarning?.title == "Forwarded SSH agent")
        #expect(mappedForwarded.effectiveWarning?.detail == "Remote host requested a signature via agent forwarding")

        let passwordKey = SSHKeyInfo(
            label: "Git Key",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA Git",
            publicKeyBlob: Data([4, 5, 6]),
            fingerprint: "SHA256:git",
            biometricPolicy: .devicePasscode
        )
        let burstRequest = SigningAuthenticationRequest(
            key: passwordKey,
            operation: .signature,
            operationLabel: "Sign a Git commit",
            callerName: "Ghostty",
            peerPid: 1,
            peerPath: "/usr/bin/git",
            allowsSessionScope: true,
            defaultScope: .untilLock,
            reason: "Sign commits",
            isUncertainCaller: false,
            isForwardedAgent: false
        )
        let mappedBurst = NotchSigningPromptAuthenticator.makeNotchRequest(from: burstRequest)
        #expect(mappedBurst.callerName == "Ghostty")
        #expect(mappedBurst.displayOperation == "Sign a Git commit")
        #expect(mappedBurst.showsScopeSelector == true)
        #expect(mappedBurst.initialScope == .untilLock)
        #expect(mappedBurst.confirmationMode == .passwordOnly)
    }

    @Test
    func compactOneShotSigningHeightAndContextOwnership() {
        let compactRequest = NotchPromptRequest(
            callerName: "Ghostty",
            callerPath: "/Applications/Ghostty.app",
            processChain: "ghostty → zsh → ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            operation: "Authenticate with SSH",
            initialScope: .once,
            showsScopeSelector: false,
            confirmationMode: .presenceOrPassword,
            kind: .signing
        )
        let vm = NotchPromptViewModel(request: compactRequest, initialPhase: .idle)
        let view = NotchTouchIDPromptView(viewModel: vm)
        #expect(view.openHeight == 152)
        vm.expand()
        #expect(vm.phase == .awaitingAuthentication)
        #expect(view.islandHeight == 152)
        vm.setPromptFocused(false)
        #expect(view.islandHeight == 152)

        let warnRequest = NotchPromptRequest(
            callerName: "ssh",
            processChain: "ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            operation: "Authenticate with SSH",
            warningText: "Forwarded SSH agent\nRemote host requested a signature via agent forwarding",
            initialScope: .once,
            showsScopeSelector: false,
            confirmationMode: .presenceOrPassword,
            kind: .signing
        )
        let warnView = NotchTouchIDPromptView(viewModel: NotchPromptViewModel(request: warnRequest, initialPhase: .awaitingAuthentication))
        #expect(warnView.openHeight == 216)
        #expect(warnView.islandHeight == 216)

        // Ownership transfer returns context once without invalidating; deny() invalidates unconsumed context.
        let takenCtx = TrackingContext()
        vm.injectAuthenticatedContextForTesting(takenCtx)
        let popped = vm.takeAuthenticatedContext()
        #expect(popped === takenCtx)
        #expect(takenCtx.isInvalidated == false)
        #expect(vm.takeAuthenticatedContext() == nil)

        let unconsumedCtx = TrackingContext()
        vm.injectAuthenticatedContextForTesting(unconsumedCtx)
        vm.deny()
        #expect(unconsumedCtx.isInvalidated == true)
    }

    @Test
    func enclosingAppBundlePathSkipsDeveloperToolchainsAndNonBundleComponents() {
        #expect(
            AppKitGitSigningGracePresenter.enclosingAppBundlePath(
                for: "/Applications/Xcode.app/Contents/Developer/usr/bin/git"
            ) == nil
        )
        #expect(
            AppKitGitSigningGracePresenter.enclosingAppBundlePath(
                for: "/Applications/Xcode.app/Contents/MacOS/Xcode"
            ) == "/Applications/Xcode.app"
        )
        #expect(
            AppKitGitSigningGracePresenter.enclosingAppBundlePath(
                for: "/Applications/Ghostty.app/Contents/MacOS/ghostty"
            ) == "/Applications/Ghostty.app"
        )
        #expect(
            AppKitGitSigningGracePresenter.enclosingAppBundlePath(
                for: "/Applications/Ghostty.app"
            ) == "/Applications/Ghostty.app"
        )
        #expect(
            AppKitGitSigningGracePresenter.enclosingAppBundlePath(
                for: "/opt/my.apple/bin/ssh"
            ) == nil
        )
        #expect(
            AppKitGitSigningGracePresenter.enclosingAppBundlePath(
                for: "/Applications/Foo.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"
            ) == "/Applications/Foo.app"
        )
    }

    @Test
    func resolveCallerMetadataAttributesGhosttyOverXcrunGitAndKeepsXcodeGUI() {
        let ghosttyChain = [
            AuditProcess(executablePath: "/usr/bin/ssh", pid: 500),
            AuditProcess(executablePath: "/Applications/Xcode.app/Contents/Developer/usr/bin/git", pid: 400),
            AuditProcess(executablePath: "/bin/zsh", pid: 300),
            AuditProcess(executablePath: "/usr/bin/login", pid: 200),
            AuditProcess(executablePath: "/Applications/Ghostty.app/Contents/MacOS/ghostty", pid: 100)
        ]
        let ghosttyResolved = AppKitGitSigningGracePresenter.resolveCallerMetadata(
            rawDescription: "/usr/bin/ssh (PID 500)",
            pid: 500,
            executablePath: "/usr/bin/ssh",
            overrideCallerName: nil,
            keyType: .personal,
            auditChainOverride: ghosttyChain
        )
        #expect(ghosttyResolved.callerName == "Ghostty")
        #expect(ghosttyResolved.callerPath == "/Applications/Ghostty.app")
        #expect(ghosttyResolved.processChain == "zsh → git → ssh")

        let xcodeChain = [
            AuditProcess(executablePath: "/usr/bin/ssh", pid: 501),
            AuditProcess(executablePath: "/Applications/Xcode.app/Contents/Developer/usr/bin/git", pid: 401),
            AuditProcess(executablePath: "/Applications/Xcode.app/Contents/MacOS/Xcode", pid: 101)
        ]
        let xcodeResolved = AppKitGitSigningGracePresenter.resolveCallerMetadata(
            rawDescription: "/usr/bin/ssh (PID 501)",
            pid: 501,
            executablePath: "/usr/bin/ssh",
            overrideCallerName: nil,
            keyType: .personal,
            auditChainOverride: xcodeChain
        )
        #expect(xcodeResolved.callerName == "Xcode")
        #expect(xcodeResolved.callerPath == "/Applications/Xcode.app")
        #expect(xcodeResolved.processChain == "Xcode → git → ssh")
        #expect(xcodeResolved.agentWarning == nil)

        // OpenCode launched inside Ghostty must attribute to OpenCode (nearest agent wins, not Ghostty).
        let opencodeInGhosttyChain = [
            AuditProcess(executablePath: "/usr/bin/ssh", pid: 700),
            AuditProcess(executablePath: "/Applications/Xcode.app/Contents/Developer/usr/bin/git", pid: 600),
            AuditProcess(executablePath: "/bin/zsh", pid: 500),
            AuditProcess(executablePath: "/nix/store/hc5xwji89n9ir1cwx63mrvms89gw44mq-opencode-2.0.32/bin/opencode", pid: 400),
            AuditProcess(executablePath: "/bin/zsh", pid: 300),
            AuditProcess(executablePath: "/usr/bin/login", pid: 200),
            AuditProcess(executablePath: "/Applications/Ghostty.app/Contents/MacOS/ghostty", pid: 100)
        ]
        let opencodeResolved = AppKitGitSigningGracePresenter.resolveCallerMetadata(
            rawDescription: "/usr/bin/ssh (PID 700)",
            pid: 700,
            executablePath: "/usr/bin/ssh",
            overrideCallerName: nil,
            keyType: .personal,
            auditChainOverride: opencodeInGhosttyChain
        )
        #expect(opencodeResolved.callerName == "OpenCode")
        #expect(opencodeResolved.callerPath == "/nix/store/hc5xwji89n9ir1cwx63mrvms89gw44mq-opencode-2.0.32/bin/opencode")
        #expect(opencodeResolved.agentWarning?.title == "Agent requests your Personal key")
        #expect(opencodeResolved.agentWarning?.detail == "Detected by: process tree (opencode)")
        #expect(ghosttyResolved.agentWarning == nil)
    }

    @Test
    func destinationAndKeyLabelTrailingDisplayFormattingAndForwarding() {
        let distinct = NotchPromptRequest(
            callerName: "Ghostty",
            processChain: "zsh → ssh",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            destination: "git@github.com",
            operation: "Authenticate with SSH"
        )
        #expect(distinct.normalizedDestination == "git@github.com")
        #expect(distinct.trailingPrimaryText == "Personal MacBook")
        #expect(distinct.trailingSecondaryText == "git@github.com")

        let duplicate = NotchPromptRequest(
            callerName: "Ghostty",
            processChain: "zsh → ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            destination: "github.com",
            operation: "Authenticate with SSH"
        )
        #expect(duplicate.trailingPrimaryText == "Github.com")
        #expect(duplicate.trailingSecondaryText == "SSH auth")

        let blank = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh-keygen",
            keyLabel: "Work Key",
            keyType: .bot,
            destination: "   \n ",
            operation: "Sign a Git commit"
        )
        #expect(blank.normalizedDestination == nil)
        #expect(blank.trailingPrimaryText == "Work Key")
        #expect(blank.trailingSecondaryText == "Git signing")

        let queued = distinct.withQueue(position: 2, count: 3)
        #expect(queued.destination == "git@github.com")
        #expect(queued.trailingPrimaryText == "Personal MacBook")
        #expect(queued.trailingSecondaryText == "git@github.com")

        let converted = distinct.convertedToFirstUse(via: "zsh → ssh")
        #expect(converted.destination == "git@github.com")

        let sshKey = SSHKeyInfo(
            label: "Personal MacBook",
            publicKeyOpenSSH: "ecdsa-sha2-nistp256 AAAA Personal",
            publicKeyBlob: Data([1, 2, 3]),
            fingerprint: "SHA256:dest",
            biometricPolicy: .userPresence
        )
        let authRequest = SigningAuthenticationRequest(
            key: sshKey,
            operation: .ssh,
            operationLabel: "Authenticate with SSH",
            callerName: "Ghostty",
            peerPid: 1,
            peerPath: "/usr/bin/ssh",
            allowsSessionScope: false,
            defaultScope: .always,
            reason: "Allow SSH",
            isUncertainCaller: false,
            isForwardedAgent: false,
            destination: "git@github.com"
        )
        let mapped = NotchSigningPromptAuthenticator.makeNotchRequest(from: authRequest)
        #expect(mapped.destination == "git@github.com")
        #expect(mapped.trailingPrimaryText == "Personal MacBook")
        #expect(mapped.trailingSecondaryText == "git@github.com")
    }

    @Test
    func twoStageAlertDecisionCapsuleTogglingAndModeSwitching() async {
        // 1. agentOnPersonal toggles between Stage 1 (214pt) and Stage 2 (312pt).
        let personalReq = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "Git Signing",
            keyType: .personal,
            operation: "Sign a Git commit",
            agentWarning: .agentOnPersonal(),
            initialScope: .fifteenMinutes,
            kind: .agentOnPersonal
        )
        let personalVM = NotchPromptViewModel(request: personalReq, initialPhase: .reviewing)
        let personalView = NotchTouchIDPromptView(viewModel: personalVM)
        #expect(personalView.islandHeight == 214)

        // Return must never bypass Stage 1 decision gate.
        personalVM.handleReturnKey()
        #expect(personalVM.phase == .reviewing)

        personalVM.toggleStage2Authentication()
        #expect(personalVM.phase == .awaitingAuthentication)
        #expect(personalView.islandHeight == 312)

        personalVM.toggleStage2Authentication()
        #expect(personalVM.phase == .reviewing)
        #expect(personalView.islandHeight == 214)

        // 2. agentFirstUse supports Stage 1 -> Allow -> in-place switch to Always Allow -> re-click collapses.
        let firstUseVM = NotchPromptViewModel(
            request: Self.makeFirstUseRequest(),
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true }
        )
        let firstUseView = NotchTouchIDPromptView(viewModel: firstUseVM)
        #expect(firstUseView.islandHeight == 214)

        firstUseVM.selectFirstUseAllow(mode: .once)
        #expect(firstUseVM.phase == .awaitingAuthentication)
        #expect(firstUseVM.allowMode == .once)
        #expect(firstUseView.islandHeight == 266)

        firstUseVM.injectEmbeddedAuthContextForTesting(TrackingContext())
        firstUseVM.passwordText = "transient"
        firstUseVM.selectFirstUseAllow(mode: .always)
        #expect(firstUseVM.phase == .awaitingAuthentication)
        #expect(firstUseVM.allowMode == .always)
        #expect(firstUseVM.embeddedAuthContext == nil)
        #expect(firstUseVM.passwordText.isEmpty)
        #expect(firstUseView.islandHeight == 266)

        firstUseVM.selectFirstUseAllow(mode: .always)
        #expect(firstUseVM.phase == .reviewing)
        #expect(firstUseView.islandHeight == 214)

        // 3. keepAccess: Review… toggles details drawer in place; Keep Access opens Stage 2 and completes.
        let keepReq = NotchPromptRequest(
            callerName: "Claude Code",
            callerPath: "/nix/store/claude/bin/claude",
            processChain: "claude → git → ssh",
            keyLabel: "Agent SSH",
            keyType: .bot,
            operation: "updated 2.1.302 → 2.1.303",
            kind: .keepAccess,
            keepAccessInfo: NotchKeepAccessInfo(
                affectedKeys: ["Agent SSH", "Agent Signing"],
                lineage: "claude-code (Nix)",
                fromVersion: "2.1.302",
                toVersion: "2.1.303"
            )
        )
        let keepVM = NotchPromptViewModel(
            request: keepReq,
            initialPhase: .reviewing,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true }
        )
        let keepView = NotchTouchIDPromptView(viewModel: keepVM)
        keepVM.toggleIdentityDetails()
        #expect(keepVM.isIdentityDetailsExpanded)
        #expect(keepView.islandHeight == 352)
        keepVM.toggleStage2Authentication()
        #expect(keepVM.phase == .awaitingAuthentication)
        await keepVM.approveWithBiometrics()
        #expect(keepVM.approvalDecision == .keepAccess(method: .biometrics))
    }

    @Test
    func identityDetailsDrawerPreservesPasswordAndBiometricState() {
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            callerPath: "/nix/store/claude/bin/claude",
            processChain: "claude → git → ssh",
            keyLabel: "Git Signing",
            keyType: .personal,
            operation: "Sign a Git commit",
            agentWarning: .agentOnPersonal(),
            initialScope: .fifteenMinutes,
            trustIdentity: "ad-hoc · Nix · claude-code 2.1.303",
            detectedBy: "Agent marker, Process chain"
        )
        #expect(request.identityDetailRows.map(\.label) == ["Trust ID", "Path", "Lineage", "Detected by"])
        #expect(request.identityDetailRows[0].value == "ad-hoc · Nix · claude-code 2.1.303")
        #expect(request.identityDetailRows[1].isMonospaced)
        #expect(request.identityDetailRows[3].value == "Agent marker, Process chain")

        let vm = NotchPromptViewModel(request: request, initialPhase: .awaitingAuthentication)
        let view = NotchTouchIDPromptView(viewModel: vm)
        let baselineHeight = view.islandHeight
        vm.selectScope(.untilLock)
        let ctx = LAContext()
        vm.injectEmbeddedAuthContextForTesting(ctx)
        vm.passwordText = "typed-secret"

        vm.toggleIdentityDetails()
        #expect(vm.isIdentityDetailsExpanded)
        #expect(view.islandHeight == baselineHeight + 8 + 4 * 26)
        #expect(vm.passwordText == "typed-secret")
        #expect(vm.embeddedAuthContext === ctx)
        #expect(vm.selectedScope == .untilLock)
        #expect(vm.phase == .awaitingAuthentication)

        // Losing focus hides the details drawer height without losing the expanded toggle, restoring on refocus.
        vm.setPromptFocused(false)
        #expect(view.islandHeight == 216)
        vm.setPromptFocused(true)
        #expect(vm.isIdentityDetailsExpanded)
        #expect(view.islandHeight == baselineHeight + 8 + 4 * 26)
    }

    @Test
    func unifiedAuthBarInlinePasswordSubmissionAndErrorDrawer() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "Terminal › zsh › ssh",
            keyLabel: "GitHub SSH",
            keyType: .personal,
            destination: "git@github.com",
            operation: "Authenticate with SSH",
            initialScope: .fifteenMinutes,
            allowsPasswordFallback: true,
            confirmationMode: .touchIDOrPassword
        )
        let vm = NotchPromptViewModel(
            request: request,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            passwordVerifier: { $0 == "clavis" }
        )
        let view = NotchTouchIDPromptView(viewModel: vm)

        // Idle state has no subline below the auth bar.
        #expect(vm.activeErrorMessage == nil)
        #expect(view.islandHeight == 198)

        // Wrong inline password directly from .awaitingAuthentication keeps .awaitingAuthentication and reveals 32pt error subline.
        vm.passwordText = "wrong"
        vm.isPasswordVisible = true
        let badOK = await vm.submitPassword()
        #expect(!badOK)
        #expect(vm.phase == .awaitingAuthentication)
        #expect(!vm.isPasswordVisible)
        #expect(vm.passwordText.isEmpty)
        #expect(vm.activeErrorMessage == "Incorrect password. Try again or use Touch ID.")
        #expect(vm.failureShakeTrigger == 1)
        #expect(view.islandHeight == 230)

        // Correct password approves cleanly.
        vm.passwordText = "clavis"
        let goodOK = await vm.submitPassword()
        #expect(goodOK)
        #expect(vm.phase == .approved)
        #expect(vm.activeErrorMessage == nil)
        #expect(!vm.isPasswordVisible)
    }

    @Test
    func ambientGlowToneAndStageSoftening() {
        let normalReq = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "ssh",
            keyLabel: "GitHub SSH",
            keyType: .personal,
            operation: "Authenticate with SSH"
        )
        #expect(normalReq.alertTone == .none)
        let normalView = NotchTouchIDPromptView(
            viewModel: NotchPromptViewModel(request: normalReq, initialPhase: .awaitingAuthentication)
        )
        #expect(normalView.ambientGlowOpacity == 0.0)

        let warnSigningReq = NotchPromptRequest(
            callerName: "ssh",
            processChain: "ssh",
            keyLabel: "GitHub SSH",
            keyType: .personal,
            operation: "Authenticate with SSH",
            warningText: "Forwarded SSH agent\nRemote host requested a signature"
        )
        #expect(warnSigningReq.alertTone == .warning)
        let warnSigningView = NotchTouchIDPromptView(
            viewModel: NotchPromptViewModel(request: warnSigningReq, initialPhase: .awaitingAuthentication)
        )
        #expect(warnSigningView.ambientGlowOpacity == 1.0)

        let firstUseReq = Self.makeFirstUseRequest()
        #expect(firstUseReq.alertTone == .info)
        let firstUseVM = NotchPromptViewModel(request: firstUseReq, initialPhase: .reviewing)
        let firstUseView = NotchTouchIDPromptView(viewModel: firstUseVM)
        #expect(firstUseView.ambientGlowOpacity == 1.0)

        firstUseVM.selectFirstUseAllow(mode: .always)
        #expect(abs(firstUseView.ambientGlowOpacity - 0.72) < 1e-6)

        firstUseVM.phase = .approved
        #expect(firstUseView.ambientGlowOpacity == 0.0)

        firstUseVM.phase = .idle
        #expect(firstUseView.ambientGlowOpacity == 0.0)
    }

    @Test
    func threeBiometricFailuresTriggerLockoutAndPreserveLockoutAcrossActions() async {
        // 1. Touch ID + password fallback allowed
        let reqWithFallback = NotchPromptRequest(
            callerName: "Ghostty",
            processChain: "zsh → git → ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            operation: "Authenticate with SSH",
            allowsPasswordFallback: true,
            confirmationMode: .touchIDOrPassword
        )
        var bioCalls = 0
        let vm = NotchPromptViewModel(
            request: reqWithFallback,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: {
                bioCalls += 1
                return false
            },
            passwordVerifier: { $0 == "clavis" }
        )
        let view = NotchTouchIDPromptView(viewModel: vm)
        #expect(view.islandHeight == 198)
        #expect(!vm.isBiometricLocked)

        await vm.approveWithBiometrics()
        #expect(vm.biometricFailedAttempts == 1)
        #expect(vm.remainingBiometricAttempts == 2)
        #expect(!vm.isBiometricLocked)
        #expect(vm.biometricFailure == .notRecognized)
        #expect(vm.activeErrorMessage == "Fingerprint not recognized. Try again (2 attempts left) or enter Mac password.")
        #expect(view.islandHeight == 230)

        await vm.approveWithBiometrics()
        #expect(vm.biometricFailedAttempts == 2)
        #expect(vm.remainingBiometricAttempts == 1)
        #expect(!vm.isBiometricLocked)
        #expect(vm.activeErrorMessage == "Fingerprint not recognized. Try again (1 attempt left) or enter Mac password.")

        await vm.approveWithBiometrics()
        #expect(bioCalls == 3)
        #expect(vm.biometricFailedAttempts == 3)
        #expect(vm.remainingBiometricAttempts == 0)
        #expect(vm.isBiometricLocked)
        #expect(vm.biometricFailure == .lockout)
        #expect(vm.activeErrorMessage == "Your password is required to continue.")
        #expect(view.islandHeight == 230)

        // Subsequent biometric attempts and scope changes keep Touch ID locked.
        await vm.approveWithBiometrics()
        vm.retryBiometrics()
        vm.selectScope(.untilLock)
        #expect(bioCalls == 3)
        #expect(vm.isBiometricLocked)
        #expect(vm.biometricFailure == .lockout)

        // Password fallback still works after biometric lockout.
        vm.passwordText = "clavis"
        let unlocked = await vm.submitPassword()
        #expect(unlocked)
        #expect(vm.phase == .approved)

        // 2. Touch ID only (password disabled by key policy)
        let bioOnlyReq = NotchPromptRequest(
            callerName: "Ghostty",
            processChain: "zsh → git → ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            operation: "Authenticate with SSH",
            allowsPasswordFallback: false,
            confirmationMode: .touchIDOrPassword
        )
        let bioOnlyVM = NotchPromptViewModel(
            request: bioOnlyReq,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { false }
        )
        await bioOnlyVM.approveWithBiometrics()
        #expect(bioOnlyVM.activeErrorMessage == "Fingerprint not recognized. Touch sensor to try again (2 attempts left).")
        await bioOnlyVM.approveWithBiometrics()
        #expect(bioOnlyVM.activeErrorMessage == "Fingerprint not recognized. Touch sensor to try again (1 attempt left).")
        await bioOnlyVM.approveWithBiometrics()
        #expect(bioOnlyVM.isBiometricLocked)
        #expect(bioOnlyVM.activeErrorMessage == "Unlock your Mac to reset Touch ID, then try again.")
    }

    @Test
    func preExistingSystemLockoutSurfacesOnOpenRecoversWithoutBypassingTouchIDOnlyPolicy() async {
        // 1. Pre-existing LAError.biometryLockout surfaces on both password-fallback and Touch-ID-only keys.
        var availabilityError: LAError.Code? = .biometryLockout
        var resetCalls = 0
        var resetSucceeded = false

        let bioOnlyReq = NotchPromptRequest(
            callerName: "Ghostty",
            processChain: "zsh → git → ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            operation: "Authenticate with SSH",
            allowsPasswordFallback: false,
            confirmationMode: .touchIDOrPassword
        )
        let bioOnlyVM = NotchPromptViewModel(
            request: bioOnlyReq,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAvailabilityProvider: { _ in availabilityError },
            biometricLockoutResetAuthenticator: {
                resetCalls += 1
                return resetSucceeded
            }
        )
        let bioOnlyView = NotchTouchIDPromptView(viewModel: bioOnlyVM)
        #expect(bioOnlyVM.isBiometricLocked)
        #expect(bioOnlyVM.isSystemBiometricLockout)
        #expect(bioOnlyVM.activeErrorMessage == "Locked by macOS. Re-enable with Mac password.")
        #expect(bioOnlyView.islandHeight == 230)

        bioOnlyVM.toggleLockoutHelp()
        #expect(bioOnlyVM.isLockoutHelpExpanded)
        #expect(bioOnlyView.islandHeight == 334)

        // Failed / cancelled macOS password check keeps lockout intact.
        #expect(!(await bioOnlyVM.reEnableBiometricsWithSystemPassword()))
        #expect(resetCalls == 1)
        #expect(bioOnlyVM.isSystemBiometricLockout)

        // Successful macOS password check clears lockout and re-arms without approving signing (INV-06).
        resetSucceeded = true
        availabilityError = nil
        #expect(await bioOnlyVM.reEnableBiometricsWithSystemPassword())
        #expect(resetCalls == 2)
        #expect(!bioOnlyVM.isBiometricLocked)
        #expect(!bioOnlyVM.isLockoutHelpExpanded)
        #expect(bioOnlyVM.phase == .awaitingAuthentication)
        #expect(bioOnlyVM.authenticatedContext == nil)
        #expect(bioOnlyVM.biometricRecoveryMessage == "Touch ID re-enabled. Rest your finger on the sensor to sign.")
        #expect(bioOnlyView.islandHeight == 230)

        // 2. Password-fallback key detects external unlock (^⌘Q) on focus return.
        var fallbackAvail: LAError.Code? = .biometryLockout
        let fallbackReq = NotchPromptRequest(
            callerName: "Ghostty",
            processChain: "zsh → git → ssh",
            keyLabel: "Github.com",
            keyType: .personal,
            operation: "Authenticate with SSH",
            allowsPasswordFallback: true,
            confirmationMode: .touchIDOrPassword
        )
        let fallbackVM = NotchPromptViewModel(
            request: fallbackReq,
            initialPhase: .awaitingAuthentication,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAvailabilityProvider: { _ in fallbackAvail }
        )
        let fallbackView = NotchTouchIDPromptView(viewModel: fallbackVM)
        #expect(fallbackVM.isSystemBiometricLockout)
        #expect(fallbackVM.activeErrorMessage == "Locked by macOS. Enter password to sign.")
        fallbackVM.toggleLockoutHelp()
        #expect(fallbackView.islandHeight == 312)

        fallbackVM.setPromptFocused(false)
        #expect(!fallbackVM.isLockoutHelpExpanded)
        fallbackAvail = nil
        fallbackVM.setPromptFocused(true)
        #expect(!fallbackVM.isBiometricLocked)
        #expect(fallbackVM.biometricRecoveryMessage == "Touch ID re-enabled. Rest your finger on the sensor to sign.")
    }
}
