import AppKit
import SwiftUI
import Testing
@testable import Clavis
@testable import ClavisCore

@Suite @MainActor
struct NotchTouchIDPromptTests {

    @Test
    func sessionScopeTitlesAndGraceMapping() {
        let all = NotchSessionScope.allCases
        #expect(all == [.once, .fifteenMinutes, .untilLock, .oneDay])
        #expect(NotchSessionScope.once.title == "Once")
        #expect(NotchSessionScope.fifteenMinutes.title == "15 min")
        #expect(NotchSessionScope.untilLock.title == "Until Lock")
        #expect(NotchSessionScope.oneDay.title == "1 Day")

        #expect(NotchSessionScope.once.gitSigningPromptChoice == .singleShot)
        #expect(NotchSessionScope.fifteenMinutes.gitSigningPromptChoice == .grantFiveMinutes)
        #expect(NotchSessionScope.untilLock.gitSigningPromptChoice == .grantFiveMinutes)
        #expect(NotchSessionScope.oneDay.gitSigningPromptChoice == .grantFiveMinutes)
    }

    @Test
    func scopeSelectionAndPhaseTransitions() async {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "commit -S",
            initialScope: .fifteenMinutes,
            showsScopeSelector: true
        )

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .idle,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            biometricAuthenticator: { true },
            onComplete: { result in
                capturedResult = result
            }
        )

        #expect(viewModel.phase == .idle)
        #expect(viewModel.selectedScope == .fifteenMinutes)

        viewModel.expand()
        #expect(viewModel.phase == .expanded)

        for scope in NotchSessionScope.allCases {
            viewModel.selectScope(scope)
            #expect(viewModel.selectedScope == scope)
        }

        viewModel.openPasswordDrawer()
        #expect(viewModel.phase == .password)

        viewModel.closePasswordDrawer()
        #expect(viewModel.phase == .expanded)

        viewModel.selectScope(.untilLock)
        await viewModel.approveWithBiometrics()
        #expect(viewModel.phase == .signed)
        #expect(capturedResult == .approved(scope: .untilLock, method: .biometrics))
    }

    @Test
    func biometricApprovalAutoCollapsesToIdle() async {
        let request = NotchPromptRequest(
            callerName: "Claude Code",
            processChain: "claude → git → ssh",
            keyLabel: "Deploy Bot",
            keyType: .bot,
            operation: "git push",
            initialScope: .once
        )

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .expanded,
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
    func passwordVerificationSuccessAndFailure() async {
        let request = NotchPromptRequest(
            callerName: "Clavis",
            processChain: "Clavis UI",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "INV-09",
            initialScope: .oneDay,
            showsScopeSelector: false
        )

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .expanded,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            autoCollapseAfterSigned: false,
            passwordVerifier: { candidate in
                candidate == "correct-horse-battery-staple"
            }
        ) { result in
            capturedResult = result
        }

        viewModel.openPasswordDrawer()
        #expect(viewModel.phase == .password)

        // Empty password fails with prompt error
        viewModel.passwordText = "   "
        let emptyOk = await viewModel.submitPassword()
        #expect(!emptyOk)
        #expect(viewModel.passwordError != nil)
        #expect(viewModel.phase == .password)
        #expect(capturedResult == nil)

        // Wrong password fails with error message
        viewModel.passwordText = "wrong-password"
        let wrongOk = await viewModel.submitPassword()
        #expect(!wrongOk)
        #expect(viewModel.passwordError == "Incorrect password. Try again or use Touch ID.")
        #expect(viewModel.phase == .password)
        #expect(capturedResult == nil)

        // Correct password transitions to .signed and completes
        viewModel.passwordText = "correct-horse-battery-staple"
        let validOk = await viewModel.submitPassword()
        #expect(validOk)
        #expect(viewModel.passwordError == nil)
        #expect(viewModel.phase == .signed)
        #expect(capturedResult == .approved(scope: .oneDay, method: .password))
    }

    @Test
    func denyCompletesAndReturnsToIdle() {
        let request = NotchPromptRequest(
            callerName: "Terminal",
            processChain: "git → ssh",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "git push"
        )

        var capturedResult: NotchPromptResult?
        let viewModel = NotchPromptViewModel(
            request: request,
            initialPhase: .expanded,
            onComplete: { result in
                capturedResult = result
            }
        )

        viewModel.deny()
        #expect(viewModel.phase == .idle)
        #expect(capturedResult == .denied)
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
            processChain: "git → ssh",
            keyLabel: "Personal MacBook",
            keyType: .personal,
            operation: "commit -S",
            initialScope: .untilLock
        )

        let result = await controller.present(
            request: request,
            verifyingDelayNanoseconds: 0,
            signedDisplayNanoseconds: 0,
            biometricAuthenticator: { true },
            onPresented: { viewModel in
                #expect(viewModel.phase == .expanded)
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

    @Test(arguments: [KeyType.personal, KeyType.bot], [NotchPromptPhase.expanded, NotchPromptPhase.password, NotchPromptPhase.signed])
    func rendersNotchTouchIDPromptInPersonalAndBotModes(keyType: KeyType, phase: NotchPromptPhase) async throws {
        let request = NotchPromptRequest(
            callerName: keyType == .personal ? "Terminal" : "Claude Code",
            processChain: keyType == .personal ? "git → ssh" : "claude → git → ssh",
            keyLabel: keyType == .personal ? "Personal MacBook" : "Deploy Bot",
            keyType: keyType,
            operation: keyType == .personal ? "commit -S" : "git push",
            warningText: keyType == .bot ? "First use of Bot Key by Claude Code." : nil,
            initialScope: .fifteenMinutes,
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
            .frame(width: 520, height: 290, alignment: .top)
            .background(Color(red: 0.10, green: 0.12, blue: 0.16))

        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: 520, height: 290)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 290),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = hostingView
        window.orderFront(nil)
        defer { window.orderOut(nil) }

        try await Task.sleep(nanoseconds: 50_000_000)
        hostingView.layoutSubtreeIfNeeded()

        let bitmap = try #require(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try #require(bitmap.representation(using: .png, properties: [:]))
        #expect(png.count > 2_000)
    }
}
