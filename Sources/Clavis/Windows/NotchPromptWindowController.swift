import AppKit
import SwiftUI
import LocalAuthentication
import ClavisCore

/// Borderless, non-activating top-of-screen panel that can accept keyboard focus when the password drawer opens.
public final class NotchOverlayPanel: NSPanel {
    public override var canBecomeKey: Bool { true }
    public override var canBecomeMain: Bool { false }
}

@MainActor
public final class NotchPromptWindowController: NSObject {
    public static let shared = NotchPromptWindowController()
    public nonisolated static let defaultPanelSize = NSSize(width: 640, height: 340)

    public private(set) var panel: NSPanel?
    public private(set) var activeViewModel: NotchPromptViewModel?
    private var activeContinuation: CheckedContinuation<NotchPromptResult, Never>?
    private var hideWorkItem: DispatchWorkItem?

    public override init() {
        super.init()
    }

    /// Computes the top-centered frame flush with the top edge (`maxY`) of the given screen frame.
    public nonisolated static func topCenterFrame(
        for screenFrame: NSRect,
        panelSize: NSSize = defaultPanelSize
    ) -> NSRect {
        NSRect(
            x: screenFrame.midX - panelSize.width / 2.0,
            y: screenFrame.maxY - panelSize.height,
            width: panelSize.width,
            height: panelSize.height
        )
    }

    /// Creates and configures the borderless, non-activating `NSPanel` for the MacBook Notch prompt.
    @discardableResult
    public func configurePanel(
        for viewModel: NotchPromptViewModel,
        screenFrame: NSRect? = nil
    ) -> NSPanel {
        let targetScreenFrame = screenFrame
            ?? NSScreen.main?.frame
            ?? NSScreen.screens.first?.frame
            ?? NSRect(x: 0, y: 0, width: 1512, height: 982)
        let frame = Self.topCenterFrame(for: targetScreenFrame, panelSize: Self.defaultPanelSize)

        let panel: NotchOverlayPanel
        if let existing = self.panel as? NotchOverlayPanel {
            panel = existing
            panel.setFrame(frame, display: true)
        } else {
            panel = NotchOverlayPanel(
                contentRect: frame,
                styleMask: [.borderless, .nonactivatingPanel],
                backing: .buffered,
                defer: false
            )
            panel.level = .statusBar + 1
            panel.appearance = NSAppearance(named: .darkAqua)
            panel.isOpaque = false
            panel.backgroundColor = .clear
            panel.hasShadow = false
            panel.hidesOnDeactivate = false
            panel.isMovable = false
            panel.isReleasedWhenClosed = false
            panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
            self.panel = panel
        }

        let rootView = NotchTouchIDPromptView(viewModel: viewModel)
            .environment(\.colorScheme, .dark)
        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(origin: .zero, size: frame.size)
        hostingView.wantsLayer = true
        hostingView.layer?.backgroundColor = NSColor.clear.cgColor
        panel.contentView = hostingView

        return panel
    }

    /// Presents the MacBook Notch Touch ID prompt at the top center of the main display and awaits user decision.
    public func present(
        request: NotchPromptRequest,
        verifyingDelayNanoseconds: UInt64 = 160_000_000,
        signedDisplayNanoseconds: UInt64 = 650_000_000,
        biometricAuthenticator: @escaping @MainActor () async -> Bool = NotchPromptWindowController.defaultBiometricAuthenticator,
        passwordVerifier: @escaping @MainActor (String) async -> Bool = NotchPromptWindowController.defaultPasswordVerifier,
        onPresented: (@MainActor (NotchPromptViewModel) -> Void)? = nil
    ) async -> NotchPromptResult {
        dismissActivePromptIfNeeded()

        return await withCheckedContinuation { continuation in
            self.activeContinuation = continuation

            let viewModel = NotchPromptViewModel(
                request: request,
                initialPhase: .idle,
                verifyingDelayNanoseconds: verifyingDelayNanoseconds,
                signedDisplayNanoseconds: signedDisplayNanoseconds,
                autoCollapseAfterSigned: true,
                biometricAuthenticator: biometricAuthenticator,
                passwordVerifier: passwordVerifier
            ) { [weak self] result in
                guard let self else { return }
                self.completeActivePrompt(with: result)
            }

            self.activeViewModel = viewModel
            let panel = self.configurePanel(for: viewModel)
            panel.contentView?.layoutSubtreeIfNeeded()
            panel.orderFrontRegardless()

            if let onPresented {
                viewModel.expand()
                onPresented(viewModel)
            } else {
                // Commit the initial collapsed 188×32 notch frame before animating width and height outward.
                DispatchQueue.main.async {
                    viewModel.expand()
                }
            }
        }
    }

    public func dismiss() {
        dismissActivePromptIfNeeded()
    }

    private func dismissActivePromptIfNeeded() {
        hideWorkItem?.cancel()
        hideWorkItem = nil
        panel?.makeFirstResponder(nil)
        if let continuation = activeContinuation {
            activeContinuation = nil
            continuation.resume(returning: .denied)
        }
        panel?.orderOut(nil)
        activeViewModel = nil
    }

    private func completeActivePrompt(with result: NotchPromptResult) {
        panel?.makeFirstResponder(nil)
        if let continuation = activeContinuation {
            activeContinuation = nil
            continuation.resume(returning: result)
        }
        if ClavisEnvironment.isTesting {
            panel?.orderOut(nil)
            activeViewModel = nil
        } else {
            // Allow the fast 0.24s shrink animation back into the 188×32 notch to finish before ordering out the panel.
            hideWorkItem?.cancel()
            let work = DispatchWorkItem { [weak self] in
                Task { @MainActor in
                    self?.panel?.orderOut(nil)
                    self?.activeViewModel = nil
                }
            }
            hideWorkItem = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.24, execute: work)
        }
    }

    public static func defaultBiometricAuthenticator() async -> Bool {
        #if DEBUG
        if ClavisEnvironment.isTesting {
            return true
        }
        #endif
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return false
        }
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "approve signing request in Clavis"
            )
        } catch {
            return false
        }
    }

    public static func defaultPasswordVerifier(_ password: String) async -> Bool {
        !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
