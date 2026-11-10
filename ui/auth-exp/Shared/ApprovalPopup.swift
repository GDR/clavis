import SwiftUI
import AppKit
import LocalAuthentication

// MARK: - Approval popup (the UX under test)
//
// A separate floating window that mimics the Clavis approval prompt: request details on top,
// mechanism-specific authentication UI in the middle (supplied by each prototype), Deny/Approve below.
// The popup stays open on authentication failure so retry behaviour can be judged.

@MainActor
public final class ApprovalSession: ObservableObject {
    public let challenge: SigningChallenge
    public let autoStart: Bool

    @Published public var errorText: String?
    @Published public var busy = false
    /// Free-form slots prototypes can use from their content/authenticate closures.
    @Published public var context: LAContext?
    @Published public var secret = ""
    public var viewResultHandler: ((Result<Void, Error>) -> Void)?

    var authenticate: ((ApprovalSession) async throws -> LAContext)!
    var finish: ((Result<LAContext, Error>) -> Void)!

    init(challenge: SigningChallenge, autoStart: Bool) {
        self.challenge = challenge
        self.autoStart = autoStart
    }

    public func approve() {
        guard !busy else { return }
        busy = true
        errorText = nil
        Task { @MainActor in
            do {
                let ctx = try await authenticate(self)
                finish(.success(ctx))
            } catch {
                busy = false
                errorText = error.localizedDescription
            }
        }
    }

    public func deny() {
        context?.invalidate()
        finish(.failure(LAError(.userCancel)))
    }
}

struct ApprovalPopupView<Extra: View>: View {
    @ObservedObject var session: ApprovalSession
    let extra: Extra

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: "key.horizontal.fill").font(.system(size: 30)).foregroundStyle(.tint)
                VStack(alignment: .leading) {
                    Text("Signature request").font(.headline)
                    Text(session.challenge.clientProcess).font(.subheadline).foregroundStyle(.secondary)
                }
            }
            Text(session.challenge.operationSummary)
            Text(session.challenge.payloadText)
                .font(.system(.caption, design: .monospaced)).lineLimit(3)
                .padding(6).frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            extra
            if let e = session.errorText {
                Text(e).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Button("Deny") { session.deny() }.keyboardShortcut(.cancelAction)
                Spacer()
                if session.busy { ProgressView().controlSize(.small) }
                if !session.autoStart || session.errorText != nil {
                    Button(session.errorText == nil ? "Approve" : "Retry") { session.approve() }
                        .keyboardShortcut(.defaultAction).disabled(session.busy)
                }
            }
        }
        .padding(20)
        .frame(width: 420)
    }
}

private final class PopupDelegate: NSObject, NSWindowDelegate {
    var onClose: (() -> Void)?
    func windowWillClose(_ notification: Notification) { onClose?() }
}

private struct PopupHost<C: View>: View {
    @ObservedObject var session: ApprovalSession
    let content: (ApprovalSession) -> C
    var body: some View { ApprovalPopupView(session: session, extra: content(session)) }
}

public enum ApprovalPopup {
    private static var openCount = 0

    /// Shows the popup and returns the authenticated context once `authenticate` succeeds.
    /// Throws `LAError.userCancel` if the user denies or closes the window.
    @MainActor
    public static func present<Content: View>(
        challenge: SigningChallenge,
        autoStart: Bool = false,
        @ViewBuilder content: @escaping (ApprovalSession) -> Content,
        authenticate: @escaping (ApprovalSession) async throws -> LAContext
    ) async throws -> LAContext {
        try await withCheckedThrowingContinuation { cont in
            let session = ApprovalSession(challenge: challenge, autoStart: autoStart)
            session.authenticate = authenticate

            let controller = NSHostingController(rootView: PopupHost(session: session, content: content))
            controller.sizingOptions = [.preferredContentSize]
            let panel = NSPanel(contentViewController: controller)
            panel.styleMask = [.titled, .closable]
            panel.title = "Clavis"
            panel.level = .floating
            panel.isReleasedWhenClosed = false

            let delegate = PopupDelegate()
            panel.delegate = delegate
            var finished = false
            session.finish = { result in
                guard !finished else { return }
                finished = true
                panel.delegate = nil
                panel.close()
                withExtendedLifetime(delegate) {}
                cont.resume(with: result)
            }
            delegate.onClose = { [weak session] in session?.deny() }

            panel.center()
            // Cascade concurrent popups so they stay distinguishable.
            let offset = CGFloat(openCount % 4) * 28
            openCount += 1
            panel.setFrameTopLeftPoint(NSPoint(x: panel.frame.minX + offset, y: panel.frame.maxY - offset))
            NSApp.activate(ignoringOtherApps: true)
            panel.makeKeyAndOrderFront(nil)
            if autoStart { session.approve() }
        }
    }
}
