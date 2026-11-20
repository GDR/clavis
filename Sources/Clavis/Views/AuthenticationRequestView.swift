import AppKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Variant 07 from ui/settings-lab. Presentation only: the host owns authentication,
/// password fallback, cancellation, and the operation waiting for authorization.
/// Do not treat displaying this view (or receiving a button callback) as authorization.
///
/// D-36 retirement note: request prompts (agent first use, keep access, signature changed,
/// agent-on-Personal) no longer use a separate floating approval card — they all render in the
/// single notch confirmation window (`NotchTouchIDPromptView` / `NotchPromptWindowController`,
/// `NotchPromptKind` + `submitApprovalRequest`). This tile survives only as the in-window
/// authentication surface for `PolicyMutationCoordinator` (settings mutations) until its callers
/// (`KeyListView.AuthenticationTileHost`, `PolicyMutationCoordinator.Phase`) migrate to the notch.
struct AuthenticationRequestView: View {
    enum Phase: Equatable {
        case waiting, failed, unavailable, saving, saveFailed, authenticated

        var status: LocalizedStringKey {
            switch self {
            case .waiting: return "Waiting for Touch ID"
            case .failed: return "Not recognized. Try again."
            case .unavailable: return "Touch ID unavailable"
            case .saving: return "Saving…"
            case .saveFailed: return "Couldn’t save. Try again."
            case .authenticated: return "Authentication complete"
            }
        }

        var allowsRetry: Bool {
            self == .failed || self == .unavailable || self == .saveFailed
        }
    }

    var phase: Phase = .waiting
    /// The exact fresh context evaluated by the host. Mount this view before evaluation.
    /// A nil context displays a static symbol, useful for previews and unavailable hardware.
    var authenticationContext: LAContext? = nil
    var onPassword: () -> Void
    var onRetry: () -> Void
    var onCancel: () -> Void

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        VStack(spacing: 0) {
            biometricSymbol
                .frame(width: 48, height: 48)
                .padding(.top, 6)
                .padding(.bottom, 16)

            Text(phase == .authenticated ? "Authenticated" : "Authentication required")
                .font(.system(size: 15, weight: .semibold))
                .multilineTextAlignment(.center)
                .accessibilityAddTraits(.isHeader)
                .padding(.bottom, 12)

            Text(phase.status)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("authenticationRequest.status")

            if phase.allowsRetry {
                Button("Try again", action: onRetry)
                    .buttonStyle(.link)
                    .font(.system(size: 11))
                    .padding(.top, 8)
            }

            if phase != .authenticated {
                Button(action: onPassword) {
                    Text("Password…")
                        .font(.system(size: 12))
                        .frame(maxWidth: .infinity, minHeight: 28)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.bordered)
                .controlSize(.regular)
                .disabled(phase == .saving)
                .accessibilityHint("Use password authentication instead of Touch ID")
                .accessibilityIdentifier("authenticationRequest.password")
                .padding(.top, 14)
            }
        }
        .frame(width: 220)
        .padding(.horizontal, 18)
        .padding(.top, 20)
        .padding(.bottom, 16)
        .background { surface }
        .overlay(alignment: .topTrailing) {
            Button(action: onCancel) {
                Image(systemName: "xmark")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .keyboardShortcut(.cancelAction)
            .accessibilityLabel(phase == .authenticated ? "Close authentication" : "Cancel authentication")
            .accessibilityIdentifier("authenticationRequest.cancel")
            .padding(4)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("authenticationRequest")
    }

    @ViewBuilder
    private var biometricSymbol: some View {
        if phase == .saving {
            ProgressView().controlSize(.small)
                .accessibilityLabel("Saving")
        } else if phase == .authenticated {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(.green)
                .accessibilityHidden(true)
        } else if let authenticationContext, phase == .waiting || phase == .failed {
            RequestTouchIDSymbol(context: authenticationContext)
                .id(ObjectIdentifier(authenticationContext))
        } else {
            Image(systemName: "touchid")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(phase == .waiting ? Color.pink : Color.secondary)
                .accessibilityHidden(true)
        }
    }

    private var surface: some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        return Group {
            if reduceTransparency {
                shape.fill(Color(nsColor: .windowBackgroundColor))
            } else {
                shape.fill(.regularMaterial)
            }
        }
        .overlay {
            shape.strokeBorder(Color.primary.opacity(contrast == .increased ? 0.6 : 0.15),
                               lineWidth: contrast == .increased ? 1.5 : 0.5)
        }
        .shadow(color: .black.opacity(0.18), radius: 18, y: 8)
    }
}

/// Context identity changes recreate the system view, avoiding stale sensor bindings.
private struct RequestTouchIDSymbol: NSViewRepresentable {
    let context: LAContext

    func makeNSView(context: Context) -> LAAuthenticationView {
        LAAuthenticationView(context: self.context, controlSize: .small)
    }

    func updateNSView(_ nsView: LAAuthenticationView, context: Context) {}
}

#if DEBUG
struct AuthenticationRequestView_Previews: PreviewProvider {
    static var previews: some View {
        AuthenticationRequestView(onPassword: {}, onRetry: {}, onCancel: {})
            .padding(40)
            .previewDisplayName("07 · Authentication tile")
    }
}
#endif
