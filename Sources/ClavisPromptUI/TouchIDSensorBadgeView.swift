import AppKit
import LocalAuthentication
import SwiftUI

public enum TouchIDSensorState: Equatable {
    case active(isFailure: Bool = false)
    case inactive(isFailure: Bool = false)
    case verifying
    case locked
    case unavailable
}

public enum TouchIDSensorSurface: Equatable {
    case notch
    case adaptive
}

/// Shared ringed Touch ID sensor control used across the Notch prompt, the lock
/// screen, and in-window authorization cards so focus transitions feel like
/// arming vs. dimming one hardware sensor instead of swapping bare icons.
public struct TouchIDSensorBadgeView: View {
    public static let symbolName = "touchid"

    public let state: TouchIDSensorState
    public let context: LAContext?
    public let size: CGFloat
    public let surface: TouchIDSensorSurface
    public let inactiveOpacity: Double
    public let shakeTrigger: Int
    public let reduceMotion: Bool
    public let onEmbeddedMount: ((LAContext) -> Void)?

    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceMotion) private var envReduceMotion

    public init(
        state: TouchIDSensorState,
        context: LAContext? = nil,
        size: CGFloat = 32,
        surface: TouchIDSensorSurface = .adaptive,
        inactiveOpacity: Double = 0.52,
        shakeTrigger: Int = 0,
        reduceMotion: Bool = false,
        onEmbeddedMount: ((LAContext) -> Void)? = nil
    ) {
        self.state = state
        self.context = context
        self.size = size
        self.surface = surface
        self.inactiveOpacity = inactiveOpacity
        self.shakeTrigger = shakeTrigger
        self.reduceMotion = reduceMotion
        self.onEmbeddedMount = onEmbeddedMount
    }

    private var effectiveReduceMotion: Bool {
        reduceMotion || envReduceMotion
    }

    private var transitionAnimation: Animation? {
        effectiveReduceMotion ? nil : .spring(response: 0.28, dampingFraction: 0.82)
    }

    private var isMutedState: Bool {
        state == .locked || state == .unavailable
    }

    private var isRedRingState: Bool {
        !isMutedState
    }

    private var isActiveVisual: Bool {
        switch state {
        case .active, .verifying:
            return true
        case .inactive, .locked, .unavailable:
            return false
        }
    }

    private var isFailure: Bool {
        switch state {
        case .active(let failed), .inactive(let failed):
            return failed
        case .verifying, .locked, .unavailable:
            return false
        }
    }

    private var isVerifying: Bool {
        state == .verifying
    }

    private var isLocked: Bool {
        state == .locked
    }

    private var usesEmbeddedContext: Bool {
        if case .active = state {
            return context != nil
        }
        return false
    }

    private var redRingOpacity: Double {
        switch state {
        case .active, .verifying:
            return 1.0
        case .inactive:
            return surface == .notch ? min(inactiveOpacity, 0.58) : (contrast == .increased ? 0.85 : 0.65)
        case .locked, .unavailable:
            return 0.0
        }
    }

    private var mutedRingOpacity: Double {
        surface == .notch ? inactiveOpacity : 1.0
    }

    public var body: some View {
        let embeddedSize = min(32, max(20, size - 4))

        ZStack {
            ringLayer

            if let context, usesEmbeddedContext {
                // Keep ancestor opacity at `1.0` and transform at identity so macOS
                // `NSOcclusionDetectionView` never fires `LAError.systemCancel`.
                NotchEmbeddedTouchIDView(context: context, iconSize: embeddedSize)
                    .id(ObjectIdentifier(context))
                    .frame(width: embeddedSize, height: embeddedSize)
                    .clipShape(Circle())
                    .transition(.identity)
                    .onAppear { onEmbeddedMount?(context) }
            } else if isVerifying {
                Image(systemName: "checkmark")
                    .font(.system(size: round(size * 0.5), weight: .medium))
                    .foregroundStyle(NotchPromptPalette.touchIDPink)
            } else if isLocked {
                Image(systemName: "lock.fill")
                    .font(.system(size: round(size * 0.38), weight: .semibold))
                    .foregroundStyle(surface == .notch ? NotchPromptPalette.t2 : Color.secondary)
                    .opacity(mutedRingOpacity)
            }
        }
        .frame(width: size, height: size)
    }

    private var ringLayer: some View {
        let neutralFillColor: Color = surface == .notch
            ? Color.white.opacity(0.06)
            : Color.primary.opacity(colorScheme == .dark ? 0.07 : 0.05)
        let neutralStrokeColor: Color = surface == .notch
            ? Color.white.opacity(0.12)
            : Color.primary.opacity(0.12)
        let ringColor = isFailure ? NotchPromptPalette.danger : NotchPromptPalette.touchIDPink

        return ZStack {
            Circle()
                .fill(neutralFillColor)
                .overlay(Circle().strokeBorder(neutralStrokeColor, lineWidth: 1.5))
                .animation(transitionAnimation) { view in
                    view.opacity(isMutedState ? mutedRingOpacity : 0)
                }

            Circle()
                .fill(
                    RadialGradient(
                        colors: [ringColor.opacity(isActiveVisual ? 0.24 : 0.14), .clear],
                        center: .center,
                        startRadius: 2,
                        endRadius: size * 0.5
                    )
                )
                .overlay(
                    Circle().strokeBorder(
                        ringColor.opacity(isFailure ? 0.72 : (isActiveVisual ? 0.48 : 0.38)),
                        lineWidth: 1.5
                    )
                )
                .animation(transitionAnimation) { view in
                    view.opacity(isRedRingState ? redRingOpacity : 0)
                }
        }
        .frame(width: size, height: size)
        .animation(transitionAnimation) { view in
            view.scaleEffect(isActiveVisual ? 1.0 : 0.94)
        }
        .modifier(
            NotchHorizontalShakeEffect(
                animatableData: (effectiveReduceMotion || usesEmbeddedContext) ? 0 : CGFloat(shakeTrigger)
            )
        )
    }
}
