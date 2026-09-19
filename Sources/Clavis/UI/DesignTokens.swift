import SwiftUI

public enum DesignTokens {
    // Backgrounds & Glass (translucent for true behindWindow frosted blur)
    public static let windowBackground = Color(nsColor: NSColor(calibratedRed: 0.09, green: 0.09, blue: 0.10, alpha: 0.50))
    public static let sidebarBackground = Color(nsColor: NSColor(calibratedRed: 0.12, green: 0.12, blue: 0.14, alpha: 0.45))
    public static let inspectorBackground = Color(nsColor: NSColor(calibratedRed: 0.10, green: 0.10, blue: 0.12, alpha: 0.50))
    public static let cardBackground = Color(nsColor: NSColor(calibratedWhite: 1.0, alpha: 0.05))
    public static let cardBorder = Color(nsColor: NSColor(calibratedWhite: 1.0, alpha: 0.08))

    // Gradients for ambient glass glow
    public static let sidebarTintBlue = Color(red: 0.0, green: 0.53, blue: 1.0).opacity(0.20)
    public static let sidebarTintViolet = Color(red: 0.58, green: 0.22, blue: 0.95).opacity(0.18)

    // Accents & Badges
    public static let accentGreen = Color(red: 0.20, green: 0.78, blue: 0.35)
    public static let accentBlue = Color(red: 0.0, green: 0.53, blue: 1.0)
    public static let accentOrange = Color(red: 1.0, green: 0.55, blue: 0.16)
    public static let accentIndigo = Color(red: 0.38, green: 0.33, blue: 0.96)
    public static let textSecondary = Color(nsColor: NSColor.secondaryLabelColor)
    public static let textTertiary = Color(nsColor: NSColor.tertiaryLabelColor)
}

public struct GlassCardModifier: ViewModifier {
    public var cornerRadius: CGFloat = 10
    public var strokeColor: Color = DesignTokens.cardBorder

    public func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .fill(Color(nsColor: NSColor.controlBackgroundColor).opacity(0.4))
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius))
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(strokeColor, lineWidth: 0.8)
            )
    }
}

public struct VisualEffectView: NSViewRepresentable {
    public var material: NSVisualEffectView.Material
    public var blendingMode: NSVisualEffectView.BlendingMode
    public var state: NSVisualEffectView.State

    public init(
        material: NSVisualEffectView.Material = .sidebar,
        blendingMode: NSVisualEffectView.BlendingMode = .behindWindow,
        state: NSVisualEffectView.State = .active
    ) {
        self.material = material
        self.blendingMode = blendingMode
        self.state = state
    }

    public func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = state
        return view
    }

    public func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
        nsView.state = state
    }
}

public extension View {
    func glassCard(cornerRadius: CGFloat = 10, strokeColor: Color = DesignTokens.cardBorder) -> some View {
        self.modifier(GlassCardModifier(cornerRadius: cornerRadius, strokeColor: strokeColor))
    }
}

public struct StatusDot: View {
    public let isActive: Bool

    public init(isActive: Bool) {
        self.isActive = isActive
    }

    public var body: some View {
        Circle()
            .fill(isActive ? DesignTokens.accentGreen : Color.secondary.opacity(0.6))
            .frame(width: 8, height: 8)
            .shadow(color: isActive ? DesignTokens.accentGreen.opacity(0.6) : .clear, radius: 4)
    }
}

public struct KeyBadge: View {
    public let isHardware: Bool

    public init(isHardware: Bool) {
        self.isHardware = isHardware
    }

    private var tintColor: Color {
        isHardware
            ? Color(red: 0.30, green: 0.85, blue: 0.55)
            : Color(red: 0.38, green: 0.68, blue: 1.0)
    }

    public var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(tintColor)
                .frame(width: 4.5, height: 4.5)
                .shadow(color: tintColor.opacity(0.8), radius: 2.5)

            Text(isHardware ? "Hardware" : "Software")
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(Color.white.opacity(0.92))
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 2.5)
        .background(
            Capsule()
                .fill(tintColor.opacity(0.14))
                .background(.ultraThinMaterial, in: Capsule())
        )
        .overlay(
            Capsule()
                .stroke(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.30),
                            tintColor.opacity(0.20),
                            Color.white.opacity(0.08)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 0.8
                )
        )
        .shadow(color: Color.black.opacity(0.2), radius: 2, x: 0, y: 1)
    }
}

public struct FirstMouseView: NSViewRepresentable {
    public init() {}
    public func makeNSView(context: Context) -> FirstMouseNSView {
        FirstMouseNSView()
    }
    public func updateNSView(_ nsView: FirstMouseNSView, context: Context) {}
}

public class FirstMouseNSView: NSView {
    public override var mouseDownCanMoveWindow: Bool { false }
    public override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

public struct LiquidGlassButtonGroup<Content: View>: View {
    @ViewBuilder let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    public var body: some View {
        HStack(spacing: 4) {
            content()
        }
        .padding(4)
        .background(FirstMouseView())
        .background(
            Capsule()
                .fill(Color.white.opacity(0.06))
                .background(.ultraThinMaterial, in: Capsule())
        )
        .overlay(
            Capsule()
                .stroke(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.18),
                            Color.white.opacity(0.06)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 0.8
                )
        )
        .shadow(color: Color.black.opacity(0.25), radius: 4, x: 0, y: 2)
    }
}

public struct LiquidGlassCircleModifier: ViewModifier {
    public var size: CGFloat = 28
    @State private var isHovered = false

    public func body(content: Content) -> some View {
        content
            .frame(width: size, height: size)
            .contentShape(Circle())
            .background(
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(isHovered ? 0.22 : 0.14),
                                Color.white.opacity(isHovered ? 0.10 : 0.04)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .background(.ultraThinMaterial, in: Circle())
            )
            .overlay(
                Circle()
                    .stroke(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(isHovered ? 0.35 : 0.22),
                                Color.white.opacity(isHovered ? 0.12 : 0.06)
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        ),
                        lineWidth: 0.8
                    )
            )
            .contentShape(Circle())
            .shadow(color: Color.black.opacity(0.2), radius: 3, x: 0, y: 1)
            .onHover { isHovered = $0 }
    }
}

public extension View {
    func liquidGlassCircle(size: CGFloat = 28) -> some View {
        self.modifier(LiquidGlassCircleModifier(size: size))
    }
}
