import SwiftUI

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
    func glassCard(cornerRadius: CGFloat = 10, strokeColor: Color = DesignTokens.cardBorder) -> some View {
        self.modifier(GlassCardModifier(cornerRadius: cornerRadius, strokeColor: strokeColor))
    }

    func liquidGlassCircle(size: CGFloat = 28) -> some View {
        self.modifier(LiquidGlassCircleModifier(size: size))
    }
}
