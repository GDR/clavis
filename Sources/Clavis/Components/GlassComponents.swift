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

@available(macOS 26.0, *)
public struct LiquidGlassButtonGroup<Content: View>: View {
    public var spacing: CGFloat
    @ViewBuilder let content: () -> Content

    public init(spacing: CGFloat = 6, @ViewBuilder content: @escaping () -> Content) {
        self.spacing = spacing
        self.content = content
    }

    public var body: some View {
        GlassEffectContainer(spacing: spacing) {
            HStack(spacing: spacing) {
                content()
            }
        }
    }
}

@available(macOS 26.0, *)
public struct LiquidGlassSegmentedBar<Content: View>: View {
    @ViewBuilder let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    public var body: some View {
        HStack(spacing: 0) {
            content()
        }
        .frame(height: 26)
        .glassEffect(.regular.interactive(), in: .capsule)
    }
}

public struct MacOSGlassSegmentDivider: View {
    public init() {}

    public var body: some View {
        Rectangle()
            .fill(Color.white.opacity(0.16))
            .frame(width: 1, height: 14)
    }
}

public struct LiquidGlassSegmentModifier: ViewModifier {
    public var width: CGFloat = 30
    @State private var isHovered = false

    public func body(content: Content) -> some View {
        content
            .frame(width: width, height: 26)
            .background(
                Rectangle()
                    .fill(isHovered ? Color.white.opacity(0.12) : Color.clear)
            )
            .contentShape(Rectangle())
            .onHover { isHovered = $0 }
    }
}

public extension View {
    func glassCard(cornerRadius: CGFloat = 10, strokeColor: Color = DesignTokens.cardBorder) -> some View {
        self.modifier(GlassCardModifier(cornerRadius: cornerRadius, strokeColor: strokeColor))
    }

    func liquidGlassSegment(width: CGFloat = 30) -> some View {
        self.modifier(LiquidGlassSegmentModifier(width: width))
    }

    func liquidGlassCircle(size: CGFloat = 28) -> some View {
        self.modifier(LiquidGlassSegmentModifier(width: size))
    }

    func liquidGlassRowSelection(isSelected: Bool, isHovered: Bool = false, cornerRadius: CGFloat = 10) -> some View {
        self.modifier(LiquidGlassRowSelectionModifier(isSelected: isSelected, isHovered: isHovered, cornerRadius: cornerRadius))
    }

    @ViewBuilder
    func disableFocusEffect() -> some View {
        if #available(macOS 14.0, *) {
            self.focusable(false).focusEffectDisabled()
        } else {
            self.focusable(false)
        }
    }
}

public struct LiquidGlassRowSelectionModifier: ViewModifier {
    public var isSelected: Bool
    public var isHovered: Bool
    public var cornerRadius: CGFloat = 10

    public func body(content: Content) -> some View {
        content
            .background(
                Group {
                    if isSelected {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [
                                        Color.white.opacity(isHovered ? 0.22 : 0.16),
                                        Color.white.opacity(isHovered ? 0.10 : 0.05)
                                    ],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                    } else if isHovered {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .fill(Color.white.opacity(0.06))
                    }
                }
            )
            .overlay(
                Group {
                    if isSelected {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .stroke(
                                LinearGradient(
                                    colors: [
                                        Color.white.opacity(isHovered ? 0.38 : 0.28),
                                        Color.white.opacity(isHovered ? 0.14 : 0.08)
                                    ],
                                    startPoint: .top,
                                    endPoint: .bottom
                                ),
                                lineWidth: 0.8
                            )
                    } else if isHovered {
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .stroke(Color.white.opacity(0.09), lineWidth: 0.8)
                    }
                }
            )
            .shadow(color: isSelected ? Color.black.opacity(0.22) : .clear, radius: 4, x: 0, y: 1.5)
    }
}

