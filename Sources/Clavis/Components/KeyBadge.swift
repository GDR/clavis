import SwiftUI

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
