import SwiftUI
import ClavisCore
import AppKit

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
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(ClavisUIStrings.Accessibility.agentStatus)
            .accessibilityValue(isActive ? ClavisUIStrings.Accessibility.statusActive : ClavisUIStrings.Accessibility.statusOffline)
    }
}

public struct KeyBadge: View {
    public let isHardware: Bool

    public init(isHardware: Bool = true) {
        self.isHardware = isHardware
    }

    private var tintColor: Color {
        DesignTokens.accentGreen
    }

    public var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(tintColor)
                .frame(width: 4.5, height: 4.5)
                .shadow(color: tintColor.opacity(0.8), radius: 2.5)

            Text(ClavisUIStrings.Badges.hardware)
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(Color(nsColor: NSColor(name: nil) { appearance in
                    appearance.isDarkMode
                        ? NSColor(calibratedWhite: 1.0, alpha: 0.92)
                        : NSColor.labelColor
                }))
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
                            Color(nsColor: NSColor(name: nil) { appearance in
                                appearance.isDarkMode
                                    ? NSColor(calibratedWhite: 1.0, alpha: 0.30)
                                    : NSColor(calibratedWhite: 0.0, alpha: 0.15)
                            }),
                            tintColor.opacity(0.20),
                            Color(nsColor: NSColor(name: nil) { appearance in
                                appearance.isDarkMode
                                    ? NSColor(calibratedWhite: 1.0, alpha: 0.08)
                                    : NSColor(calibratedWhite: 0.0, alpha: 0.05)
                            })
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 0.8
                )
        )
        .shadow(
            color: Color(nsColor: NSColor(name: nil) { appearance in
                appearance.isDarkMode
                    ? NSColor(calibratedWhite: 0.0, alpha: 0.20)
                    : NSColor(calibratedWhite: 0.0, alpha: 0.08)
            }),
            radius: 2,
            x: 0,
            y: 1
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel(ClavisUIStrings.Badges.hardware)
    }
}

public struct PurposeBadge: View {
    public let purpose: KeyPurpose

    public init(purpose: KeyPurpose) {
        self.purpose = purpose
    }

    public var body: some View {
        Group {
            if purpose == .gitSigningOnly {
                HStack(spacing: 3) {
                    Image(systemName: "arrow.triangle.branch")
                        .font(.system(size: 8, weight: .bold))
                    Text(ClavisUIStrings.Badges.gitOnly)
                        .font(.system(size: 9, weight: .semibold))
                }
                .foregroundColor(DesignTokens.accentOrange)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(DesignTokens.accentOrange.opacity(0.15))
                .cornerRadius(4)
            } else if purpose == .agent {
                HStack(spacing: 3) {
                    Image(systemName: "cpu")
                        .font(.system(size: 8, weight: .bold))
                    Text(ClavisUIStrings.Badges.agent)
                        .font(.system(size: 9, weight: .semibold))
                }
                .foregroundColor(DesignTokens.accentPurple)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(DesignTokens.accentPurple.opacity(0.15))
                .cornerRadius(4)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(purpose.title)
    }
}


