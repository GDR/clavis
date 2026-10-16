import SwiftUI
import AppKit

public enum DesignTokens {
    // Backgrounds & Glass (translucent for true behindWindow frosted blur)
    public static let windowBackground = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.09, green: 0.09, blue: 0.10, alpha: 0.50)
            : NSColor(calibratedWhite: 0.98, alpha: 0.65)
    })

    public static let sidebarBackground = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.12, green: 0.12, blue: 0.14, alpha: 0.0)
            : NSColor(calibratedWhite: 0.94, alpha: 0.45)
    })

    public static let inspectorBackground = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.10, green: 0.10, blue: 0.12, alpha: 0.50)
            : NSColor(calibratedWhite: 0.99, alpha: 0.60)
    })

    public static let menuBarBackground = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.11, green: 0.11, blue: 0.13, alpha: 0.60)
            : NSColor(calibratedWhite: 0.95, alpha: 0.70)
    })

    public static let cardBackground = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedWhite: 1.0, alpha: 0.05)
            : NSColor(calibratedWhite: 0.0, alpha: 0.04)
    })

    public static let cardBorder = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedWhite: 1.0, alpha: 0.08)
            : NSColor(calibratedWhite: 0.0, alpha: 0.12)
    })

    // Accents & Status (WCAG AA >= 4.5:1 text, >= 3:1 icons)
    public static let accentGreen = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.20, green: 0.78, blue: 0.35, alpha: 1.0) // #33C759
            : NSColor(calibratedRed: 0.08, green: 0.52, blue: 0.22, alpha: 1.0) // #148538 (~4.76:1)
    })

    public static let accentBlue = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.0, green: 0.53, blue: 1.0, alpha: 1.0)  // #0087FF
            : NSColor(calibratedRed: 0.0, green: 0.40, blue: 0.82, alpha: 1.0)  // #0066D1 (~5.5:1)
    })

    public static let accentOrange = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 1.0, green: 0.55, blue: 0.16, alpha: 1.0) // #FF8C29
            : NSColor(calibratedRed: 0.75, green: 0.31, blue: 0.0, alpha: 1.0)  // #BF5000 (~4.83:1)
    })

    public static let accentIndigo = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.50, green: 0.48, blue: 1.0, alpha: 1.0)  // #807AFF (~5.25:1)
            : NSColor(calibratedRed: 0.28, green: 0.22, blue: 0.82, alpha: 1.0) // #4738D1 (~7.61:1)
    })

    public static let accentPurple = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.isDarkMode
            ? NSColor(calibratedRed: 0.75, green: 0.38, blue: 0.95, alpha: 1.0) // #BF61F2 (~5.30:1)
            : NSColor(calibratedRed: 0.52, green: 0.18, blue: 0.72, alpha: 1.0) // #852EB8 (~6.84:1)
    })

    public static let textSecondary = Color(nsColor: NSColor.secondaryLabelColor)
    public static let textTertiary = Color(nsColor: NSColor.tertiaryLabelColor)
}

extension NSAppearance {
    public var isDarkMode: Bool {
        bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    }
}

public extension View {
    @ViewBuilder
    func groupedEmbeddedForm(zeroMargins: Bool = false) -> some View {
        if #available(macOS 14.0, *), zeroMargins {
            self
                .formStyle(.grouped)
                .scrollDisabled(true)
                .scrollContentBackground(.hidden)
                .contentMargins(.zero, for: .scrollContent)
        } else {
            self
                .formStyle(.grouped)
                .scrollDisabled(true)
                .scrollContentBackground(.hidden)
        }
    }
}

