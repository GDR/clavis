import SwiftUI

public enum DesignTokens {
    // Backgrounds & Glass (translucent for true behindWindow frosted blur)
    public static let windowBackground = Color(nsColor: NSColor(calibratedRed: 0.09, green: 0.09, blue: 0.10, alpha: 0.50))
    public static let sidebarBackground = Color(nsColor: NSColor(calibratedRed: 0.12, green: 0.12, blue: 0.14, alpha: 0.0))
    public static let inspectorBackground = Color(nsColor: NSColor(calibratedRed: 0.10, green: 0.10, blue: 0.12, alpha: 0.50))
    public static let menuBarBackground = Color(nsColor: NSColor(name: nil) { appearance in
        if appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
            return NSColor(calibratedRed: 0.11, green: 0.11, blue: 0.13, alpha: 0.60)
        } else {
            return NSColor(calibratedWhite: 0.95, alpha: 0.70)
        }
    })
    public static let cardBackground = Color(nsColor: NSColor(calibratedWhite: 1.0, alpha: 0.05))
    public static let cardBorder = Color(nsColor: NSColor(calibratedWhite: 1.0, alpha: 0.08))

    // Accents & Status
    public static let accentGreen = Color(red: 0.20, green: 0.78, blue: 0.35)
    public static let accentBlue = Color(red: 0.0, green: 0.53, blue: 1.0)
    public static let accentOrange = Color(red: 1.0, green: 0.55, blue: 0.16)
    public static let accentIndigo = Color(red: 0.38, green: 0.33, blue: 0.96)
    public static let accentPurple = Color(red: 0.69, green: 0.32, blue: 0.87)
    public static let textSecondary = Color(nsColor: NSColor.secondaryLabelColor)
    public static let textTertiary = Color(nsColor: NSColor.tertiaryLabelColor)
}
