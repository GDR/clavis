import SwiftUI

public enum DesignTokens {
    // Backgrounds & Glass (translucent for true behindWindow frosted blur)
    public static let windowBackground = Color(nsColor: NSColor(calibratedRed: 0.09, green: 0.09, blue: 0.10, alpha: 0.50))
    public static let sidebarBackground = Color(nsColor: NSColor(calibratedRed: 0.12, green: 0.12, blue: 0.14, alpha: 0.45))
    public static let inspectorBackground = Color(nsColor: NSColor(calibratedRed: 0.10, green: 0.10, blue: 0.12, alpha: 0.50))
    public static let cardBackground = Color(nsColor: NSColor(calibratedWhite: 1.0, alpha: 0.05))
    public static let cardBorder = Color(nsColor: NSColor(calibratedWhite: 1.0, alpha: 0.08))

    // Accents & Status
    public static let accentGreen = Color(red: 0.20, green: 0.78, blue: 0.35)
    public static let accentBlue = Color(red: 0.0, green: 0.53, blue: 1.0)
    public static let accentOrange = Color(red: 1.0, green: 0.55, blue: 0.16)
    public static let accentIndigo = Color(red: 0.38, green: 0.33, blue: 0.96)
    public static let textSecondary = Color(nsColor: NSColor.secondaryLabelColor)
    public static let textTertiary = Color(nsColor: NSColor.tertiaryLabelColor)
}
