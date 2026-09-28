import CryptoKit
import Foundation

public enum PlatformSupport {
    public static var hasSecureEnclave: Bool {
        SecureEnclave.isAvailable
    }

    public static var unsupportedMessage: String {
        ClavisUIStrings.App.unsupportedMessage
    }
}
