import CryptoKit
import Foundation

public enum PlatformSupport {
    public static var hasSecureEnclave: Bool {
        SecureEnclave.isAvailable
    }

    public static let unsupportedMessage = "Clavis requires a Mac with Secure Enclave support."
}
