import Foundation

public enum ClavisUIStrings {

    public enum Common {
        public static let appName = "Clavis"
        public static let cancel = "Cancel"
        public static let delete = "Delete"
        public static let copy = "Copy"
        public static let copied = "Copied"
        public static let copiedFeedback = "Copied!"
        public static let end = "End"
        public static let addKey = "Add Key"
    }

    public enum MenuBar {
        public static let title = "Clavis Agent"
        public static let agentOffline = "Agent offline"
        public static func activeWithPID(_ pid: pid_t) -> String { "Active (PID \(pid))" }
        public static func identitiesReady(count: Int) -> String { "\(count) identities ready" }
        public static let lockAll = "Lock All"
        public static func gitSessionTitle(label: String) -> String { "Git Session: \(label)" }
        public static func gitSessionDetails(timeRemaining: String, opsLeft: Int) -> String {
            "\(timeRemaining) remaining • \(opsLeft) ops left"
        }
        public static let identitiesHeader = "Identities"
        public static let noKeysAvailable = "No keys available"
        public static let useNewKeyHint = "Use 'New Key…' to generate an identity."
        public static let searchPlaceholder = "Search keys..."
        public static let noKeysFound = "No Keys Found"
        public static let noKeysHint = "Create or import an SSH key to start"
        public static let preferences = "Preferences..."
        public static let settings = "Settings…"
        public static let newKey = "New Key…"
        public static let importKey = "Import Key…"
        public static let openKeyManager = "Open Key Manager…"
        public static let restartAgent = "Restart SSH Agent…"
        public static let startAgent = "Start SSH Agent…"
        public static let quit = "Quit Clavis"
        public static let lockActiveSession = "Lock Active Session"
    }

    public enum Inspector {
        public static let publicKey = "Public Key"
        public static let fingerprint = "Fingerprint"
        public static let created = "Created"
        public static let algorithm = "Algorithm"
        public static let storageTarget = "Storage Target"
        public static let biometricPolicy = "Biometric Policy"
        public static let keyPurpose = "Key Purpose"

        public static let lock = "Lock"
        public static let unlock = "Unlock"
        public static let copyPublicKey = "Copy Public Key"
        public static let exportAgeRecipient = "Export age recipient"
        public static let deleteKey = "Delete Key"

        public static let hardwareIsolated = "Hardware Isolated · Touch ID per operation"
        public static func unlockedWithTime(_ remaining: String) -> String { "Unlocked · \(remaining)" }
        public static let unlockedActive = "Unlocked · Active in session"
        public static let lockedTouchIdRequired = "Locked · Touch ID required"

        public static let deleteAlertTitle = "Delete Key"
        public static func deleteAlertMessage(label: String) -> String {
            "Are you sure you want to delete '\(label)'? This action cannot be undone."
        }
    }

    public enum CreateKey {
        public static let title = "Create New Key"
        public static let subtitle = "Select a key type preset. Storage and cryptographic algorithm are configured automatically."
        public static let namePlaceholder = "Key Name (e.g. github-macbook)"
        public static let generateButton = "Generate Key"

        public static let softwareTitle = "Software Key (Ed25519)"
        public static let softwareBadge = "KEYCHAIN"
        public static let softwareSubtitle = "Standard Edwards-curve key. Supported by age/agenix, SSH, and Git commit signing, with session TTL memory caching."

        public static let hardwareTitle = "Hardware Key (Secure Enclave)"
        public static let hardwareBadge = "APPLE SILICON"
        public static let hardwareSubtitle = "Hardware-bound NIST P-256 key isolated inside the Apple Silicon chip. Private key never leaves hardware. Always prompts Touch ID per operation."
    }

    public enum Settings {
        public static let startupSection = "SYSTEM STARTUP"
        public static let launchAtLoginTitle = "Launch at Login"
        public static let launchAtLoginSubtitle = "Automatically start Clavis daemon on user login"

        public static let sshSection = "SSH INTEGRATION"
        public static let agentSocketTitle = "Agent Socket"
        public static let envVarTitle = "Terminal Environment Variable"
        public static let envVarCommand = "export SSH_AUTH_SOCK=~/.ssh/clavis.sock"

        public static let sessionCacheSection = "SESSION CACHE"
        public static let cacheLifetimeTitle = "Cache Lifetime"
        public static let cacheLifetimeSubtitle = "How long software keys stay in secure RAM"
    }
}
