import Foundation

public enum ClavisUIStrings {

    private static func localized(_ key: StaticString, _ defaultValue: String) -> String {
        String(localized: key, defaultValue: String.LocalizationValue(defaultValue), bundle: .module)
    }

    public enum Common {
        public static var appName: String { localized("common.app_name", "Clavis") }
        public static var cancel: String { localized("common.cancel", "Cancel") }
        public static var delete: String { localized("common.delete", "Delete") }
        public static var copy: String { localized("common.copy", "Copy") }
        public static var copied: String { localized("common.copied", "Copied") }
        public static var copiedFeedback: String { localized("common.copied_feedback", "Copied!") }
        public static var end: String { localized("common.end", "End") }
        public static var addKey: String { localized("common.add_key", "Add Key") }
    }

    public enum MenuBar {
        public static var title: String { localized("menubar.title", "Clavis Agent") }
        public static var agentOffline: String { localized("menubar.agent_offline", "Agent offline") }
        public static func activeWithPID(_ pid: pid_t) -> String {
            "Active (PID \(pid))"
        }
        public static func identitiesReady(count: Int) -> String {
            "\(count) identities ready"
        }
        public static var lockAll: String { localized("menubar.lock_all", "Lock All") }
        public static func gitSessionTitle(label: String) -> String { "Git Session: \(label)" }
        public static func gitSessionDetails(timeRemaining: String, opsLeft: Int) -> String {
            "\(timeRemaining) remaining • \(opsLeft) ops left"
        }
        public static var identitiesHeader: String { localized("menubar.identities_header", "Identities") }
        public static var noKeysAvailable: String { localized("menubar.no_keys_available", "No keys available") }
        public static var useNewKeyHint: String { localized("menubar.use_new_key_hint", "Use 'New Key…' to generate an identity.") }
        public static var searchPlaceholder: String { localized("menubar.search_placeholder", "Search keys...") }
        public static var noKeysFound: String { localized("menubar.no_keys_found", "No Keys Found") }
        public static var noKeysHint: String { localized("menubar.no_keys_hint", "Create or import an SSH key to start") }
        public static var preferences: String { localized("menubar.preferences", "Preferences...") }
        public static var settings: String { localized("menubar.settings", "Settings…") }
        public static var newKey: String { localized("menubar.new_key", "New Key…") }
        public static var importKey: String { localized("menubar.import_key", "Import Key…") }
        public static var openKeyManager: String { localized("menubar.open_key_manager", "Open Key Manager…") }
        public static var restartAgent: String { localized("menubar.restart_agent", "Restart SSH Agent…") }
        public static var startAgent: String { localized("menubar.start_agent", "Start SSH Agent…") }
        public static var quit: String { localized("menubar.quit", "Quit Clavis") }
        public static var lockActiveSession: String { localized("menubar.lock_active_session", "Lock Active Session") }
    }

    public enum Inspector {
        public static var publicKey: String { localized("inspector.public_key", "Public Key") }
        public static var fingerprint: String { localized("inspector.fingerprint", "Fingerprint") }
        public static var created: String { localized("inspector.created", "Created") }
        public static var algorithm: String { localized("inspector.algorithm", "Algorithm") }
        public static var storageTarget: String { localized("inspector.storage_target", "Storage Target") }
        public static var biometricPolicy: String { localized("inspector.biometric_policy", "Biometric Policy") }
        public static var keyPurpose: String { localized("inspector.key_purpose", "Key Purpose") }

        public static var lock: String { localized("inspector.lock", "Lock") }
        public static var unlock: String { localized("inspector.unlock", "Unlock") }
        public static var copyPublicKey: String { localized("inspector.copy_public_key", "Copy Public Key") }
        public static var exportAgeRecipient: String { localized("inspector.export_age_recipient", "Export age recipient") }
        public static var deleteKey: String { localized("inspector.delete_key", "Delete Key") }

        public static var hardwareIsolated: String { localized("inspector.hardware_isolated", "Hardware Isolated · Touch ID per operation") }
        public static func unlockedWithTime(_ remaining: String) -> String { "Unlocked · \(remaining)" }
        public static var unlockedActive: String { localized("inspector.unlocked_active", "Unlocked · Active in session") }
        public static var lockedTouchIdRequired: String { localized("inspector.locked_touch_id_required", "Locked · Touch ID required") }

        public static var deleteAlertTitle: String { localized("inspector.delete_alert_title", "Delete Key") }
        public static func deleteAlertMessage(label: String) -> String {
            "Are you sure you want to delete '\(label)'? This action cannot be undone."
        }
    }

    public enum CreateKey {
        public static var title: String { localized("create_key.title", "Create New Key") }
        public static var subtitle: String { localized("create_key.subtitle", "Select a key type preset. Storage and cryptographic algorithm are configured automatically.") }
        public static var namePlaceholder: String { localized("create_key.name_placeholder", "Key Name (e.g. github-macbook)") }
        public static var generateButton: String { localized("create_key.generate_button", "Generate Key") }

        public static var softwareTitle: String { localized("create_key.software_title", "Software Key (Ed25519)") }
        public static var softwareBadge: String { localized("create_key.software_badge", "KEYCHAIN") }
        public static var softwareSubtitle: String { localized("create_key.software_subtitle", "Standard Edwards-curve key. Supported by age/agenix, SSH, and Git commit signing, with session TTL memory caching.") }

        public static var hardwareTitle: String { localized("create_key.hardware_title", "Hardware Key (Secure Enclave)") }
        public static var hardwareBadge: String { localized("create_key.hardware_badge", "APPLE SILICON") }
        public static var hardwareSubtitle: String { localized("create_key.hardware_subtitle", "Hardware-bound NIST P-256 key isolated inside the Apple Silicon chip. Private key never leaves hardware. Always prompts Touch ID per operation.") }
    }

    public enum Settings {
        public static var startupSection: String { localized("settings.startup_section", "SYSTEM STARTUP") }
        public static var launchAtLoginTitle: String { localized("settings.launch_at_login_title", "Launch at Login") }
        public static var launchAtLoginSubtitle: String { localized("settings.launch_at_login_subtitle", "Automatically start Clavis daemon on user login") }

        public static var sshSection: String { localized("settings.ssh_section", "SSH INTEGRATION") }
        public static var agentSocketTitle: String { localized("settings.agent_socket_title", "Agent Socket") }
        public static var envVarTitle: String { localized("settings.env_var_title", "Terminal Environment Variable") }
        public static var envVarCommand: String { "export SSH_AUTH_SOCK=~/.ssh/clavis.sock" }

        public static var sessionCacheSection: String { localized("settings.session_cache_section", "SESSION CACHE") }
        public static var cacheLifetimeTitle: String { localized("settings.cache_lifetime_title", "Cache Lifetime") }
        public static var cacheLifetimeSubtitle: String { localized("settings.cache_lifetime_subtitle", "How long software keys stay in secure RAM") }
    }
}
