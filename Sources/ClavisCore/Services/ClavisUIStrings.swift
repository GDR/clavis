import Foundation

public enum ClavisUIStrings {

    private static func localized(_ key: StaticString, _ defaultValue: String) -> String {
        String(localized: key, defaultValue: String.LocalizationValue(defaultValue), bundle: .module)
    }

    private static func localizedFormat(_ key: StaticString, _ defaultValue: String, _ arguments: CVarArg...) -> String {
        let format = String(localized: key, defaultValue: String.LocalizationValue(defaultValue), bundle: .module)
        return String(format: format, arguments: arguments)
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
        public static var error: String { localized("common.error", "Error") }
        public static var ok: String { localized("common.ok", "OK") }
        public static func minRemaining(_ mins: Int) -> String {
            localizedFormat("common.min_remaining", "%d min remaining", mins)
        }
    }

    public enum MenuBar {
        public static var title: String { localized("menubar.title", "Clavis Agent") }
        public static var agentOffline: String { localized("menubar.agent_offline", "Agent offline") }
        public static func activeWithPID(_ pid: pid_t) -> String {
            localizedFormat("menubar.active_with_pid", "Active (PID %d)", pid)
        }
        public static func identitiesReady(count: Int) -> String {
            if count == 1 {
                return localizedFormat("menubar.identities_ready_singular", "%d identity ready", count)
            } else {
                return localizedFormat("menubar.identities_ready_plural", "%d identities ready", count)
            }
        }
        public static var lockAll: String { localized("menubar.lock_all", "Lock All") }
        public static func gitSessionTitle(label: String) -> String {
            localizedFormat("menubar.git_session_title", "Git Session: %@", label)
        }
        public static func gitSessionDetails(timeRemaining: String, opsLeft: Int) -> String {
            localizedFormat("menubar.git_session_details", "%@ remaining • %d ops left", timeRemaining, opsLeft)
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
        public static var quitConfirmationTitle: String { localized("menubar.quit_confirmation_title", "Quit Clavis?") }
        public static var quitConfirmationDetailsWithAgent: String {
            localized("menubar.quit_confirmation_details_with_agent", "Clavis and its background SSH Agent will stop. Active caches and Git signing sessions will be cleared.")
        }
        public static var quitConfirmationDetailsSimple: String {
            localized("menubar.quit_confirmation_details_simple", "Clavis will stop and active caches will be cleared.")
        }
    }

    public enum KeyList {
        public static var title: String { localized("key_list.title", "Keys") }
        public static func identitiesAvailable(count: Int) -> String {
            if count == 1 {
                return localizedFormat("key_list.identities_available_singular", "%d identity available", count)
            } else {
                return localizedFormat("key_list.identities_available_plural", "%d identities available", count)
            }
        }
        public static var noKeySelectedTitle: String { localized("key_list.no_key_selected_title", "No Key Selected") }
        public static var noKeySelectedSubtitle: String { localized("key_list.no_key_selected_subtitle", "Select an identity from the sidebar to inspect its public credentials and security attributes.") }
        public static func deletedKey(label: String) -> String {
            localizedFormat("key_list.deleted_key", "Deleted key '%@'.", label)
        }
        public static var addOrImportKeyHelp: String { localized("key_list.add_or_import_key_help", "Add or Import Key") }
        public static var lockAllKeysHelp: String { localized("key_list.lock_all_keys_help", "Lock All Keys") }
        public static var noUnlockedKeysHelp: String { localized("key_list.no_unlocked_keys_help", "No Unlocked Keys") }
        public static var allCachedKeysLocked: String { localized("key_list.all_cached_keys_locked", "All cached keys locked.") }
        public static var settingsHelp: String { localized("key_list.settings_help", "Settings (Auto Start, Timeout, Nix)") }
    }

    public enum SessionTimeout {
        public static var never: String { localized("session_timeout.never", "Off (Always Prompt)") }
        public static var fiveMinutes: String { localized("session_timeout.five_minutes", "5 Minutes") }
        public static var fifteenMinutes: String { localized("session_timeout.fifteen_minutes", "15 Minutes") }
        public static var oneHour: String { localized("session_timeout.one_hour", "1 Hour") }
    }

    public enum Inspector {
        public static var publicKey: String { localized("inspector.public_key", "Public Key") }
        public static var fingerprint: String { localized("inspector.fingerprint", "Fingerprint") }
        public static var fingerprintLabel: String { fingerprint }
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
        public static func unlockedWithTime(_ remaining: String) -> String {
            localizedFormat("inspector.unlocked_with_time", "Unlocked · %@", remaining)
        }
        public static var unlockedActive: String { localized("inspector.unlocked_active", "Unlocked · Active in session") }
        public static var lockedTouchIdRequired: String { localized("inspector.locked_touch_id_required", "Touch ID required to sign") }

        public static var deleteAlertTitle: String { localized("inspector.delete_alert_title", "Delete Key") }
        public static func deleteAlertMessage(label: String) -> String {
            localizedFormat("inspector.delete_alert_message", "Are you sure you want to delete '%@'? This action cannot be undone.", label)
        }

        // Header & Context Menu
        public static func keySubtitle(algorithm: String, isHardware: Bool) -> String {
            let typeName = isHardware ? localized("inspector.badge_hardware", "Hardware") : localized("inspector.badge_software", "Software")
            return localizedFormat("inspector.key_subtitle", "%@ · %@ Key", algorithm, typeName)
        }
        public static var alwaysPromptBadge: String { localized("inspector.always_prompt_badge", "Always Prompt") }
        public static var copyAgeRecipientMenu: String { localized("inspector.copy_age_recipient_menu", "Copy age Recipient") }
        public static var copyOpenSSHKeyMenu: String { localized("inspector.copy_openssh_key_menu", "Copy OpenSSH Key") }
        public static var copyFingerprintMenu: String { localized("inspector.copy_fingerprint_menu", "Copy Fingerprint") }
        public static var deleteKeyMenu: String { localized("inspector.delete_key_menu", "Delete Key…") }

        // Public Identity Section
        public static var publicIdentitySection: String { localized("inspector.public_identity_section", "PUBLIC IDENTITY") }
        public static var ageRecipientDescription: String { localized("inspector.age_recipient_description", "Recipient for age and agenix encryption") }
        public static var copyRecipientButton: String { localized("inspector.copy_recipient_button", "Copy Recipient") }
        public static var hardwareAgeIncompatible: String { localized("inspector.hardware_age_incompatible", "Hardware key (Secure Enclave / P-256) is incompatible with age & agenix.") }
        public static func algorithmAgeIncompatible(_ algorithm: String) -> String {
            localizedFormat("inspector.algorithm_age_incompatible", "%@ key cannot be used for age / agenix (requires Curve25519).", algorithm)
        }
        public static var openSSHPublicKey: String { localized("inspector.openssh_public_key", "OpenSSH Public Key") }
        public static var openSSHDescription: String { localized("inspector.openssh_description", "For GitHub, GitLab, and ~/.ssh/authorized_keys") }
        public static var copySSHKeyButton: String { localized("inspector.copy_ssh_key_button", "Copy SSH Key") }
        public static var fingerprintVerificationHint: String { localized("inspector.fingerprint_verification_hint", "(Verification hash, not for GitHub)") }
        public static var copyFingerprintHelp: String { localized("inspector.copy_fingerprint_help", "Copy SHA-256 Fingerprint") }

        // Integrations (Used By) Section
        public static var usedBySection: String { localized("inspector.used_by_section", "USED BY") }
        public static var agePluginRegistered: String { localized("inspector.age_plugin_registered", "Registered CLI plugin") }
        public static func agePluginIncompatible(_ algorithm: String) -> String {
            localizedFormat("inspector.age_plugin_incompatible", "Incompatible (%@ not supported by age)", algorithm)
        }
        public static var statusReady: String { localized("inspector.status_ready", "Ready") }
        public static var statusUnsupported: String { localized("inspector.status_unsupported", "Unsupported") }
        public static var agenixWorkflow: String { localized("inspector.agenix_workflow", "NixOS secret workflow") }
        public static var agenixHardwareIncompatible: String { localized("inspector.agenix_hardware_incompatible", "Hardware key incompatible with agenix") }
        public static func agenixAlgorithmIncompatible(_ algorithm: String) -> String {
            localizedFormat("inspector.agenix_algorithm_incompatible", "Incompatible with %@", algorithm)
        }
        public static var statusConfigured: String { localized("inspector.status_configured", "Configured") }
        public static var statusIncompatible: String { localized("inspector.status_incompatible", "Incompatible") }
        public static var statusActive: String { localized("inspector.status_active", "Active") }
        public static var statusOffline: String { localized("inspector.status_offline", "Offline") }

        // Security Section
        public static var securitySection: String { localized("inspector.security_section", "SECURITY") }
        public static var storageLabel: String { localized("inspector.storage_label", "Storage") }
        public static var storageHardwareEnclave: String { localized("inspector.storage_hardware_enclave", "Apple Secure Enclave (Hardware Chip)") }
        public static var storageSoftwareKeychain: String { localized("inspector.storage_software_keychain", "macOS Login Keychain (Software)") }
        public static var sessionCacheLabel: String { localized("inspector.session_cache_label", "Session Cache") }
        public static var sessionCacheHardwarePrompt: String { localized("inspector.session_cache_hardware_prompt", "Disabled (Prompt on each signature)") }
        public static var sessionCacheAlwaysPrompt: String { localized("inspector.session_cache_always_prompt", "Disabled (Always Prompt)") }
        public static func sessionCacheActiveTimeout(_ timeout: String) -> String {
            localizedFormat("inspector.session_cache_active_timeout", "Active (%@)", timeout)
        }
        public static var authenticationLabel: String { localized("inspector.authentication_label", "Authentication") }
        public static var authTouchIdOnlyStrict: String { localized("inspector.auth_touch_id_only_strict", "Touch ID Only (Strict Current Set)") }
        public static var authUserPresence: String { localized("inspector.auth_user_presence", "User Presence (Touch ID / Watch / Password)") }
        public static var authTouchIdProtectedSeed: String { localized("inspector.auth_touch_id_protected_seed", "Touch ID (Protected Seed)") }

        // Session Cache Section
        public static var sessionCacheSection: String { localized("inspector.session_cache_section", "SESSION CACHE") }
        public static var hardwareIsolationStrictTitle: String { localized("inspector.hardware_isolation_strict_title", "Hardware Isolation (Strict Biometrics)") }
        public static var hardwareIsolationPresenceTitle: String { localized("inspector.hardware_isolation_presence_title", "Hardware Isolation (User Presence)") }
        public static var hardwareIsolationStrictDesc: String { localized("inspector.hardware_isolation_strict_desc", "Secure Enclave strictly requires Touch ID matching the current biometric enrollment. Device password fallback is disabled. Changes to enrolled fingerprints will invalidate this key.") }
        public static var hardwareIsolationPresenceDesc: String { localized("inspector.hardware_isolation_presence_desc", "Secure Enclave keys cannot be cached in session memory. Every signature requires explicit Touch ID user presence (password fallback allowed).") }
        public static var cacheTimeoutTitle: String { localized("inspector.cache_timeout_title", "Cache Timeout") }
        public static var cacheTimeoutSubtitle: String { localized("inspector.cache_timeout_subtitle", "Require Touch ID authentication after inactivity") }
        public static var memoryProtectionTitle: String { localized("inspector.memory_protection_title", "Memory Protection") }
        public static var memoryProtectionSubtitle: String { localized("inspector.memory_protection_subtitle", "Locked into non-pageable memory (mlock). Purged on screen lock or sleep.") }

        // Feedback Toasts
        public static var feedbackCopiedRecipient: String { localized("inspector.feedback_copied_recipient", "Copied age recipient to clipboard") }
        public static var feedbackCopiedFingerprint: String { localized("inspector.feedback_copied_fingerprint", "Copied fingerprint to clipboard") }
        public static var feedbackCopiedOpenSSH: String { localized("inspector.feedback_copied_openssh", "Copied OpenSSH public key to clipboard") }
        public static func feedbackLockedKey(_ label: String) -> String {
            localizedFormat("inspector.feedback_locked_key", "Locked '%@'", label)
        }
        public static func feedbackUnlockedKey(_ label: String) -> String {
            localizedFormat("inspector.feedback_unlocked_key", "Unlocked '%@'", label)
        }
    }

    public enum Badges {
        public static var hardware: String { localized("badge.hardware", "Hardware") }
        public static var software: String { localized("badge.software", "Software") }
        public static var gitOnly: String { localized("badge.git_only", "Git Only") }
    }

    public enum AddKeyPopover {
        public static var header: String { localized("add_key_popover.header", "ADD KEY") }
        public static var newKeyTitle: String { localized("add_key_popover.new_key_title", "New Key…") }
        public static var newKeySubtitle: String { localized("add_key_popover.new_key_subtitle", "Generate a new cryptographic identity") }
        public static var importKeyTitle: String { localized("add_key_popover.import_key_title", "Import Key…") }
        public static var importKeySubtitle: String { localized("add_key_popover.import_key_subtitle", "Store an existing private key securely") }
    }

    public enum CreateKey {
        public static var title: String { localized("create_key.title", "Create New Key") }
        public static var subtitle: String { localized("create_key.subtitle", "Select a key type preset. Storage and cryptographic algorithm are configured automatically.") }
        public static var nameLabel: String { localized("create_key.name_label", "Key Name") }
        public static var namePlaceholder: String { localized("create_key.name_placeholder", "Key Name (e.g. github-macbook)") }
        public static var nameExamplePlaceholder: String { localized("create_key.name_placeholder", "e.g. Personal age, Work GitHub, staging-server") }
        public static var typeLabel: String { localized("create_key.type_label", "Key Type") }
        public static var biometricPolicyLabel: String { localized("create_key.biometric_policy_label", "Biometric Authentication Policy") }
        public static var biometricWarning: String { localized("create_key.biometric_warning", "Warning: Adding or removing any fingerprint in macOS Touch ID settings will permanently invalidate this key.") }
        public static var purposeLabel: String { localized("create_key.purpose_label", "Key Purpose & Scope") }
        public static var generateButton: String { localized("create_key.generate_button", "Generate Key") }

        public static var softwareTitle: String { localized("create_key.software_title", "Software Key (Ed25519)") }
        public static var softwareBadge: String { localized("create_key.software_badge", "KEYCHAIN") }
        public static var softwareSubtitle: String { localized("create_key.software_subtitle", "Standard Edwards-curve key. Supported by age/agenix, SSH, and Git commit signing, with session TTL memory caching.") }

        public static var hardwareTitle: String { localized("create_key.hardware_title", "Hardware Key (Secure Enclave)") }
        public static var hardwareBadge: String { localized("create_key.hardware_badge", "APPLE SILICON") }
        public static var hardwareSubtitle: String { localized("create_key.hardware_subtitle", "Hardware-bound NIST P-256 key isolated inside the Apple Silicon chip. Private key never leaves hardware. Always prompts Touch ID per operation.") }
        public static var enclaveUnavailable: String { localized("create_key.enclave_unavailable", "Apple Secure Enclave is not available on this device.") }
        public static var tagSSH: String { localized("create_key.tag_ssh", "SSH") }
        public static var tagGitSigning: String { localized("create_key.tag_git_signing", "Git Signing") }
        public static var tagAge: String { localized("create_key.tag_age", "age / agenix") }
        public static var tagAgeIncompatible: String { localized("create_key.tag_age_incompatible", "Incompatible with age") }
    }

    public enum ImportKey {
        public static var title: String { localized("import_key.title", "Import Existing Key") }
        public static var subtitle: String { localized("import_key.subtitle", "Import a raw 32-byte Ed25519 private seed into the secure macOS Keychain.") }
        public static var nameLabel: String { localized("import_key.name_label", "Key Name / Label") }
        public static var namePlaceholder: String { localized("import_key.name_placeholder", "e.g. Work SSH, Legacy Server, backup_identity") }
        public static var seedLabel: String { localized("import_key.seed_label", "32-Byte Raw Seed (Hex)") }
        public static var seedHint: String { localized("import_key.seed_hint", "64 hex characters") }
        public static var seedPlaceholder: String { localized("import_key.seed_placeholder", "Paste 64-character hexadecimal seed...") }
        public static var seedValid: String { localized("import_key.seed_valid", "Valid Ed25519 Seed Detected") }
        public static var seedWaiting: String { localized("import_key.seed_waiting", "Waiting for valid 64-char hex seed...") }
        public static var seedCompatibility: String { localized("import_key.seed_compatibility", "Compatible with OpenSSH (ssh-ed25519) and age/agenix encryption") }
        public static var storageTitle: String { localized("import_key.storage_title", "Destination: Login Keychain") }
        public static var storageSubtitle: String { localized("import_key.storage_subtitle", "Guarded by macOS Keychain access control and biometric authentication.") }
        public static var button: String { localized("import_key.button", "Import Key") }
        public static var errorInvalidInput: String { localized("import_key.error_invalid_input", "Please enter a valid label and 64-character hex seed.") }
    }

    public enum BiometricPolicyStrings {
        public static var userPresenceTitle: String { localized("biometric_policy.user_presence_title", "User Presence") }
        public static var userPresenceSubtitle: String { localized("biometric_policy.user_presence_subtitle", "Touch ID, Apple Watch, or device password fallback") }
        public static var currentSetTitle: String { localized("biometric_policy.current_set_title", "Strict Biometrics") }
        public static var currentSetSubtitle: String { localized("biometric_policy.current_set_subtitle", "Touch ID only. Invalidated if system fingerprints change") }
    }

    public enum KeyPurposeStrings {
        public static var generalTitle: String { localized("key_purpose.general_title", "General (SSH & Git)") }
        public static var generalSubtitle: String { localized("key_purpose.general_subtitle", "Available for SSH login and Git commit/tag signing") }
        public static var gitSigningOnlyTitle: String { localized("key_purpose.git_signing_only_title", "Git Signing Only") }
        public static var gitSigningOnlySubtitle: String { localized("key_purpose.git_signing_only_subtitle", "Restricted strictly to Git commits. Hidden from SSH login") }
    }

    public enum Prompt {
        public static func sshAuthentication(keyLabel: String) -> String {
            localizedFormat("prompt.ssh_auth", "use \u{201c}%@\u{201d} for SSH authentication", keyLabel)
        }
        public static func sshAuthentication(keyLabel: String, requester: String) -> String {
            localizedFormat("prompt.ssh_auth_requester", "use \u{201c}%1$@\u{201d} for SSH authentication (requested by %2$@)", keyLabel, requester)
        }
        public static func dataSigning(keyLabel: String, requester: String) -> String {
            localizedFormat("prompt.sign_data_requester", "sign data requested by %2$@ with \u{201c}%1$@\u{201d}", keyLabel, requester)
        }
        public static func gitCommitSigning(keyLabel: String, requester: String) -> String {
            localizedFormat("prompt.git_commit_requester", "sign a Git commit with \u{201c}%1$@\u{201d} (requested by %2$@)", keyLabel, requester)
        }
        public static func gitCommitSigning(keyLabel: String) -> String {
            localizedFormat("prompt.git_commit", "sign a Git commit with \u{201c}%@\u{201d}", keyLabel)
        }
        public static func gitSigningSession(keyLabel: String) -> String {
            localizedFormat("prompt.git_session", "authorize a 5-minute Git signing session with \u{201c}%@\u{201d}", keyLabel)
        }
    }

    public enum Settings {
        public static var windowTitle: String { localized("settings.window_title", "Settings") }
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

    public enum App {
        public static var unsupportedTitle: String { localized("app.unsupported_title", "Clavis cannot run on this Mac") }
        public static var unsupportedMessage: String { localized("app.unsupported_message", "Clavis requires a Mac with Secure Enclave support.") }
    }

    public enum Auth {
        public static var errorTimedOut: String { localized("auth.error_timed_out", "User authentication timed out") }
        public static var errorRejected: String { localized("auth.error_rejected", "User authentication failed or was cancelled") }
    }
}
