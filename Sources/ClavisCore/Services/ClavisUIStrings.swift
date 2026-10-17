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
        public static var retry: String { localized("common.retry", "Retry") }
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
        public static var noKeysHint: String { localized("menubar.no_keys_hint", "Create an SSH key to start") }
        public static func showAllKeys(count: Int) -> String {
            localizedFormat("menubar.show_all_keys", "Show all %d keys…", count)
        }
        public static var showAllKeysSimple: String { localized("menubar.show_all_keys_simple", "Show all keys…") }
        public static var preferences: String { localized("menubar.preferences", "Preferences...") }
        public static var settings: String { localized("menubar.settings", "Settings…") }
        public static var history: String { localized("menubar.history", "History…") }
        public static var newKey: String { localized("menubar.new_key", "New Key…") }
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
        public static var lockAllKeysHelp: String { localized("key_list.lock_all_keys_help", "Lock All Keys") }
        public static var noUnlockedKeysHelp: String { localized("key_list.no_unlocked_keys_help", "No Unlocked Keys") }
        public static var allCachedKeysLocked: String { localized("key_list.all_cached_keys_locked", "All cached keys locked.") }
        public static var settingsHelp: String { localized("key_list.settings_help", "Settings (Auto Start, Timeout, Nix)") }
        public static var searchHelp: String { localized("key_list.search_help", "Search keys (⌘F)") }
        public static var addKeyHelp: String { localized("key_list.add_key_help", "Create New Key (⌘N)") }
        public static var onboardingTitle: String { localized("key_list.onboarding_title", "Welcome to Clavis") }
        public static var onboardingSubtitle: String { localized("key_list.onboarding_subtitle", "Generate your first hardware-bound SSH key to get started.") }
        public static var onboardingSshConfigTitle: String { localized("key_list.onboarding_ssh_config_title", "SSH Configuration (~/.ssh/config)") }
        public static var onboardingGitConfigTitle: String { localized("key_list.onboarding_git_config_title", "Git Commit Signing Setup") }
        public static var onboardingEnvVarTitle: String { localized("key_list.onboarding_env_var_title", "Terminal Environment Variable") }
        public static var contextMenuCopyPublicKey: String { localized("key_list.context_menu_copy_public_key", "Copy Public Key") }
        public static var contextMenuCopyFingerprint: String { localized("key_list.context_menu_copy_fingerprint", "Copy Fingerprint") }
        public static var contextMenuDeleteKey: String { localized("key_list.context_menu_delete_key", "Delete Key…") }
        public static var filterAll: String { localized("key_list.filter_all", "All") }
        public static var filterPersonal: String { localized("key_list.filter_personal", "Personal") }
        public static var filterAgent: String { localized("key_list.filter_agent", "Agent") }
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
        public static var deleteKey: String { localized("inspector.delete_key", "Delete Key") }

        public static var hardwareIsolated: String { localized("inspector.hardware_isolated", "Hardware Isolated · Touch ID per operation") }
        public static var lockedTouchIdRequired: String { localized("inspector.locked_touch_id_required", "Touch ID required to sign") }

        public static var deleteAlertTitle: String { localized("inspector.delete_alert_title", "Delete Key") }
        public static func deleteAlertMessage(label: String) -> String {
            localizedFormat("inspector.delete_alert_message", "Are you sure you want to delete '%@'? This action cannot be undone.", label)
        }
        public static func deleteAlertMessage(label: String, fingerprint: String) -> String {
            localizedFormat("inspector.delete_alert_message_with_fingerprint", "Are you sure you want to delete '%1$@' (%2$@)? This action cannot be undone.", label, fingerprint)
        }

        public static var copyDeployKey: String { KeyDetail.copyDeployKey }
        public static var changePurpose: String { KeyDetail.changePurpose }
        public static var changeKind: String { changePurpose }
        public static var changePurposeConfirm: String { KeyDetail.changePurposeConfirm }
        public static var changeKindConfirm: String { changePurposeConfirm }

        // Header & Context Menu
        public static func keySubtitle(algorithm: String, isHardware: Bool) -> String {
            let typeName = isHardware ? localized("inspector.badge_hardware", "Hardware") : localized("inspector.badge_software", "Software")
            return localizedFormat("inspector.key_subtitle", "%@ · %@ Key", algorithm, typeName)
        }
        public static var alwaysPromptBadge: String { localized("inspector.always_prompt_badge", "Always Prompt") }
        public static var copyOpenSSHKeyMenu: String { localized("inspector.copy_openssh_key_menu", "Copy OpenSSH Key") }
        public static var copyFingerprintMenu: String { localized("inspector.copy_fingerprint_menu", "Copy Fingerprint") }
        public static var deleteKeyMenu: String { localized("inspector.delete_key_menu", "Delete Key…") }

        // Public Identity Section
        public static var publicIdentitySection: String { localized("inspector.public_identity_section", "PUBLIC IDENTITY") }
        public static var openSSHPublicKey: String { localized("inspector.openssh_public_key", "OpenSSH Public Key") }
        public static var openSSHDescription: String { localized("inspector.openssh_description", "For GitHub, GitLab, and ~/.ssh/authorized_keys") }
        public static var copySSHKeyButton: String { localized("inspector.copy_ssh_key_button", "Copy SSH Key") }
        public static var fingerprintVerificationHint: String { localized("inspector.fingerprint_verification_hint", "(Verification hash, not for GitHub)") }
        public static var copyFingerprintHelp: String { localized("inspector.copy_fingerprint_help", "Copy SHA-256 Fingerprint") }

        // Integrations (Used By) Section
        public static var usedBySection: String { localized("inspector.used_by_section", "USED BY") }
        public static var statusReady: String { localized("inspector.status_ready", "Ready") }
        public static var statusUnsupported: String { localized("inspector.status_unsupported", "Unsupported") }
        public static var statusConfigured: String { localized("inspector.status_configured", "Configured") }
        public static var statusIncompatible: String { localized("inspector.status_incompatible", "Incompatible") }
        public static var statusActive: String { localized("inspector.status_active", "Active") }
        public static var statusOffline: String { localized("inspector.status_offline", "Offline") }

        // Security Section
        public static var securitySection: String { localized("inspector.security_section", "SECURITY") }
        public static var storageLabel: String { localized("inspector.storage_label", "Storage") }
        public static var storageHardwareEnclave: String { localized("inspector.storage_hardware_enclave", "Apple Secure Enclave (Hardware Chip)") }
        public static var authenticationLabel: String { localized("inspector.authentication_label", "Authentication") }
        public static var authTouchIdOnlyStrict: String { localized("inspector.auth_touch_id_only_strict", "Touch ID Only (Strict Current Set)") }
        public static var authUserPresence: String { localized("inspector.auth_user_presence", "User Presence (Touch ID / Watch / Password)") }
        public static var authTouchIdProtectedSeed: String { localized("inspector.auth_touch_id_protected_seed", "Touch ID (Protected Seed)") }

        // Dynamic Security Posture & Socket
        public static var postureGeneral: String { localized("inspector.posture_general", "Prompts Touch ID for each SSH authentication or Git signing request.") }
        public static var postureGitSigningOnly: String { localized("inspector.posture_git_signing_only", "Prompts Touch ID once to begin a 5-minute Git signing session. Blocked from SSH login.") }
        public static var postureAgent: String { localized("inspector.posture_agent", "Controlled by agent policy. Signs automatically or prompts based on session rules.") }
        public static var socketStatusActive: String { localized("inspector.socket_status_active", "Active") }
        public static var socketStatusOffline: String { localized("inspector.socket_status_offline", "Offline") }

        // Change Key Purpose
        public static var changeKeyPurpose: String { localized("inspector.change_key_purpose", "Change Key Purpose…") }
        public static var changeKeyPurposeTitle: String { localized("inspector.change_key_purpose_title", "Change Key Purpose") }
        public static func changeKeyPurposeMessage(label: String, purpose: String) -> String {
            localizedFormat("inspector.change_key_purpose_message", "Are you sure you want to change the purpose of '%1$@' to %2$@? Confirmation with Touch ID is required.", label, purpose)
        }

        // Active Git Signing Grace Session
        public static var activeGitSessionSection: String { localized("inspector.active_git_session_section", "ACTIVE GIT SIGNING SESSION") }
        public static var revokeGitSession: String { localized("inspector.revoke_git_session", "Revoke Session") }
        public static var revokeGitSessionButton: String { localized("inspector.revoke_git_session_button", "Revoke") }
        public static func gitSessionOperationsLeft(_ count: Int) -> String {
            localizedFormat("inspector.git_session_operations_left", "%d operations remaining", count)
        }

        // Hardware Isolation
        public static var hardwareIsolationStrictTitle: String { localized("inspector.hardware_isolation_strict_title", "Hardware Isolation (Strict Biometrics)") }
        public static var hardwareIsolationPresenceTitle: String { localized("inspector.hardware_isolation_presence_title", "Hardware Isolation (User Presence)") }
        public static var hardwareIsolationStrictDesc: String { localized("inspector.hardware_isolation_strict_desc", "Secure Enclave strictly requires Touch ID matching the current biometric enrollment. Device password fallback is disabled. Changes to enrolled fingerprints will invalidate this key.") }
        public static var hardwareIsolationPresenceDesc: String { localized("inspector.hardware_isolation_presence_desc", "Secure Enclave keys cannot be cached in session memory. Every signature requires explicit Touch ID user presence (password fallback allowed).") }

        // Feedback Toasts
        public static var feedbackCopiedFingerprint: String { localized("inspector.feedback_copied_fingerprint", "Copied fingerprint to clipboard") }
        public static var feedbackCopiedOpenSSH: String { localized("inspector.feedback_copied_openssh", "Copied OpenSSH public key to clipboard") }
        public static func feedbackLockedKey(_ label: String) -> String {
            localizedFormat("inspector.feedback_locked_key", "Locked '%@'", label)
        }
        public static var feedbackChangedPurposeToAgent: String {
            localized("inspector.feedback_changed_purpose_agent", "Changed purpose to Agent")
        }
        public static var feedbackChangedPurposeToGeneral: String {
            localized("inspector.feedback_changed_purpose_general", "Changed purpose to General")
        }
        public static func feedbackChangedPurpose(to target: KeyPurpose) -> String {
            switch target {
            case .agent:
                return feedbackChangedPurposeToAgent
            case .general, .gitSigningOnly:
                return feedbackChangedPurposeToGeneral
            }
        }

        // Destructive Section & Footprint Hint
        public static func deleteKeyDescription(label: String, fingerprint: String) -> String {
            localizedFormat("inspector.delete_key_description", "Permanently remove '%1$@' (%2$@) from the Secure Enclave.", label, fingerprint)
        }

        // Socket Display Names
        public static var socketNameSSHAgent: String {
            localized("inspector.socket_name_ssh_agent", "ssh-agent socket")
        }
        public static var socketNameAgent: String {
            localized("inspector.socket_name_agent", "agent socket")
        }

        // Security Badges
        public static var badgeSilent: String { localized("inspector.badge_silent", "Silent") }
        public static var badgeNotify: String { localized("inspector.badge_notify", "Notify") }
        public static var badgeGraceActive: String { localized("inspector.badge_grace_active", "Grace Active") }

        // Dynamic Security Subtitles
        public static var subtitleGitGraceActive: String {
            localized("inspector.subtitle_git_grace_active", "Hardware Isolated · Git signing grace active")
        }
        public static var subtitleAgentSilent: String {
            localized("inspector.subtitle_agent_silent", "Hardware Isolated · Silent agent lease")
        }
        public static var subtitleAgentNotify: String {
            localized("inspector.subtitle_agent_notify", "Hardware Isolated · Agent lease with notification")
        }
        public static var subtitleAgentAsk: String {
            localized("inspector.subtitle_agent_ask", "Hardware Isolated · Touch ID prompt per agent signature")
        }
        public static var subtitleGitSigningOnly: String {
            localized("inspector.subtitle_git_signing_only", "Hardware Isolated · Git commit signing only")
        }

        // Security Posture Footnotes & Titles
        public static var postureAgentTitle: String {
            localized("inspector.posture_agent_title", "Hardware Isolation (Agent Policy)")
        }
        public static func postureAgentSilentDesc(lease: String) -> String {
            localizedFormat("inspector.posture_agent_silent_desc", "Agent sessions operate silently without prompts for up to %@ once authorized. Private key material remains hardware-bound in the Apple Secure Enclave.", lease)
        }
        public static func postureAgentNotifyDesc(lease: String) -> String {
            localizedFormat("inspector.posture_agent_notify_desc", "Agent sessions post a notification on each signature without prompting for up to %@. Private key material remains hardware-bound in the Apple Secure Enclave.", lease)
        }
        public static var postureAgentAskDesc: String {
            localized("inspector.posture_agent_ask_desc", "Every agent signature requires explicit Touch ID user confirmation. Private key material remains hardware-bound in the Apple Secure Enclave.")
        }
        public static var postureGitSigningOnlyTitle: String {
            localized("inspector.posture_git_signing_only_title", "Hardware Isolation (Git Signing Only)")
        }
        public static var postureGitSigningOnlyDesc: String {
            localized("inspector.posture_git_signing_only_desc", "Restricted strictly to local Git commit and tag signing. Forwarded agent requests are blocked. Every signature requires Touch ID per operation (optional 5-minute process-scoped Git signing grace window).")
        }
        public static var postureGitGraceActiveSuffix: String {
            localized("inspector.posture_git_grace_active_suffix", " A 5-minute Git signing grace session is currently active for this key.")
        }
        public static var postureGeneralStrictDesc: String {
            localized("inspector.posture_general_strict_desc", "Secure Enclave strictly requires Touch ID matching current biometric enrollment. Every signature requires explicit Touch ID per operation (optional 5-minute process-scoped Git signing grace window). Device password fallback is disabled.")
        }
        public static var postureGeneralPresenceDesc: String {
            localized("inspector.posture_general_presence_desc", "Signatures require Touch ID user presence per operation (optional 5-minute process-scoped Git signing grace window). Keys cannot be cached in general session memory.")
        }
    }

    public enum Badges {
        public static var hardware: String { localized("badge.hardware", "Hardware") }
        public static var software: String { localized("badge.software", "Software") }
        public static var gitOnly: String { localized("badge.git_only", "Git Only") }
        public static var agent: String { localized("badge.agent", "Agent") }
    }

    public enum AddKeyPopover {
        public static var header: String { localized("add_key_popover.header", "ADD KEY") }
        public static var newKeyTitle: String { localized("add_key_popover.new_key_title", "New Key…") }
        public static var newKeySubtitle: String { localized("add_key_popover.new_key_subtitle", "Generate a new cryptographic identity") }
    }

    public enum CreateKey {
        public static var title: String { localized("create_key.title", "Create New Key") }
        public static var subtitle: String { localized("create_key.subtitle", "Select a key type preset. Storage and cryptographic algorithm are configured automatically.") }
        public static var nameLabel: String { localized("create_key.name_label", "Key Name") }
        public static var namePlaceholder: String { localized("create_key.name_placeholder", "Key Name (e.g. github-macbook)") }
        public static var nameExamplePlaceholder: String { localized("create_key.name_placeholder", "e.g. Work GitHub, staging-server") }
        public static var typeLabel: String { localized("create_key.type_label", "Key Type") }
        public static var biometricPolicyLabel: String { localized("create_key.biometric_policy_label", "Biometric Authentication Policy") }
        public static var biometricWarning: String { localized("create_key.biometric_warning", "Warning: Adding or removing any fingerprint in macOS Touch ID settings will permanently invalidate this key.") }
        public static var purposeLabel: String { localized("create_key.purpose_label", "Key Purpose & Scope") }
        public static var generateButton: String { localized("create_key.generate_button", "Generate Key") }

        public static var hardwareTitle: String { localized("create_key.hardware_title", "Hardware Key (Secure Enclave)") }
        public static var hardwareBadge: String { localized("create_key.hardware_badge", "APPLE SILICON") }
        public static var hardwareSubtitle: String { localized("create_key.hardware_subtitle", "Hardware-bound NIST P-256 key isolated inside the Apple Silicon chip. Private key never leaves hardware. Always prompts Touch ID per operation.") }
        public static var hardwareEnclaveCardTitle: String { localized("create_key.hardware_enclave_card_title", "Apple Secure Enclave") }
        public static var hardwareEnclaveCardSubtitle: String { localized("create_key.hardware_enclave_card_subtitle", "Hardware-bound NIST P-256 identity protected by biometric authentication.") }
        public static var enclaveUnavailable: String { localized("create_key.enclave_unavailable", "Apple Secure Enclave is not available on this device.") }
        public static var tagSSH: String { localized("create_key.tag_ssh", "SSH") }
        public static var tagGitSigning: String { localized("create_key.tag_git_signing", "Git Signing") }
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
        public static var agentTitle: String { localized("key_purpose.agent_title", "Agent") }
        public static var agentSubtitle: String { localized("key_purpose.agent_subtitle", "Only usable by agents you start through Clavis. Never offered to your terminal.") }
    }

    public enum KeyDetail {
        public static var copyDeployKey: String { localized("key_detail.copy_deploy_key", "Copy Deploy Key") }
        public static var changePurpose: String { localized("key_detail.change_kind", "Change Purpose…") }
        public static var changeKind: String { changePurpose }
        public static var changePurposeConfirm: String { localized("key_detail.change_kind_confirm", "Change Purpose") }
        public static var changeKindConfirm: String { changePurposeConfirm }
        public static func changePurposeAlertMessage(label: String, newPurpose: KeyPurpose) -> String {
            localizedFormat("key_detail.change_kind_message", "Are you sure you want to change the purpose of key '%1$@' to %2$@? This requires confirmation with user presence.", label, newPurpose.title)
        }
        public static func changeKindAlertMessage(label: String, newPurpose: KeyPurpose) -> String {
            changePurposeAlertMessage(label: label, newPurpose: newPurpose)
        }
    }

    public enum Prompt {
        public static func sshAuthentication(keyLabel: String) -> String {
            localizedFormat("prompt.ssh_auth", "use \u{201c}%@\u{201d} for SSH authentication", keyLabel)
        }
        public static func sshAuthentication(keyLabel: String, requester: String) -> String {
            localizedFormat("prompt.ssh_auth_requester", "use \u{201c}%1$@\u{201d} for SSH authentication (requested by %2$@)", keyLabel, requester)
        }
        /// `ssh -A` presents the local `/usr/bin/ssh` as the peer, so the dialog cannot name the remote host.
        public static func sshAuthenticationFromForwardedAgent(keyLabel: String, requester: String) -> String {
            localizedFormat(
                "prompt.ssh_auth_forwarded_agent",
                "use \u{201c}%1$@\u{201d} for SSH authentication (requested by %2$@). This request may come from a forwarded agent; the remote host is not visible",
                keyLabel,
                requester
            )
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

        public static var vaultSection: String { localized("settings.vault_section", "VAULT INTEGRITY") }
        public static var vaultHealthy: String { localized("settings.vault_healthy", "Hardware vault cache is synchronized and healthy.") }
        public static var vaultDesyncWarning: String { localized("settings.vault_desync_warning", "Vault desynchronization detected") }
        public static func vaultDesyncDetails(_ count: Int) -> String {
            localizedFormat("settings.vault_desync_details", "%d anomalies detected between keychain and public key store.", count)
        }
        public static var vaultRepairButton: String { localized("settings.vault_repair_button", "Repair Vault") }
        public static var vaultRepaired: String { localized("settings.vault_repaired", "Vault repaired successfully.") }
        public static var aboutSection: String { localized("settings.about_section", "ABOUT CLAVIS") }
        public static var versionLabel: String { localized("settings.version_label", "Version") }
        public static var commitShaLabel: String { localized("settings.commit_sha_label", "Commit SHA") }
        public static var codeSigningLabel: String { localized("settings.code_signing_label", "Code Signing Identity") }
        public static var daemonParityLabel: String { localized("settings.daemon_parity_label", "Daemon Version Parity") }
        public static var daemonParityMatch: String { localized("settings.daemon_parity_match", "Matching") }
        public static var daemonParityMismatch: String { localized("settings.daemon_parity_mismatch", "Version mismatch") }
    }

    public enum App {
        public static var unsupportedTitle: String { localized("app.unsupported_title", "Clavis cannot run on this Mac") }
        public static var unsupportedMessage: String { localized("app.unsupported_message", "Clavis requires a Mac with Secure Enclave support.") }
    }

    public enum Auth {
        public static var errorTimedOut: String { localized("auth.error_timed_out", "User authentication timed out") }
        public static var errorRejected: String { localized("auth.error_rejected", "User authentication failed or was cancelled") }
    }

    public enum History {
        public static var windowTitle: String { localized("history.window_title", "Signing History") }
        public static var showHistory: String { localized("history.show_history", "Show History") }
        public static var retry: String { ClavisUIStrings.Common.retry }
        public static var refresh: String { localized("history.refresh", "Refresh") }
        public static var refreshHelp: String { localized("history.refresh_help", "Refresh History (⌘R)") }

        // MARK: Search tokens (story 009)
        public static var searchField: String { localized("history.search_field_placeholder", "Search history") }
        public static var searchFieldAccessibility: String { localized("history.search_field_accessibility", "Search history") }
        public static var addFilter: String { localized("history.add_filter", "Filter") }
        public static var addFilterAccessibility: String { localized("history.add_filter_accessibility", "Add filter") }
        public static var filterBy: String { localized("history.filter_by", "Filter by") }
        public static func matchAny(_ value: String) -> String {
            localizedFormat("history.match_any", "Match any selected %@", value)
        }
        public static var noMatchingValues: String { localized("history.no_matching_values", "No matching values. You can continue typing.") }
        public static var suggestionsAccessibility: String { localized("history.suggestions_accessibility", "Filter suggestions") }
        public static var clearFilters: String { localized("history.clear_filters", "Clear Filters") }
        public static var back: String { localized("history.back", "Back") }
        public static var dateRange: String { localized("history.date_range", "Date range") }
        public static var sortOrder: String { localized("history.sort_order", "Sort order") }
        public static var dateFrom: String { localized("history.date_from", "From") }
        public static var dateTo: String { localized("history.date_to", "To") }
        public static var newestFirst: String { localized("history.newest_first", "Newest first") }
        public static var oldestFirst: String { localized("history.oldest_first", "Oldest first") }
        public static func removeBadge(_ value: String) -> String {
            localizedFormat("history.remove_badge", "Remove %@", value)
        }
        public static func clearDate(_ value: String) -> String {
            localizedFormat("history.clear_date", "Clear %@ date", value)
        }
        public static func matchingCount(_ value: String) -> String {
            localizedFormat("history.matching_count", "%@ matching events", value)
        }
        public static var matchingCountOne: String { localized("history.matching_count_one", "1 matching event") }
        public static func matchingSoFar(_ value: String) -> String {
            localizedFormat("history.matching_so_far", "%@ matching events so far", value)
        }
        public static var matchingSoFarOne: String { localized("history.matching_so_far_one", "1 matching event so far") }
        public static func unreadableCount(_ value: String) -> String {
            localizedFormat("history.unreadable_count", "%@ unreadable", value)
        }
        public static var unreadableHelp: String { localized("history.unreadable_help", "These events have encrypted details that can't be read right now, so they can't match host, process or text filters.") }
        public static var loadingEvents: String { localized("history.loading_events", "Loading events…") }
        public static func sessionBanner(_ value: String) -> String {
            localizedFormat("history.session_banner", "Session: %@", value)
        }
        public static var noEventsYet: String { localized("history.no_events_yet", "No events yet") }
        public static var noMatchingEvents: String { localized("history.no_matching_events", "No matching events") }
        public static var tryRemovingFilter: String { localized("history.try_removing_filter", "Try removing a filter or widening the dates.") }
        public static var loadingMore: String { localized("history.loading_more", "Loading more events…") }
        public static var endOfHistory: String { localized("history.end_of_history", "End of history") }
        public static var copySessionID: String { localized("history.copy_session_id", "Copy Session ID") }
        public static var copyFingerprint: String { localized("history.copy_fingerprint", "Copy Fingerprint") }
        public static var filterByKey: String { localized("history.filter_by_key", "Filter by this Key") }
        public static var copyHost: String { localized("history.copy_host", "Copy Host") }
        public static var filterByHost: String { localized("history.filter_by_host", "Filter by this Host") }
        public static var copyProcessPath: String { localized("history.copy_process_path", "Copy Process Path") }
        public static var filterByProcess: String { localized("history.filter_by_process", "Filter by this Process") }
        public static var copyFullRow: String { localized("history.copy_full_row", "Copy Full Row Details") }
        public static func filterByHostNamed(_ value: String) -> String {
            localizedFormat("history.filter_by_host_named", "Filter by host %@", value)
        }
        public static var searchPlaceholder: String { localized("history.search_placeholder", "Search by key, host, or process...") }
        public static var filterHost: String { localized("history.filter_host", "Host") }
        public static var filterProcess: String { localized("history.filter_process", "Process") }
        public static var loadMore: String { localized("history.load_more", "Load More Events") }
        public static var loading: String { localized("history.loading", "Loading…") }
        public static func showingEvents(count: Int, total: Int) -> String {
            localizedFormat("history.showing_events", "Showing %1$d of %2$d events", count, total)
        }
        public static var eventDetails: String { localized("history.event_details", "Event Details") }
        public static var processChain: String { localized("history.process_chain", "Process Chain") }
        public static var processId: String { localized("history.process_id", "Process ID") }
        public static var recordHash: String { localized("history.record_hash", "Record SHA-256 Hash") }
        public static var sessionId: String { localized("history.session_id", "Session ID") }
        public static var copyDetails: String { localized("history.copy_details", "Copy Event Details") }
        public static var copyHash: String { localized("history.copy_hash", "Copy SHA-256 Hash") }
        public static var filterAllKeys: String { localized("history.filter_all_keys", "All Keys") }
        public static var filterAllKinds: String { localized("history.filter_all_kinds", "All Types") }
        public static var filterKindPersonal: String { localized("history.filter_kind_personal", "Personal") }
        public static var filterKindAgent: String { localized("history.filter_kind_agent", "Agent") }
        public static var filterAllResult: String { localized("history.filter_all_results", "All Results") }
        public static var filterRangeHour: String { localized("history.filter_range_hour", "Last Hour") }
        public static var filterRangeDay: String { localized("history.filter_range_day", "Last 24 Hours") }
        public static var filterRangeWeek: String { localized("history.filter_range_week", "Last 7 Days") }
        public static var filterRangeAll: String { localized("history.filter_range_all", "All Time") }
        public static var resultAllowed: String { localized("history.result_allowed", "Allowed") }
        public static var resultDenied: String { localized("history.result_denied", "Denied") }
        public static var resultCancelled: String { localized("history.result_cancelled", "Cancelled") }
        public static var resultFailed: String { localized("history.result_failed", "Failed") }
        public static var resultInfo: String { localized("history.result_info", "Info") }
        public static var empty: String { localized("history.empty", "No audit events recorded") }
        public static var export: String { localized("history.export", "Export…") }
        public static var unreadable: String { localized("history.unreadable", "Unreadable (history key changed)") }
        public static var omitted: String { localized("history.omitted", "—") }
        public static var omittedTooltip: String { localized("history.omitted_tooltip", "Details were not recorded") }
        public static func suppressedCount(_ count: Int) -> String {
            localizedFormat("history.suppressed_count", "%d similar events suppressed", count)
        }
        public static var checkIntegrity: String { localized("history.check_integrity", "Check Integrity") }
        public static var checkIntegrityTitle: String { localized("history.check_integrity_title", "Audit History Integrity") }
        public static var checkingIntegrity: String { localized("history.checking_integrity", "Checking history integrity…") }
        public static var checkStatusOk: String { localized("history.check_status_ok", "History is intact") }
        public static var checkStatusOkDesc: String { localized("history.check_status_ok_desc", "No missing or altered records detected within the verification window.") }
        public static var checkStatusProblems: String { localized("history.check_status_problems", "Potential tampering detected") }
        public static var checkStatusProblemsDesc: String { localized("history.check_status_problems_desc", "Discrepancies found between local database and system witness records.") }
        public static var checkStatusUnavailable: String { localized("history.check_status_unavailable", "Integrity check unavailable") }
        public static func checkCheckedRows(_ count: Int) -> String {
            localizedFormat("history.check_checked_rows", "Checked rows: %d", count)
        }
        public static func checkMissingRows(_ count: Int) -> String {
            localizedFormat("history.check_missing_rows", "Missing rows: %d", count)
        }
        public static func checkInconsistentRows(_ count: Int) -> String {
            localizedFormat("history.check_inconsistent_rows", "Inconsistent rows: %d", count)
        }
        public static var checkTruncatedTail: String { localized("history.check_truncated_tail", "History tail truncated: Yes") }
        public static var checkProblemsHeader: String { localized("history.check_problems_header", "Detected Problems") }
        public static func checkMissingRowFormat(seq: Int64, witnessedAt: String) -> String {
            localizedFormat("history.check_missing_row_format", "Missing sequence %1$lld (witnessed %2$@)", seq, witnessedAt)
        }
        public static func checkInconsistentRowFormat(seq: Int64) -> String {
            localizedFormat("history.check_inconsistent_row_format", "Inconsistent row sequence %lld", seq)
        }
        public static var checkRetentionExplanation: String {
            localized("history.check_retention_explanation", "Unified log witness records are kept by macOS for up to several days. Verification only covers events within the retention window.")
        }
        public static var checkLearnMore: String { localized("history.check_learn_more", "Learn more") }
        public static func gapBanner(count: Int64) -> String {
            localizedFormat("history.gap_banner", "%lld entries missing (gap detected)", count)
        }
    }

    public enum PanelLock {
        public static var title: String { localized("panel_lock.title", "Clavis is locked") }
        public static var clarification: String { localized("panel_lock.clarification", "Locking the control panel does not disable background SSH authentication or agent signing.") }
        public static var unlock: String { localized("panel_lock.unlock", "Unlock") }
        public static var enterPinToUnlock: String { localized("panel_lock.enter_pin_to_unlock", "Press Return to unlock") }
        public static var unlockMenu: String { localized("panel_lock.unlock_menu", "Unlock Clavis…") }
        public static var reason: String { localized("panel_lock.reason", "unlock Clavis") }
        public static var disableReason: String { localized("panel_lock.disable_reason", "Modify control panel lock settings") }
        public static var settingsSection: String { localized("panel_lock.settings_section", "Control Panel Lock") }
        public static var settingsToggle: String { localized("panel_lock.settings_toggle", "Require authentication to open Clavis") }
        public static var settingsIdle: String { localized("panel_lock.settings_idle", "Lock after inactivity") }
        public static func minutesFormat(_ minutes: Int) -> String {
            localizedFormat("panel_lock.minutes_format", "%d min", minutes)
        }
        public static func agentSessionsCount(_ count: Int) -> String {
            localizedFormat("panel_lock.agent_sessions_count", "%d agent sessions running", count)
        }
    }

    public enum AgentSession {
        public static func approvePrompt(
            tool: String,
            keyLabel: String,
            minutes: Int,
            requester: String? = nil,
            mode: AgentKeyPolicy.Mode? = nil,
            allowedHosts: [AgentAllowedHost] = []
        ) -> String {
            let basename = String(AuditEvent.sanitizedPath((tool as NSString).lastPathComponent).prefix(64))
            guard requester != nil || mode != nil || !allowedHosts.isEmpty else {
                return localizedFormat(
                    "agent_session.approve_prompt",
                    "Start agent session for “%@” with key “%@” for %d minutes",
                    basename,
                    keyLabel,
                    minutes
                )
            }

            let sanitizedFullPath = String(AuditEvent.sanitizedPath(tool).prefix(128))
            let toolDisplay: String
            if tool.contains("/") && sanitizedFullPath != basename {
                toolDisplay = "\(basename) (\(sanitizedFullPath))"
            } else {
                toolDisplay = basename
            }

            var details: [String] = []
            if let mode {
                details.append("mode: \(mode.rawValue)")
            }
            let hostsSummary: String
            if allowedHosts.isEmpty {
                hostsSummary = "any host"
            } else {
                let names = allowedHosts.prefix(3).map { AuditEvent.sanitizedPath($0.name) }.joined(separator: ", ")
                hostsSummary = allowedHosts.count > 3 ? "\(names), +\(allowedHosts.count - 3) more" : names
            }
            if mode != nil || !allowedHosts.isEmpty {
                details.append("hosts: \(hostsSummary)")
            }
            if let requester, !requester.isEmpty {
                details.append("requested by \(requester)")
            }

            let suffix = details.isEmpty ? "" : " (\(details.joined(separator: ", ")))"
            return localizedFormat(
                "agent_session.approve_prompt_detailed",
                "Start agent session for “%1$@” with key “%2$@” for %3$d minutes%4$@",
                toolDisplay,
                keyLabel,
                minutes,
                suffix
            )
        }
        public static var menuSection: String { localized("agent_session.menu_section", "Agent Sessions") }
        public static var end: String { localized("agent_session.end", "End") }
        public static func remainingFormat(minutes: Int) -> String {
            localizedFormat("agent_session.remaining_format", "%d min remaining", minutes)
        }
        public static var historyShowSession: String { localized("agent_session.history_show_session", "Show session") }
        public static var historyEndSession: String { localized("agent_session.history_end_session", "End session") }
        public static var extend: String { localized("agent_session.extend", "Extend…") }
        public static var extend30m: String { localized("agent_session.extend_30m", "+30 min") }
        public static var extend1h: String { localized("agent_session.extend_1h", "+1 hour") }
        public static var extend4h: String { localized("agent_session.extend_4h", "+4 hours") }
        public static var extendPrompt: String { localized("agent_session.extend_prompt", "Extend agent session") }
        public static func extendAuthReason(keyLabel: String, tool: String, minutes: Int, requester: String) -> String {
            let sanitizedTool = String(AuditEvent.sanitizedPath((tool as NSString).lastPathComponent).prefix(64))
            return localizedFormat(
                "agent_session.extend_auth_reason",
                "extend agent session for \u{201c}%1$@\u{201d} with key \u{201c}%2$@\u{201d} by %3$d minutes (requested by %4$@)",
                sanitizedTool,
                keyLabel,
                minutes,
                requester
            )
        }
        public static var askPrompt: String { localized("agent_session.ask_prompt", "Approve agent signature") }
        public static func askPrompt(keyLabel: String, tool: String, requester: String, host: String? = nil) -> String {
            let sanitizedTool = String(AuditEvent.sanitizedPath((tool as NSString).lastPathComponent).prefix(64))
            if let host, !host.isEmpty {
                return localizedFormat(
                    "agent_session.ask_prompt_with_host",
                    "approve agent signature with \u{201c}%1$@\u{201d} for \u{201c}%2$@\u{201d} on %3$@ (requested by %4$@)",
                    keyLabel,
                    sanitizedTool,
                    host,
                    requester
                )
            } else {
                return localizedFormat(
                    "agent_session.ask_prompt_requester",
                    "approve agent signature with \u{201c}%1$@\u{201d} for \u{201c}%2$@\u{201d} (requested by %3$@)",
                    keyLabel,
                    sanitizedTool,
                    requester
                )
            }
        }
        public static var revokeAll: String { localized("agent_session.revoke_all", "Revoke all agent sessions") }
        public static var notificationSignedTitle: String { localized("agent_session.notification_signed_title", "Agent signed") }
        public static var notificationRateLimitedTitle: String { localized("agent_session.notification_rate_limited_title", "Agent rate limited") }
    }

    public enum AgentPolicy {
        public static var sectionTitle: String { localized("agent_policy.section_title", "Agent Session Policy") }
        public static var modeTitle: String { localized("agent_policy.mode_title", "Approval Mode") }
        public static var modeNone: String { localized("agent_policy.mode_none", "None (Silent)") }
        public static var modeNotify: String { localized("agent_policy.mode_notify", "Notify") }
        public static var modeAsk: String { localized("agent_policy.mode_ask", "Ask every time") }
        public static var leaseTitle: String { localized("agent_policy.lease_title", "Session Length") }
        public static var allowedHostsTitle: String { localized("agent_policy.allowed_hosts_title", "Allowed Hosts") }
        public static var allowedHostsAny: String { localized("agent_policy.allowed_hosts_any", "Any host") }
        public static var addHost: String { localized("agent_policy.add_host", "Add host…") }
        public static var addHostButton: String { localized("agent_policy.add_host_button", "Add") }
        public static var hostNotFound: String { localized("agent_policy.host_not_found", "Host not found in known_hosts — connect once with ssh first") }
        public static var rateLimitTitle: String { localized("agent_policy.rate_limit_title", "Rate Limit") }
        public static var burstTitle: String { localized("agent_policy.burst_title", "Burst") }
        public static var refillTitle: String { localized("agent_policy.refill_title", "Refill per minute") }
        public static var saveButton: String { localized("agent_policy.save_button", "Save Policy") }
        public static var savedFeedback: String { localized("agent_policy.saved_feedback", "Policy saved") }
        public static var unsavedChanges: String { localized("agent_policy.unsaved_changes", "Unsaved changes") }
        public static var discardChanges: String { localized("agent_policy.discard_changes", "Discard Changes") }
        public static var notificationPermissionDenied: String { localized("agent_policy.notification_permission_denied", "Notifications are disabled in macOS System Settings. Notification banners will not be displayed.") }
        public static var invalidRateLimit: String { localized("agent_policy.invalid_rate_limit", "Max signatures per minute must be a positive integer greater than 0.") }
        public static var invalidHostPattern: String { localized("agent_policy.invalid_host_pattern", "Invalid host pattern. Enter a valid hostname, IP, or wildcard pattern.") }
        public static var globalMaxLease: String { localized("agent_policy.global_max_lease", "Maximum agent session length") }
        public static var changePrompt: String { localized("agent_policy.change_prompt", "Change agent session policy") }
        public static func authReason(
            keyLabel: String,
            requester: String,
            mode: AgentKeyPolicy.Mode? = nil,
            leaseMinutes: Int? = nil
        ) -> String {
            if let mode, let leaseMinutes {
                return localizedFormat(
                    "agent_policy.auth_reason_detailed",
                    "change agent session policy for \u{201c}%1$@\u{201d} to mode=%2$@, lease=%3$dm (requested by %4$@)",
                    keyLabel,
                    mode.rawValue,
                    leaseMinutes,
                    requester
                )
            } else if let leaseMinutes {
                return localizedFormat(
                    "agent_policy.auth_reason_lease",
                    "change agent session policy for \u{201c}%1$@\u{201d} to maxLease=%2$dm (requested by %3$@)",
                    keyLabel,
                    leaseMinutes,
                    requester
                )
            }
            return localizedFormat(
                "agent_policy.auth_reason",
                "change agent session policy for \u{201c}%1$@\u{201d} (requested by %2$@)",
                keyLabel,
                requester
            )
        }
    }

    public enum PinUnlock {
        public static var pinLabel: String { localized("pin_unlock.pin_label", "PIN") }
        public static var pinPlaceholder: String { localized("pin_unlock.pin_placeholder", "Enter PIN") }
        public static var unlock: String { localized("pin_unlock.unlock", "Unlock") }
        public static var useTouchID: String { localized("pin_unlock.use_touch_id", "Use Touch ID") }
        public static var usePassword: String { localized("pin_unlock.use_password", "Use login password…") }
        public static var wrongPIN: String { localized("pin_unlock.wrong_pin", "Incorrect PIN") }
        public static func waitFormat(_ seconds: Int) -> String {
            localizedFormat("pin_unlock.wait_format", "Try again in %d s", seconds)
        }
        public static var passwordRequired: String { localized("pin_unlock.password_required", "PIN is disabled. Login password required.") }
        public static var historyBanner: String { localized("pin_unlock.history_banner", "Enter PIN to read details") }
        public static var confirmPinPlaceholder: String { localized("pin_unlock.confirm_pin_placeholder", "Confirm PIN") }
        public static var warningOrMode: String { localized("pin_unlock.warning_or_mode", "A PIN is easier to guess than your login password. Anyone who learns it can unlock Clavis and read your history.") }
        public static var resetWarning: String { localized("pin_unlock.reset_warning", "Your existing history will become unreadable.") }
        public static var tooShort: String { localized("pin_unlock.too_short", "PIN must be at least 6 characters.") }
        public static var pinMismatch: String { localized("pin_unlock.pin_mismatch", "PINs do not match.") }
        public static var changePIN: String { localized("pin_unlock.change_pin", "Change PIN…") }
        public static var forgotPIN: String { localized("pin_unlock.forgot_pin", "Forgot PIN…") }
        public static var settingsSection: String { localized("pin_unlock.settings_section", "Unlock Method") }
        public static var modePasswordOrBiometry: String { localized("pin_unlock.mode_password_or_biometry", "Touch ID or password") }
        public static var modeBiometryOrPIN: String { localized("pin_unlock.mode_biometry_or_pin", "Touch ID or PIN") }
        public static var modeBiometryAndPIN: String { localized("pin_unlock.mode_biometry_and_pin", "Touch ID and PIN") }
        public static var setPinTitle: String { localized("pin_unlock.set_pin_title", "Set PIN") }
    }

    public enum Accessibility {
        public static var addKey: String { localized("accessibility.add_key", "Create new SSH key") }
        public static var lockAll: String { localized("accessibility.lock_all", "Lock all active keys") }
        public static var settings: String { localized("accessibility.settings", "Settings") }
        public static var history: String { localized("accessibility.history", "Signing history") }
        public static var statusActive: String { localized("accessibility.status_active", "Status: active") }
        public static var statusOffline: String { localized("accessibility.status_offline", "Status: offline") }
        public static var pinDigit: String { localized("accessibility.pin_digit", "PIN digit entry") }
        public static var copyPublicKey: String { localized("accessibility.copy_public_key", "Copy public key") }
        public static var copyFingerprint: String { localized("accessibility.copy_fingerprint", "Copy SHA-256 fingerprint") }
        public static var agentStatus: String { localized("accessibility.agent_status", "Agent status") }
        public static var moreActions: String { localized("accessibility.more_actions", "More actions") }
        public static var deleteHost: String { localized("accessibility.delete_host", "Remove allowed host") }
        public static var expandDetails: String { localized("accessibility.expand_details", "Expand details") }
        public static var collapseDetails: String { localized("accessibility.collapse_details", "Collapse details") }
        public static var expanded: String { localized("accessibility.expanded", "Expanded") }
        public static var collapsed: String { localized("accessibility.collapsed", "Collapsed") }
        public static var copyProcessInfo: String { localized("accessibility.copy_process_info", "Copy process path and PID") }
        public static func copyItem(label: String) -> String {
            localizedFormat("accessibility.copy_item", "Copy %@", label)
        }
    }
}



