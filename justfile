set shell := ["bash", "-euo", "pipefail", "-c"]

config := env_var_or_default("CONFIG", "release")
version := env_var_or_default("CLAVIS_VERSION", "0.4.5")
build_version := env_var_or_default("CLAVIS_BUILD_VERSION", "1")
keychain := env_var_or_default("CLAVIS_KEYCHAIN", "")
sign_identity := env_var_or_default("CLAVIS_SIGN_IDENTITY", "")
team_id := env_var_or_default("CLAVIS_TEAM_ID", "4G6X3KNZUS")
allow_adhoc := env_var_or_default("CLAVIS_ALLOW_ADHOC_SIGNING", "0")
expected_team_id := env_var_or_default("CLAVIS_EXPECTED_TEAM_ID", "")
app_profile := env_var_or_default("CLAVIS_APP_PROVISION_PROFILE", "")
agent_profile := env_var_or_default("CLAVIS_AGENT_PROVISION_PROFILE", "")
require_provisioning := env_var_or_default("CLAVIS_REQUIRE_PROVISIONING", "0")
auto_provision := env_var_or_default("CLAVIS_AUTO_PROVISION", "1")
# auto: secure (Apple-timestamped) signatures for Developer ID builds, none for local builds.
timestamp_mode := env_var_or_default("CLAVIS_TIMESTAMP", "auto")
# Set to 1 to notarize and staple release artifacts (requires a Developer ID Application identity).
notarize := env_var_or_default("CLAVIS_NOTARIZE", "0")

build_dir := ".build/" + config
app_bundle := build_dir + "/Clavis.app"
resource_bundle := build_dir + "/Clavis_ClavisCore.bundle"
dmg_name := "clavis-macos-arm64.dmg"
archive_name := "clavis-macos-arm64.tar.gz"

# Default target: build, bundle, and sign
default: (sign config)

# Compile binaries with SwiftPM
build config=config:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    if [ ! -f "$sdkroot/SDKSettings.plist" ]; then
        echo "❌ Active Xcode returned an invalid macOS SDK path: $sdkroot" >&2
        exit 1
    fi
    mkdir -p .build && touch .build/.metadata_never_index
    echo "🔨 Building Clavis ({{ config }})..."
    SDKROOT="$sdkroot" swift build -c {{ config }}

# Compile all test targets without running tests
build-tests:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    if [ ! -f "$sdkroot/SDKSettings.plist" ]; then
        echo "❌ Active Xcode returned an invalid macOS SDK path: $sdkroot" >&2
        exit 1
    fi
    mkdir -p .build && touch .build/.metadata_never_index
    echo "🔨 Building test targets..."
    SDKROOT="$sdkroot" swift build --build-tests

# Compile only ClavisCore library
build-core:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    if [ ! -f "$sdkroot/SDKSettings.plist" ]; then
        echo "❌ Active Xcode returned an invalid macOS SDK path: $sdkroot" >&2
        exit 1
    fi
    mkdir -p .build && touch .build/.metadata_never_index
    echo "🔨 Building ClavisCore..."
    SDKROOT="$sdkroot" swift build --target ClavisCore

# Compile only Clavis application executable
build-app:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    if [ ! -f "$sdkroot/SDKSettings.plist" ]; then
        echo "❌ Active Xcode returned an invalid macOS SDK path: $sdkroot" >&2
        exit 1
    fi
    mkdir -p .build && touch .build/.metadata_never_index
    echo "🔨 Building Clavis App..."
    SDKROOT="$sdkroot" swift build --target Clavis

# Assemble Clavis.app bundle with helpers and resources
bundle config=config: (build config)
    #!/usr/bin/env bash
    set -euo pipefail
    build_dir=".build/{{ config }}"
    app_bundle="$build_dir/Clavis.app"
    agent_bundle="$app_bundle/Contents/Helpers/Clavis Agent.app"
    resource_bundle="$build_dir/Clavis_ClavisCore.bundle"
    contents="$app_bundle/Contents"

    if [ ! -d "$resource_bundle" ]; then
        echo "❌ Missing SwiftPM resource bundle: $resource_bundle" >&2
        exit 1
    fi

    echo "📦 Assembling Clavis.app..."
    rm -rf "$app_bundle"
    mkdir -p "$contents/MacOS" \
             "$contents/Helpers" \
             "$contents/Resources" \
             "$agent_bundle/Contents/MacOS" \
             "$agent_bundle/Contents/Resources"

    cp "$build_dir/Clavis" "$contents/MacOS/Clavis"
    cp "$build_dir/clavis-agent" "$agent_bundle/Contents/MacOS/clavis-agent"
    cp "$build_dir/clavis-cli" "$contents/Helpers/clavis-cli"

    cp packaging/macos/Info.plist "$contents/Info.plist"
    cp packaging/macos/AgentInfo.plist "$agent_bundle/Contents/Info.plist"
    if [ -f packaging/macos/AppIcon.icns ]; then
        cp packaging/macos/AppIcon.icns "$contents/Resources/AppIcon.icns"
        cp packaging/macos/AppIcon.icns "$agent_bundle/Contents/Resources/AppIcon.icns"
    fi
    /usr/bin/plutil -replace CFBundleShortVersionString -string "{{ version }}" "$contents/Info.plist"
    /usr/bin/plutil -replace CFBundleVersion -string "{{ build_version }}" "$contents/Info.plist"
    /usr/bin/plutil -replace CFBundleShortVersionString -string "{{ version }}" "$agent_bundle/Contents/Info.plist"
    /usr/bin/plutil -replace CFBundleVersion -string "{{ build_version }}" "$agent_bundle/Contents/Info.plist"
    /usr/bin/ditto "$resource_bundle" "$contents/Resources/Clavis_ClavisCore.bundle"
    /usr/bin/ditto "$resource_bundle" "$agent_bundle/Contents/Resources/Clavis_ClavisCore.bundle"
    /usr/bin/plutil -lint "$contents/Info.plist"
    /usr/bin/plutil -lint "$agent_bundle/Contents/Info.plist"
    test -d "$agent_bundle/Contents/Resources/Clavis_ClavisCore.bundle"

# Codesign standalone binaries and the .app bundle
sign config=config: (bundle config)
    #!/usr/bin/env bash
    set -euo pipefail
    build_dir=".build/{{ config }}"
    app_bundle="$build_dir/Clavis.app"
    agent_bundle="$app_bundle/Contents/Helpers/Clavis Agent.app"
    keychain="{{ keychain }}"
    entitlements="Entitlements.plist"

    resolved="$(/usr/bin/python3 packaging/macos/resolve-signing-identity.py \
        --keychain "$keychain" \
        --requested "{{ sign_identity }}" \
        --preferred-team-id "{{ team_id }}" \
        --expected-team-id "{{ expected_team_id }}" \
        --notarize "{{ notarize }}" \
        --allow-adhoc "{{ allow_adhoc }}" \
        --timestamp-mode "{{ timestamp_mode }}" \
        --app-profile "{{ app_profile }}" \
        --agent-profile "{{ agent_profile }}" \
        --require-provisioning "{{ require_provisioning }}")"
    eval "$resolved"

    if [ "$PROVISION_MODE" != "data-protection" ] && [ "$SIGN_ARG" != "-" ] && [ -n "$SIGN_TEAM_ID" ] && [[ "$SIGN_CN" == "Apple Development"* ]] && [ "{{ auto_provision }}" = "1" ] && [ -z "{{ app_profile }}" ] && [ -z "{{ agent_profile }}" ]; then
        /usr/bin/python3 packaging/macos/bootstrap-provisioning.py --team-id "$SIGN_TEAM_ID" --quiet-if-unavailable || true
        resolved="$(/usr/bin/python3 packaging/macos/resolve-signing-identity.py \
            --keychain "$keychain" \
            --requested "{{ sign_identity }}" \
            --preferred-team-id "{{ team_id }}" \
            --expected-team-id "{{ expected_team_id }}" \
            --notarize "{{ notarize }}" \
            --allow-adhoc "{{ allow_adhoc }}" \
            --timestamp-mode "{{ timestamp_mode }}" \
            --app-profile "{{ app_profile }}" \
            --agent-profile "{{ agent_profile }}" \
            --require-provisioning "{{ require_provisioning }}")"
        eval "$resolved"
    fi

    echo "🔐 Signing binaries with identity: $SIGN_LABEL ($TIMESTAMP_FLAG)..."

    rm -f "$app_bundle/Contents/embedded.provisionprofile" \
          "$agent_bundle/Contents/embedded.provisionprofile"

    app_ent="$entitlements"
    agent_ent="$entitlements"
    expect_provisioned="0"
    tmp_app_ent=""
    tmp_agent_ent=""

    cleanup_sign_tmp() {
        if [ -n "${tmp_app_ent:-}" ]; then rm -f "$tmp_app_ent"; fi
        if [ -n "${tmp_agent_ent:-}" ]; then rm -f "$tmp_agent_ent"; fi
    }
    trap cleanup_sign_tmp EXIT

    write_provisioned_entitlements() {
        local out_path="$1"
        local app_identifier="$2"
        cat > "$out_path" <<PLIST
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>com.apple.application-identifier</key>
        <string>$app_identifier</string>
        <key>com.apple.developer.team-identifier</key>
        <string>$SIGN_TEAM_ID</string>
        <key>keychain-access-groups</key>
        <array>
            <string>$KEYCHAIN_ACCESS_GROUP</string>
        </array>
    </dict>
    </plist>
    PLIST
        /usr/bin/plutil -lint "$out_path" >/dev/null
    }

    if [ "$PROVISION_MODE" = "data-protection" ]; then
        if [ -z "$SIGN_TEAM_ID" ] || [ -z "$KEYCHAIN_ACCESS_GROUP" ] || [ -z "$APP_PROVISION_PROFILE" ] || [ -z "$AGENT_PROVISION_PROFILE" ]; then
            echo "❌ Incomplete Data Protection provisioning resolution." >&2
            exit 1
        fi
        tmp_app_ent="$(mktemp "${TMPDIR:-/tmp}/clavis-app-entitlements.XXXXXX")"
        tmp_agent_ent="$(mktemp "${TMPDIR:-/tmp}/clavis-agent-entitlements.XXXXXX")"
        app_ent="$tmp_app_ent"
        agent_ent="$tmp_agent_ent"
        expect_provisioned="1"

        write_provisioned_entitlements "$app_ent" "$SIGN_TEAM_ID.com.clavis.app"
        write_provisioned_entitlements "$agent_ent" "$SIGN_TEAM_ID.com.clavis.agent"

        cp "$APP_PROVISION_PROFILE" "$app_bundle/Contents/embedded.provisionprofile"
        cp "$AGENT_PROVISION_PROFILE" "$agent_bundle/Contents/embedded.provisionprofile"
        chmod 0644 "$app_bundle/Contents/embedded.provisionprofile" \
                   "$agent_bundle/Contents/embedded.provisionprofile"
        echo "🛡️  Data Protection Keychain enabled (group: $KEYCHAIN_ACCESS_GROUP)"
    else
        echo "ℹ️  Data Protection provisioning inactive ($PROVISION_MODE); signing without keychain-access-groups."
    fi

    verify_signature_metadata() {
        local target="$1"
        local require_identifier="${2:-1}"
        local sign_details

        sign_details="$(/usr/bin/codesign --display --verbose=4 "$target" 2>&1)"
        if [ "$require_identifier" = "1" ] && ! echo "$sign_details" | grep -Fq "Identifier=Clavis"; then
            echo "❌ Shared Code Signing Identifier is missing from $target." >&2
            exit 1
        fi

        if [ "$TIMESTAMP_FLAG" = "--timestamp" ] && ! echo "$sign_details" | grep -q "^Timestamp="; then
            echo "❌ Expected a secure timestamp on $target but none was recorded." >&2
            exit 1
        fi

        if [ "$SIGN_ARG" != "-" ]; then
            if echo "$sign_details" | grep -q "Signature=adhoc"; then
                echo "❌ Expected certificate signing, but $target has an ad-hoc signature." >&2
                exit 1
            fi
            if [ -n "$SIGN_TEAM_ID" ] && ! echo "$sign_details" | grep -Fq "TeamIdentifier=$SIGN_TEAM_ID"; then
                echo "❌ $target is not signed by resolved TeamIdentifier '$SIGN_TEAM_ID'." >&2
                exit 1
            fi
            if [ -n "{{ expected_team_id }}" ] && ! echo "$sign_details" | grep -Fq "TeamIdentifier={{ expected_team_id }}"; then
                echo "❌ $target is not signed by expected TeamIdentifier '{{ expected_team_id }}'." >&2
                exit 1
            fi
        fi
    }

    sign_resource_bundle() {
        local target="$1"
        if [ ! -e "$target" ]; then
            echo "❌ Resource bundle not found: $target" >&2
            exit 1
        fi
        echo "  Signing resource bundle $target..."
        /usr/bin/xattr -cr "$target" 2>/dev/null || true
        /usr/bin/codesign \
            --force \
            ${keychain:+--keychain "$keychain"} \
            --sign "$SIGN_ARG" \
            "$TIMESTAMP_FLAG" \
            "$target"
        /usr/bin/codesign --verify --strict --verbose=2 "$target"
        verify_signature_metadata "$target" 0
    }

    sign_and_verify() {
        local target="$1"
        local is_deep="${2:-0}"
        local ent_file="${3:-$entitlements}"
        local target_provisioned="${4:-0}"

        if [ ! -e "$target" ]; then
            echo "❌ Target not found: $target" >&2
            exit 1
        fi

        echo "  Signing $target..."
        /usr/bin/xattr -cr "$target" 2>/dev/null || true
        /usr/bin/codesign \
            --force \
            ${keychain:+--keychain "$keychain"} \
            --sign "$SIGN_ARG" \
            --identifier "Clavis" \
            ${DESIGNATED_REQ:+--requirements "$DESIGNATED_REQ"} \
            --options runtime \
            "$TIMESTAMP_FLAG" \
            --entitlements "$ent_file" \
            "$target"

        if [ "$is_deep" = "1" ]; then
            /usr/bin/codesign --verify --deep --strict --verbose=2 "$target"
        else
            /usr/bin/codesign --verify --strict --verbose=2 "$target"
        fi

        local signed_ent
        signed_ent="$(/usr/bin/codesign -d --entitlements - "$target" 2>&1 || true)"
        if echo "$signed_ent" | grep -Fq '$(AppIdentifierPrefix)'; then
            echo "❌ Unexpanded \$(AppIdentifierPrefix) found in signed entitlements of $target." >&2
            exit 1
        fi
        if [ "$target_provisioned" = "1" ]; then
            if ! echo "$signed_ent" | grep -Fq "keychain-access-groups" || ! echo "$signed_ent" | grep -Fq "$KEYCHAIN_ACCESS_GROUP"; then
                echo "❌ Expected Data Protection keychain-access-groups '$KEYCHAIN_ACCESS_GROUP' in signed entitlements of $target." >&2
                exit 1
            fi
        elif echo "$signed_ent" | grep -Eq "keychain-access-groups|com.apple.security.application-groups|com.apple.application-identifier"; then
            echo "❌ Provisioning-dependent entitlement unexpectedly present in $target." >&2
            exit 1
        fi

        verify_signature_metadata "$target" 1
    }

    # Re-sign SwiftPM data bundles inside-out so no ad-hoc signature breaks notarization
    for resource_bundle in "$build_dir/Clavis_ClavisCore.bundle" \
                           "$agent_bundle/Contents/Resources/Clavis_ClavisCore.bundle" \
                           "$app_bundle/Contents/Resources/Clavis_ClavisCore.bundle"; do
        sign_resource_bundle "$resource_bundle"
    done

    # Sign standalone CLIs and nested bundle helpers (always unprovisioned)
    for binary in "$build_dir/Clavis" \
                  "$build_dir/clavis-agent" \
                  "$build_dir/clavis-cli" \
                  "$app_bundle/Contents/Helpers/clavis-cli"; do
        sign_and_verify "$binary" 0 "$entitlements" "0"
    done

    # Sign the nested agent app so macOS can attribute authentication prompts
    # to a bundle with the Clavis icon instead of a generic executable.
    sign_and_verify "$agent_bundle" 1 "$agent_ent" "$expect_provisioned"

    # Sign the top-level Clavis.app bundle
    sign_and_verify "$app_bundle" 1 "$app_ent" "$expect_provisioned"
    echo "✅ Signing and verification complete."

# Create drag-to-install disk image (.dmg)
dmg config=config: (sign config)
    #!/usr/bin/env bash
    set -euo pipefail
    staging=".build/{{ config }}/dmg"
    dmg="{{ dmg_name }}"
    app_bundle=".build/{{ config }}/Clavis.app"
    keychain="{{ keychain }}"

    echo "💿 Creating $dmg..."
    rm -rf "$staging" "$dmg" "$dmg.sha256"
    mkdir -p "$staging"

    /usr/bin/ditto "$app_bundle" "$staging/Clavis.app"
    ln -s /Applications "$staging/Applications"
    /usr/sbin/diskutil image create from \
        --format UDZO \
        --volumeName "Clavis" \
        "$staging" \
        "$dmg"

    /usr/bin/hdiutil verify "$dmg"

    # Resolve signing identity so the disk image itself is signed when using a real certificate
    resolved="$(/usr/bin/python3 packaging/macos/resolve-signing-identity.py \
        --keychain "$keychain" \
        --requested "{{ sign_identity }}" \
        --preferred-team-id "{{ team_id }}" \
        --expected-team-id "{{ expected_team_id }}" \
        --notarize "{{ notarize }}" \
        --allow-adhoc "1" \
        --timestamp-mode "{{ timestamp_mode }}" \
        --app-profile "{{ app_profile }}" \
        --agent-profile "{{ agent_profile }}" \
        --require-provisioning "{{ require_provisioning }}")"
    eval "$resolved"

    if [ "$SIGN_ARG" != "-" ]; then
        echo "🔐 Signing $dmg with identity: $SIGN_LABEL ($TIMESTAMP_FLAG)..."
        /usr/bin/codesign --force ${keychain:+--keychain "$keychain"} --sign "$SIGN_ARG" --identifier "com.clavis.dmg" "$TIMESTAMP_FLAG" "$dmg"
        /usr/bin/codesign --verify --strict --verbose=2 "$dmg"
    fi

    if [ "{{ notarize }}" = "1" ]; then
        # Stapling rewrites the image, so notarize before computing the checksum.
        just --justfile "{{ justfile() }}" notarize "$dmg"
        # Also staple Clavis.app so the tar.gz / Nix release archive carries an offline-verifiable ticket.
        echo "🔖 Stapling $app_bundle..."
        /usr/bin/xcrun stapler staple "$app_bundle"
        /usr/bin/xcrun stapler validate "$app_bundle"
        /usr/sbin/spctl --assess --type execute -vv "$app_bundle"
    fi
    shasum -a 256 "$dmg" > "$dmg.sha256"
    echo "✅ Created $dmg and checksum."

# Notarize (and staple when supported) a signed disk image, app bundle, pkg, or zip archive.
# Credentials come from either CLAVIS_NOTARY_PROFILE (a `notarytool store-credentials`
# keychain profile) or an App Store Connect API key: CLAVIS_NOTARY_KEY_PATH,
# CLAVIS_NOTARY_KEY_ID, CLAVIS_NOTARY_ISSUER.
notarize file:
    #!/usr/bin/env bash
    set -euo pipefail
    file="{{ file }}"

    if [ -n "${CLAVIS_NOTARY_PROFILE:-}" ]; then
        auth=(--keychain-profile "$CLAVIS_NOTARY_PROFILE")
    elif [ -n "${CLAVIS_NOTARY_KEY_PATH:-}" ] && [ -n "${CLAVIS_NOTARY_KEY_ID:-}" ] && [ -n "${CLAVIS_NOTARY_ISSUER:-}" ]; then
        auth=(--key "$CLAVIS_NOTARY_KEY_PATH" --key-id "$CLAVIS_NOTARY_KEY_ID" --issuer "$CLAVIS_NOTARY_ISSUER")
    else
        echo "❌ Set CLAVIS_NOTARY_PROFILE, or CLAVIS_NOTARY_KEY_PATH + CLAVIS_NOTARY_KEY_ID + CLAVIS_NOTARY_ISSUER." >&2
        exit 1
    fi

    result="$(mktemp)"
    trap 'rm -f "$result"' EXIT

    echo "📮 Submitting $file for notarization..."
    /usr/bin/xcrun notarytool submit "$file" "${auth[@]}" --wait --output-format json > "$result" || true
    status="$(/usr/bin/plutil -extract status raw -o - "$result" 2>/dev/null || true)"
    submission_id="$(/usr/bin/plutil -extract id raw -o - "$result" 2>/dev/null || true)"

    if [ "$status" != "Accepted" ]; then
        echo "❌ Notarization finished with status '${status:-unknown}'." >&2
        if [ -n "$submission_id" ]; then
            /usr/bin/xcrun notarytool log "$submission_id" "${auth[@]}" >&2 || true
        fi
        exit 1
    fi

    case "$file" in
        *.dmg)
            /usr/bin/xcrun stapler staple "$file"
            /usr/bin/xcrun stapler validate "$file"
            /usr/sbin/spctl --assess --type open --context context:primary-signature -vv "$file"
            echo "✅ Notarized and stapled $file."
            ;;
        *.app)
            /usr/bin/xcrun stapler staple "$file"
            /usr/bin/xcrun stapler validate "$file"
            /usr/sbin/spctl --assess --type execute -vv "$file"
            echo "✅ Notarized and stapled $file."
            ;;
        *.pkg)
            /usr/bin/xcrun stapler staple "$file"
            /usr/bin/xcrun stapler validate "$file"
            echo "✅ Notarized and stapled $file."
            ;;
        *.zip)
            echo "✅ Notarized $file (CDHashes registered with Apple Notary Service; .zip containers cannot be stapled)."
            ;;
        *)
            echo "❌ Unsupported file type for notarization post-processing: $file" >&2
            exit 1
            ;;
    esac

# Package DMG, Nix archive, and checksums for release
package config=config: (dmg config)
    #!/usr/bin/env bash
    set -euo pipefail
    build_dir=".build/{{ config }}"
    archive="{{ archive_name }}"

    if [ "{{ notarize }}" = "1" ]; then
        standalone_stage="$(mktemp -d -t clavis-standalone)"
        standalone_zip="$(mktemp -u -t clavis-standalone).zip"
        trap 'rm -rf "$standalone_stage" "$standalone_zip"' EXIT
        cp "$build_dir/Clavis" "$build_dir/clavis-agent" "$build_dir/clavis-cli" "$standalone_stage/"
        /usr/bin/ditto -c -k --keepParent "$standalone_stage" "$standalone_zip"
        just --justfile "{{ justfile() }}" notarize "$standalone_zip"
    fi

    echo "📦 Packaging artifacts..."
    tar -czf "$archive" -C "$build_dir" \
        Clavis \
        clavis-agent \
        clavis-cli \
        Clavis_ClavisCore.bundle \
        Clavis.app
    shasum -a 256 "$archive" > "$archive.sha256"
    echo "✅ Created $archive and checksum."

# Inspect local code-signing certificates and active identity selection
signing-status:
    @/usr/bin/python3 packaging/macos/resolve-signing-identity.py \
        --status \
        --keychain "{{ keychain }}" \
        --requested "{{ sign_identity }}" \
        --preferred-team-id "{{ team_id }}" \
        --expected-team-id "{{ expected_team_id }}" \
        --notarize "{{ notarize }}" \
        --allow-adhoc "{{ allow_adhoc }}" \
        --timestamp-mode "{{ timestamp_mode }}" \
        --app-profile "{{ app_profile }}" \
        --agent-profile "{{ agent_profile }}" \
        --require-provisioning "{{ require_provisioning }}"

# Bootstrap local macOS Data Protection provisioning profile(s) via Xcode
provision:
    /usr/bin/python3 packaging/macos/bootstrap-provisioning.py --team-id "{{ team_id }}"
    just --justfile "{{ justfile() }}" signing-status

# Inspect or upload GitHub Release signing & notarization configuration (Team {{ team_id }})
ci-signing-setup p12_path="" notary_p8_path="" notary_key_id="" notary_issuer_id="" repo="GDR/clavis" app_profile_path="" agent_profile_path="":
    #!/usr/bin/env bash
    set -euo pipefail
    repo="{{ repo }}"
    team="{{ team_id }}"
    p12_path="{{ p12_path }}"
    notary_p8_path="{{ notary_p8_path }}"
    notary_key_id="{{ notary_key_id }}"
    notary_issuer_id="{{ notary_issuer_id }}"
    app_profile_path="{{ app_profile_path }}"
    agent_profile_path="{{ agent_profile_path }}"

    if command -v gh >/dev/null 2>&1; then
        echo "🔎 GitHub configuration for $repo (environment: release):"
        gh variable list -R "$repo" --env release || true
        echo ""
        echo "🔎 GitHub secrets for $repo (environment: release):"
        gh secret list -R "$repo" --env release || true
        echo ""
        echo "🔎 GitHub repository secrets for $repo:"
        gh secret list -R "$repo" || true
        echo ""
    fi

    if [ -z "$p12_path" ]; then
        cat <<EOF
    Next steps to configure Developer ID signing, Data Protection provisioning & notarization for team $team:
      1. In Xcode -> Settings -> Accounts -> Damir Garifullin ($team) -> Manage Certificates -> '+' -> Developer ID Application.
         Export that certificate + private key from Keychain Access as DeveloperID.p12.
      2. Create an App Store Connect API Key (https://appstoreconnect.apple.com/access/integrations/api, role Developer or App Manager),
         download AuthKey_<KEY_ID>.p8, and copy <KEY_ID> and <ISSUER_ID>.
      3. In Apple Developer Portal (https://developer.apple.com/account/resources/identifiers/list) for team $team:
         - Register explicit App IDs 'com.clavis.app' and 'com.clavis.agent' with the Keychain Sharing capability enabled.
         - Under Profiles -> '+' -> Distribution -> Developer ID (macOS), create one provisioning profile for 'com.clavis.app'
           (save as Clavis.provisionprofile) and one for 'com.clavis.agent' (save as ClavisAgent.provisionprofile),
           both tied to your Developer ID Application certificate.
      4. Run (with optional provisioning profile pair at the end to enable Data Protection Keychain in release CI):
         MACOS_CERTIFICATE_PWD='<p12-password>' just ci-signing-setup \\
           path/to/DeveloperID.p12 path/to/AuthKey_XXXX.p8 <KEY_ID> <ISSUER_ID> $repo \\
           path/to/Clavis.provisionprofile path/to/ClavisAgent.provisionprofile
    EOF
        exit 0
    fi

    if [ -z "$notary_p8_path" ] || [ -z "$notary_key_id" ] || [ -z "$notary_issuer_id" ]; then
        echo "❌ Usage: MACOS_CERTIFICATE_PWD='<pwd>' just ci-signing-setup <p12_path> <notary_p8_path> <notary_key_id> <notary_issuer_id> [repo] [app_profile_path] [agent_profile_path]" >&2
        exit 1
    fi
    if [ -n "$app_profile_path$agent_profile_path" ] && { [ -z "$app_profile_path" ] || [ -z "$agent_profile_path" ]; }; then
        echo "❌ Both app_profile_path and agent_profile_path must be provided together (atomic Data Protection pair)." >&2
        exit 1
    fi
    if [ ! -f "$p12_path" ]; then
        echo "❌ Certificate archive not found: $p12_path" >&2
        exit 1
    fi
    if [ ! -f "$notary_p8_path" ]; then
        echo "❌ Notary API key (.p8) not found: $notary_p8_path" >&2
        exit 1
    fi
    if ! head -n 1 "$notary_p8_path" | grep -q -- "-----BEGIN PRIVATE KEY-----"; then
        echo "❌ $notary_p8_path does not look like a PKCS#8 .p8 private key." >&2
        exit 1
    fi
    if [ -n "$app_profile_path" ] && [ ! -f "$app_profile_path" ]; then
        echo "❌ App provisioning profile not found: $app_profile_path" >&2
        exit 1
    fi
    if [ -n "$agent_profile_path" ] && [ ! -f "$agent_profile_path" ]; then
        echo "❌ Agent provisioning profile not found: $agent_profile_path" >&2
        exit 1
    fi
    if ! command -v gh >/dev/null 2>&1 || ! gh auth status >/dev/null 2>&1; then
        echo "❌ GitHub CLI ('gh') must be installed and authenticated." >&2
        exit 1
    fi

    p12_pwd="${MACOS_CERTIFICATE_PWD:-}"
    if [ -z "$p12_pwd" ]; then
        if [ -t 0 ]; then
            read -rsp "Enter .p12 export password: " p12_pwd
            echo ""
        else
            echo "❌ Set MACOS_CERTIFICATE_PWD in the environment when running non-interactively." >&2
            exit 1
        fi
    fi
    if [ -z "$p12_pwd" ]; then
        echo "❌ Certificate password must not be empty." >&2
        exit 1
    fi

    export CLAVIS_P12_PWD="$p12_pwd"
    certs_pem="$(/usr/bin/openssl pkcs12 -in "$p12_path" -clcerts -nokeys -passin env:CLAVIS_P12_PWD 2>/dev/null || true)"
    has_privkey=0
    if /usr/bin/openssl pkcs12 -in "$p12_path" -nocerts -nodes -passin env:CLAVIS_P12_PWD 2>/dev/null | grep -q -- "PRIVATE KEY"; then
        has_privkey=1
    fi
    unset CLAVIS_P12_PWD
    if [ -z "$certs_pem" ] || [ "$has_privkey" != "1" ]; then
        echo "❌ Failed to read certificate + private key from '$p12_path'. Check MACOS_CERTIFICATE_PWD and ensure the private key was included when exporting the .p12." >&2
        exit 1
    fi

    CLAVIS_CERTS_PEM="$certs_pem" /usr/bin/python3 - "$team" "$app_profile_path" "$agent_profile_path" << 'PY'
    import hashlib, importlib.util, os, re, subprocess, sys, time
    team, app_profile_path, agent_profile_path = sys.argv[1], sys.argv[2], sys.argv[3]
    pem_all = os.environ["CLAVIS_CERTS_PEM"]
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_all, re.S)
    matched = []
    matched_sha1s = []
    subjects = []
    for pem in blocks:
        out = subprocess.check_output(
            ["/usr/bin/openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
            input=pem,
            text=True,
        ).strip()
        subjects.append(out)
        if re.search(r"CN=Developer ID Application:", out) and re.search(rf"(?:^|[,/])\s*OU={re.escape(team)}(?:\s*(?:[,/]|$))", out):
            der = subprocess.check_output(
                ["/usr/bin/openssl", "x509", "-outform", "DER"],
                input=pem.encode("utf-8"),
            )
            matched.append(out)
            matched_sha1s.append(hashlib.sha1(der).hexdigest().upper())
    if not matched:
        print(f"❌ No 'Developer ID Application' certificate with OU={team} found in .p12.", file=sys.stderr)
        for s in subjects:
            print(f"   Found: {s}", file=sys.stderr)
        sys.exit(1)
    print(f"✅ Verified certificate in .p12: {matched[0]}")

    if app_profile_path and agent_profile_path:
        spec = importlib.util.spec_from_file_location("resolve_signing", "packaging/macos/resolve-signing-identity.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        now_ts = time.time()
        shared_group = f"{team}.com.clavis.shared"
        for label, bundle_id, prof_path in (
            ("app", "com.clavis.app", app_profile_path),
            ("agent", "com.clavis.agent", agent_profile_path),
        ):
            try:
                prof = mod.load_provisioning_profile(prof_path, explicit=True)
            except mod.ResolutionError as err:
                print(str(err), file=sys.stderr)
                sys.exit(1)
            if not any(
                mod.profile_matches(
                    prof,
                    bundle_id=bundle_id,
                    team_id=team,
                    cert_sha1=sha1,
                    shared_group=shared_group,
                    now_ts=now_ts,
                )
                for sha1 in matched_sha1s
            ):
                reasons = mod.profile_mismatch_reasons(
                    prof,
                    bundle_id=bundle_id,
                    team_id=team,
                    cert_sha1=matched_sha1s[0],
                    shared_group=shared_group,
                    now_ts=now_ts,
                )
                print(
                    f"❌ Invalid {label} provisioning profile '{prof_path}' for {bundle_id}: {'; '.join(reasons)}",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"✅ Verified {label} provisioning profile: {prof.name or prof.uuid} ({bundle_id})")
    PY

    echo "☁️ Updating GitHub environment 'release' on $repo..."
    gh variable set CLAVIS_EXPECTED_TEAM_ID --env release -R "$repo" --body "$team"
    gh variable set CLAVIS_SIGN_IDENTITY --env release -R "$repo" --body "Developer ID Application"
    gh variable set CLAVIS_NOTARIZE --env release -R "$repo" --body "1"
    gh variable delete CLAVIS_ALLOW_NON_DEVID_RELEASE --env release -R "$repo" 2>/dev/null || true

    base64 < "$p12_path" | tr -d '\n' | gh secret set MACOS_CERTIFICATE_BASE64 --env release -R "$repo"
    printf '%s' "$p12_pwd" | gh secret set MACOS_CERTIFICATE_PWD --env release -R "$repo"
    base64 < "$notary_p8_path" | tr -d '\n' | gh secret set NOTARY_KEY_BASE64 --env release -R "$repo"
    printf '%s' "$notary_key_id" | gh secret set NOTARY_KEY_ID --env release -R "$repo"
    printf '%s' "$notary_issuer_id" | gh secret set NOTARY_ISSUER_ID --env release -R "$repo"

    if [ -n "$app_profile_path" ] && [ -n "$agent_profile_path" ]; then
        base64 < "$app_profile_path" | tr -d '\n' | gh secret set MACOS_APP_PROVISION_PROFILE_BASE64 --env release -R "$repo"
        base64 < "$agent_profile_path" | tr -d '\n' | gh secret set MACOS_AGENT_PROVISION_PROFILE_BASE64 --env release -R "$repo"
    fi

    echo "✅ GitHub release environment secrets & variables configured for $repo (team $team)."

# Run test suite with parallel Swift Testing (supports extra flags via args)
test *args:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    mkdir -p .build && touch .build/.metadata_never_index
    SDKROOT="${sdkroot:-}" swift test --parallel --enable-swift-testing --disable-xctest {{ args }}

# Run core test suite (decoupled from SwiftUI/AppKit)
test-core *args:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    mkdir -p .build && touch .build/.metadata_never_index
    SDKROOT="${sdkroot:-}" swift test --filter ClavisCoreTests --parallel --enable-swift-testing --disable-xctest {{ args }}

# Run UI and application test suite
test-app *args:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    mkdir -p .build && touch .build/.metadata_never_index
    SDKROOT="${sdkroot:-}" swift test --filter ClavisAppTests --parallel --enable-swift-testing --disable-xctest {{ args }}

# Run tests without recompilation (fast re-run on warm binaries)
test-fast *args:
    #!/usr/bin/env bash
    set -euo pipefail
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    mkdir -p .build && touch .build/.metadata_never_index
    SDKROOT="${sdkroot:-}" swift test --skip-build --parallel --enable-swift-testing --disable-xctest {{ args }}

# Build and relaunch Clavis.app locally
run config="debug":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "🛑 Terminating running Clavis and clavis-agent instances..."
    killall Clavis clavis-agent 2>/dev/null || true
    for _ in {1..50}; do
        pgrep -x "Clavis|clavis-agent" >/dev/null || break
        sleep 0.1
    done
    if pgrep -x "Clavis|clavis-agent" >/dev/null; then
        echo "❌ Processes did not exit" >&2
        exit 1
    fi

    just sign "{{ config }}"

    echo "🚀 Relaunching Clavis ({{ config }})..."
    mkdir -p ".build/{{ config }}"
    nohup ".build/{{ config }}/Clavis.app/Contents/MacOS/Clavis" \
        >>".build/{{ config }}/run.log" 2>&1 &
    app_pid=$!
    disown
    # Keep the just recipe script alive until Clavis and clavis-agent finish execve;
    # otherwise just unlinks its temp script while syspolicyd is still scanning p_textvp.
    for _ in {1..50}; do
        if ! kill -0 "$app_pid" 2>/dev/null; then
            echo "❌ Clavis exited immediately after launch (PID $app_pid). Check .build/{{ config }}/run.log or unified logs." >&2
            exit 1
        fi
        if pgrep -x Clavis >/dev/null && pgrep -x clavis-agent >/dev/null; then
            break
        fi
        sleep 0.1
    done
    if ! pgrep -x Clavis >/dev/null; then
        echo "❌ Clavis did not finish starting within 5s (PID $app_pid)." >&2
        exit 1
    fi
    echo "✅ Clavis running (PID $app_pid)"

# --- Auth lab (ui/auth-exp): three prototype apps comparing authentication UX ---

# Build one auth-lab app bundle: system | embedded | password | all (ad-hoc signed, .build/apps/)
auth-exp-build app="all":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ app }}" in
        system)   apps=("AuthSystemPrompt") ;;
        embedded) apps=("AuthEmbedded") ;;
        password) apps=("AuthApplicationPassword") ;;
        all)      apps=("AuthSystemPrompt" "AuthEmbedded" "AuthApplicationPassword") ;;
        *) echo "❌ app must be system, embedded, password or all" >&2; exit 1 ;;
    esac
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path)"
    cd ui/auth-exp
    SDKROOT="$sdkroot" swift build
    for name in "${apps[@]}"; do
        bundle=".build/apps/$name.app"
        rm -rf "$bundle"
        mkdir -p "$bundle/Contents/MacOS"
        cp ".build/debug/$name" "$bundle/Contents/MacOS/$name"
        cat > "$bundle/Contents/Info.plist" <<PLIST
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>$name</string>
    <key>CFBundleIdentifier</key><string>com.clavis.authlab.$name</string>
    <key>CFBundleName</key><string>$name</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>15.0</string>
    <key>NSHighResolutionCapable</key><true/>
    </dict></plist>
    PLIST
        /usr/bin/codesign --force --sign - "$bundle"
        echo "✅ ui/auth-exp/$bundle"
    done

# Launch an auth-lab app: just auth-exp system|embedded|password
auth-exp app="embedded": (auth-exp-build app)
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ app }}" in
        system)   name="AuthSystemPrompt" ;;
        embedded) name="AuthEmbedded" ;;
        password) name="AuthApplicationPassword" ;;
        *) echo "❌ app must be system, embedded or password" >&2; exit 1 ;;
    esac
    killall "$name" 2>/dev/null || true
    open "ui/auth-exp/.build/apps/$name.app"

# Clean build artifacts
clean:
    swift package clean
    rm -rf {{ dmg_name }} {{ dmg_name }}.sha256 {{ archive_name }} {{ archive_name }}.sha256 .build/release/dmg .build/debug/dmg

# Clean all build artifacts, caches, and .build directory
clean-all: clean
    rm -rf .build
