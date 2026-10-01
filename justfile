set shell := ["bash", "-euo", "pipefail", "-c"]

config := env_var_or_default("CONFIG", "release")
version := env_var_or_default("CLAVIS_VERSION", "0.2.0")
build_version := env_var_or_default("CLAVIS_BUILD_VERSION", "1")
keychain := env_var_or_default("CLAVIS_KEYCHAIN", "")
sign_identity := env_var_or_default("CLAVIS_SIGN_IDENTITY", "")
allow_adhoc := env_var_or_default("CLAVIS_ALLOW_ADHOC_SIGNING", "0")
expected_team_id := env_var_or_default("CLAVIS_EXPECTED_TEAM_ID", "")
# auto: secure (Apple-timestamped) signatures for Developer ID builds, none for local builds.
timestamp_mode := env_var_or_default("CLAVIS_TIMESTAMP", "auto")
# Set to 1 to notarize and staple the DMG (requires a Developer ID Application identity).
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
    cp "$build_dir/age-plugin-clavis" "$contents/Helpers/age-plugin-clavis"

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

    # Resolve signing identity if not explicitly specified
    identity="{{ sign_identity }}"
    if [ -z "$identity" ]; then
        target_kc="${keychain:+-k $keychain}"
        if [ "{{ notarize }}" = "1" ]; then
            if /usr/bin/security find-identity -v -p codesigning ${keychain:+$keychain} 2>/dev/null | grep -q "Developer ID Application"; then
                identity="Developer ID Application"
            else
                echo "❌ CLAVIS_NOTARIZE=1 requires a 'Developer ID Application' certificate." >&2
                exit 1
            fi
        elif /usr/bin/security find-identity -v -p codesigning ${keychain:+$keychain} 2>/dev/null | grep -q "Apple Development"; then
            identity="Apple Development"
        elif /usr/bin/security find-identity -v -p codesigning ${keychain:+$keychain} 2>/dev/null | grep -q "Clavis Local Development"; then
            identity="Clavis Local Development"
        elif [ "{{ allow_adhoc }}" = "1" ]; then
            identity="-"
        else
            echo "❌ No code-signing certificate found; refusing to create an unsigned/ad-hoc build." >&2
            echo "   Install a signing certificate, set CLAVIS_SIGN_IDENTITY, or pass CLAVIS_ALLOW_ADHOC_SIGNING=1." >&2
            exit 1
        fi
    fi

    if [ "{{ notarize }}" = "1" ]; then
        case "$identity" in
            "Developer ID Application"*) ;;
            *)
                echo "❌ Notarization requires a 'Developer ID Application' identity, got '$identity'." >&2
                exit 1
                ;;
        esac
    fi

    # Secure timestamps keep a release signature valid after the signing certificate expires and
    # are required for notarization. They need network access, so local builds skip them.
    case "{{ timestamp_mode }}" in
        secure) timestamp_flag="--timestamp" ;;
        none)   timestamp_flag="--timestamp=none" ;;
        auto)
            case "$identity" in
                "Developer ID Application"*) timestamp_flag="--timestamp" ;;
                *)                           timestamp_flag="--timestamp=none" ;;
            esac
            ;;
        *)
            echo "❌ CLAVIS_TIMESTAMP must be auto, secure or none." >&2
            exit 1
            ;;
    esac
    if [ "{{ notarize }}" = "1" ] && [ "$timestamp_flag" != "--timestamp" ]; then
        echo "❌ Notarization requires secure timestamps (CLAVIS_TIMESTAMP must be auto or secure)." >&2
        exit 1
    fi

    echo "🔐 Signing binaries with identity: '$identity' ($timestamp_flag)..."

    sign_and_verify() {
        local target="$1"
        local is_deep="${2:-0}"

        if [ ! -e "$target" ]; then
            echo "❌ Target not found: $target" >&2
            exit 1
        fi

        echo "  Signing $target..."
        /usr/bin/xattr -cr "$target" 2>/dev/null || true
        /usr/bin/codesign \
            --force \
            ${keychain:+--keychain "$keychain"} \
            --sign "$identity" \
            --identifier "Clavis" \
            --options runtime \
            "$timestamp_flag" \
            --entitlements "$entitlements" \
            "$target"

        if [ "$is_deep" = "1" ]; then
            /usr/bin/codesign --verify --deep --strict --verbose=2 "$target"
        else
            /usr/bin/codesign --verify --strict --verbose=2 "$target"
        fi

        local signed_ent sign_details
        signed_ent="$(/usr/bin/codesign -d --entitlements - "$target" 2>&1 || true)"
        if echo "$signed_ent" | grep -Eq "keychain-access-groups|com.apple.security.application-groups"; then
            echo "❌ Provisioning-dependent entitlement unexpectedly present in $target." >&2
            exit 1
        fi

        sign_details="$(/usr/bin/codesign --display --verbose=4 "$target" 2>&1)"
        if ! echo "$sign_details" | grep -Fq "Identifier=Clavis"; then
            echo "❌ Shared Code Signing Identifier is missing from $target." >&2
            exit 1
        fi

        if [ "$timestamp_flag" = "--timestamp" ] && ! echo "$sign_details" | grep -q "^Timestamp="; then
            echo "❌ Expected a secure timestamp on $target but none was recorded." >&2
            exit 1
        fi

        if [ "$identity" != "-" ]; then
            if echo "$sign_details" | grep -q "Signature=adhoc"; then
                echo "❌ Expected certificate signing, but $target has an ad-hoc signature." >&2
                exit 1
            fi
            if [ -n "{{ expected_team_id }}" ] && ! echo "$sign_details" | grep -Fq "TeamIdentifier={{ expected_team_id }}"; then
                echo "❌ $target is not signed by expected TeamIdentifier '{{ expected_team_id }}'." >&2
                exit 1
            fi
        fi
    }

    # Sign standalone CLIs and nested bundle helpers
    for binary in "$build_dir/Clavis" \
                  "$build_dir/clavis-agent" \
                  "$build_dir/clavis-cli" \
                  "$build_dir/age-plugin-clavis" \
                  "$app_bundle/Contents/Helpers/clavis-cli" \
                  "$app_bundle/Contents/Helpers/age-plugin-clavis"; do
        sign_and_verify "$binary" 0
    done

    # Sign the nested agent app so macOS can attribute authentication prompts
    # to a bundle with the Clavis icon instead of a generic executable.
    sign_and_verify "$agent_bundle" 1

    # Sign the top-level Clavis.app bundle
    sign_and_verify "$app_bundle" 1
    echo "✅ Signing and verification complete."

# Create drag-to-install disk image (.dmg)
dmg config=config: (sign config)
    #!/usr/bin/env bash
    set -euo pipefail
    staging=".build/{{ config }}/dmg"
    dmg="{{ dmg_name }}"
    app_bundle=".build/{{ config }}/Clavis.app"

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
    if [ "{{ notarize }}" = "1" ]; then
        # Stapling rewrites the image, so notarize before computing the checksum.
        just --justfile "{{ justfile() }}" notarize "$dmg"
    fi
    shasum -a 256 "$dmg" > "$dmg.sha256"
    echo "✅ Created $dmg and checksum."

# Notarize and staple a signed disk image. Credentials come from either
# CLAVIS_NOTARY_PROFILE (a `notarytool store-credentials` keychain profile) or an App Store
# Connect API key: CLAVIS_NOTARY_KEY_PATH, CLAVIS_NOTARY_KEY_ID, CLAVIS_NOTARY_ISSUER.
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

    /usr/bin/xcrun stapler staple "$file"
    /usr/bin/xcrun stapler validate "$file"
    /usr/sbin/spctl --assess --type open --context context:primary-signature -vv "$file"
    echo "✅ Notarized and stapled $file."

# Package DMG, Nix archive, and checksums for release
package config=config: (dmg config)
    #!/usr/bin/env bash
    set -euo pipefail
    build_dir=".build/{{ config }}"
    archive="{{ archive_name }}"

    echo "📦 Packaging artifacts..."
    tar -czf "$archive" -C "$build_dir" \
        Clavis \
        clavis-agent \
        clavis-cli \
        age-plugin-clavis \
        Clavis_ClavisCore.bundle \
        Clavis.app
    shasum -a 256 "$archive" > "$archive.sha256"
    echo "✅ Created $archive and checksum."

# Run test suite
test:
    mkdir -p .build && touch .build/.metadata_never_index
    swift test

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
    disown

# Clean build artifacts
clean:
    swift package clean
    rm -rf {{ dmg_name }} {{ dmg_name }}.sha256 {{ archive_name }} {{ archive_name }}.sha256 .build/release/dmg .build/debug/dmg
