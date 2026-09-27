set shell := ["bash", "-euo", "pipefail", "-c"]

config := env_var_or_default("CONFIG", "release")
version := env_var_or_default("CLAVIS_VERSION", "0.2.0") # x-release-please-version
build_version := env_var_or_default("CLAVIS_BUILD_VERSION", "1")
keychain := env_var_or_default("CLAVIS_KEYCHAIN", "")
sign_identity := env_var_or_default("CLAVIS_SIGN_IDENTITY", "")
allow_adhoc := env_var_or_default("CLAVIS_ALLOW_ADHOC_SIGNING", "0")
expected_team_id := env_var_or_default("CLAVIS_EXPECTED_TEAM_ID", "")

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
    resource_bundle="$build_dir/Clavis_ClavisCore.bundle"
    contents="$app_bundle/Contents"

    if [ ! -d "$resource_bundle" ]; then
        echo "❌ Missing SwiftPM resource bundle: $resource_bundle" >&2
        exit 1
    fi

    echo "📦 Assembling Clavis.app..."
    rm -rf "$app_bundle"
    mkdir -p "$contents/MacOS" "$contents/Helpers" "$contents/Resources"

    cp "$build_dir/Clavis" "$contents/MacOS/Clavis"
    cp "$build_dir/clavis-agent" "$contents/Helpers/clavis-agent"
    cp "$build_dir/clavis-cli" "$contents/Helpers/clavis-cli"
    cp "$build_dir/age-plugin-clavis" "$contents/Helpers/age-plugin-clavis"

    cp packaging/macos/Info.plist "$contents/Info.plist"
    /usr/bin/plutil -replace CFBundleShortVersionString -string "{{ version }}" "$contents/Info.plist"
    /usr/bin/plutil -replace CFBundleVersion -string "{{ build_version }}" "$contents/Info.plist"
    /usr/bin/ditto "$resource_bundle" "$contents/Resources/Clavis_ClavisCore.bundle"
    /usr/bin/plutil -lint "$contents/Info.plist"

# Codesign standalone binaries and the .app bundle
sign config=config: (bundle config)
    #!/usr/bin/env bash
    set -euo pipefail
    build_dir=".build/{{ config }}"
    app_bundle="$build_dir/Clavis.app"
    keychain="{{ keychain }}"
    entitlements="Entitlements.plist"

    # Resolve signing identity if not explicitly specified
    identity="{{ sign_identity }}"
    if [ -z "$identity" ]; then
        target_kc="${keychain:+-k $keychain}"
        if /usr/bin/security find-identity -v -p codesigning ${keychain:+$keychain} 2>/dev/null | grep -q "Apple Development"; then
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

    echo "🔐 Signing binaries with identity: '$identity'..."

    keychain_args=()
    if [ -n "$keychain" ]; then
        keychain_args=(--keychain "$keychain")
    fi

    sign_and_verify() {
        local target="$1"
        local is_deep="${2:-0}"

        if [ ! -e "$target" ]; then
            echo "❌ Target not found: $target" >&2
            exit 1
        fi

        echo "  Signing $target..."
        /usr/bin/codesign \
            --force \
            "${keychain_args[@]}" \
            --sign "$identity" \
            --identifier "Clavis" \
            --options runtime \
            --timestamp=none \
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
                  "$app_bundle/Contents/Helpers/clavis-agent" \
                  "$app_bundle/Contents/Helpers/clavis-cli" \
                  "$app_bundle/Contents/Helpers/age-plugin-clavis"; do
        sign_and_verify "$binary" 0
    done

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
    shasum -a 256 "$dmg" > "$dmg.sha256"
    echo "✅ Created $dmg and checksum."

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
    echo "🛑 Terminating running Clavis instance..."
    killall Clavis 2>/dev/null || true
    for _ in {1..50}; do
        pgrep -x Clavis >/dev/null || break
        sleep 0.1
    done
    if pgrep -x Clavis >/dev/null; then
        echo "❌ Clavis did not exit" >&2
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
