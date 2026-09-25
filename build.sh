#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ACTIVE_MACOS_SDK="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path)"
if [[ ! -f "$ACTIVE_MACOS_SDK/SDKSettings.plist" ]]; then
    echo "❌ Active Xcode returned an invalid macOS SDK path: $ACTIVE_MACOS_SDK" >&2
    exit 1
fi
export SDKROOT="$ACTIVE_MACOS_SDK"

echo "🔐 Detecting Code Signing Identity..."
SIGN_IDENTITY="${CLAVIS_SIGN_IDENTITY:-}"
SIGNING_MODE="identity"

if [[ "$SIGN_IDENTITY" == "-" && "${CLAVIS_ALLOW_ADHOC_SIGNING:-0}" != "1" ]]; then
    echo "❌ Refusing ad-hoc signing for a release build." >&2
    echo "   Set CLAVIS_ALLOW_ADHOC_SIGNING=1 only for an explicitly local build." >&2
    exit 1
elif [[ "$SIGN_IDENTITY" == "-" ]]; then
    SIGNING_MODE="adhoc"
    echo "⚠️  Using explicitly requested ad-hoc signing; this is a local-only build."
elif [[ -n "$SIGN_IDENTITY" ]]; then
    echo "  Using explicitly configured certificate: '$SIGN_IDENTITY'"
elif /usr/bin/security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Development"; then
    SIGN_IDENTITY="Apple Development"
    echo "  Using Apple Development certificate"
elif /usr/bin/security find-identity -v -p codesigning 2>/dev/null | grep -q "Clavis Local Development"; then
    SIGN_IDENTITY="Clavis Local Development"
    echo "  Using local certificate: 'Clavis Local Development'"
else
    echo "❌ No code-signing certificate found; refusing to create an ad-hoc release." >&2
    echo "   Install a signing certificate, set CLAVIS_SIGN_IDENTITY, or explicitly opt" >&2
    echo "   into a local-only build with CLAVIS_ALLOW_ADHOC_SIGNING=1." >&2
    exit 1
fi

echo "🔨 Building Clavis (GUI), clavis-agent (Daemon), clavis-cli (CLI), and age-plugin-clavis (Release)..."
echo "  Using macOS SDK: $SDKROOT"
swift build -c release

echo "🔐 Signing binaries and embedding entitlements..."
BINARIES=(
    ".build/release/Clavis"
    ".build/release/clavis-agent"
    ".build/release/clavis-cli"
    ".build/release/age-plugin-clavis"
)

for binary in "${BINARIES[@]}"; do
    if [[ ! -x "$binary" ]]; then
        echo "❌ Expected executable is missing: $binary" >&2
        exit 1
    fi

    /usr/bin/codesign \
        --force \
        --sign "$SIGN_IDENTITY" \
        --identifier "Clavis" \
        --options runtime \
        --timestamp=none \
        --entitlements Entitlements.plist \
        "$binary"
    /usr/bin/codesign --verify --strict --verbose=2 "$binary"

    SIGNED_ENTITLEMENTS="$(/usr/bin/codesign -d --entitlements - "$binary" 2>&1)"
    if /usr/bin/grep -Eq "keychain-access-groups|com.apple.security.application-groups" <<<"$SIGNED_ENTITLEMENTS"; then
        echo "❌ Provisioning-dependent entitlement unexpectedly present in $binary." >&2
        exit 1
    fi

    SIGNING_DETAILS="$(/usr/bin/codesign --display --verbose=4 "$binary" 2>&1)"
    if ! /usr/bin/grep -Fq "Identifier=Clavis" <<<"$SIGNING_DETAILS"; then
        echo "❌ Shared Code Signing Identifier is missing from $binary." >&2
        exit 1
    fi

    if [[ "$SIGNING_MODE" == "identity" ]]; then
        if /usr/bin/grep -q "Signature=adhoc" <<<"$SIGNING_DETAILS"; then
            echo "❌ Expected certificate signing, but $binary has an ad-hoc signature." >&2
            exit 1
        fi
        if [[ -n "${CLAVIS_EXPECTED_TEAM_ID:-}" ]]; then
            if ! /usr/bin/grep -Fq "TeamIdentifier=$CLAVIS_EXPECTED_TEAM_ID" <<<"$SIGNING_DETAILS"; then
                echo "❌ $binary is not signed by expected TeamIdentifier '$CLAVIS_EXPECTED_TEAM_ID'." >&2
                exit 1
            fi
        fi
    fi
done

if [[ "$SIGNING_MODE" == "adhoc" ]]; then
    echo "✅ Local-only build, hardened runtime ad-hoc signing, and integrity verification complete."
else
    echo "✅ Release build, hardened runtime certificate signing, and signature verification complete!"
fi
echo ""
echo "🚀 To run Clavis GUI App:"
echo "  .build/release/Clavis"
echo ""
echo "🔑 To run standalone Clavis SSH Agent Daemon:"
echo "  .build/release/clavis-agent"
echo ""
echo "💻 To use Clavis CLI:"
echo "  .build/release/clavis-cli list"
echo "  .build/release/clavis-cli generate <label>"
echo "  .build/release/clavis-cli export-pub <label>"
echo "  .build/release/clavis-cli delete <label>"
echo ""
echo "🔑 To use with SSH:"
echo "  export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
