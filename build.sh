#!/usr/bin/env bash
set -e

echo "🔨 Building Clavis (GUI), clavis-cli (CLI), and age-plugin-clavis (Release)..."
swift build -c release

echo "🔐 Detecting Code Signing Identity..."
SIGN_IDENTITY="-"
if /usr/bin/security find-identity -v -p codesigning 2>/dev/null | grep -q "Clavis Local Development"; then
    SIGN_IDENTITY="Clavis Local Development"
    echo "  Using local certificate: 'Clavis Local Development'"
elif /usr/bin/security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Development"; then
    SIGN_IDENTITY="Apple Development"
    echo "  Using Apple Development certificate"
else
    echo "  No developer certificate found, falling back to ad-hoc signing (-)"
fi

echo "🔐 Signing binaries and embedding entitlements..."
codesign --force --deep --sign "$SIGN_IDENTITY" --entitlements Entitlements.plist .build/release/Clavis 2>/dev/null || true
codesign --force --deep --sign "$SIGN_IDENTITY" --entitlements Entitlements.plist .build/release/clavis-cli 2>/dev/null || true
codesign --force --deep --sign "$SIGN_IDENTITY" --entitlements Entitlements.plist .build/release/age-plugin-clavis 2>/dev/null || true

echo "✅ Build and entitlements signing complete!"
echo ""
echo "🚀 To run Clavis GUI App & Socket Daemon:"
echo "  swift run Clavis"
echo "  or: .build/release/Clavis"
echo ""
echo "💻 To use Clavis CLI:"
echo "  swift run clavis-cli list"
echo "  swift run clavis-cli generate <label>"
echo "  swift run clavis-cli export-pub <label>"
echo "  swift run clavis-cli delete <label>"
echo ""
echo "🔑 To use with SSH:"
echo "  export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
