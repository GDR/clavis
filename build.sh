#!/usr/bin/env bash
set -e

echo "🔨 Building clavis (CLI), ClavisGUI (GUI), and age-plugin-clavis (Release)..."
swift build -c release

echo "🔐 Embedding Keychain Entitlements via codesign..."
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/clavis 2>/dev/null || true
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/clavis-cli 2>/dev/null || true
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/ClavisGUI 2>/dev/null || true
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/age-plugin-clavis 2>/dev/null || true

echo "✅ Build and entitlements signing complete!"
echo ""
echo "💻 To use Clavis CLI:"
echo "  swift run clavis generate <label>"
echo "  swift run clavis list"
echo "  swift run clavis export-pub <label>"
echo "  swift run clavis delete <label>"
echo ""
echo "🚀 To run Clavis GUI App & Socket Daemon:"
echo "  .build/release/ClavisGUI"
echo ""
echo "🔑 To use with SSH:"
echo "  export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
