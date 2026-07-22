#!/usr/bin/env bash
set -e

echo "🔨 Building Clavis (GUI), clavis-cli (CLI), and age-plugin-clavis (Release)..."
swift build -c release

echo "🔐 Embedding Keychain Entitlements via codesign..."
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/Clavis 2>/dev/null || true
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/clavis-cli 2>/dev/null || true
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/age-plugin-clavis 2>/dev/null || true

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
