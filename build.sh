#!/usr/bin/env bash
set -e

echo "🔨 Building clavis-cli (CLI), Clavis (GUI), and age-plugin-clavis (Release)..."
swift build -c release

echo "🔐 Embedding Keychain Entitlements via codesign..."
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/clavis-cli
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/Clavis
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/age-plugin-clavis

echo "✅ Build and entitlements signing complete!"
echo ""
echo "💻 To use Clavis CLI:"
echo "  .build/release/clavis-cli generate <label>"
echo "  .build/release/clavis-cli list"
echo "  .build/release/clavis-cli export-pub <label>"
echo "  .build/release/clavis-cli delete <label>"
echo ""
echo "🚀 To run Clavis GUI App & Socket Daemon:"
echo "  .build/release/Clavis"
echo ""
echo "🔑 To use with SSH:"
echo "  export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
