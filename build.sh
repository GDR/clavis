#!/usr/bin/env bash
set -e

echo "🔨 Building Clavis & age-plugin-clavis (Release)..."
swift build -c release

echo "🔐 Embedding Keychain Entitlements via codesign..."
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/Clavis
codesign --force --deep --sign - --entitlements Entitlements.plist .build/release/age-plugin-clavis

echo "✅ Build and entitlements signing complete!"
echo ""
echo "🚀 To run Clavis GUI & Socket Daemon:"
echo "  .build/release/Clavis"
echo ""
echo "🔑 To use with SSH:"
echo "  export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
