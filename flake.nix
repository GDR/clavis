{
  description = "Clavis — Native macOS Swift/SwiftUI Ed25519 Keychain SSH Agent & age plugin with Touch ID";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
        isDarwin = pkgs.stdenv.isDarwin;
        appleSdk = if isDarwin then (pkgs.apple-sdk_26 or pkgs.apple-sdk_15) else null;
      in
      rec {
        packages = {
          clavis = if isDarwin then pkgs.stdenv.mkDerivation {
            pname = "clavis";
            version = "0.1.0";
            src = ./.;

            dontConfigure = true;
            dontFixup = true;

            buildPhase = ''
              export HOME=$TMPDIR
              export DEVELOPER_DIR="${builtins.getEnv "APPLE_XCODE_DEVELOPER_DIR"}"

              if [ -z "$DEVELOPER_DIR" ]; then
                if [ -d "/Applications/Xcode.app/Contents/Developer" ]; then
                  export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
                elif [ -d "/Applications/Xcode-beta.app/Contents/Developer" ]; then
                  export DEVELOPER_DIR="/Applications/Xcode-beta.app/Contents/Developer"
                elif [ -d "/Applications/Xcode-26.app/Contents/Developer" ]; then
                  export DEVELOPER_DIR="/Applications/Xcode-26.app/Contents/Developer"
                fi
              fi

              if [ -n "$DEVELOPER_DIR" ] && [ -x /usr/bin/xcrun ]; then
                export SDKROOT="$(DEVELOPER_DIR="$DEVELOPER_DIR" /usr/bin/xcrun --sdk macosx --show-sdk-path)"
                export PATH="$DEVELOPER_DIR/usr/bin:/usr/bin:$PATH"
              elif [ -x /usr/bin/xcrun ]; then
                export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
              elif [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk ]; then
                export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
              fi

              /usr/bin/xcrun swift build -c release --disable-sandbox
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp .build/release/Clavis $out/bin/clavis
              cp .build/release/clavis-cli $out/bin/clavis-cli
              cp .build/release/age-plugin-clavis $out/bin/age-plugin-clavis

              # macOS Application Bundle for nix-darwin / home-manager
              mkdir -p $out/Applications/Clavis.app/Contents/MacOS
              mkdir -p $out/Applications/Clavis.app/Contents/Resources
              cp .build/release/Clavis $out/Applications/Clavis.app/Contents/MacOS/Clavis

              cat << 'EOF' > $out/Applications/Clavis.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Clavis</string>
    <key>CFBundleIdentifier</key>
    <string>com.clavis.app</string>
    <key>CFBundleName</key>
    <string>Clavis</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

              for binary in \
                $out/bin/clavis \
                $out/bin/clavis-cli \
                $out/bin/age-plugin-clavis \
                $out/Applications/Clavis.app/Contents/MacOS/Clavis; do
                /usr/bin/codesign \
                  --force \
                  --sign - \
                  --options runtime \
                  --timestamp=none \
                  --entitlements $src/Entitlements.plist \
                  "$binary"
                /usr/bin/codesign --verify --strict --verbose=2 "$binary"
              done

              /usr/bin/codesign \
                --force \
                --sign - \
                --options runtime \
                --timestamp=none \
                --entitlements $src/Entitlements.plist \
                $out/Applications/Clavis.app
              /usr/bin/codesign --verify --deep --strict --verbose=2 $out/Applications/Clavis.app
            '';
          } else pkgs.hello;

          default = packages.clavis;
        };

        apps = {
          clavis = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "clavis" ''
              exec "${packages.clavis}/bin/clavis" "$@"
            '';
            name = "clavis";
          };

          cli = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "clavis-cli" ''
              exec "${packages.clavis}/bin/clavis-cli" "$@"
            '';
            name = "clavis-cli";
          };

          default = apps.clavis;
        };

        devShells.default = pkgs.mkShell {
          name = "clavis-dev-shell";

          packages = with pkgs; [
            git
            cmake
            ninja
            pkg-config
            swiftformat
            swiftlint
            sops
            age
          ];

          shellHook = ''
            export DEVELOPER_DIR="${builtins.getEnv "APPLE_XCODE_DEVELOPER_DIR"}"

            if [ -z "$DEVELOPER_DIR" ]; then
              if [ -d "/Applications/Xcode.app/Contents/Developer" ]; then
                export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
              elif [ -d "/Applications/Xcode-26.app/Contents/Developer" ]; then
                export DEVELOPER_DIR="/Applications/Xcode-26.app/Contents/Developer"
              fi
            fi

            if [ -n "$DEVELOPER_DIR" ] && [ -x /usr/bin/xcrun ]; then
              export SDKROOT="$(DEVELOPER_DIR="$DEVELOPER_DIR" /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null)"
              export PATH="$DEVELOPER_DIR/usr/bin:$PATH"
            elif [ -x /usr/bin/xcrun ]; then
              export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null)"
            fi

            echo "🔑 Clavis Dev Environment"
            echo "Xcode:     $(/usr/bin/xcodebuild -version 2>/dev/null | head -1 || echo 'N/A')"
            echo "SDK:       $(/usr/bin/xcrun --sdk macosx --show-sdk-version 2>/dev/null || echo 'N/A')"
            echo "SDKROOT:   $SDKROOT"
            echo "Swift:     $(/usr/bin/xcrun swift --version 2>/dev/null | head -1 || echo 'N/A')"
          '';
        };
      }
    ) // {
      overlays.default = final: prev: {
        clavis = self.packages.${prev.system}.default;
      };
    };
}
