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
        appleSdk = if isDarwin then (pkgs.apple-sdk_27 or pkgs.apple-sdk_26 or pkgs.apple-sdk_15) else null;
      in
      rec {
        packages = {
          clavis = if pkgs.stdenv.hostPlatform.isDarwin && pkgs.stdenv.hostPlatform.isAarch64 then pkgs.stdenv.mkDerivation rec {
            pname = "clavis";
            version = "0.1.1";

            src = pkgs.fetchurl {
              url = "https://github.com/GDR/clavis/releases/download/v${version}/clavis-macos-arm64.tar.gz";
              hash = "sha256-CReuciaXLe9hbG7sWvmVFZaehojNmU09M5a8BInybCI=";
            };

            sourceRoot = ".";

            dontConfigure = true;
            dontBuild = true;
            dontFixup = true;

            installPhase = ''
              mkdir -p $out/bin
              cp Clavis $out/bin/clavis
              cp clavis-agent $out/bin/clavis-agent
              cp clavis-cli $out/bin/clavis-cli
              cp age-plugin-clavis $out/bin/age-plugin-clavis
              cp -R Clavis_ClavisCore.bundle $out/bin/Clavis_ClavisCore.bundle

              # Preserve the complete application bundle and its CI signature.
              mkdir -p $out/Applications
              cp -R Clavis.app $out/Applications/Clavis.app
            '';

            meta = with pkgs.lib; {
              description = "Native macOS Swift/SwiftUI Ed25519 Keychain SSH Agent & age plugin with Touch ID";
              homepage = "https://github.com/GDR/clavis";
              license = licenses.mit;
              platforms = [ "aarch64-darwin" ];
              mainProgram = "clavis";
            };
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

          agent = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "clavis-agent" ''
              exec "${packages.clavis}/bin/clavis-agent" "$@"
            '';
            name = "clavis-agent";
          };

          cli = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "clavis-cli" ''
              exec "${packages.clavis}/bin/clavis-cli" "$@"
            '';
            name = "clavis-cli";
          };

          age-plugin = flake-utils.lib.mkApp {
            drv = pkgs.writeShellScriptBin "age-plugin-clavis" ''
              exec "${packages.clavis}/bin/age-plugin-clavis" "$@"
            '';
            name = "age-plugin-clavis";
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
              elif [ -d "/Applications/Xcode-beta.app/Contents/Developer" ]; then
                export DEVELOPER_DIR="/Applications/Xcode-beta.app/Contents/Developer"
              elif [ -d "/Applications/Xcode-27.app/Contents/Developer" ]; then
                export DEVELOPER_DIR="/Applications/Xcode-27.app/Contents/Developer"
              elif [ -d "/Applications/Xcode-26.app/Contents/Developer" ]; then
                export DEVELOPER_DIR="/Applications/Xcode-26.app/Contents/Developer"
              fi
            fi

            if [ -n "$DEVELOPER_DIR" ] && [ -x /usr/bin/xcrun ]; then
              export SDKROOT="$(DEVELOPER_DIR="$DEVELOPER_DIR" env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null)"
              export PATH="$DEVELOPER_DIR/usr/bin:$PATH"
            elif [ -x /usr/bin/xcrun ]; then
              export SDKROOT="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null)"
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
