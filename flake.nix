{
  description = "Clavis — Native macOS Swift/SwiftUI Secure Enclave SSH Agent with Touch ID";

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

        perlesSources = {
          "aarch64-darwin" = {
            suffix = "darwin_arm64";
            hash = "sha256-/RJc8TQI/e6TFXKcwhxwdwYFbUmEZwPGCqNDEMjPlKM=";
          };
          "x86_64-darwin" = {
            suffix = "darwin_amd64";
            hash = "sha256-SLfwYqbKCLSFbjJue1XQ+eUUHQuntg/j0t7/sP80IfY=";
          };
          "aarch64-linux" = {
            suffix = "linux_arm64";
            hash = "sha256-UoIqFM28Y8/qYsbxLr9ogUW5N2Pw4l/WgiJx+BS4iyI=";
          };
          "x86_64-linux" = {
            suffix = "linux_amd64";
            hash = "sha256-sRGhQ8955towf1slR3fMXtkw7FDDgP0pEnZVhJqO+W0=";
          };
        };

        perles =
          let
            version = "0.9.0";
            srcInfo = perlesSources.${system} or null;
          in
          if srcInfo != null then
            pkgs.stdenvNoCC.mkDerivation {
              pname = "perles";
              inherit version;

              src = pkgs.fetchurl {
                url = "https://github.com/zjrosen/perles/releases/download/v${version}/perles_${version}_${srcInfo.suffix}.tar.gz";
                hash = srcInfo.hash;
              };

              sourceRoot = ".";

              dontConfigure = true;
              dontBuild = true;
              dontFixup = true;

              installPhase = ''
                runHook preInstall
                install -Dm755 perles "$out/bin/perles"
                runHook postInstall
              '';

              meta = with pkgs.lib; {
                description = "Terminal UI for beads issue tracking";
                homepage = "https://github.com/zjrosen/perles";
                license = licenses.mit;
                platforms = builtins.attrNames perlesSources;
                mainProgram = "perles";
              };
            }
          else
            null;
      in
      rec {
        packages = {
          clavis = if pkgs.stdenv.hostPlatform.isDarwin && pkgs.stdenv.hostPlatform.isAarch64 then pkgs.stdenv.mkDerivation rec {
            pname = "clavis";
            version = "0.4.5";

            src = pkgs.fetchurl {
              url = "https://github.com/GDR/clavis/releases/download/v${version}/clavis-macos-arm64.tar.gz";
              hash = "sha256-Asg7oVoZU1sn51a+sxePDjmp8PMbW/5akFRlWRA5tgw=";
            };

            sourceRoot = ".";

            dontConfigure = true;
            dontBuild = true;
            dontFixup = true;

            installPhase = ''
              mkdir -p $out/bin $out/Applications

              # Preserve the complete application bundle and its CI signature.
              cp -R Clavis.app $out/Applications/Clavis.app

              # Wrap executables into Clavis.app so Bundle.main.executableURL resolves
              # inside the bundle for AgentLifecycleManager and Bundle.clavisCore.
              cat > $out/bin/clavis-cli <<EOF
              #!/bin/sh
              exec "$out/Applications/Clavis.app/Contents/Helpers/clavis-cli" "\$@"
              EOF

              cat > $out/bin/clavis <<EOF
              #!/bin/sh
              exec "$out/Applications/Clavis.app/Contents/MacOS/Clavis" "\$@"
              EOF

              cat > $out/bin/clavis-agent <<EOF
              #!/bin/sh
              exec "$out/Applications/Clavis.app/Contents/Helpers/Clavis Agent.app/Contents/MacOS/clavis-agent" "\$@"
              EOF

              chmod +x $out/bin/clavis $out/bin/clavis-agent $out/bin/clavis-cli
            '';

            meta = with pkgs.lib; {
              description = "Native macOS Swift/SwiftUI Secure Enclave SSH Agent with Touch ID";
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

          default = apps.clavis;
        };

        devShells.default = pkgs.mkShellNoCC {
          name = "clavis-dev-shell";

          packages = with pkgs; [
            just
            git
            cmake
            ninja
            pkg-config
            swiftformat
            swiftlint
            sops
            age
            beads
          ] ++ pkgs.lib.optional (perles != null) perles;

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
              export PATH="$DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin:$DEVELOPER_DIR/usr/bin:$PATH"
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
