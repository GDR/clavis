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

            nativeBuildInputs = [ pkgs.swift pkgs.swiftpm ];
            buildInputs = [ appleSdk ];

            buildPhase = ''
              export HOME=$TMPDIR
              if [ -z "$SDKROOT" ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk ]; then
                export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
              fi
              swift build -c release --disable-sandbox
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp .build/release/Clavis $out/bin/clavis 2>/dev/null || true
              cp .build/release/age-plugin-clavis $out/bin/age-plugin-clavis 2>/dev/null || true
            '';
          } else pkgs.hello;

          default = packages.clavis;
        };

        apps = {
          clavis = flake-utils.lib.mkApp {
            drv = packages.clavis;
            name = "clavis";
          };
          default = apps.clavis;
        };

        devShells.default = pkgs.mkShell {
          name = "clavis-dev-shell";

          buildInputs = with pkgs; [
            swift
            swiftpm
            git
            sops
            age
          ] ++ (if isDarwin then [ appleSdk ] else []);

          shellHook = ''
            echo "🔑 Clavis Dev Environment"
            if [ -z "$SDKROOT" ] && [ -d /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk ]; then
              export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
            fi
            echo "Run 'swift build' to build Clavis and age-plugin-clavis."
            echo "Run 'swift test' to run unit tests."
          '';
        };
      }
    );
}
