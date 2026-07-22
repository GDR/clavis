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
      in
      {
        packages = rec {
          clavis = if isDarwin then pkgs.stdenv.mkDerivation {
            pname = "clavis";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs = [ pkgs.swift pkgs.swiftpm ];
            buildInputs = with pkgs.darwin.apple_sdk.frameworks; [
              Security
              LocalAuthentication
              AppKit
              Foundation
            ];

            buildPhase = ''
              export HOME=$TMPDIR
              swift build -c release --disable-sandbox
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp .build/release/Clavis $out/bin/clavis 2>/dev/null || true
              cp .build/release/age-plugin-clavis $out/bin/age-plugin-clavis 2>/dev/null || true
            '';
          } else pkgs.hello;

          default = clavis;
        };

        devShells.default = pkgs.mkShell {
          name = "clavis-dev-shell";

          buildInputs = with pkgs; [
            swift
            swiftpm
            git
            sops
            age
          ] ++ (if isDarwin then (with pkgs.darwin.apple_sdk.frameworks; [
            Security
            LocalAuthentication
            AppKit
            Foundation
          ]) else []);

          shellHook = ''
            echo "🔑 Clavis Dev Environment"
            echo "Run 'swift build' to build Clavis and age-plugin-clavis."
            echo "Run 'swift test' to run unit tests."
          '';
        };
      }
    );
}
