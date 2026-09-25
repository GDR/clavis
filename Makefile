.DEFAULT_GOAL := all

CONFIG ?= release
BUILD_DIR := .build/$(CONFIG)
ENTITLEMENTS := Entitlements.plist
BINARIES := $(BUILD_DIR)/Clavis $(BUILD_DIR)/clavis-agent $(BUILD_DIR)/clavis-cli $(BUILD_DIR)/age-plugin-clavis

SDKROOT ?= $(shell env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null)
export SDKROOT

CLAVIS_KEYCHAIN ?= $(KEYCHAIN_PATH)

CLAVIS_SIGN_IDENTITY ?= $(shell \
	TARGET_KEYCHAIN="$(if $(CLAVIS_KEYCHAIN),$(CLAVIS_KEYCHAIN),)"; \
	if /usr/bin/security find-identity -v -p codesigning $$TARGET_KEYCHAIN 2>/dev/null | grep -q "Apple Development"; then \
		echo "Apple Development"; \
	elif /usr/bin/security find-identity -v -p codesigning $$TARGET_KEYCHAIN 2>/dev/null | grep -q "Clavis Local Development"; then \
		echo "Clavis Local Development"; \
	elif [ "$${CLAVIS_ALLOW_ADHOC_SIGNING:-0}" = "1" ]; then \
		echo "-"; \
	fi)

.PHONY: all build sign package test clean help

all: build sign

build:
	@if [ ! -f "$$SDKROOT/SDKSettings.plist" ]; then \
		echo "❌ Active Xcode returned an invalid macOS SDK path: $$SDKROOT" >&2; \
		exit 1; \
	fi
	@mkdir -p .build && touch .build/.metadata_never_index
	@echo "🔨 Building Clavis (GUI), clavis-agent, clavis-cli, and age-plugin-clavis ($(CONFIG))..."
	@echo "  Using macOS SDK: $$SDKROOT"
	swift build -c $(CONFIG)

sign:
	@if [ -z "$(CLAVIS_SIGN_IDENTITY)" ]; then \
		echo "❌ No code-signing certificate found; refusing to create an unsigned/ad-hoc build." >&2; \
		echo "   Install a signing certificate, set CLAVIS_SIGN_IDENTITY, or pass CLAVIS_ALLOW_ADHOC_SIGNING=1." >&2; \
		exit 1; \
	fi
	@echo "🔐 Signing binaries with identity: '$(CLAVIS_SIGN_IDENTITY)'..."
	@for binary in $(BINARIES); do \
		if [ ! -x "$$binary" ]; then \
			echo "❌ Missing executable: $$binary" >&2; \
			exit 1; \
		fi; \
		echo "  Signing $$binary..."; \
		KEYCHAIN_ARG="$(if $(CLAVIS_KEYCHAIN),--keychain $(CLAVIS_KEYCHAIN),)"; \
		/usr/bin/codesign \
			--force \
			$$KEYCHAIN_ARG \
			--sign "$(CLAVIS_SIGN_IDENTITY)" \
			--identifier "Clavis" \
			--options runtime \
			--timestamp=none \
			--entitlements $(ENTITLEMENTS) \
			"$$binary"; \
		/usr/bin/codesign --verify --strict --verbose=2 "$$binary"; \
		SIGNED_ENT="$$(/usr/bin/codesign -d --entitlements - "$$binary" 2>&1)"; \
		if echo "$$SIGNED_ENT" | grep -Eq "keychain-access-groups|com.apple.security.application-groups"; then \
			echo "❌ Provisioning-dependent entitlement unexpectedly present in $$binary." >&2; \
			exit 1; \
		fi; \
		SIGN_DETAILS="$$(/usr/bin/codesign --display --verbose=4 "$$binary" 2>&1)"; \
		if ! echo "$$SIGN_DETAILS" | grep -Fq "Identifier=Clavis"; then \
			echo "❌ Shared Code Signing Identifier is missing from $$binary." >&2; \
			exit 1; \
		fi; \
		if [ "$(CLAVIS_SIGN_IDENTITY)" != "-" ]; then \
			if echo "$$SIGN_DETAILS" | grep -q "Signature=adhoc"; then \
				echo "❌ Expected certificate signing, but $$binary has an ad-hoc signature." >&2; \
				exit 1; \
			fi; \
			if [ -n "$${CLAVIS_EXPECTED_TEAM_ID:-}" ]; then \
				if ! echo "$$SIGN_DETAILS" | grep -Fq "TeamIdentifier=$$CLAVIS_EXPECTED_TEAM_ID"; then \
					echo "❌ $$binary is not signed by expected TeamIdentifier '$$CLAVIS_EXPECTED_TEAM_ID'." >&2; \
					exit 1; \
				fi; \
			fi; \
		fi; \
	done
	@echo "✅ Signing and verification complete."

package: all
	@echo "📦 Packaging artifacts..."
	tar -czf clavis-macos-arm64.tar.gz -C $(BUILD_DIR) Clavis clavis-agent clavis-cli age-plugin-clavis
	shasum -a 256 clavis-macos-arm64.tar.gz > clavis-macos-arm64.tar.gz.sha256
	@echo "✅ Created clavis-macos-arm64.tar.gz and checksum."

test:
	@mkdir -p .build && touch .build/.metadata_never_index
	swift test

clean:
	swift package clean
	rm -f clavis-macos-arm64.tar.gz clavis-macos-arm64.tar.gz.sha256

help:
	@echo "Available targets:"
	@echo "  make (or make all)   Build and sign release binaries"
	@echo "  make build           Compile release binaries with SwiftPM"
	@echo "  make sign            Codesign built binaries and verify integrity"
	@echo "  make package         Build, sign, and create release tar.gz + sha256"
	@echo "  make test            Run test suite"
	@echo "  make clean           Clean build outputs and archives"
