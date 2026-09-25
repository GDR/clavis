.DEFAULT_GOAL := all

CONFIG ?= release
BUILD_DIR := .build/$(CONFIG)
ENTITLEMENTS := Entitlements.plist
BINARIES := $(BUILD_DIR)/Clavis $(BUILD_DIR)/clavis-agent $(BUILD_DIR)/clavis-cli $(BUILD_DIR)/age-plugin-clavis
RESOURCE_BUNDLE := $(BUILD_DIR)/Clavis_ClavisCore.bundle
APP_BUNDLE := $(BUILD_DIR)/Clavis.app
APP_CONTENTS := $(APP_BUNDLE)/Contents
APP_HELPERS := $(APP_CONTENTS)/Helpers/clavis-agent $(APP_CONTENTS)/Helpers/clavis-cli $(APP_CONTENTS)/Helpers/age-plugin-clavis
DMG_STAGING_DIR := $(BUILD_DIR)/dmg
DMG := clavis-macos-arm64.dmg
CLAVIS_VERSION ?= 0.1.0
CLAVIS_BUILD_VERSION ?= 1

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

.PHONY: all build bundle sign dmg package test clean help

all: sign

build:
	@if [ ! -f "$$SDKROOT/SDKSettings.plist" ]; then \
		echo "❌ Active Xcode returned an invalid macOS SDK path: $$SDKROOT" >&2; \
		exit 1; \
	fi
	@mkdir -p .build && touch .build/.metadata_never_index
	@echo "🔨 Building Clavis (GUI), clavis-agent, clavis-cli, and age-plugin-clavis ($(CONFIG))..."
	@echo "  Using macOS SDK: $$SDKROOT"
	swift build -c $(CONFIG)

bundle: build
	@if [ ! -d "$(RESOURCE_BUNDLE)" ]; then \
		echo "❌ Missing SwiftPM resource bundle: $(RESOURCE_BUNDLE)" >&2; \
		exit 1; \
	fi
	@echo "📦 Assembling Clavis.app..."
	rm -rf "$(APP_BUNDLE)"
	mkdir -p "$(APP_CONTENTS)/MacOS" "$(APP_CONTENTS)/Helpers" "$(APP_CONTENTS)/Resources"
	cp "$(BUILD_DIR)/Clavis" "$(APP_CONTENTS)/MacOS/Clavis"
	cp "$(BUILD_DIR)/clavis-agent" "$(APP_CONTENTS)/Helpers/clavis-agent"
	cp "$(BUILD_DIR)/clavis-cli" "$(APP_CONTENTS)/Helpers/clavis-cli"
	cp "$(BUILD_DIR)/age-plugin-clavis" "$(APP_CONTENTS)/Helpers/age-plugin-clavis"
	cp packaging/macos/Info.plist "$(APP_CONTENTS)/Info.plist"
	/usr/bin/plutil -replace CFBundleShortVersionString -string "$(CLAVIS_VERSION)" "$(APP_CONTENTS)/Info.plist"
	/usr/bin/plutil -replace CFBundleVersion -string "$(CLAVIS_BUILD_VERSION)" "$(APP_CONTENTS)/Info.plist"
	/usr/bin/ditto "$(RESOURCE_BUNDLE)" "$(APP_CONTENTS)/Resources/Clavis_ClavisCore.bundle"
	/usr/bin/plutil -lint "$(APP_CONTENTS)/Info.plist"

sign: bundle
	@if [ -z "$(CLAVIS_SIGN_IDENTITY)" ]; then \
		echo "❌ No code-signing certificate found; refusing to create an unsigned/ad-hoc build." >&2; \
		echo "   Install a signing certificate, set CLAVIS_SIGN_IDENTITY, or pass CLAVIS_ALLOW_ADHOC_SIGNING=1." >&2; \
		exit 1; \
	fi
	@echo "🔐 Signing binaries with identity: '$(CLAVIS_SIGN_IDENTITY)'..."
	@for binary in $(BINARIES) $(APP_HELPERS); do \
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
			"$$binary" || exit 1; \
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
	@echo "  Signing $(APP_BUNDLE)..."
	@KEYCHAIN_ARG="$(if $(CLAVIS_KEYCHAIN),--keychain $(CLAVIS_KEYCHAIN),)"; \
	/usr/bin/codesign \
		--force \
		$$KEYCHAIN_ARG \
		--sign "$(CLAVIS_SIGN_IDENTITY)" \
		--identifier "Clavis" \
		--options runtime \
		--timestamp=none \
		--entitlements $(ENTITLEMENTS) \
		"$(APP_BUNDLE)" || exit 1; \
	/usr/bin/codesign --verify --deep --strict --verbose=2 "$(APP_BUNDLE)"; \
	SIGN_DETAILS="$$(/usr/bin/codesign --display --verbose=4 "$(APP_BUNDLE)" 2>&1)"; \
	if ! echo "$$SIGN_DETAILS" | grep -Fq "Identifier=Clavis"; then \
		echo "❌ Shared Code Signing Identifier is missing from $(APP_BUNDLE)." >&2; \
		exit 1; \
	fi; \
	if [ "$(CLAVIS_SIGN_IDENTITY)" != "-" ]; then \
		if echo "$$SIGN_DETAILS" | grep -q "Signature=adhoc"; then \
			echo "❌ Expected certificate signing, but $(APP_BUNDLE) has an ad-hoc signature." >&2; \
			exit 1; \
		fi; \
		if [ -n "$${CLAVIS_EXPECTED_TEAM_ID:-}" ] && ! echo "$$SIGN_DETAILS" | grep -Fq "TeamIdentifier=$$CLAVIS_EXPECTED_TEAM_ID"; then \
			echo "❌ $(APP_BUNDLE) is not signed by expected TeamIdentifier '$$CLAVIS_EXPECTED_TEAM_ID'." >&2; \
			exit 1; \
		fi; \
	fi
	@echo "✅ Signing and verification complete."

dmg: all
	@echo "💿 Creating $(DMG)..."
	rm -rf "$(DMG_STAGING_DIR)"
	rm -f "$(DMG)" "$(DMG).sha256"
	mkdir -p "$(DMG_STAGING_DIR)"
	/usr/bin/ditto "$(APP_BUNDLE)" "$(DMG_STAGING_DIR)/Clavis.app"
	ln -s /Applications "$(DMG_STAGING_DIR)/Applications"
	/usr/sbin/diskutil image create from \
		--format UDZO \
		--volumeName "Clavis" \
		"$(DMG_STAGING_DIR)" \
		"$(DMG)"
	/usr/bin/hdiutil verify "$(DMG)"
	shasum -a 256 "$(DMG)" > "$(DMG).sha256"
	@echo "✅ Created $(DMG) and checksum."

package: dmg
	@echo "📦 Packaging artifacts..."
	tar -czf clavis-macos-arm64.tar.gz -C $(BUILD_DIR) \
		Clavis \
		clavis-agent \
		clavis-cli \
		age-plugin-clavis \
		Clavis_ClavisCore.bundle \
		Clavis.app
	shasum -a 256 clavis-macos-arm64.tar.gz > clavis-macos-arm64.tar.gz.sha256
	@echo "✅ Created clavis-macos-arm64.tar.gz and checksum."

test:
	@mkdir -p .build && touch .build/.metadata_never_index
	swift test

clean:
	swift package clean
	rm -f clavis-macos-arm64.tar.gz clavis-macos-arm64.tar.gz.sha256 "$(DMG)" "$(DMG).sha256"

help:
	@echo "Available targets:"
	@echo "  make (or make all)   Build, bundle, and sign the release"
	@echo "  make build           Compile release binaries with SwiftPM"
	@echo "  make bundle          Assemble Clavis.app with helpers and resources"
	@echo "  make sign            Codesign standalone binaries and Clavis.app"
	@echo "  make dmg             Create a drag-to-Applications disk image"
	@echo "  make package         Create the DMG, Nix archive, and checksums"
	@echo "  make test            Run test suite"
	@echo "  make clean           Clean build outputs and archives"
