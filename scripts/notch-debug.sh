#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

resolve_sdkroot() {
    local sdkroot
    sdkroot="$(env -u SDKROOT /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    if [ ! -f "$sdkroot/SDKSettings.plist" ]; then
        echo "error: invalid macOS SDK path: $sdkroot" >&2
        exit 1
    fi
    printf '%s' "$sdkroot"
}

build_harness() {
    local sdkroot bin_dir
    sdkroot="$(resolve_sdkroot)"
    mkdir -p .build && touch .build/.metadata_never_index
    SDKROOT="$sdkroot" swift build --target NotchDebugHarness >&2
    bin_dir="$(SDKROOT="$sdkroot" swift build --target NotchDebugHarness --show-bin-path)"
    printf '%s/NotchDebugHarness' "$bin_dir"
}

usage() {
    cat <<'EOF'
Usage:
  scripts/notch-debug.sh play [scenario=open] [harness flags...]
  scripts/notch-debug.sh capture [scenario=all] [harness flags...]
  scripts/notch-debug.sh record [seconds=4] [out_dir=/private/tmp/clavis-notch-debug]
  scripts/notch-debug.sh slice <video.mov> [harness flags...]
  scripts/notch-debug.sh notch-rect [harness flags...]

Examples:
  ./scripts/notch-debug.sh play open --anim-scale 0.25
  ./scripts/notch-debug.sh capture open --anim-scale 0.25 --frames 12
  ./scripts/notch-debug.sh capture all --out /private/tmp/clavis-notch-debug/after
  ./scripts/notch-debug.sh capture open --screencapture
  ./scripts/notch-debug.sh record 4
  ./scripts/notch-debug.sh slice /path/to/recording.mov --motion --out strip.png
EOF
}

cmd="${1:-help}"
if [ $# -gt 0 ]; then
    shift
fi

case "$cmd" in
    play)
        scenario="open"
        if [ $# -gt 0 ] && [[ "${1}" != -* ]]; then
            scenario="$1"
            shift
        fi
        bin="$(build_harness)"
        exec "$bin" play --scenario "$scenario" "$@"
        ;;
    capture)
        scenario="all"
        if [ $# -gt 0 ] && [[ "${1}" != -* ]]; then
            scenario="$1"
            shift
        fi
        bin="$(build_harness)"
        exec "$bin" capture --scenario "$scenario" "$@"
        ;;
    record)
        seconds="4"
        out_dir="/private/tmp/clavis-notch-debug"
        if [ $# -gt 0 ] && [[ "${1}" != -* ]]; then
            seconds="$1"
            shift
        fi
        if [ $# -gt 0 ] && [[ "${1}" != -* ]]; then
            out_dir="$1"
            shift
        fi
        mkdir -p "$out_dir"
        bin="$(build_harness)"
        rect="$("$bin" notch-rect)"
        stamp="$(date +%Y%m%d-%H%M%S)"
        mov_path="$out_dir/live-$stamp.mov"
        strip_path="$out_dir/live-$stamp-strip.png"
        echo "Recording notch region ($rect) for ${seconds}s -> $mov_path"
        /usr/sbin/screencapture -v -R "$rect" -V "$seconds" -x "$mov_path"
        "$bin" slice "$mov_path" --motion --out "$strip_path" "$@"
        echo "Video:     $mov_path"
        echo "Filmstrip: $strip_path"
        ;;
    slice)
        if [ $# -lt 1 ]; then
            usage >&2
            exit 1
        fi
        bin="$(build_harness)"
        exec "$bin" slice "$@"
        ;;
    notch-rect)
        bin="$(build_harness)"
        exec "$bin" notch-rect "$@"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo "error: unknown command '$cmd'" >&2
        usage >&2
        exit 1
        ;;
esac
