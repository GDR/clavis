# Native Halo management lock screen

Implemented on 2026-11-05 from `clavis-ux/ux/lock_screen/?design=4` and decision D-34.

The locked gate now uses a behind-window AppKit material across the title-bar region, a centered bundled icon and identity, one native Liquid Glass authentication bar, and an inset password control. The existing nonopaque, clear AppKit window and hosting layer are retained. macOS 13–25 use native regular material for the bar. Reduce Transparency supplies opaque surfaces; Increased Contrast strengthens boundaries and secondary text.

Halo uses feathered static Core Graphics bitmaps and Core Animation transforms/opacity. The colour field rotates inside a stationary elliptical feather mask, so the outer silhouette does not spin. Rotation takes 42 seconds; breathing takes 12 seconds per direction. Only decorative layers animate, and they stop when inactive, hidden, minimized or under Reduce Motion. The native window clips the decoration; it is excluded from hit testing and accessibility.

Password presentation coexists with the system-owned `LAAuthenticationView`. Evaluation waits for that view to mount. Submitting the Mac login password cancels the biometric context and changes the attempt generation; stale completions cannot unlock, overwrite lockout state or clear a replacement attempt. Deactivation and dismissal cancel pending work and clear view secrets. The existing PIN form and PIN recovery service remain in use; the new direct password verifier rejects PIN modes. The active locked Halo screen starts passive biometrics, including after idle or Lock Now; PIN-mode automatic-prompt suppression is retained.

The footer uses acknowledged request-pause state and agent availability. Unknown daemon state is displayed as unknown rather than implying signing is available. The local daemon reported unknown availability during live review.

## Public API limitation

An exact three-failed-scan application limit is **not implemented**. The public [`LAAuthenticationView`](https://developer.apple.com/documentation/localauthenticationembeddedui/laauthenticationview) interface supplies a context and control size, with no delegate or per-fingerprint-failure callback. [`LAContext.evaluatePolicy`](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)) replies when the evaluation finishes; that completion must not be counted as one scan. Both interfaces were checked against the installed macOS 27 SDK headers.

System `.biometryLockout` is honoured at availability checks and evaluation completion. A terminal `.authenticationFailed` result also latches the screen into password-required recovery. Refocus, reconstruction, reopening and replacement contexts do not reset that state. There is no retry button. Only successful management authentication clears the application latch; the next biometric availability check still honours any remaining system lockout. The number of scans macOS allows before its terminal result remains OS-controlled.

## Automated validation

- Debug executable build passed.
- Optimized release executable build passed.
- Application suite passed: **418 tests in 36 suites**, including mount-before-evaluate, unavailable sensor, immediate system lockout, persistent terminal failure, password/biometric races, stale context replacement, deactivation, cancellation ordering, and PIN protection.
- Halo compositor tests check timing, removal of animation work, visible colour and transparent bitmap edges.
- `git diff --check` passed.

Commands:

```sh
swift build --product Clavis
swift build -c release --product Clavis
CLAVIS_HALO_CAPTURE_DIR="$PWD/.build/halo-review" swift test \
  --filter ClavisAppTests --enable-swift-testing --disable-xctest
```

## Native review and screenshots

The development bundle was rebuilt, signed with its existing Apple Development identity and relaunched. The installed Nix/Home Manager application and signing daemon were not replaced.

Live review on macOS 27.0.1 covered Light and Dark, the real embedded Touch ID glyph, password focus and blue focus ring, reveal preserving a harmless typed test value, Return submission, field clearing, inline incorrect-password feedback, Reduce Transparency, Increased Contrast and Reduce Motion. Backgrounding cancels the embedded glyph; returning/opening activates passive evaluation. The system appearance/accessibility preferences used for review were restored to their original values: Dark; Reduce Motion off; Reduce Transparency off; Increase Contrast off.

Live screenshots appear in the implementation chat. Reproducible **inactive native layout renders**, distinct from live composited screenshots and hardware acceptance, are exported by `HaloLockLayoutCaptureTests` into `.build/halo-review/`:

- `light-typical.png`, `dark-typical.png`: 958 × 724 point content.
- `light-minimum.png`, `dark-minimum.png`: 713 × 610 point content.
- `light-narrow.png`: 460 × 610 point adaptation, below the current application minimum.
- `light-contrast.png`: high-contrast AppKit appearance.
- `light-unavailable.png`, `dark-locked.png`: injected sensor/lockout presentation.

These renders have no live sensor, desktop backdrop, title-bar controls or authentication attempt. They validate layout, not full window compositing. Offscreen caching does not reproduce Liquid Glass vibrancy reliably: labels within inactive glass can have incorrect colours, especially in Dark. Use the live screenshots in the chat for material and contrast review. The narrower layout reserves extra room for its stacked status footer and an inline error. Native minimum-size resizing was attempted through the automation surface but did not change the window; minimum/narrow inspection therefore used the render captures.

## Physical-device acceptance still required

- Successful real fingerprint and correct Mac-password authentication into the real key list, with no intermediate screen. Automated tests verify the direct gate transition; no real credential was supplied during review.
- Real failed fingerprint scans, hardware removal/unavailability and system lockout. Those states were injected in automated coverage; no real lockout was deliberately induced.
- Desktop/wallpaper translucency across varied backgrounds and displays, and older macOS material fallback. Window-only captures do not establish wallpaper acceptance.
- A spoken VoiceOver pass and keyboard navigation with the user's preferred macOS keyboard-navigation settings. Accessibility labels and native controls were inspected through the accessibility tree.

## Responsive and material refinement

Following review of the tall-window screenshot, the identity and authentication bar now form one centered group with a fixed 40-point gap. The status footer is independently anchored 20 points above the window bottom. Extra height sits outside the group rather than enlarging the gap between identity and authentication. The Halo remains aligned with the identity, grows modestly with width and caps its scale. The native backdrop now uses the lighter sidebar material at full opacity. An initial 86% opacity treatment was rejected during live review because it removed the perceived blur; that treatment has been removed. Increased Contrast retains the original under-window material and Reduce Transparency retains the opaque fallback.

The refinement passed 30 focused layout, compositor and lock-screen tests, including the stationary mask and animation stop checks. Layout captures now also include `dark-tall.png` (1030 × 1010 points), `dark-full-screen.png` and `light-full-screen.png` (1728 × 1080 points). These remain inactive render captures with the compositing limitations described above.
