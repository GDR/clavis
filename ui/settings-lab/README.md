# Clavis main window: assessment and interactive study

**Selected implementation direction: [02 · Prominent](http://127.0.0.1:8786/?header=prominent).** See the [Gemini 4 Swift implementation specification](GEMINI_IMPLEMENTATION_PROMPT.md) for approved requirements, repository stories, Apple references, and native acceptance criteria. The comparison page still defaults to Balanced; that default is not the selected implementation direction.

Open `index.html` directly, or serve this folder:

```sh
python3 -m http.server 8786 --bind 127.0.0.1 --directory ui/settings-lab
```

Then visit http://127.0.0.1:8786. No build, dependencies, remote assets, or backend.

## Why the current window feels different

The screenshots already contain several good macOS patterns: a source list, system accent selection, inset form dividers, right-aligned values, and standard switches. The problem is the relationship between the window chrome, surfaces, and controls. Enlarging or shrinking every element would not fix it. The attached screenshots appear to use Retina scaling; image pixels must not be treated as macOS layout points.

1. **The toolbar is visually imitated inside the sidebar.** `WindowManager.swift` creates an empty `NSToolbar`, while `KeyListView.sidebarHeader` draws its own controls and reserves space for traffic lights with `Spacer(minLength: 72)`. `SidebarHeaderPillButton` fixes a plain button label to 30 × 24 points with a 13-point symbol. `AdaptiveGlassCapsule` applies the material to the shared parent. Consequently, three unrelated actions read as segments in one narrow pill, rather than system-owned toolbar actions. The buttons can be too shallow even when their symbols appear large in the screenshot. The outer padding in `sidebarHeader` is outside the capsule; it does not provide the same internal breathing room as native toolbar layout.
2. **The transparency is asymmetric by construction.** The root uses `.underWindowBackground` with `.behindWindow`, and the actual window is clear/nonopaque. But `DesignTokens.inspectorBackground` overlays that material with alpha 0.96 in dark mode and 0.98 in light mode. The sidebar's alpha is 0.35/0.55. This explains the tinted sidebar next to the nearly solid charcoal inspector. Window transparency alone cannot solve that opaque overlay.
3. **The form is recognizably native in structure but visually overoutlined.** `SettingsGroupCardModifier` strokes every group with a 1-point border; the groups also have a distinct fill and row dividers. Together these produce a nested-panel appearance. Keep row alignment and grouping, soften the outside edges, and use fewer competing contrasts. The existing 13-point labels and approximately 38–40-point rows are already reasonable; this is not a blanket typography-size problem.
4. **A lot of custom work now owns system behavior.** `GlassComponents.swift` includes scroll-pocket inspection and backdrop-group adjustments using AppKit implementation class names/selectors. These may address actual rendering bugs, but they are fragile foundations for native appearance. Reassess their necessity when moving actions into the actual toolbar; do not remove them blindly before testing the affected scroll behavior.

System Settings in the reference is primarily a legible form, with subdued surface separation. It is not a reason to turn every form group into Liquid Glass. Clavis can borrow its rhythm while allowing more desktop atmosphere into the main window.

## Proposed direction

- Keep the two-pane key library and inspector. This study does not change Clavis's data model.
- Put **New Key** and **Lock** above the key library as separate sidebar toolbar actions. Put **History** at the trailing edge of the main toolbar. Remove the redundant Key Settings title. History has a text label to make its purpose explicit.
- Use a single blurred foundation. Use closely matched pane tints, with only four percentage points of opacity difference. The default is intentionally restrained; a more transparent option lets the user compare how much wallpaper is comfortable.
- Keep form groups flat. Quiet fills, subtle half-pixel browser edges, and inset separators provide structure without raised glass cards.
- Use the existing hierarchy with small improvements: compact key header, separate metadata line, short helper copy, aligned trailing controls, consistent gaps between sections.
- Preserve a legible opaque mode and distinguish an inactive window. Support light/dark appearance and reduced motion.

### Study metrics, not Apple requirements

| Element | HTML study target |
| --- | --- |
| Toolbar band | 56 CSS px |
| Toolbar controls | 36 CSS px high, 18 px symbols |
| Sidebar | 246 px, narrower at compact widths |
| Body / helper text | 13 / 11 px |
| Form rows | 42 px minimum |
| Group radius | 10 px |
| Inspector width | Up to 720 px including insets |

These are visual exploration values, not an Apple-prescribed universal toolbar size. CSS pixels and browser font rendering are not proof of native macOS point metrics. The production app should inherit standard control sizes and let the toolbar manage placement.

## Native implementation recommendation

1. Populate the real `NSToolbar` with standard items, using an `NSToolbarItemGroup` only for genuinely related actions, or move to a window structure where SwiftUI `.toolbar` owns the toolbar. Choose one owner. Use a split-view tracking separator for sidebar alignment if staying with AppKit. Avoid maintaining a second fake toolbar in content.
2. Start with automatic/regular button styles and control size. Remove the fixed 30 × 24 label frames, custom hover fills, and the shared New/History/Lock capsule. Native toolbar items get their platform appearance from the system; do not add another glass background on top.
3. Prefer `NavigationSplitView`/a real split view for sidebar geometry and a grouped `Form` with `Section`, standard `Picker`, `Toggle`, and `LabeledContent` for the inspector. Native form defaults are the baseline; customize only after comparing the running app with System Settings at the same display scale.
4. Keep `NSWindow.isOpaque = false` and a clear hosting surface if required by the chosen material implementation. Establish one semantic, behind-window visual-effect foundation. Replace the almost-opaque inspector token with a deliberately denser but translucent reading surface. Tune against real wallpaper; the CSS alpha values are not Swift implementation constants. `.underWindowBackground` is not interchangeable with Liquid Glass.
5. Respect Reduce Transparency, Increase Contrast, active/inactive appearance, light/dark, and older-macOS fallbacks. Make long fingerprints truncate in the middle, with full values accessible to assistive technology and copy actions.
6. Verify on the native app at the current 958 × 724 default and 713 × 610 minimum sizes, then on a larger window. Check scrolling, toolbar overflow, traffic-light alignment, keyboard focus, sheets, inactive selection, different displays/scales, and a busy desktop. Browser acceptance cannot establish native Liquid Glass correctness.

## Interactions and boundaries

Implemented: search, key selection, inline rename (Enter/blur commits, Escape cancels), in-memory key creation/deletion, profile/confirmation selectors, capability toggles, adding/removing sample applications, copying clearly marked sample values, key-scoped/all-key sample History, Back, simulated Lock/Unlock, appearance/material/wallpaper switching, inactive state, and design notes. Reload resets all sample state. Cmd/Ctrl+F and Cmd/Ctrl+N work while the study has focus; browser shortcuts may intercept Cmd/Ctrl+L.

The form is a layout study. It does not validate or implement the production authorization policy. Bot/profile options are illustrative and need to be mapped to actual supported settings before any native port. The GitHub link opens GitHub's SSH-key page; it does not upload a key. Traffic lights are decorative. Settings explains the study controls. Unlock explicitly simulates success. Clipboard strings are sample data, not valid cryptographic keys.

The wallpaper is drawn in CSS. Backdrop blur approximates a frosted window but does not recreate system refraction, native vibrancy, dynamic Liquid Glass responses, or blur of other applications. No Swift files were changed for this study.

## Apple references

- [Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass): use standard components/spacing and apply custom glass sparingly.
- [Toolbars](https://developer.apple.com/design/human-interface-guidelines/toolbars): logical grouping, standard components, useful titles, fewer custom backgrounds, system-managed overflow.
- [Materials](https://developer.apple.com/design/human-interface-guidelines/materials): maintain hierarchy and legibility while using translucent surfaces.
- [Meet Liquid Glass, WWDC25](https://developer.apple.com/videos/play/wwdc2025/219/): distinguish the control/navigation layer from content and avoid stacking glass.

## Verification performed

Browser-reviewed at 958 × 724 and 713 × 610 outer window sizes: no horizontal page/inspector overflow; the inspector scrolls and the sidebar footer stays within the window. Also reviewed the narrower default browser panel, dark/balanced and light/clear materials, and light/reduced-transparency/inactive state over a high-contrast desktop. Exercised key navigation, scoped/all-key History, creation, rename, capability toggles, application add/remove, empty search results, simulated lock/unlock, and design notes. Checked HTML ID uniqueness, SVG references, required files, and whitespace. An initial SVG/control ID collision was fixed before these checks. Native Swift builds and native visual acceptance were outside this prototype change.

## Follow-up refinement

Removed the Key Settings toolbar label; moved Lock beside New Key in the sidebar toolbar. Search uses a 32px-high rounded glass capsule with readable 13px text, a subtle edge highlight, and a shortcut revealed on hover/focus. Sidebar and detail now use nearly identical neutral tints with a four-percentage-point opacity difference in both translucent modes. Opaque fallbacks also use closely related colors.

## Sticky key header

Key identity now occupies the top of the main pane. Its default 40px icon shares a center line with the 36px History, Lock, and New Key controls; both pane toolbar bands are 56px tall. The header sits inside the inspector scroll container with `position: sticky`. As form content passes beneath it, it gains a blurred translucent backing and a subtle lower edge. Rename and key changes update the sticky identity directly. This remains a browser approximation of Liquid Glass; the native port should use the system toolbar and scroll-edge APIs.

## Five larger header variants

Use the Key Header selector above the window, or open `?header=balanced`, `?header=prominent`, `?header=badge`, `?header=stacked`, or `?header=quiet`. Balanced is the default. All five use a 56px toolbar band, 36px action buttons, a shared vertical center line, sticky placement, and the same scroll-dependent glass backing. Switching variants preserves selected key, form state, and scroll position.

| Variant | Identity treatment |
| --- | --- |
| Balanced | 40px icon, 22px name, 11px metadata |
| Prominent | 48px icon, 24px bold name |
| Type badge | 40px icon, 22px name with inline profile badge |
| Stacked | 44px icon, type eyebrow, 23px name, hardware below |
| Quiet | 40px neutral icon, 24px medium-weight name |

At compact widths, long names and metadata truncate to preserve the full-sized History button. Lock, New Key, and History remain 32px high in every variant.

Verified all five variants in-browser: all action heights are 32px, all icon/action center lines match, no header/action overlap, and no horizontal page overflow at the reviewed panel width. Also checked light appearance and profile badge updates when changing keys.

## Glass sidebar footer

The sidebar footer is a pinned translucent control surface. Long key lists scroll behind its blurred backing; bottom content padding allows the final key to be brought fully above it. At rest the background is continuous with the sidebar, without a darker fill, divider or shadow. A masked vertical blur gradient progressively diffuses rows passing underneath; the sidebar tint is not applied a second time. Reduce Transparency uses an opaque fallback. The current footer controls are preserved; changing them to a status-only footer or moving Settings remains a proposal, not an approved change.

The footer gradient modulates only its glass/blur mask when key rows underlap it. It never paints a background gradient or additional tint. Without underlapping rows the glass overlay is disabled, leaving the sidebar surface unchanged.

The top bands were compacted from 88px to 56px after comparison with Contacts. Prominent retains its 48px icon, 24px title and 36px action controls; controls and traffic lights now center 28px below the window top, with 4px clearance above the icon. Search moves upward with the shortened band.

Top toolbar action controls were increased to 36px high with 18px symbols, retaining the 56px header band and shared 28px center line. Search remains 32px high.

## Header spacing solutions (not yet selected)

Three additional spacing studies are available in the Spacing selector, independently of the five identity variants:

- `?header=balanced&layout=comfortable`: 64px shared band, same title/icon, 4px extra padding above and below.
- `?header=balanced&layout=light`: original 56px band, 36px icon, 20px title, shorter metadata; algorithm remains in the detail content.
- `?header=balanced&layout=two-tier`: 56px primary row plus a 24px sticky metadata strip; the icon/actions remain centered at 28px, while metadata gets its own line below.

No spacing solution is selected for native implementation yet. The existing approved implementation spec remains unchanged pending selection.

## In-app key-settings authentication study

Open [settings-auth.html](settings-auth.html) / [live preview](http://127.0.0.1:8786/settings-auth.html?header=prominent&layout=light). This separate page uses Prominent + Lighter Identity and stages key-specific SSH/Git capability or Personal/Bot type changes behind an in-window Touch ID sheet. See [interaction and native handoff notes](settings-auth.README.md). Authentication, demo-password verification, save outcomes and settings are simulated; no real credentials are requested. Use the displayed demo password `clavis`.

## Compact approval alternatives

The large in-app approval sheet was rejected as too large. [Eight compact alternatives](settings-auth-variants.html?approval=1) now explore three sliding Liquid Glass panels plus five other in-window layouts. See [comparison notes](settings-auth-variants.README.md). No compact direction has been selected for native implementation.

The approval comparison has since been rebuilt as [eight distinct architectures](approval-designs.html), with different review flows and DOM structures. [Research notes](settings-auth-design-research.md) link the Apple guidance and public product references that informed each direction.
