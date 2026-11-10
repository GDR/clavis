# Clavis · Five key-first UX studies

The [current comparison page](../index.html) contains five navigation alternatives based on the preferred history window. See [navigation notes](NAVIGATION.md). The earlier key-layout comparison is preserved in [previous.html](../previous.html).

Open either page directly or with a loopback server:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory ui/redesign
```

No backend, dependencies or external assets are required. All data and authentication are simulated; changes reset on reload.

## Directions

| Prototype | Key browsing |
| --- | --- |
| [01 · Library](01-library.html) | Navigation, a left key list, and right inspector |
| [02 · Key Table](02-key-table.html) | Compact native-style table; selected key opens its settings sheet |
| [03 · Key Settings](03-key-settings.html) | Keys inside the navigation sidebar; per-key settings in the main pane |
| [04 · Split View](04-split-view.html) | Toolbar navigation; key source list on the left and inspector on the right |
| [05 · Menu Bar](05-menu-bar.html) | Compact popover opening a full key-management window |

There is no named-owner entity, owner selector, Requests/requesters view, or global authentication destination. Application code identity and process verification remain relevant to access decisions. Earlier URLs redirect to the revised directions.

Each direction includes Keys, Application Profiles and Activity. Authentication is edited from each key's settings. App icons are retained in profiles, access prompts and activity. Access approval is a transient dialog with Allow Once, Always for This Key and Add to Profile scopes. Profile expansion lists all affected keys and operations before confirmation.

## History reference

`history.html` adapts the supplied local `clavis-history-filter-studies.html#tokens` reference, preserving its search expressions, suggestions, removable tokens, date and sort controls, expandable events, incremental loading and sticky date groups. It adds app icons and receives the current prototype's keys and simulated decisions. It is isolated in an iframe to avoid collisions between the reference's CSS/event handlers and the five window layouts. The original file is not modified.

A key-specific activity action adds a removable Key filter. Removing that token broadens to all keys while preserving the other filters. Same-field values combine with OR; different fields combine with AND. A general Activity navigation action starts without key scope. The history component follows parent light/dark and reduced-transparency previews.

## Shared controls and materials

`app.js` supplies mock data, access scopes, profiles, key settings and controls. `style.css` supplies color, spacing, radius, shadow and material tokens. Glass belongs to navigation and control layers; reading surfaces use conventional materials. CSS approximates native macOS materials and does not reproduce Apple's rendering.

Use Appearance and Glass/Solid to preview material modes. CSS supports reduced motion, reduced transparency and increased contrast. Cmd/Ctrl+N creates a mock key; Cmd/Ctrl+K focuses key search. History supports Cmd/Ctrl+F, token suggestions and ordinary keyboard navigation. Escape dismisses menus/dialogs. Key creation starts with no application grants. Key disabling preserves configured grants while making them ineffective. Long-lived authentication options are explicitly experimental mock settings.

## Design sources

- [Apple: Designing for macOS](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/)
- [Apple: Materials](https://developer.apple.com/design/human-interface-guidelines/materials)
- [Apple: Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/liquid-glass)
- [Apple: Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass)

## Verification scope

JavaScript syntax, local assets and whitespace are checked. Browser review covers revised key layouts, removal of owner/requester/global-policy navigation and embedded token history. This does not validate real process attribution, macOS authentication, Swift rendering, system accessibility preferences or cryptographic behavior.

Revision checks on 2026-10-28: Key Table, Key Settings and Split View were visually inspected in the browser; primary navigation shows only Keys, Application Profiles and Activity. Key creation has Name and Purpose, with no owner selector. In Activity, Personal Git scope yielded 15 events; adding Host:github.com narrowed to 2, and removing only the Key token retained Host:github.com and broadened to 16 events. The requested source file was read and copied, not modified.
