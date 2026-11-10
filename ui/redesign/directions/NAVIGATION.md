# Clavis · macOS 27 navigation alternatives

These five HTML interaction studies replace the former global navigation rail. The supplied `clavis-history-filter-studies.html#tokens` file is the visual/interaction reference. It was read, not modified. The existing key-layout studies remain available through `../previous.html`.

| Variant | Key selection | Navigation |
| --- | --- | --- |
| [01 · Reference Source List](01-reference-source.html) | One 218px source list with traffic lights, search, key glyphs and hairline row dividers | Compact controls in the content toolbar; profile management also accessible from the source-list footer |
| [02 · Compact Source List](02-compact-source.html) | A narrower, denser 184px list | A labeled toolbar group replaces the earlier app sidebar |
| [03 · Title-bar Picker](03-title-picker.html) | A transient key menu in the title bar | No permanent sidebar; settings/history/profiles use the full window |
| [04 · Horizontal Key Strip](04-key-strip.html) | A horizontal row of key buttons below the unified toolbar | No left column; key strip and toolbar remain outside the scrolling history |
| [05 · Key Browser](05-key-browser.html) | A compact full-width key table opens a key in place | Back returns to the key browser; history and profiles remain in the toolbar |

01 is closest to the reference window. 03–05 explore removing a permanent sidebar entirely. These are navigation alternatives, not five different authorization models.

## Preserved requirements

- No owner hierarchy, owner selectors, Requests/requesters screen or global authentication destination.
- Authentication is edited for the selected key in key settings.
- Application icons remain in history rows, profiles and access prompts.
- Profiles and first-use scope disclosure continue to use the existing shared mock model.
- History retains its token field, prefix suggestions, removable Key scope, date controls, sorting, grouped sticky date headings and expandable events.
- Selecting a key from the new source list or picker updates the existing history scope without discarding other tokens. Removing the Key token updates the external selection and retains Host/Process/Result criteria.
- All variants support light/dark and reduced-transparency previews and visible keyboard focus.

Glass is restricted to source-list/toolbar/control/transient layers. Content is an opaque reading surface. CSS provides an approximation of macOS materials, not Apple's native optical rendering. Event, key, verification and authentication data are fixtures. No backend or Swift behavior changes.

## Implementation

Each variant is a small HTML entry point using shared `style.css`, `navigation.css` and `app.js`. The earlier variants continue using their earlier window layouts. `history.html` supports a content-only embedding mode to prevent nested sidebars and a narrow parent/component message contract for key scope, appearance and focus. Messages are accepted only from the matching parent/frame window. The local comparison page uses live, noninteractive thumbnail frames and links to full prototypes.

## Verification, 2026-10-28

- All five navigation alternatives loaded and were visually inspected in the in-app browser at desktop size.
- 01: Host:github.com produced 16 matching fixture events. Selecting Personal Git preserved Host and added Key scope, narrowing to 2. Removing the Key token restored 16 events and deselected the source row while keeping Host.
- 03: the title key menu opened; selecting Personal Git produced its removable Key token and 15 matching events.
- 05: selecting Personal Git opened key settings in place with a Back control. Light appearance and reduced transparency were visually checked.
- JavaScript syntax and local asset/link checks are run before handoff. No real code-signing, authentication, security enforcement or native Swift rendering has been tested by these HTML studies.
