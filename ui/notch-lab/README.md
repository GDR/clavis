# Clavis direction 11 — focus-aware approval prototype

Open `index.html` directly in a browser. Standalone HTML/CSS/JavaScript, with no dependencies, real authentication or network requests.

Only direction 11 remains. Animation selectors, timing/easing controls, other layout directions and requester-to-key animation graphics were removed. Opening/closing transitions remain and honor the OS reduced-motion preference.

The operation (Sign a Git commit or Authenticate with SSH) occupies the upper-right shoulder previously labeled Review request. There is no duplicate operation row below the identities.

The prompt opens focused. Review app/key and session duration, then Continue to reveal Touch ID and the inline password fallback. Losing focus (clicking outside, tabbing out, window blur or a hidden browser tab) collapses the session picker, step hint and action rows, and reduces panel opacity to 82%. App/key and operation stay visible; an agent warning remains visible, and Touch ID stays visible after Continue. Clicking or tabbing back into the panel restores the controls. Scope, review step and password-drawer state are preserved. Losing focus never completes or denies a request.

Hidden controls are inert. External controls offer replay, three mock request scenarios, desktop appearance and simulated authentication results. Password entry substitutes a fixed demo value; Verify simulates approval. Native rendering, policy enforcement and device authentication are outside this prototype.

Simulation controls are exempt from prompt focus loss: pointer activation preserves prompt focus, and keyboard focus moving into the simulation controls does not collapse the panel. Failed-scan simulation replays a short fingerprint shake and expanding red ring, followed by persistent error copy. Clicking the mock desktop still collapses normally. Reduced motion suppresses the failure animation.

Two heading arrangements are selectable above the mock display: A places the icons at the outside edges (app icon + app name → key name + key icon); B places each icon before its label. The identity heading is centered below the physical notch. Process ancestry and Personal key remain secondary labels; the operation stays in the top-right shoulder. Switching headings preserves scope, authentication step and password-drawer state, and does not collapse the prompt.
