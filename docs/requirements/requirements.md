IDE-1898: The Eclipse plugin shall successfully complete LSP initialization regardless of the number of workspace folders.
IDE-1898: When a feature flag is deactivated, the IDE plugin shall observe the change within 60 seconds.
IDE-1898: When a user authenticates, the IDE plugin shall immediately re-evaluate feature flags without waiting for any previously cached authentication failures to expire.
IDE-1992: In IDEs that save automatically (e.g. VS Code), a user shall not lose unsaved settings changes when the settings panel is hidden or closed by the IDE, while any text or combo box input control has focus.
IDE-1992: In IDEs with an explicit OK/Cancel flow (IntelliJ, Eclipse, Visual Studio), a user shall see their settings saved when clicking the OK button in the settings panel while any text or combo box input control has focus.
IDE-1992: A user's settings shall remain unchanged when the settings panel is dismissed via the Cancel button, the Escape key (handled natively by the IDE dialog container, not the webview), or the panel close (X) button in IDEs with an explicit OK/Cancel flow (IntelliJ, Eclipse, Visual Studio).
IDE-1992: Each behaviour shall apply within the IDE scope stated in the relevant requirement above, covering all supported IDEs: VS Code, Eclipse, IntelliJ, and Visual Studio.
IDE-1992: The fallback settings HTML page (distributed separately because it is statically bundled in each IDE plugin rather than shipped with the LS binary) shall be automatically distributed to all IDE repos within one CI pipeline run after a change is merged to the main branch of snyk-ls.
IDE-1992: The fallback HTML page distributed to all IDE repos shall be the version that implements all behaviours described in the requirements above, including auto-save-on-hide for auto-save IDEs and save-on-OK / cancel-discard for IDEs with an explicit OK/Cancel flow.
IDE-2078: The tree-view hover style shall set both background and foreground using IDE theme variables so that text remains readable across light and dark themes.
IDE-2078: The tree-view hover style shall fall back to the list-active-selection variables when no IDE-supplied list-hover-foreground variable is provided.
IDE-2078: The tree-view CSS shall not hard-code colour values for the hover state; all colours shall come from CSS custom properties bound to `--vscode-*` variables (with sensible neutral fallbacks).
IDE-2078: Hover styling shall remain correct when the IDE injects its own theme CSS via the `${ideStyle}` placeholder.
