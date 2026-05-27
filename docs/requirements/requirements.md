IDE-1992: A user shall not lose unsaved settings changes when closing the settings panel while any input control has focus.
IDE-1992: A user shall see their settings saved when clicking the OK button in the settings panel while any input control has focus.
IDE-1992: A user's settings shall remain unchanged when the settings panel is dismissed via the Cancel button or the panel close (X) button.
IDE-1992: The behaviours described in the requirements above shall apply in all supported IDEs: VS Code, Eclipse, IntelliJ, and Visual Studio.
IDE-1992: The fallback settings HTML page (distributed separately because it is statically bundled in each IDE plugin rather than shipped with the LS binary) shall be automatically distributed to all IDE repos within one CI pipeline run after a change is merged to the main branch of snyk-ls.
IDE-1992: The fallback HTML page distributed to all IDE repos shall be the version that implements the save-on-OK and cancel-discard behaviours described in the requirements above.
