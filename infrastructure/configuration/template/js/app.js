(function () {
	var dom = window.ConfigApp.dom;

	// Initialize on window load
	dom.addEvent(window, "load", function () {
		// Authentication buttons
		var authBtn = dom.get("authenticate-btn");
		if (authBtn && window.ConfigApp.authentication) {
			dom.addEvent(authBtn, "click", window.ConfigApp.authentication.authenticate);
		}

		var logoutBtn = dom.get("logout-btn");
		if (logoutBtn && window.ConfigApp.authentication) {
			dom.addEvent(logoutBtn, "click", window.ConfigApp.authentication.logout);
		}

		// Store original endpoint for auto-save change detection
		var endpointInput = dom.get("endpoint");
		if (endpointInput && window.ConfigApp.autoSave) {
			window.ConfigApp.autoSave.setOriginalEndpoint(endpointInput.value);
		}

		// Initialize all validation event listeners
		if (window.ConfigApp.validation) {
			window.ConfigApp.validation.initializeAllValidation();
		}

		// Initialize folder organization field toggles
		var folders = window.ConfigApp.folders;
		if (folders && folders.initializeFolderOrgFields) {
			folders.initializeFolderOrgFields();
		}

		// Add event listener for Add Trusted Folder button
		var addTrustedFolderBtn = dom.get("addTrustedFolderBtn");
		if (addTrustedFolderBtn && folders && folders.handleAddTrustedFolder) {
			dom.addEvent(addTrustedFolderBtn, "click", folders.handleAddTrustedFolder);
		}

		// Add event listeners for Remove Trusted Folder buttons
		if (folders && folders.initializeTrustedFolderHandlers) {
			folders.initializeTrustedFolderHandlers();
		}

		// Initialize dirty tracking (must happen before authFieldMonitor is registered as a change listener)
		var formState = window.ConfigApp.formState;
		if (formState && formState.initializeDirtyTracking) {
			formState.initializeDirtyTracking();
		}

		// Register auth field monitor as a change listener on the dirty tracker
		window.dirtyTracker.addChangeListener(window.ConfigApp.authFieldMonitor.onDataChange);

		// Set initial button states based on token presence at page load
		var tokenInput = dom.get("token");
		var hasToken = !!(tokenInput && tokenInput.value);
		var authBtn = dom.get("authenticate-btn");
		var logoutBtn = dom.get("logout-btn");
		if (authBtn) { authBtn.disabled = hasToken; }
		if (logoutBtn) { logoutBtn.disabled = !hasToken; }

		// Attach form state listeners (handles both dirty tracking and auto-save)
		if (formState && formState.attachFormStateListeners) {
			formState.attachFormStateListeners();
		}

		// Initialize tooltips
		if (window.ConfigApp.tooltips) {
			window.ConfigApp.tooltips.initialize();
		}

		// Initialize reset handlers
		if (window.ConfigApp.resetHandler) {
			window.ConfigApp.resetHandler.init();
		}
	});
})();
