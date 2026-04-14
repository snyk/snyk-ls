// ABOUTME: Main initialization script that wires up all event handlers and modules
// ABOUTME: Runs on window load to set up the complete configuration dialog functionality

(function () {
	var dom = window.ConfigApp.dom;

	// Initialize on window load
	dom.addEvent(window, "load", function () {
		// Authentication buttons
		var authBtn = dom.get("authenticate-btn");
		dom.addEvent(authBtn, "click", window.ConfigApp.authentication.authenticate);

		var logoutBtn = dom.get("logout-btn");
		dom.addEvent(logoutBtn, "click", window.ConfigApp.authentication.logout);

		// Initialize all validation event listeners
		window.ConfigApp.validation.initializeAllValidation();

		// Initialize folder organization field toggles
		var folders = window.ConfigApp.folders;
		folders.initializeFolderOrgFields();

		// Add event listener for Add Trusted Folder button
		var addTrustedFolderBtn = dom.get("addTrustedFolderBtn");
		dom.addEvent(addTrustedFolderBtn, "click", folders.handleAddTrustedFolder);

		// Add event listeners for Remove Trusted Folder buttons
		folders.initializeTrustedFolderHandlers();

		// Initialize dirty tracking
		var formState = window.ConfigApp.formState;
		formState.initializeDirtyTracking();

		// Attach form state listeners (handles both dirty tracking and auto-save)
		formState.attachFormStateListeners();

		// Register auth field monitor to detect endpoint/authMethod changes requiring re-auth
		window.dirtyTracker.addChangeListener(window.ConfigApp.authFieldMonitor.onDataChange);

		// Initialize auth controls visibility and disabled states
		if (window.ConfigApp.authFieldMonitor.syncAuthControls) {
			window.ConfigApp.authFieldMonitor.syncAuthControls();
		}

		// Initialize tabs and folder dropdown
		try { window.ConfigApp.tabs.initialize(); } catch (e) { if (typeof console !== 'undefined') console.error('tabs init failed:', e); }

		// Initialize tooltips
		window.ConfigApp.tooltips.initialize();

		// Initialize reset handlers
		window.ConfigApp.resetHandler.init();
	});
})();
