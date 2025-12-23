// ABOUTME: Main initialization script that wires up all event handlers and modules
// ABOUTME: Runs on window load to set up the complete configuration dialog functionality

(function () {
	var helpers = window.ConfigApp.helpers;

	// Initialize on window load
	helpers.addEvent(window, "load", function () {
		// Authentication buttons
		var authBtn = helpers.get("authenticate-btn");
		if (authBtn) {
			helpers.addEvent(authBtn, "click", window.ConfigApp.authentication.authenticate);
		}

		var logoutBtn = helpers.get("logout-btn");
		if (logoutBtn) {
			helpers.addEvent(logoutBtn, "click", window.ConfigApp.authentication.logout);
		}

		// Store original endpoint for auto-save change detection
		var endpointInput = helpers.get("endpoint");
		if (endpointInput) {
			window.ConfigApp.autoSave.setOriginalEndpoint(endpointInput.value);
		}

		// Initialize all validation event listeners
		window.ConfigApp.validation.initializeAllValidation();

		// Initialize folder organization field toggles
		window.ConfigApp.folderManagement.initializeFolderOrgFields();

		// Add event listener for Add Trusted Folder button
		var addTrustedFolderBtn = helpers.get("addTrustedFolderBtn");
		if (addTrustedFolderBtn) {
			helpers.addEvent(addTrustedFolderBtn, "click", window.ConfigApp.trustedFolders.handleAddTrustedFolder);
		}

		// Add event listeners for Remove Trusted Folder buttons
		window.ConfigApp.trustedFolders.initializeTrustedFolderHandlers();

		// Initialize dirty tracking
		window.ConfigApp.formStateTracking.initializeDirtyTracking();

		// Attach form state listeners (handles both dirty tracking and auto-save)
		window.ConfigApp.formStateTracking.attachFormStateListeners();

		// Initialize Bootstrap 4 tooltips
		if (typeof $ !== "undefined" && $.fn && $.fn.tooltip) {
			// All elements with data-toggle="tooltip" (spans inside labels, checkboxes, and buttons)
			$('[data-toggle="tooltip"]').tooltip({
				placement: 'top',
				boundary: 'window',
				trigger: 'hover'
			});
		}
	});
})();
