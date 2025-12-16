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

		// Endpoint validation
		var endpointInput = helpers.get("endpoint");
		if (endpointInput) {
			window.ConfigApp.autoSave.setOriginalEndpoint(endpointInput.value);
			// Add input event listener for real-time validation
			helpers.addEvent(endpointInput, "input", window.ConfigApp.validation.validateEndpointOnInput);
		}

		// Risk score validation
		var riskScoreInput = helpers.get("riskScoreThreshold");
		if (riskScoreInput) {
			// Add input event listener for real-time validation
			helpers.addEvent(riskScoreInput, "input", window.ConfigApp.validation.validateRiskScoreOnInput);
		}

		// Additional env validation
		var additionalEnvInput = helpers.get("additionalEnv");
		if (additionalEnvInput) {
			// Add input event listener for real-time validation
			helpers.addEvent(additionalEnvInput, "input", window.ConfigApp.validation.validateAdditionalEnvOnInput);
		}

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
		window.ConfigApp.dirtyTracking.initializeDirtyTracking();

		// Attach auto-save listeners to all form inputs
		window.ConfigApp.autoSave.attachAutoSaveListeners();

		// Attach dirty tracking listeners to all form inputs
		window.ConfigApp.dirtyTracking.attachDirtyTrackingListeners();

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
