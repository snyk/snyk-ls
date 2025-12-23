// ABOUTME: Folder-specific configuration management functions
// ABOUTME: Handles organization field toggling and CLI path browsing for folder configs

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var folderManagement = {};
	var helpers = window.ConfigApp.helpers;

	// Toggle organization field based on auto-org checkbox
	// skipTrigger: if true, don't trigger dirty check/auto-save (used during initialization)
	folderManagement.toggleOrgField = function(folderIndex, skipTrigger) {
		var autoOrgCheckbox = helpers.get("folder_" + folderIndex + "_autoOrg");
		var orgInput = helpers.get("folder_" + folderIndex + "_preferredOrg");
		var orgSetByUserInput = helpers.get("folder_" + folderIndex + "_orgSetByUser");

		if (!autoOrgCheckbox || !orgInput || !orgSetByUserInput) {
			return;
		}

		var isAutoOrg = autoOrgCheckbox.checked;
		var preferredOrg = orgInput.getAttribute("data-preferred-org") || "";
		var autoOrg = orgInput.getAttribute("data-auto-org") || "";

		if (isAutoOrg) {
			// Auto select is ON: show AutoDeterminedOrg (readonly)
			orgInput.value = autoOrg;
			orgInput.setAttribute("readonly", "readonly");
			orgSetByUserInput.value = "false";
		} else {
			// Auto select is OFF: show PreferredOrg (editable)
			orgInput.value = preferredOrg;
			orgInput.removeAttribute("readonly");
			orgSetByUserInput.value = "true";
		}

		// Trigger dirty check and auto-save since we changed the value programmatically
		// Skip during initialization to avoid premature auto-save
		if (!skipTrigger && window.ConfigApp.formStateTracking && window.ConfigApp.formStateTracking.triggerChangeHandlers) {
			window.ConfigApp.formStateTracking.triggerChangeHandlers();
		}
	};

	// Initialize all folder org fields on page load
	folderManagement.initializeFolderOrgFields = function() {
		var allInputs = document.getElementsByTagName("input");
		for (var i = 0; i < allInputs.length; i++) {
			var input = allInputs[i];
			var inputId = input.id || "";
			if (
				input.type === "checkbox" &&
				inputId.indexOf("_autoOrg") !== -1 &&
				input.getAttribute("data-index") !== null
			) {
				var folderIndex = input.getAttribute("data-index");

				// Initialize the field state (skip triggering handlers during init)
				folderManagement.toggleOrgField(folderIndex, true);

				// Attach click event listener (CSP-compliant)
				(function(index) {
					helpers.addEvent(input, "change", function() {
						folderManagement.toggleOrgField(index);
					});
				})(folderIndex);
			}
		}
	};

	window.ConfigApp.folderManagement = folderManagement;
})();
