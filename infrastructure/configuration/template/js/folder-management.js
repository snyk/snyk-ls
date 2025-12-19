// ABOUTME: Folder-specific configuration management functions
// ABOUTME: Handles organization field toggling and CLI path browsing for folder configs

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var folderManagement = {};
	var helpers = window.ConfigApp.helpers;

	// Toggle organization field based on auto-org checkbox
	folderManagement.toggleOrgField = function(folderIndex) {
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

		// Trigger dirty check since we changed the value programmatically
		if (window.ConfigApp.dirtyTracking && window.ConfigApp.dirtyTracking.debouncedDirtyCheck) {
			window.ConfigApp.dirtyTracking.debouncedDirtyCheck();
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

				// Initialize the field state
				folderManagement.toggleOrgField(folderIndex);

				// Attach click event listener (CSP-compliant)
				(function(index) {
					helpers.addEvent(input, "change", function() {
						folderManagement.toggleOrgField(index);
					});
				})(folderIndex);
			}
		}
	};

	// Handle file picker for CLI Path
	folderManagement.handleCliPathBrowse = function() {
		var filePicker = helpers.get("cliPathPicker");
		var cliPathInput = helpers.get("cliPath");

		if (!filePicker || !cliPathInput) {
			return;
		}

		// Trigger file picker
		filePicker.click();

		// When file is selected, update the CLI Path input
		helpers.addEvent(filePicker, "change", function () {
			if (filePicker.files && filePicker.files.length > 0) {
				cliPathInput.value = filePicker.files[0].path || filePicker.value;
				// Trigger auto-save if enabled
				if (window.__IS_IDE_AUTOSAVE_ENABLED__ && window.ConfigApp.autoSave) {
					window.ConfigApp.autoSave.debouncedSave();
				}
				// Trigger dirty check
				if (window.ConfigApp.dirtyTracking && window.ConfigApp.dirtyTracking.debouncedDirtyCheck) {
					window.ConfigApp.dirtyTracking.debouncedDirtyCheck();
				}
			}
		});
	};

	window.ConfigApp.folderManagement = folderManagement;
})();
