// ABOUTME: Folder configuration management for organization fields and trusted folders
// ABOUTME: Handles folder-specific settings, organization field toggling, and trusted folder list management

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var folders = {};
	var dom = window.ConfigApp.dom;

	var trustedFolderIndex = 0;

	// === Organization Field Management ===

	// Toggle organization field based on auto-org checkbox
	// skipTrigger: if true, don't trigger dirty check/auto-save (used during initialization)
	folders.toggleOrgField = function(folderIndex, skipTrigger) {
		var autoOrgCheckbox = dom.get("folder_" + folderIndex + "_autoOrg");
		var orgInput = dom.get("folder_" + folderIndex + "_preferredOrg");
		var orgSetByUserInput = dom.get("folder_" + folderIndex + "_orgSetByUser");

		if (!autoOrgCheckbox || !orgInput || !orgSetByUserInput) {
			return;
		}

		var isAutoOrg = autoOrgCheckbox.checked;
		var preferredOrg = orgInput.getAttribute("data-preferred-org") || "";
		var autoOrg = orgInput.getAttribute("data-auto-org") || "";

		if (isAutoOrg) {
			// Auto select is ON: show AutoDeterminedOrg (readonly) and clear preferred org
			orgInput.value = autoOrg;
			orgInput.setAttribute("readonly", "readonly");
			orgInput.setAttribute("data-preferred-org", "");
			orgSetByUserInput.value = "false";
		} else {
			// Auto select is OFF: show PreferredOrg (editable)
			orgInput.value = preferredOrg;
			orgInput.removeAttribute("readonly");
			orgSetByUserInput.value = "true";
		}

		// Trigger dirty check and auto-save since we changed the value programmatically
		// Skip during initialization to avoid premature auto-save
		if (!skipTrigger) {
			var formState = window.ConfigApp.formState;
			if (formState && formState.triggerChangeHandlers) {
				formState.triggerChangeHandlers();
			}
		}
	};

	// Initialize all folder org fields on page load
	folders.initializeFolderOrgFields = function() {
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
				folders.toggleOrgField(folderIndex, true);

				// Attach click event listener (CSP-compliant)
				(function(index) {
					dom.addEvent(input, "change", function() {
						folders.toggleOrgField(index);
					});
				})(folderIndex);
			}
		}
	};

	// === Trusted Folder Management ===

	folders.handleAddTrustedFolder = function() {
		var trustedFoldersList = dom.get("trustedFoldersList");
		if (!trustedFoldersList) return;

		// Create new folder item
		var folderItem = document.createElement("div");
		folderItem.className = "trusted-folder-item";
		folderItem.setAttribute("data-index", trustedFolderIndex);
		folderItem.style.marginBottom = "10px";

		// Create button group container
		var buttonGroup = document.createElement("div");
		buttonGroup.className = "button-group";

		// Create text input
		var input = document.createElement("input");
		input.type = "text";
		input.name = "trustedFolder_" + trustedFolderIndex;
		input.placeholder = "/path/to/trusted/folder";

		// Attach blur listener for form state tracking
		var formState = window.ConfigApp.formState;
		if (formState && formState.triggerChangeHandlers) {
			dom.addEvent(input, "blur", formState.triggerChangeHandlers);
		}

		// Create remove button with X icon
		var removeBtn = document.createElement("button");
		removeBtn.type = "button";
		removeBtn.className = "remove-trusted-folder";
		removeBtn.setAttribute("data-index", trustedFolderIndex);
		removeBtn.setAttribute("title", "Remove");
		removeBtn.textContent = "✕";
		dom.addEvent(removeBtn, "click", folders.handleRemoveTrustedFolder);

		// Assemble elements
		buttonGroup.appendChild(input);
		buttonGroup.appendChild(removeBtn);
		folderItem.appendChild(buttonGroup);
		trustedFoldersList.appendChild(folderItem);

		trustedFolderIndex++;
	};

	folders.handleRemoveTrustedFolder = function() {
		var btn = this;
		var buttonGroup = btn.parentNode;
		var folderItem = buttonGroup ? buttonGroup.parentNode : null;
		if (folderItem && folderItem.parentNode) {
			folderItem.parentNode.removeChild(folderItem);
		}

		// Trigger dirty check and auto-save
		var formState = window.ConfigApp.formState;
		if (formState && formState.triggerChangeHandlers) {
			formState.triggerChangeHandlers();
		}
	};

	folders.initializeTrustedFolderHandlers = function() {
		// Initialize remove buttons
		var removeButtons = document.querySelectorAll(".remove-trusted-folder");
		for (var i = 0; i < removeButtons.length; i++) {
			dom.addEvent(removeButtons[i], "click", folders.handleRemoveTrustedFolder);
			var buttonGroup = removeButtons[i].parentNode;
			var folderItem = buttonGroup ? buttonGroup.parentNode : null;
			if (folderItem) {
				var index = parseInt(folderItem.getAttribute("data-index") || "0");
				if (index >= trustedFolderIndex) {
					trustedFolderIndex = index + 1;
				}
			}
		}
	};

	window.ConfigApp.folders = folders;
})();
