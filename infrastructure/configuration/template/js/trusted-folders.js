// ABOUTME: Trusted folder management functions for adding and removing trusted folders
// ABOUTME: Handles dynamic trusted folder list manipulation in the Permissions section

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var trustedFolders = {};
	var helpers = window.ConfigApp.helpers;

	var trustedFolderIndex = 0;

	trustedFolders.handleAddTrustedFolder = function() {
		var trustedFoldersList = helpers.get("trustedFoldersList");
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
		if (window.ConfigApp.formStateTracking && window.ConfigApp.formStateTracking.triggerChangeHandlers) {
			helpers.addEvent(input, "blur", window.ConfigApp.formStateTracking.triggerChangeHandlers);
		}

		// Create remove button with X icon
		var removeBtn = document.createElement("button");
		removeBtn.type = "button";
		removeBtn.className = "remove-trusted-folder";
		removeBtn.setAttribute("data-index", trustedFolderIndex);
		removeBtn.setAttribute("title", "Remove");
		removeBtn.textContent = "✕";
		helpers.addEvent(removeBtn, "click", trustedFolders.handleRemoveTrustedFolder);

		// Assemble elements
		buttonGroup.appendChild(input);
		buttonGroup.appendChild(removeBtn);
		folderItem.appendChild(buttonGroup);
		trustedFoldersList.appendChild(folderItem);

		trustedFolderIndex++;
	};

	trustedFolders.handleRemoveTrustedFolder = function() {
		var btn = this;
		var buttonGroup = btn.parentNode;
		var folderItem = buttonGroup ? buttonGroup.parentNode : null;
		if (folderItem && folderItem.parentNode) {
			folderItem.parentNode.removeChild(folderItem);
		}

		// Trigger dirty check and auto-save
		if (window.ConfigApp.formStateTracking && window.ConfigApp.formStateTracking.triggerChangeHandlers) {
			window.ConfigApp.formStateTracking.triggerChangeHandlers();
		}
	};

	trustedFolders.initializeTrustedFolderHandlers = function() {
		// Initialize remove buttons
		var removeButtons = document.querySelectorAll(".remove-trusted-folder");
		for (var i = 0; i < removeButtons.length; i++) {
			helpers.addEvent(removeButtons[i], "click", trustedFolders.handleRemoveTrustedFolder);
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

	window.ConfigApp.trustedFolders = trustedFolders;
})();
