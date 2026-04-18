// ABOUTME: Manages dynamic user-override indicators for folder-specific and project default settings
// ABOUTME: Attaches listeners to inputs within .override-indicator-wrapper to toggle source-override class
// ABOUTME: For project defaults, also triggers propagation to folder fields

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var indicatorManager = {};
	var dom = window.ConfigApp.dom;

	// Initialize indicator listeners
	indicatorManager.initialize = function () {
		var wrappers = document.querySelectorAll(".override-indicator-wrapper");

		for (var i = 0; i < wrappers.length; i++) {
			var wrapper = wrappers[i];
			var input = findInputElement(wrapper);

			if (!input) continue;

			// Attach change listener
			dom.addEvent(input, "change", function (e) {
				handleInputChange(e.target);
			});

			// For text inputs, also attach input event for real-time feedback
			if (input.type === "text") {
				dom.addEvent(input, "input", function (e) {
					handleInputChange(e.target);
				});
			}
		}
	};

	// Find the input element within a wrapper
	function findInputElement(wrapper) {
		var input = wrapper.querySelector("input");
		if (input) return input;

		var select = wrapper.querySelector("select");
		if (select) return select;

		return null;
	}

	// Handle input change event
	function handleInputChange(input) {
		// Special handling for auto-org checkbox
		if (input.type === "checkbox" && input.id && input.id.indexOf("_auto_org") !== -1) {
			handleAutoOrgChange(input);
			return;
		}

		// Find the parent .override-indicator-wrapper
		var wrapper = input.closest(".override-indicator-wrapper");
		if (!wrapper) return;

		// Check if this is a project default field (in #fallbacks-pane)
		var fallbacksPane = document.getElementById("fallbacks-pane");
		var isProjectDefault = fallbacksPane && fallbacksPane.contains(wrapper);

		// Add the appropriate indicator class when user interacts with the field
		// It will only be removed by the reset button
		var indicatorClass = isProjectDefault ? "source-global" : "source-override";

		// Remove all source classes before adding the new one
		dom.removeClass(wrapper, "source-[^\\s]*");
		dom.addClass(wrapper, indicatorClass);

		// Remove the source indicator (office building emoji) since the value is now user-overridden
		var sourceIndicator = wrapper.querySelector(".source-indicator");
		if (sourceIndicator) {
			sourceIndicator.remove();
		}

		// If this is a project default field, trigger propagation to folder fields
		if (isProjectDefault) {
			var settingName = input.name;
			var newValue = getInputValue(input);
			indicatorManager.propagateProjectDefaultToFolders(settingName, newValue);
		}
	}

	// Get the value from an input element
	function getInputValue(input) {
		if (input.type === "checkbox") {
			return input.checked;
		}
		return input.value;
	}

	// Propagate project default changes to folder fields
	// When a project default is changed, update all folder fields that inherit from it
	indicatorManager.propagateProjectDefaultToFolders = function(settingName, newValue) {
		// Find all folder panes
		var folderPanes = document.querySelectorAll(".folder-pane");

		for (var i = 0; i < folderPanes.length; i++) {
			// Look for the corresponding folder field
			// Folder fields are named: folder_{{$index}}_override_{{settingName}}
			var folderFieldName = "folder_" + i + "_override_" + settingName;
			var folderInput = dom.getByName(folderFieldName)[0];

			if (!folderInput) continue;

			// Only update if the folder field doesn't have a user override or is org set
			var folderWrapper = folderInput.closest(".override-indicator-wrapper");
			if (!folderWrapper) continue;

			// Skip if field has user override or is org-locked
			if (dom.hasClass(folderWrapper, "source-override") ||
			    dom.hasClass(folderWrapper, "source-org-locked") ||
			    dom.hasClass(folderWrapper, "source-org")) {
				continue;
			}

			// Update the field value to match the project default
			if (folderInput.type === "checkbox") {
				folderInput.checked = newValue;
			} else {
				folderInput.value = newValue;
			}
		}
	};

	// Special handling for auto-org checkbox changes
	function handleAutoOrgChange(autoOrgCheckbox) {
		var folderIndex = autoOrgCheckbox.getAttribute("data-index");
		if (!folderIndex) return;

		// Add indicator to the auto-org checkbox wrapper
		var autoOrgWrapper = autoOrgCheckbox.closest(".override-indicator-wrapper");
		if (autoOrgWrapper) {
			dom.addClass(autoOrgWrapper, "source-override");
			var sourceIndicator = autoOrgWrapper.querySelector(".source-indicator");
			if (sourceIndicator) {
				sourceIndicator.remove();
			}
		}

		// Update indicator on the preferred_org wrapper based on auto-org state
		var preferredOrgInput = dom.get("folder_" + folderIndex + "_preferred_org");
		if (!preferredOrgInput) return;

		var preferredOrgWrapper = preferredOrgInput.closest(".override-indicator-wrapper");
		if (!preferredOrgWrapper) return;

		var isAutoOrg = autoOrgCheckbox.checked;

		if (isAutoOrg) {
			// Auto-org is ON: preferred_org is auto-determined, remove indicator
			dom.removeClass(preferredOrgWrapper, "source-override");
		} else {
			// Auto-org is OFF: preferred_org is user-set, add indicator
			dom.addClass(preferredOrgWrapper, "source-override");
			// Also remove source indicator if present
			var sourceIndicator = preferredOrgWrapper.querySelector(".source-indicator");
			if (sourceIndicator) {
				sourceIndicator.remove();
			}
		}
	}

	window.ConfigApp.indicatorManager = indicatorManager;
})();
