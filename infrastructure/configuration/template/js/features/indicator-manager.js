// ABOUTME: Manages dynamic user-override indicators for folder-specific settings
// ABOUTME: Attaches listeners to inputs within .override-indicator-wrapper to toggle has-user-override class

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

		// Add the indicator permanently when user interacts with the field
		// It will only be removed by the reset button
		dom.addClass(wrapper, "has-user-override");

		// Remove the source indicator (office building emoji) since the value is now user-overridden
		var sourceIndicator = wrapper.querySelector(".source-indicator");
		if (sourceIndicator) {
			sourceIndicator.remove();
		}
	}

	// Special handling for auto-org checkbox changes
	function handleAutoOrgChange(autoOrgCheckbox) {
		var folderIndex = autoOrgCheckbox.getAttribute("data-index");
		if (!folderIndex) return;

		// Add indicator to the auto-org checkbox wrapper
		var autoOrgWrapper = autoOrgCheckbox.closest(".override-indicator-wrapper");
		if (autoOrgWrapper) {
			dom.addClass(autoOrgWrapper, "has-user-override");
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
			dom.removeClass(preferredOrgWrapper, "has-user-override");
		} else {
			// Auto-org is OFF: preferred_org is user-set, add indicator
			dom.addClass(preferredOrgWrapper, "has-user-override");
			// Also remove source indicator if present
			var sourceIndicator = preferredOrgWrapper.querySelector(".source-indicator");
			if (sourceIndicator) {
				sourceIndicator.remove();
			}
		}
	}

	window.ConfigApp.indicatorManager = indicatorManager;
})();
