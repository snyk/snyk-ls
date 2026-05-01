// ABOUTME: Reset functionality for settings sections
// ABOUTME: Handles resetting individual sections and folder overrides to defaults

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var resetHandler = {};
	var dom = window.ConfigApp.dom;

	// Default values for each section
	var sectionDefaults = {
		scanConfiguration: {
			snyk_oss_enabled: false,
			snyk_code_enabled: false,
			snyk_iac_enabled: false,
			snyk_secrets_enabled: false,
			scan_automatic: "true",
			organization: ""
		},
		filteringDisplay: {
			severity_filter_critical: true,
			severity_filter_high: true,
			severity_filter_medium: true,
			severity_filter_low: true,
			issue_view_open_issues: true,
			issue_view_ignored_issues: false,
			risk_score_threshold: "",
			scan_net_new: "false"
		},
		authentication: {
			authentication_method: "oauth",
			api_endpoint: "https://api.snyk.io",
			proxy_insecure: false
		},
		cliConfiguration: {
			automatic_download: true,
			cli_release_channel: "stable",
			cli_release_channel_custom: "",
			binary_base_url: "https://downloads.snyk.io/"
		},
		permissions: {
			trusted_folders: []
		}
	};

	// Initialize reset handlers
	resetHandler.init = function () {
		// Attach click handlers to all reset section buttons
		var resetButtons = document.querySelectorAll(".reset-section-btn");
		for (var i = 0; i < resetButtons.length; i++) {
			resetButtons[i].addEventListener("click", handleSectionReset);
		}

		// Attach click handlers to all folder override reset buttons
		var overrideResetButtons = document.querySelectorAll(".reset-overrides-btn");
		for (var j = 0; j < overrideResetButtons.length; j++) {
			overrideResetButtons[j].addEventListener("click", handleFolderOverrideReset);
		}
	};

	// Handle section reset button click
	function handleSectionReset(event) {
		var section = event.target.getAttribute("data-section");
		if (!section || !sectionDefaults[section]) {
			console.warn("Unknown section for reset:", section);
			return;
		}

		if (!confirm("Reset " + formatSectionName(section) + " to defaults?")) {
			return;
		}

		var defaults = sectionDefaults[section];
		applyDefaults(defaults, section);

		// Trigger dirty tracking update
		if (window.dirtyTracker) {
			window.dirtyTracker.runChangeListeners();
			window.dirtyTracker.checkDirty();
		}
	}

	// Handle folder override reset button click
	function handleFolderOverrideReset(event) {
		var folderIndex = event.target.getAttribute("data-folder-index");
		if (folderIndex === null) {
			console.warn("No folder index for reset");
			return;
		}

		if (!confirm("Reset all overrides for this folder to defaults? Your custom overrides will be removed.")) {
			return;
		}

		resetFolderOverrides(parseInt(folderIndex));

		// Trigger dirty tracking update
		if (window.dirtyTracker) {
			window.dirtyTracker.runChangeListeners();
			window.dirtyTracker.checkDirty();
		}
	}

	// Apply default values to form fields
	function applyDefaults(defaults, section) {
		for (var fieldName in defaults) {
			if (!defaults.hasOwnProperty(fieldName)) continue;

			var defaultValue = defaults[fieldName];

			// Special handling for trusted folders
			if (fieldName === "trusted_folders") {
				resetTrustedFolders();
				continue;
			}

			var element = dom.get(fieldName) || dom.getByName(fieldName)[0];
			if (!element) continue;

			if (element.type === "checkbox") {
				element.checked = defaultValue;
			} else if (element.tagName === "SELECT") {
				element.value = defaultValue;
			} else {
				element.value = defaultValue;
			}

			// Hide custom version input when resetting cli_release_channel
			if (fieldName === "cli_release_channel_custom" && element.className.indexOf("d-none") === -1) {
				element.className += " d-none";
			}

			// Trigger change event for any listeners
			triggerChange(element);
		}
	}

	// Reset trusted folders to empty
	function resetTrustedFolders() {
		var container = dom.get("trustedFoldersList");
		if (container) {
			container.innerHTML = "";
		}
	}

	// Reset folder overrides - marks the folder so all org-scope fields are set to null on save
	function resetFolderOverrides(folderIndex) {
		// Mark the folder for reset — on save, formHandler.applyFolderResets() will
		// set all org-scope LspFolderConfig fields to null (clear overrides)
		if (window.ConfigApp.formHandler && window.ConfigApp.formHandler.markFolderForReset) {
			window.ConfigApp.formHandler.markFolderForReset(folderIndex);
		}
	}

	// Format section name for display
	function formatSectionName(section) {
		var names = {
			scanConfiguration: "Scan configuration",
			filteringDisplay: "Filters and views",
			authentication: "Authentication",
			cliConfiguration: "CLI configuration",
			permissions: "Trust settings"
		};
		return names[section] || section;
	}

	// Trigger change event on element
	function triggerChange(element) {
		var event;
		if (typeof Event === "function") {
			event = new Event("change", { bubbles: true });
		} else {
			event = document.createEvent("Event");
			event.initEvent("change", true, true);
		}
		element.dispatchEvent(event);
	}

	window.ConfigApp.resetHandler = resetHandler;
})();
