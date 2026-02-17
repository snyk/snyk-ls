// ABOUTME: Reset functionality for settings sections
// ABOUTME: Handles resetting individual sections and folder overrides to defaults

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var resetHandler = {};
	var dom = window.ConfigApp.dom;

	// Default values for each section
	var sectionDefaults = {
		scanConfiguration: {
			activateSnykOpenSource: false,
			activateSnykCode: false,
			activateSnykIac: false,
			scanningMode: "auto",
			organization: ""
		},
		filteringDisplay: {
			filterSeverity_critical: true,
			filterSeverity_high: true,
			filterSeverity_medium: true,
			filterSeverity_low: true,
			issueViewOptions_openIssues: true,
			issueViewOptions_ignoredIssues: false,
			riskScoreThreshold: "",
			enableDeltaFindings: "false"
		},
		authentication: {
			authenticationMethod: "oauth",
			endpoint: "https://api.snyk.io",
			insecure: false
		},
		cliConfiguration: {
			manageBinariesAutomatically: true,
			cliReleaseChannel: "stable",
			cliBaseDownloadURL: "https://downloads.snyk.io/"
		},
		permissions: {
			trustedFolders: []
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
		if (window.ConfigApp.dirtyTracker) {
			window.ConfigApp.dirtyTracker.checkDirty();
		}
	}

	// Handle folder override reset button click
	function handleFolderOverrideReset(event) {
		var folderIndex = event.target.getAttribute("data-folder-index");
		if (folderIndex === null) {
			console.warn("No folder index for reset");
			return;
		}

		if (!confirm("Reset all overrides for this folder to organization defaults? Your custom overrides will be removed.")) {
			return;
		}

		resetFolderOverrides(parseInt(folderIndex));

		// Trigger dirty tracking update
		if (window.ConfigApp.dirtyTracker) {
			window.ConfigApp.dirtyTracker.checkDirty();
		}
	}

	// Apply default values to form fields
	function applyDefaults(defaults, section) {
		for (var fieldName in defaults) {
			if (!defaults.hasOwnProperty(fieldName)) continue;

			var defaultValue = defaults[fieldName];

			// Special handling for trusted folders
			if (fieldName === "trustedFolders") {
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

		// Visual feedback - update source badges to show they will be reset
		updateSourceBadgesForReset(folderIndex);
	}

	// Update source badges to show pending reset
	function updateSourceBadgesForReset(folderIndex) {
		var container = dom.get("folder-" + folderIndex + "-overrides");
		if (!container) return;

		var badges = container.querySelectorAll(".source-badge");
		for (var i = 0; i < badges.length; i++) {
			var badge = badges[i];
			// Only update non-locked badges
			if (!badge.classList.contains("source-org-locked")) {
				badge.textContent = "Will Reset";
				badge.className = "source-badge source-default";
			}
		}
	}

	// Format section name for display
	function formatSectionName(section) {
		var names = {
			scanConfiguration: "Scan Configuration",
			filteringDisplay: "Filtering and Display",
			authentication: "Authentication",
			cliConfiguration: "CLI Configuration",
			permissions: "Permissions"
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
