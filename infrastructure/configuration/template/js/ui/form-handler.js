// ABOUTME: Form data collection and serialization functions
// ABOUTME: Handles gathering all form inputs and converting them to JSON format

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var formHandler = {};
	var dom = window.ConfigApp.dom;

	// Collect form data
	formHandler.collectData = function () {
		var data = {
			folderConfigs: [],
			trustedFolders: [],
		};

		var form = dom.get("configForm");
		if (!form) return data;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");

		// Process all elements (global settings, folder-scope fields, scanConfig)
		processElements(inputs, data);
		processElements(selects, data);

		// Process complex global objects
		processFilterSeverity(data);
		processIssueViewOptions(data);

		// Process per-folder org-scope overrides into LspFolderConfig-shaped fields
		processFolderOverrides(data);

		return data;
	};

	function processElements(elements, data) {
		for (var i = 0; i < elements.length; i++) {
			var el = elements[i];
			var name = el.name;

			if (!name) continue;

			// Skip complex object fields (handled separately)
			if (
				name.indexOf("filterSeverity_") === 0 ||
				name.indexOf("issueViewOptions_") === 0
			) {
				continue;
			}

			// Trusted folder logic: trustedFolder_INDEX
			if (name.indexOf("trustedFolder_") === 0) {
				// Only add non-empty values
				if (el.value && el.value.trim()) {
					data.trustedFolders.push(el.value);
				}
				continue;
			}

			// Folder logic: folder_INDEX_FIELD or folder_INDEX_scanConfig_PRODUCT_FIELD
			if (name.indexOf("folder_") === 0) {
				var parts = name.split("_");
				if (parts.length >= 3) {
					var index = parseInt(parts[1]);

					if (!data.folderConfigs[index]) {
						data.folderConfigs[index] = {};
					}

					// Skip override fields — handled by processFolderOverrides()
					if (parts[2] === "override") {
						continue;
					}

					// Check if this is a scanConfig field: folder_INDEX_scanConfig_PRODUCT_PARTS_FIELD
					if (parts.length >= 5 && parts[2] === "scanConfig") {
						// Product name is everything between "scanConfig" and the last part (field name)
						// e.g., folder_0_scanConfig_Snyk_Open_Source_preScanCommand
						// parts = ["folder", "0", "scanConfig", "Snyk", "Open", "Source", "preScanCommand"]
						// product = "Snyk Open Source"
						// field = "preScanCommand"
						var productParts = parts.slice(3, -1); // ["Snyk", "Open", "Source"]
						var product = productParts.join(" ");
						var field = parts[parts.length - 1]; // "preScanCommand"

						if (!data.folderConfigs[index].scanCommandConfig) {
							data.folderConfigs[index].scanCommandConfig = {};
						}
						if (!data.folderConfigs[index].scanCommandConfig[product]) {
							data.folderConfigs[index].scanCommandConfig[product] = {};
						}

						if (el.type === "checkbox") {
							data.folderConfigs[index].scanCommandConfig[product][field] =
								el.checked;
						} else {
							// Always set the value, even if empty, to allow clearing
							data.folderConfigs[index].scanCommandConfig[product][field] =
								el.value;
						}
					} else {
						var field = parts.slice(2).join("_");
						if (field === "additionalParameters") {
							// Split by whitespace and filter out empty strings
							data.folderConfigs[index][field] = el.value ? el.value.trim().split(/\s+/).filter(function(item) { return item.length > 0; }) : [];
							continue;
						}

						// Skip preferredOrg if orgSetByUser is false (auto-org is enabled)
						if (field === "preferredOrg") {
							var orgSetByUserInput = dom.get("folder_" + index + "_orgSetByUser");
							if (orgSetByUserInput && orgSetByUserInput.value === "false") {
								continue;
							}
						}

						setFieldValue(data.folderConfigs[index], field, el);
					}
				}
			} else {
				// Global setting
				setFieldValue(data, name, el);
			}
		}
	}

	function setFieldValue(obj, field, el) {
		if (el.type === "checkbox") {
			obj[field] = el.checked;
		} else if (el.type === "number") {
			obj[field] = el.value ? parseInt(el.value) : null;
		} else {
			// Convert string boolean values to actual booleans
			if (el.value === "true") {
				obj[field] = true;
			} else if (el.value === "false") {
				obj[field] = false;
			} else {
				obj[field] = el.value;
			}
		}
	}

	function processFilterSeverity(data) {
		var critical = dom.getByName("filterSeverity_critical")[0];
		var high = dom.getByName("filterSeverity_high")[0];
		var medium = dom.getByName("filterSeverity_medium")[0];
		var low = dom.getByName("filterSeverity_low")[0];

		if (critical || high || medium || low) {
			data.filterSeverity = {
				critical: critical ? critical.checked : false,
				high: high ? high.checked : false,
				medium: medium ? medium.checked : false,
				low: low ? low.checked : false,
			};
		}
	}

	function processIssueViewOptions(data) {
		var openIssues = dom.getByName("issueViewOptions_openIssues")[0];
		var ignoredIssues = dom.getByName("issueViewOptions_ignoredIssues")[0];

		if (openIssues || ignoredIssues) {
			data.issueViewOptions = {
				openIssues: openIssues ? openIssues.checked : false,
				ignoredIssues: ignoredIssues ? ignoredIssues.checked : false,
			};
		}
	}

	// Collect per-folder org-scope override fields and map them to LspFolderConfig JSON field names.
	// The HTML form uses "folder_X_override_*" names; this maps them to the LspFolderConfig wire format
	// so the IDE can treat them identically to $/snyk.folderConfigs notifications.
	function processFolderOverrides(data) {
		if (!data.folderConfigs) return;

		for (var i = 0; i < data.folderConfigs.length; i++) {
			if (!data.folderConfigs[i]) continue;
			var fc = data.folderConfigs[i];
			var prefix = "folder_" + i + "_override_";

			// scanAutomatic: select with value "auto"/"manual" → bool
			var scanAutoEl = dom.get(prefix + "scan_automatic");
			if (scanAutoEl) {
				fc.scanAutomatic = scanAutoEl.value === "auto";
			}

			// scanNetNew: select with value "true"/"false" → bool
			var scanNetNewEl = dom.get(prefix + "scan_net_new");
			if (scanNetNewEl) {
				fc.scanNetNew = scanNetNewEl.value === "true";
			}

			// enabledSeverities: checkboxes → SeverityFilter object
			var sevCritical = dom.getByName(prefix + "severity_critical")[0];
			var sevHigh = dom.getByName(prefix + "severity_high")[0];
			var sevMedium = dom.getByName(prefix + "severity_medium")[0];
			var sevLow = dom.getByName(prefix + "severity_low")[0];
			if (sevCritical || sevHigh || sevMedium || sevLow) {
				fc.enabledSeverities = {
					critical: sevCritical ? sevCritical.checked : false,
					high: sevHigh ? sevHigh.checked : false,
					medium: sevMedium ? sevMedium.checked : false,
					low: sevLow ? sevLow.checked : false
				};
			}

			// Product enablement: individual checkboxes → individual bool fields
			var ossEl = dom.getByName(prefix + "snyk_oss_enabled")[0];
			if (ossEl) {
				fc.snykOssEnabled = ossEl.checked;
			}
			var codeEl = dom.getByName(prefix + "snyk_code_enabled")[0];
			if (codeEl) {
				fc.snykCodeEnabled = codeEl.checked;
			}
			var iacEl = dom.getByName(prefix + "snyk_iac_enabled")[0];
			if (iacEl) {
				fc.snykIacEnabled = iacEl.checked;
			}

			// issueViewOpenIssues: checkbox → bool
			var issueOpenEl = dom.getByName(prefix + "issueViewOpenIssues")[0];
			if (issueOpenEl) {
				fc.issueViewOpenIssues = issueOpenEl.checked;
			}

			// issueViewIgnoredIssues: checkbox → bool
			var issueIgnoredEl = dom.getByName(prefix + "issueViewIgnoredIssues")[0];
			if (issueIgnoredEl) {
				fc.issueViewIgnoredIssues = issueIgnoredEl.checked;
			}

			// riskScoreThreshold: number input → int
			var riskScoreEl = dom.get(prefix + "riskScoreThreshold");
			if (riskScoreEl) {
				fc.riskScoreThreshold = riskScoreEl.value !== "" ? parseInt(riskScoreEl.value, 10) : null;
			}
		}
	}

	// Mark a folder for complete reset (all org-scope overrides will be set to null)
	formHandler.markFolderForReset = function(folderIndex) {
		window.ConfigApp.folderResets = window.ConfigApp.folderResets || {};
		window.ConfigApp.folderResets[folderIndex] = true;
	};

	// Check if a folder is marked for reset
	formHandler.isFolderMarkedForReset = function(folderIndex) {
		return window.ConfigApp.folderResets && window.ConfigApp.folderResets[folderIndex];
	};

	// Apply reset: set all org-scope fields to null on the folder config
	formHandler.applyFolderResets = function(data) {
		if (!data.folderConfigs) return;
		for (var i = 0; i < data.folderConfigs.length; i++) {
			if (formHandler.isFolderMarkedForReset(i) && data.folderConfigs[i]) {
				var fc = data.folderConfigs[i];
				fc.scanAutomatic = null;
				fc.scanNetNew = null;
				fc.enabledSeverities = null;
				fc.snykOssEnabled = null;
				fc.snykCodeEnabled = null;
				fc.snykIacEnabled = null;
				fc.issueViewOpenIssues = null;
				fc.issueViewIgnoredIssues = null;
				fc.riskScoreThreshold = null;
			}
		}
		window.ConfigApp.folderResets = {};
	};

	window.ConfigApp.formHandler = formHandler;
})();
