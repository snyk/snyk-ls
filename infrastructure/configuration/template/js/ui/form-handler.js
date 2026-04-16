// ABOUTME: Form data collection and serialization functions
// ABOUTME: Handles gathering all form inputs and converting them to JSON format

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var formHandler = {};
	var dom = window.ConfigApp.dom;

	// Collect only changed fields by diffing current form data against the dirty tracker baseline.
	// Global fields are included only when their value differs from the original.
	// Folder configs are included only when at least one field changed; unchanged fields are stripped.
	formHandler.collectChangedData = function () {
		var current = formHandler.collectData();
		var tracker = window.dirtyTracker;
		if (!tracker || !tracker.originalData) {
			return current;
		}
		var original = tracker.originalData;
		var result = {};
		var keys = window.FormUtils.getKeys(current);

		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];
			if (key === "folderConfigs") {
				continue;
			}
			if (!tracker.deepEquals(current[key], original[key])) {
				result[key] = current[key];
			}
		}

		// Folder configs: per-folder, only include changed fields
		if (current.folderConfigs) {
			var changedFolders = [];
			var origFolders = original.folderConfigs || [];
			for (var fi = 0; fi < current.folderConfigs.length; fi++) {
				var curFc = current.folderConfigs[fi] || {};
				var origFc = origFolders[fi] || {};
				var changedFc = null;
				var fcKeys = window.FormUtils.getKeys(curFc);

				for (var ki = 0; ki < fcKeys.length; ki++) {
					var fk = fcKeys[ki];
					if (fk === "folderPath") continue;
					if (!tracker.deepEquals(curFc[fk], origFc[fk])) {
						if (!changedFc) {
							changedFc = {};
						}
						changedFc[fk] = curFc[fk];
					}
				}

				if (changedFc && curFc.folderPath) {
					changedFc.folderPath = curFc.folderPath;
					changedFolders[fi] = changedFc;
				}
			}
			var compactFolders = [];
			for (var ci = 0; ci < changedFolders.length; ci++) {
				if (changedFolders[ci]) {
					compactFolders.push(changedFolders[ci]);
				}
			}
			if (compactFolders.length > 0) {
				result.folderConfigs = compactFolders;
			}
		}

		return result;
	};

	// Collect form data
	formHandler.collectData = function () {
		var data = {
			folderConfigs: [],
			trusted_folders: [],
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
				name.indexOf("enabled_severities_") === 0 ||
				name.indexOf("issue_view_") === 0
			) {
				continue;
			}

			// Trusted folder logic: trustedFolder_INDEX
			if (name.indexOf("trustedFolder_") === 0) {
				// Only add non-empty values
				if (el.value && el.value.trim()) {
					data.trusted_folders.push(el.value);
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

						if (!data.folderConfigs[index].scan_command_config) {
							data.folderConfigs[index].scan_command_config = {};
						}
						if (!data.folderConfigs[index].scan_command_config[product]) {
							data.folderConfigs[index].scan_command_config[product] = {};
						}

						if (el.type === "checkbox") {
							data.folderConfigs[index].scan_command_config[product][field] =
								el.checked;
						} else {
							// Always set the value, even if empty, to allow clearing
							data.folderConfigs[index].scan_command_config[product][field] =
								el.value;
						}
					} else {
						var field = parts.slice(2).join("_");
						if (field === "additional_parameters") {
							// Split by whitespace and filter out empty strings
							data.folderConfigs[index][field] = el.value ? el.value.trim().split(/\s+/).filter(function(item) { return item.length > 0; }) : [];
							continue;
						}

						// Skip preferredOrg if orgSetByUser is false (auto-org is enabled)
						if (field === "preferred_org") {
							var orgSetByUserInput = dom.get("folder_" + index + "_org_set_by_user");
							if (orgSetByUserInput && orgSetByUserInput.value === "false") {
								continue;
							}
						}

						// autoDeterminedOrg is read-only (set by LS via LDX-Sync); never send it back
						if (field === "auto_determined_org") {
							continue;
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
		var critical = dom.getByName("enabled_severities_critical")[0];
		var high = dom.getByName("enabled_severities_high")[0];
		var medium = dom.getByName("enabled_severities_medium")[0];
		var low = dom.getByName("enabled_severities_low")[0];

		if (critical || high || medium || low) {
			data.severity_filter_critical = critical ? critical.checked : false;
      data.severity_filter_high = high ? high.checked : false;
      data.severity_filter_medium = medium ? medium.checked : false;
      data.severity_filter_low = low ? low.checked : false;
		}
	}

	function processIssueViewOptions(data) {
		var openIssues = dom.getByName("issue_view_open_issues")[0];
		var ignoredIssues = dom.getByName("issue_view_ignored_issues")[0];

		if (openIssues || ignoredIssues) {
			data.issue_view_open_issues = openIssues ? openIssues.checked : false;
			data.issue_view_ignored_issues = ignoredIssues ? ignoredIssues.checked : false;
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

			// scan_automatic: select with value "auto"/"manual" → bool
			var scanAutoEl = dom.get(prefix + "scan_automatic");
			if (scanAutoEl) {
				fc.scan_automatic = scanAutoEl.value === "auto";
			}

			// scan_net_new: select with value "true"/"false" → bool
			var scanNetNewEl = dom.get(prefix + "scan_net_new");
			if (scanNetNewEl) {
				fc.scan_net_new = scanNetNewEl.value === "true";
			}

			// enabled_severities: checkboxes → SeverityFilter object
			var sevCritical = dom.getByName(prefix + "severity_filter_critical")[0];
			var sevHigh = dom.getByName(prefix + "severity_filter_high")[0];
			var sevMedium = dom.getByName(prefix + "severity_filter_medium")[0];
			var sevLow = dom.getByName(prefix + "severity_filter_low")[0];
			if (sevCritical || sevHigh || sevMedium || sevLow) {
				fc.severity_filter_critical = sevCritical ? sevCritical.checked : false;
				fc.severity_filter_high = sevHigh ? sevHigh.checked : false;
				fc.severity_filter_medium = sevMedium ? sevMedium.checked : false;
				fc.severity_filter_low = sevLow ? sevLow.checked : false;
			}

			// Product enablement: individual checkboxes → individual bool fields
			var ossEl = dom.getByName(prefix + "snyk_oss_enabled")[0];
			if (ossEl) {
				fc.snyk_oss_enabled = ossEl.checked;
			}
			var codeEl = dom.getByName(prefix + "snyk_code_enabled")[0];
			if (codeEl) {
				fc.snyk_code_enabled = codeEl.checked;
			}
			var iacEl = dom.getByName(prefix + "snyk_iac_enabled")[0];
			if (iacEl) {
				fc.snyk_iac_enabled = iacEl.checked;
			}
			var secretsEl = dom.getByName(prefix + "snyk_secrets_enabled")[0];
			if (secretsEl) {
				fc.snyk_secrets_enabled = secretsEl.checked;
			}

			// issue_view_open_issues: checkbox → bool
			var issueOpenEl = dom.getByName(prefix + "issue_view_open_issues")[0];
			if (issueOpenEl) {
				fc.issue_view_open_issues = issueOpenEl.checked;
			}

			// issue_view_ignored_issues: checkbox → bool
			var issueIgnoredEl = dom.getByName(prefix + "issue_view_ignored_issues")[0];
			if (issueIgnoredEl) {
				fc.issue_view_ignored_issues = issueIgnoredEl.checked;
			}

			// risk_score_threshold: number input → int
			var riskScoreEl = dom.get(prefix + "risk_score_threshold");
			if (riskScoreEl) {
				fc.risk_score_threshold = riskScoreEl.value !== "" ? parseInt(riskScoreEl.value, 10) : null;
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
				fc.scan_automatic = null;
				fc.scan_net_new = null;
				fc.severity_filter_critical = null;
				fc.severity_filter_high = null;
				fc.severity_filter_medium = null;
				fc.severity_filter_low = null;
				fc.snyk_oss_enabled = null;
				fc.snyk_code_enabled = null;
				fc.snyk_iac_enabled = null;
				fc.snyk_secrets_enabled = null;
				fc.issue_view_open_issues = null;
				fc.issue_view_ignored_issues = null;
				fc.risk_score_threshold = null;
			}
		}
		window.ConfigApp.folderResets = {};
	};

	window.ConfigApp.formHandler = formHandler;
})();
