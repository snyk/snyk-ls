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

		// Process all elements
		processElements(inputs, data);
		processElements(selects, data);

		// Process complex objects
		processFilterSeverity(data);
		processIssueViewOptions(data);

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
              continue
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

	// Track initial effective values for folder configs to detect modifications
	var initialFolderEffectiveValues = {};

	// Initialize tracking of folder effective values from the page data
	formHandler.initializeFolderTracking = function(folderConfigs) {
		initialFolderEffectiveValues = {};
		if (!folderConfigs) return;

		for (var i = 0; i < folderConfigs.length; i++) {
			var fc = folderConfigs[i];
			if (fc.effectiveConfig) {
				initialFolderEffectiveValues[fc.folderPath] = window.FormUtils.deepClone(fc.effectiveConfig);
			}
		}
	};

	// Get modified fields for a folder by comparing current form values to initial effective values
	formHandler.getModifiedFieldsForFolder = function(folderPath, currentValues) {
		var initial = initialFolderEffectiveValues[folderPath];
		if (!initial) return null;

		var modifiedFields = {};
		var hasModifications = false;

		// Check each setting that has an effective value
		for (var settingName in initial) {
			if (initial.hasOwnProperty(settingName)) {
				var initialValue = initial[settingName].value;
				var currentValue = currentValues[settingName];

				// Compare values - if different, it's a modification
				// Use dirtyTracker's deepEquals if available, otherwise simple comparison
				var areEqual = window.dirtyTracker 
					? window.dirtyTracker.deepEquals(initialValue, currentValue)
					: (window.FormUtils.normalizeValue(initialValue) === window.FormUtils.normalizeValue(currentValue));
				
				if (!areEqual) {
					modifiedFields[settingName] = currentValue;
					hasModifications = true;
				}
			}
		}

		return hasModifications ? modifiedFields : null;
	};

	// Enhanced collectData that includes modifiedFields for folder configs
	formHandler.collectDataWithModifiedFields = function() {
		var data = formHandler.collectData();

		// List of all org-scope settings that can be reset
		var orgScopeSettings = [
			"scan_automatic",
			"scan_net_new",
			"enabled_severities",
			"enabled_products",
			"issue_view_open_issues",
			"issue_view_ignored_issues",
			"risk_score_threshold"
		];

		// For each folder config, compute modifiedFields
		if (data.folderConfigs) {
			for (var i = 0; i < data.folderConfigs.length; i++) {
				var fc = data.folderConfigs[i];
				if (fc.folderPath) {
					// Check if this folder is marked for complete reset
					if (formHandler.isFolderMarkedForReset(i)) {
						// Set all org-scope settings to null to indicate reset
						fc.modifiedFields = {};
						for (var j = 0; j < orgScopeSettings.length; j++) {
							fc.modifiedFields[orgScopeSettings[j]] = null;
						}
					} else {
						// Collect current effective values from form for this folder
						var currentEffectiveValues = collectFolderEffectiveValues(i);
						var modifiedFields = formHandler.getModifiedFieldsForFolder(fc.folderPath, currentEffectiveValues);
						if (modifiedFields) {
							fc.modifiedFields = modifiedFields;
						}
					}
				}
			}
		}

		return data;
	};

	// Collect current form values that correspond to effective config settings for a folder
	function collectFolderEffectiveValues(folderIndex) {
		var values = {};

		// Scanning Mode Override
		var scanAutomatic = dom.get("folder_" + folderIndex + "_override_scan_automatic");
		if (scanAutomatic) {
			values.scan_automatic = scanAutomatic.value;
		}

		// Delta Findings Override
		var scanNetNew = dom.get("folder_" + folderIndex + "_override_scan_net_new");
		if (scanNetNew) {
			values.scan_net_new = scanNetNew.value === "true";
		}

		// Severity Filter Override
		var severityCritical = dom.getByName("folder_" + folderIndex + "_override_severity_critical")[0];
		var severityHigh = dom.getByName("folder_" + folderIndex + "_override_severity_high")[0];
		var severityMedium = dom.getByName("folder_" + folderIndex + "_override_severity_medium")[0];
		var severityLow = dom.getByName("folder_" + folderIndex + "_override_severity_low")[0];

		if (severityCritical || severityHigh || severityMedium || severityLow) {
			values.enabled_severities = {
				critical: severityCritical ? severityCritical.checked : false,
				high: severityHigh ? severityHigh.checked : false,
				medium: severityMedium ? severityMedium.checked : false,
				low: severityLow ? severityLow.checked : false
			};
		}

		// Enabled Products Override
		var productOss = dom.getByName("folder_" + folderIndex + "_override_product_oss")[0];
		var productCode = dom.getByName("folder_" + folderIndex + "_override_product_code")[0];
		var productIac = dom.getByName("folder_" + folderIndex + "_override_product_iac")[0];

		if (productOss || productCode || productIac) {
			var products = [];
			if (productOss && productOss.checked) products.push("oss");
			if (productCode && productCode.checked) products.push("code");
			if (productIac && productIac.checked) products.push("iac");
			values.enabled_products = products;
		}

		// Issue View Options Override
		var issueViewOpen = dom.getByName("folder_" + folderIndex + "_override_issueViewOpenIssues")[0];
		if (issueViewOpen) {
			values.issue_view_open_issues = issueViewOpen.checked;
		}

		var issueViewIgnored = dom.getByName("folder_" + folderIndex + "_override_issueViewIgnoredIssues")[0];
		if (issueViewIgnored) {
			values.issue_view_ignored_issues = issueViewIgnored.checked;
		}

		// Risk Score Threshold Override
		var riskScore = dom.get("folder_" + folderIndex + "_override_riskScoreThreshold");
		if (riskScore && riskScore.value !== "") {
			values.risk_score_threshold = parseInt(riskScore.value, 10);
		}

		return values;
	}

	// Mark a folder for complete reset (all overrides will be set to null)
	formHandler.markFolderForReset = function(folderIndex) {
		window.ConfigApp.folderResets = window.ConfigApp.folderResets || {};
		window.ConfigApp.folderResets[folderIndex] = true;
	};

	// Check if a folder is marked for reset
	formHandler.isFolderMarkedForReset = function(folderIndex) {
		return window.ConfigApp.folderResets && window.ConfigApp.folderResets[folderIndex];
	};

	// Clear folder reset markers after save
	formHandler.clearFolderResets = function() {
		window.ConfigApp.folderResets = {};
	};

	window.ConfigApp.formHandler = formHandler;
})();
