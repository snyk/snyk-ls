// ABOUTME: Form data collection and serialization functions
// ABOUTME: Handles gathering all form inputs and converting them to JSON format

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var formData = {};
	var helpers = window.ConfigApp.helpers;

	// Collect form data
	formData.collectData = function() {
		var data = {
			folderConfigs: [],
		};

		var form = helpers.get("configForm");
		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");
		var textareas = form.getElementsByTagName("textarea");

		// Process all elements
		processElements(inputs, data);
		processElements(selects, data);
		processElements(textareas, data);

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

			// Folder logic: folder_INDEX_FIELD or folder_INDEX_scanConfig_PRODUCT_FIELD
			if (name.indexOf("folder_") === 0) {
				var parts = name.split("_");
				if (parts.length >= 3) {
					var index = parseInt(parts[1]);

					if (!data.folderConfigs[index]) {
						data.folderConfigs[index] = {};
					}

					// Check if this is a scanConfig field: folder_INDEX_scanConfig_PRODUCT_FIELD
					if (parts.length >= 5 && parts[2] === "scanConfig") {
						var product = parts[3]; // oss, code, or iac
						var field = parts[4]; // preScanCommand, postScanCommand, preScanOnlyReferenceFolder, postScanOnlyReferenceFolder

						if (!data.folderConfigs[index].scanCommandConfig) {
							data.folderConfigs[index].scanCommandConfig = {};
						}
						if (!data.folderConfigs[index].scanCommandConfig[product]) {
							data.folderConfigs[index].scanCommandConfig[product] = {};
						}

						// Map UI field names to JSON field names
						var jsonField = field;
						if (field === "preScanCommand") {
							jsonField = "command"; // PreScanCommand uses 'command' in JSON
						}

						if (el.type === "checkbox") {
							data.folderConfigs[index].scanCommandConfig[product][jsonField] =
								el.checked;
						} else {
							// Always set the value, even if empty, to allow clearing
							data.folderConfigs[index].scanCommandConfig[product][jsonField] =
								el.value;
						}
					} else {
						var field = parts.slice(2).join("_");
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
		} else if (el.tagName.toLowerCase() === "textarea") {
			// Try to parse as JSON, fallback to string
			try {
				if (el.value && el.value.trim()) {
					obj[field] = JSON.parse(el.value);
				} else {
					obj[field] = null;
				}
			} catch (e) {
				obj[field] = el.value;
			}
		} else {
			obj[field] = el.value;
		}
	}

	function processFilterSeverity(data) {
		var critical = helpers.getByName("filterSeverity_critical")[0];
		var high = helpers.getByName("filterSeverity_high")[0];
		var medium = helpers.getByName("filterSeverity_medium")[0];
		var low = helpers.getByName("filterSeverity_low")[0];

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
		var openIssues = helpers.getByName("issueViewOptions_openIssues")[0];
		var ignoredIssues = helpers.getByName("issueViewOptions_ignoredIssues")[0];

		if (openIssues || ignoredIssues) {
			data.issueViewOptions = {
				openIssues: openIssues ? openIssues.checked : false,
				ignoredIssues: ignoredIssues ? ignoredIssues.checked : false,
			};
		}
	}

	window.ConfigApp.formData = formData;
})();
