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
					changedFolders.push(changedFc);
				}
			}
			if (changedFolders.length > 0) {
				result.folderConfigs = changedFolders;
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

		// Resolve cli_release_channel: use custom text input value when "Specify version" is selected
		resolveCliReleaseChannel(data);

		// Remove UI-only helper field
		delete data.cli_release_channel_custom;

		return data;
	};

	function processElements(elements, data) {
		for (var i = 0; i < elements.length; i++) {
			var el = elements[i];
			var name = el.name;

			if (!name) continue;

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
					var index = parseInt(parts[1], 10);
					if (!isFinite(index) || index < 0) {
						continue;
					}

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
							data.folderConfigs[index][field] = el.value
								? el.value
										.trim()
										.split(/\s+/)
										.filter(function (item) {
											return item.length > 0;
										})
								: [];
							continue;
						}

						// Skip preferredOrg if orgSetByUser is false (auto-org is enabled)
						if (field === "preferred_org") {
							var orgSetByUserInput = dom.get(
								"folder_" + index + "_org_set_by_user"
							);
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
			obj[field] = el.value ? parseInt(el.value, 10) : null;
		} else if (el.dataset && el.dataset.bool === "1") {
			obj[field] = el.value === "true";
		} else {
			obj[field] = el.value;
		}
	}

	function resolveCliReleaseChannel(data) {
		if (data.cli_release_channel === "custom") {
			var version = (data.cli_release_channel_custom || "").trim();
			if (version && version.charAt(0) !== "v") {
				version = "v" + version;
			}
			data.cli_release_channel = version || "stable";
		}
	}

	// Mark a folder for complete reset (all org-scope overrides will be set to null)
	formHandler.markFolderForReset = function (folderIndex) {
		window.ConfigApp.folderResets = window.ConfigApp.folderResets || {};
		window.ConfigApp.folderResets[folderIndex] = true;
	};

	// Check if a folder is marked for reset
	formHandler.isFolderMarkedForReset = function (folderIndex) {
		return (
			window.ConfigApp.folderResets &&
			window.ConfigApp.folderResets[folderIndex]
		);
	};

	// Apply reset: set all org-scope fields to null on the folder config
	formHandler.applyFolderResets = function (data) {
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
