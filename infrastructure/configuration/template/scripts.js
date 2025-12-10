(function () {
	// IE7 Compatible Script

	// Helper to get element by ID
	function get(id) {
		return document.getElementById(id);
	}

	// Helper to get elements by name
	function getByName(name) {
		return document.getElementsByName(name);
	}

	// Helper to add event listener (IE7 compatible)
	function addEvent(element, event, handler) {
		if (element.addEventListener) {
			element.addEventListener(event, handler, false);
		} else if (element.attachEvent) {
			element.attachEvent("on" + event, handler);
		} else {
			element["on" + event] = handler;
		}
	}

	// Helper to remove class (IE7 compatible)
	function removeClass(element, className) {
		if (!element) return;
		var reg = new RegExp("(\\s|^)" + className + "(\\s|$)");
		element.className = element.className.replace(reg, " ");
	}

	// Helper to add class (IE7 compatible)
	function addClass(element, className) {
		if (!element) return;
		if (element.className.indexOf(className) === -1) {
			element.className += " " + className;
		}
	}

	// Validate Endpoint
	function validateEndpoint(url) {
		if (!url) return true; // Empty URL allows default
		// Regex for api.*.snyk.io or api.*.snykgov.io
		var snykRegex = /^https:\/\/api\..*\.snyk\.io/;
		var snykgovRegex = /^https:\/\/api\..*\.snykgov\.io/;

		return (
			snykRegex.test(url) ||
			snykgovRegex.test(url) ||
			url === "https://api.snyk.io"
		);
	}

	// Collect form data
	function collectData() {
		var data = {
			folderConfigs: [],
		};

		var form = get("configForm");
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
	}

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
		var critical = getByName("filterSeverity_critical")[0];
		var high = getByName("filterSeverity_high")[0];
		var medium = getByName("filterSeverity_medium")[0];
		var low = getByName("filterSeverity_low")[0];

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
		var openIssues = getByName("issueViewOptions_openIssues")[0];
		var ignoredIssues = getByName("issueViewOptions_ignoredIssues")[0];

		if (openIssues || ignoredIssues) {
			data.issueViewOptions = {
				openIssues: openIssues ? openIssues.checked : false,
				ignoredIssues: ignoredIssues ? ignoredIssues.checked : false,
			};
		}
	}

	var originalEndpoint = "";

	// Toggle organization field based on auto-org checkbox
	function toggleOrgField(folderIndex) {
		var autoOrgCheckbox = get("folder_" + folderIndex + "_autoOrg");
		var orgInput = get("folder_" + folderIndex + "_preferredOrg");
		var orgSetByUserInput = get("folder_" + folderIndex + "_orgSetByUser");

		if (!autoOrgCheckbox || !orgInput || !orgSetByUserInput) {
			return;
		}

		var isAutoOrg = autoOrgCheckbox.checked;
		var preferredOrg = orgInput.getAttribute("data-preferred-org") || "";
		var autoOrg = orgInput.getAttribute("data-auto-org") || "";

		if (isAutoOrg) {
			// Auto select is ON: show AutoDeterminedOrg (readonly)
			orgInput.value = autoOrg;
			orgInput.setAttribute("readonly", "readonly");
			orgSetByUserInput.value = "false";
		} else {
			// Auto select is OFF: show PreferredOrg (editable)
			orgInput.value = preferredOrg;
			orgInput.removeAttribute("readonly");
			orgSetByUserInput.value = "true";
		}

		// Trigger dirty check since we changed the value programmatically
		if (debouncedDirtyCheck) {
			debouncedDirtyCheck();
		}
	}

	// Handle file picker for CLI Path
	function handleCliPathBrowse() {
		var filePicker = get("cliPathPicker");
		var cliPathInput = get("cliPath");

		if (!filePicker || !cliPathInput) {
			return;
		}

		// Trigger file picker
		filePicker.click();

		// When file is selected, update the CLI Path input
		addEvent(filePicker, "change", function () {
			if (filePicker.files && filePicker.files.length > 0) {
				cliPathInput.value = filePicker.files[0].path || filePicker.value;
				// Trigger auto-save if enabled
				if (window.__IS_IDE_AUTOSAVE_ENABLED__) {
					debouncedSave();
				}
				// Trigger dirty check
				if (debouncedDirtyCheck) {
					debouncedDirtyCheck();
				}
			}
		});
	}

	// Initialize all folder org fields on page load
	function initializeFolderOrgFields() {
		var allInputs = document.getElementsByTagName("input");
		for (var i = 0; i < allInputs.length; i++) {
			var input = allInputs[i];
			var inputId = input.id || "";
			if (
				input.type === "checkbox" &&
				inputId.indexOf("_autoOrg") !== -1 &&
				input.getAttribute("data-index") !== null
			) {
				var folderIndex = input.getAttribute("data-index");

				// Initialize the field state
				toggleOrgField(folderIndex);

				// Attach click event listener (CSP-compliant)
				(function(index) {
					addEvent(input, "change", function() {
						toggleOrgField(index);
					});
				})(folderIndex);
			}
		}
	}

	var saveTimeout = null;
	var SAVE_DELAY = 500; // milliseconds delay for debouncing

	// Check if auto-save is enabled (default false)
	if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === "undefined") {
		window.__IS_IDE_AUTOSAVE_ENABLED__ = false;
	}

	// Get current form data, validate, and call __saveIdeConfig__
	function getAndSaveIdeConfig() {
		var endpointInput = get("endpoint");
		var endpointError = get("endpoint-error");
		var currentEndpoint = endpointInput.value;

		// Validate endpoint
		if (currentEndpoint && !validateEndpoint(currentEndpoint)) {
			removeClass(endpointError, "hidden");
			return;
		} else {
			addClass(endpointError, "hidden");
		}

		// Validate risk score
		var riskScoreInput = get("riskScoreThreshold");
		var riskScoreError = get("riskScore-error");
		if (riskScoreInput && riskScoreError) {
			if (!validateRiskScore(riskScoreInput.value)) {
				removeClass(riskScoreError, "hidden");
				return;
			} else {
				addClass(riskScoreError, "hidden");
			}
		}

		var data = collectData();
		var jsonString = JSON.stringify(data);

		try {
			window.__saveIdeConfig__(jsonString);

			// Reset dirty state after successful save
			if (window.dirtyTracker) {
				window.dirtyTracker.reset(data);
			}

			// If endpoint changed, trigger logout
			if (originalEndpoint && currentEndpoint !== originalEndpoint) {
				if (typeof window.__ideLogout__ !== "undefined") {
					window.__ideLogout__();
				}
			}
		} catch (e) {
			// Keep dirty state on save failure
			alert("Error saving configuration: " + e.message);
		}
	}

	// Expose getAndSaveIdeConfig to window for IDEs to call
	window.getAndSaveIdeConfig = getAndSaveIdeConfig;

	// Debounced save - delays save until user stops changing inputs
	function debouncedSave() {
		if (saveTimeout) {
			clearTimeout(saveTimeout);
		}
		saveTimeout = setTimeout(function () {
			getAndSaveIdeConfig();
		}, SAVE_DELAY);
	}

	// Attach auto-save listeners to all form inputs
	function attachAutoSaveListeners() {
		if (!window.__IS_IDE_AUTOSAVE_ENABLED__) return; // Don't attach listeners if auto-save not enabled

		var form = get("configForm");
		if (!form) return;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");
		var textareas = form.getElementsByTagName("textarea");

		// Add blur event listeners to all inputs
		for (var i = 0; i < inputs.length; i++) {
			addEvent(inputs[i], "blur", debouncedSave);
			// Also save on change for checkboxes and radios
			if (inputs[i].type === "checkbox" || inputs[i].type === "radio") {
				addEvent(inputs[i], "change", debouncedSave);
			}
		}

		for (var j = 0; j < selects.length; j++) {
			addEvent(selects[j], "change", debouncedSave);
		}

		for (var k = 0; k < textareas.length; k++) {
			addEvent(textareas[k], "blur", debouncedSave);
		}
	}

	function authenticate() {
		// Save config before authenticating, because of possible endpoint/token type changes
		getAndSaveIdeConfig();
		window.__ideLogin__();
	}

	function logout() {
		window.__ideLogout__();
	}

	// Validate endpoint on input
	function validateEndpointOnInput() {
		var endpointInput = get("endpoint");
		var endpointError = get("endpoint-error");

		if (!endpointInput || !endpointError) return;

		var currentEndpoint = endpointInput.value;

		if (currentEndpoint && !validateEndpoint(currentEndpoint)) {
			removeClass(endpointError, "hidden");
		} else {
			addClass(endpointError, "hidden");
		}
	}

	// Validate risk score
	function validateRiskScore(value) {
		if (value === "" || value === null || value === undefined) {
			return true; // Empty is valid (will use default)
		}

		var num = parseInt(value);
		return !isNaN(num) && num >= 0 && num <= 1000;
	}

	// Validate risk score on input
	function validateRiskScoreOnInput() {
		var riskScoreInput = get("riskScoreThreshold");
		var riskScoreError = get("riskScore-error");

		if (!riskScoreInput || !riskScoreError) return;

		var currentValue = riskScoreInput.value;

		if (!validateRiskScore(currentValue)) {
			removeClass(riskScoreError, "hidden");
		} else {
			addClass(riskScoreError, "hidden");
		}
	}

	// Initialize dirty tracking
	function initializeDirtyTracking() {
		// Only initialize if DirtyTracker is available
		if (typeof window.DirtyTracker === "undefined") {
			return;
		}

		// Create global dirty tracker instance
		window.dirtyTracker = new window.DirtyTracker();
		window.dirtyTracker.initialize(collectData);

		// Expose IDE interface functions
		window.__isFormDirty__ = function () {
			return window.dirtyTracker ? window.dirtyTracker.getDirtyState() : false;
		};

		window.__resetDirtyState__ = function () {
			if (window.dirtyTracker) {
				window.dirtyTracker.reset();
			}
		};
	}

	// Debounced dirty check function
	var debouncedDirtyCheck = null;

	// Attach dirty tracking listeners to all form inputs
	function attachDirtyTrackingListeners() {
		if (!window.dirtyTracker) {
			return; // Dirty tracking not initialized
		}

		// Create debounced dirty check function
		if (window.FormUtils && window.FormUtils.debounce) {
			debouncedDirtyCheck = window.FormUtils.debounce(function () {
				window.dirtyTracker.checkDirty();
			}, 100);
		} else {
			// Fallback if FormUtils not available
			debouncedDirtyCheck = function () {
				if (saveTimeout) {
					clearTimeout(saveTimeout);
				}
				saveTimeout = setTimeout(function () {
					window.dirtyTracker.checkDirty();
				}, 100);
			};
		}

		var form = get("configForm");
		if (!form) return;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");
		var textareas = form.getElementsByTagName("textarea");

		// Add listeners to all inputs
		for (var i = 0; i < inputs.length; i++) {
			addEvent(inputs[i], "change", debouncedDirtyCheck);
			addEvent(inputs[i], "input", debouncedDirtyCheck);
		}

		// Add listeners to all selects
		for (var j = 0; j < selects.length; j++) {
			addEvent(selects[j], "change", debouncedDirtyCheck);
		}

		// Add listeners to all textareas
		for (var k = 0; k < textareas.length; k++) {
			addEvent(textareas[k], "input", debouncedDirtyCheck);
			addEvent(textareas[k], "change", debouncedDirtyCheck);
		}
	}

	// Trusted Folder Management
	var trustedFolderIndex = 0;

	function handleAddTrustedFolder() {
		var trustedFoldersList = get("trustedFoldersList");
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

		// Create remove button with X icon
		var removeBtn = document.createElement("button");
		removeBtn.type = "button";
		removeBtn.className = "remove-trusted-folder";
		removeBtn.setAttribute("data-index", trustedFolderIndex);
		removeBtn.setAttribute("title", "Remove");
		removeBtn.textContent = "✕";
		addEvent(removeBtn, "click", handleRemoveTrustedFolder);

		// Assemble elements
		buttonGroup.appendChild(input);
		buttonGroup.appendChild(removeBtn);
		folderItem.appendChild(buttonGroup);
		trustedFoldersList.appendChild(folderItem);

		trustedFolderIndex++;

		// Trigger dirty check
		if (window.dirtyTracker) {
			window.dirtyTracker.markDirty();
		}
	}

	function handleRemoveTrustedFolder() {
		var btn = this;
		var buttonGroup = btn.parentNode;
		var folderItem = buttonGroup ? buttonGroup.parentNode : null;
		if (folderItem && folderItem.parentNode) {
			folderItem.parentNode.removeChild(folderItem);
		}

		// Trigger dirty check
		if (window.dirtyTracker) {
			window.dirtyTracker.markDirty();
		}
	}

	function initializeTrustedFolderHandlers() {
		// Initialize remove buttons
		var removeButtons = document.querySelectorAll(".remove-trusted-folder");
		for (var i = 0; i < removeButtons.length; i++) {
			addEvent(removeButtons[i], "click", handleRemoveTrustedFolder);
			var buttonGroup = removeButtons[i].parentNode;
			var folderItem = buttonGroup ? buttonGroup.parentNode : null;
			if (folderItem) {
				var index = parseInt(folderItem.getAttribute("data-index") || "0");
				if (index >= trustedFolderIndex) {
					trustedFolderIndex = index + 1;
				}
			}
		}
	}

	// Initialize
	addEvent(window, "load", function () {
		var authBtn = get("authenticate-btn");
		if (authBtn) {
			addEvent(authBtn, "click", authenticate);
		}

		var logoutBtn = get("logout-btn");
		if (logoutBtn) {
			addEvent(logoutBtn, "click", logout);
		}

		var endpointInput = get("endpoint");
		if (endpointInput) {
			originalEndpoint = endpointInput.value;
			// Add input event listener for real-time validation
			addEvent(endpointInput, "input", validateEndpointOnInput);
		}

		var riskScoreInput = get("riskScoreThreshold");
		if (riskScoreInput) {
			// Add input event listener for real-time validation
			addEvent(riskScoreInput, "input", validateRiskScoreOnInput);
		}

		// Initialize folder organization field toggles
		initializeFolderOrgFields();

		// Add event listener for Browse button
		var browseBtn = get("browse-cli-btn");
		if (browseBtn) {
			addEvent(browseBtn, "click", handleCliPathBrowse);
		}

		// Add event listener for Add Trusted Folder button
		var addTrustedFolderBtn = get("addTrustedFolderBtn");
		if (addTrustedFolderBtn) {
			addEvent(addTrustedFolderBtn, "click", handleAddTrustedFolder);
		}

		// Add event listeners for Remove Trusted Folder buttons
		initializeTrustedFolderHandlers();

		// Initialize dirty tracking
		initializeDirtyTracking();

		// Attach auto-save listeners to all form inputs
		attachAutoSaveListeners();

		// Attach dirty tracking listeners to all form inputs
		attachDirtyTrackingListeners();

		// Initialize Bootstrap tooltips
		if (typeof bootstrap !== "undefined" && bootstrap.Tooltip) {
			var tooltipTriggerList = document.querySelectorAll(
				'[data-bs-toggle="tooltip"]',
			);
			for (var i = 0; i < tooltipTriggerList.length; i++) {
				new bootstrap.Tooltip(tooltipTriggerList[i]);
			}
		}
	});
})();
