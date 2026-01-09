// ABOUTME: Consolidated form state coordination for dirty state and auto-save
// ABOUTME: Manages state transitions and coordinates between dirty tracking and auto-save

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var formState = {};

	var debouncedDirtyCheck = null;

	// Initialize dirty tracking
	formState.initializeDirtyTracking = function () {
		if (typeof window.DirtyTracker === "undefined") {
			return;
		}

		// Create global dirty tracker instance
		window.dirtyTracker = new window.DirtyTracker();

		if (
			window.ConfigApp.formHandler &&
			window.ConfigApp.formHandler.collectData
		) {
			window.dirtyTracker.initialize(window.ConfigApp.formHandler.collectData);
		}

		// Create debounced dirty check function
		debouncedDirtyCheck = window.FormUtils.debounce(function () {
			window.dirtyTracker.checkDirty();
		}, 100);
	};

	// Consolidated function that triggers both dirty check and auto-save
	formState.triggerChangeHandlers = function () {
		// Trigger dirty check
		if (debouncedDirtyCheck) {
			debouncedDirtyCheck();
		}
		// Trigger auto-save
		if (
			window.ConfigApp.autoSave &&
			window.ConfigApp.ideBridge.isAutoSaveEnabled()
		) {
			window.ConfigApp.autoSave.getAndSaveIdeConfig();
		}
	};

	// Attach listeners to all form inputs (consolidated for both dirty tracking and auto-save)
	formState.attachFormStateListeners = function () {
		if (!window.dirtyTracker) {
			return;
		}

		var dom = window.ConfigApp.dom;
		if (!dom) return;

		var form = dom.get("configForm");
		if (!form) return;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");

		// Add blur listeners to all text inputs
		for (var i = 0; i < inputs.length; i++) {
			dom.addEvent(inputs[i], "blur", formState.triggerChangeHandlers);
			// Also track change for checkboxes and radios
			if (inputs[i].type === "checkbox" || inputs[i].type === "radio") {
				dom.addEvent(inputs[i], "change", formState.triggerChangeHandlers);
			}
		}

		// Add change listeners to all selects
		for (var j = 0; j < selects.length; j++) {
			dom.addEvent(selects[j], "change", formState.triggerChangeHandlers);
		}
	};

	window.ConfigApp.formState = formState;
})();
