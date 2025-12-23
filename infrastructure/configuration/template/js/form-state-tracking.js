// ABOUTME: Consolidated form state tracking for dirty state and auto-save
// ABOUTME: Monitors form changes via blur/change events and triggers both dirty tracking and auto-save

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var formStateTracking = {};
	var helpers = window.ConfigApp.helpers;

	var debouncedDirtyCheck = null;

	// Initialize dirty tracking
	formStateTracking.initializeDirtyTracking = function() {
		if (typeof window.DirtyTracker === "undefined") {
			return;
		}

		// Create global dirty tracker instance
		window.dirtyTracker = new window.DirtyTracker();
		window.dirtyTracker.initialize(window.ConfigApp.formData.collectData);

		// Expose IDE interface functions
		window.__isFormDirty__ = function () {
			return window.dirtyTracker ? window.dirtyTracker.getDirtyState() : false;
		};

		window.__resetDirtyState__ = function () {
			if (window.dirtyTracker) {
				window.dirtyTracker.reset();
			}
		};

		// Create debounced dirty check function
		debouncedDirtyCheck = window.FormUtils.debounce(function () {
			window.dirtyTracker.checkDirty();
		}, 100);
	};

	// Consolidated function that triggers both dirty check and auto-save
	formStateTracking.triggerChangeHandlers = function() {
		// Trigger dirty check
		if (debouncedDirtyCheck) {
			debouncedDirtyCheck();
		}
		// Trigger auto-save
		if (window.ConfigApp.autoSave && window.ConfigApp.autoSave.debouncedSave) {
			window.ConfigApp.autoSave.debouncedSave();
		}
	};

	// Attach listeners to all form inputs (consolidated for both dirty tracking and auto-save)
	formStateTracking.attachFormStateListeners = function() {
		if (!window.dirtyTracker) {
			return;
		}

		var form = helpers.get("configForm");
		if (!form) return;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");
		var textareas = form.getElementsByTagName("textarea");

		// Add blur listeners to all text inputs
		for (var i = 0; i < inputs.length; i++) {
			helpers.addEvent(inputs[i], "blur", formStateTracking.triggerChangeHandlers);
			// Also track change for checkboxes and radios
			if (inputs[i].type === "checkbox" || inputs[i].type === "radio") {
				helpers.addEvent(inputs[i], "change", formStateTracking.triggerChangeHandlers);
			}
		}

		// Add change listeners to all selects
		for (var j = 0; j < selects.length; j++) {
			helpers.addEvent(selects[j], "change", formStateTracking.triggerChangeHandlers);
		}

		// Add blur listeners to all textareas
		for (var k = 0; k < textareas.length; k++) {
			helpers.addEvent(textareas[k], "blur", formStateTracking.triggerChangeHandlers);
		}
	};

	window.ConfigApp.formStateTracking = formStateTracking;
})();
