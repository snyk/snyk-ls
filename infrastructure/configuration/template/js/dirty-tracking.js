// ABOUTME: Dirty state tracking for form changes to prevent data loss
// ABOUTME: Monitors form modifications and exposes dirty state to IDE integrations

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var dirtyTracking = {};
	var helpers = window.ConfigApp.helpers;

	var saveTimeout = null;

	// Initialize dirty tracking
	dirtyTracking.initializeDirtyTracking = function() {
		// Only initialize if DirtyTracker is available
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
	};

	// Debounced dirty check function
	var debouncedDirtyCheck = null;

	// Attach dirty tracking listeners to all form inputs
	dirtyTracking.attachDirtyTrackingListeners = function() {
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

		var form = helpers.get("configForm");
		if (!form) return;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");
		var textareas = form.getElementsByTagName("textarea");

		// Add listeners to all inputs
		for (var i = 0; i < inputs.length; i++) {
			helpers.addEvent(inputs[i], "change", debouncedDirtyCheck);
			helpers.addEvent(inputs[i], "input", debouncedDirtyCheck);
		}

		// Add listeners to all selects
		for (var j = 0; j < selects.length; j++) {
			helpers.addEvent(selects[j], "change", debouncedDirtyCheck);
		}

		// Add listeners to all textareas
		for (var k = 0; k < textareas.length; k++) {
			helpers.addEvent(textareas[k], "input", debouncedDirtyCheck);
			helpers.addEvent(textareas[k], "change", debouncedDirtyCheck);
		}
	};

	// Expose debouncedDirtyCheck for other modules to use
	dirtyTracking.debouncedDirtyCheck = function() {
		if (debouncedDirtyCheck) {
			debouncedDirtyCheck();
		}
	};

	window.ConfigApp.dirtyTracking = dirtyTracking;
})();
