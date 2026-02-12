// ABOUTME: Consolidated form state coordination for dirty state and auto-save
// ABOUTME: Manages state transitions and coordinates between dirty tracking and auto-save

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var formState = {};

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
	};

	// Consolidated function that triggers both dirty check and auto-save
	formState.triggerChangeHandlers = function () {
    window.dirtyTracker.checkDirty();
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

		for (var i = 0; i < inputs.length; i++) {
			if (inputs[i].type === "checkbox" || inputs[i].type === "radio") {
				dom.addEvent(inputs[i], "change", formState.triggerChangeHandlers);
			} else {
        dom.addEvent(inputs[i], "blur", formState.triggerChangeHandlers);
      }
		}

		// Add change listeners to all selects
		for (var j = 0; j < selects.length; j++) {
			dom.addEvent(selects[j], "change", formState.triggerChangeHandlers);
		}
	};

	window.ConfigApp.formState = formState;
})();
