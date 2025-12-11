// ABOUTME: Dirty form tracking module for detecting unsaved configuration changes
// ABOUTME: Tracks form state and fires events on clean/dirty state transitions
(function (window) {
	"use strict";

	/**
	 * DirtyTracker - Tracks form dirty state
	 * @constructor
	 */
	function DirtyTracker() {
		this.originalData = null;
		this.isDirty = false;
		this.collectDataFn = null;
	}

	/**
	 * Initialize the dirty tracker with a data collection function
	 * @param {Function} collectDataFn - Function that returns current form data
	 */
	DirtyTracker.prototype.initialize = function (collectDataFn) {
		this.collectDataFn = collectDataFn;

		// Capture initial state
		if (collectDataFn) {
			var initialData = collectDataFn();
			this.originalData = window.FormUtils.deepClone(initialData);
		}

		this.isDirty = false;
	};

	/**
	 * Check if form is dirty and fire event if state changed
	 * @returns {boolean} Current dirty state
	 */
	DirtyTracker.prototype.checkDirty = function () {
		if (!this.collectDataFn || !this.originalData) {
			return false;
		}

		var currentData = this.collectDataFn();
		var wasDirty = this.isDirty;

		// Perform deep comparison
		this.isDirty = !this.deepEquals(this.originalData, currentData);

		// Fire event only on state transition
		if (wasDirty !== this.isDirty) {
			this._notifyStateChange(this.isDirty);
		}

		return this.isDirty;
	};

	/**
	 * Deep equality comparison for form data
	 * @param {*} a - First value to compare
	 * @param {*} b - Second value to compare
	 * @returns {boolean} True if values are deeply equal
	 */
	DirtyTracker.prototype.deepEquals = function (a, b) {
		// Normalize values first
		var normA = window.FormUtils.normalizeValue(a);
		var normB = window.FormUtils.normalizeValue(b);

		// Handle identical primitives and null/undefined
		if (normA === normB) {
			return true;
		}

		// If either is null after normalization, they're not equal
		if (normA === null || normB === null) {
			return false;
		}

		// Handle arrays
		if (window.FormUtils.isArray(normA) && window.FormUtils.isArray(normB)) {
			return this._compareArrays(normA, normB);
		}

		// Handle objects
		if (typeof normA === "object" && typeof normB === "object") {
			return this._compareObjects(normA, normB);
		}

		// Different types or values
		return false;
	};

	/**
	 * Compare two arrays for deep equality
	 * @private
	 * @param {Array} arr1 - First array
	 * @param {Array} arr2 - Second array
	 * @returns {boolean} True if arrays are deeply equal
	 */
	DirtyTracker.prototype._compareArrays = function (arr1, arr2) {
		if (arr1.length !== arr2.length) {
			return false;
		}

		for (var i = 0; i < arr1.length; i++) {
			if (!this.deepEquals(arr1[i], arr2[i])) {
				return false;
			}
		}

		return true;
	};

	/**
	 * Compare two objects for deep equality
	 * @private
	 * @param {Object} obj1 - First object
	 * @param {Object} obj2 - Second object
	 * @returns {boolean} True if objects are deeply equal
	 */
	DirtyTracker.prototype._compareObjects = function (obj1, obj2) {
		var keys1 = window.FormUtils.getKeys(obj1);
		var keys2 = window.FormUtils.getKeys(obj2);

		// Different number of keys
		if (keys1.length !== keys2.length) {
			return false;
		}

		// Check each key
		for (var i = 0; i < keys1.length; i++) {
			var key = keys1[i];

			// Key doesn't exist in obj2
			if (!obj2.hasOwnProperty(key)) {
				return false;
			}

			// Values for this key are different
			if (!this.deepEquals(obj1[key], obj2[key])) {
				return false;
			}
		}

		return true;
	};

	/**
	 * Reset the dirty tracker with new original data
	 * Called after a successful save
	 * @param {Object} newData - Optional new data to set as original (if null, recollects)
	 */
	DirtyTracker.prototype.reset = function (newData) {
		var dataToStore = newData;

		if (!dataToStore && this.collectDataFn) {
			dataToStore = this.collectDataFn();
		}

		if (dataToStore) {
			this.originalData = window.FormUtils.deepClone(dataToStore);
		}

		var wasDirty = this.isDirty;
		this.isDirty = false;

		// Notify if state changed
		if (wasDirty !== this.isDirty) {
			this._notifyStateChange(this.isDirty);
		}
	};

	/**
	 * Notify IDE of dirty state change
	 * @private
	 * @param {boolean} isDirty - Current dirty state
	 */
	DirtyTracker.prototype._notifyStateChange = function (isDirty) {
		// Call IDE-injected handler if available
		if (typeof window.__onFormDirtyChange__ === "function") {
			try {
				window.__onFormDirtyChange__(isDirty);
			} catch (e) {
				// Silently ignore errors in IDE handler
				if (window.console && window.console.error) {
					console.error("Error in __onFormDirtyChange__ handler:", e);
				}
			}
		}
	};

	/**
	 * Get current dirty state without checking
	 * @returns {boolean} Current dirty state
	 */
	DirtyTracker.prototype.getDirtyState = function () {
		return this.isDirty;
	};

	/**
	 * Force a specific dirty state (for edge cases)
	 * @param {boolean} isDirty - The dirty state to set
	 */
	DirtyTracker.prototype.setDirtyState = function (isDirty) {
		var wasDirty = this.isDirty;
		this.isDirty = isDirty;

		// Notify if state changed
		if (wasDirty !== this.isDirty) {
			this._notifyStateChange(this.isDirty);
		}
	};

	// Expose DirtyTracker to window
	window.DirtyTracker = DirtyTracker;
})(window);
