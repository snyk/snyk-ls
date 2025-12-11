// ABOUTME: IE7-compatible utility functions for form handling and dirty tracking
// ABOUTME: Provides deep cloning, debouncing, and value normalization
(function (window) {
	"use strict";

	// Utility namespace
	var FormUtils = {};

	/**
	 * Deep clone an object or array (IE7 compatible)
	 * Handles nested objects, arrays, primitives, null, and undefined
	 * @param {*} obj - The object to clone
	 * @returns {*} A deep copy of the object
	 */
	FormUtils.deepClone = function (obj) {
		// Handle primitives and null/undefined
		if (obj === null || typeof obj !== "object") {
			return obj;
		}

		// Handle Date
		if (obj instanceof Date) {
			return new Date(obj.getTime());
		}

		// Handle Array
		if (obj instanceof Array || Object.prototype.toString.call(obj) === "[object Array]") {
			var arrCopy = [];
			for (var i = 0; i < obj.length; i++) {
				arrCopy[i] = FormUtils.deepClone(obj[i]);
			}
			return arrCopy;
		}

		// Handle Object
		if (obj instanceof Object || typeof obj === "object") {
			var objCopy = {};
			for (var key in obj) {
				if (obj.hasOwnProperty(key)) {
					objCopy[key] = FormUtils.deepClone(obj[key]);
				}
			}
			return objCopy;
		}

		// Fallback
		return obj;
	};

	/**
	 * Normalize a value for comparison
	 * Handles empty strings, null, undefined, and boolean strings
	 * @param {*} val - The value to normalize
	 * @returns {*} The normalized value
	 */
	FormUtils.normalizeValue = function (val) {
		// Convert empty strings to null for consistent comparison
		if (val === "") {
			return null;
		}

		// Handle null and undefined as equivalent
		if (val === null || val === undefined) {
			return null;
		}

		// Convert boolean strings to booleans for comparison
		if (val === "true") {
			return true;
		}
		if (val === "false") {
			return false;
		}

		// Handle numbers that might be strings
		if (typeof val === "string") {
			var num = parseFloat(val);
			if (!isNaN(num) && num.toString() === val) {
				return num;
			}
		}

		return val;
	};

	/**
	 * Create a debounced version of a function
	 * IE7-compatible implementation
	 * @param {Function} func - The function to debounce
	 * @param {number} wait - The delay in milliseconds
	 * @returns {Function} The debounced function
	 */
	FormUtils.debounce = function (func, wait) {
		var timeout = null;

		return function () {
			var context = this;
			var args = arguments;

			var later = function () {
				timeout = null;
				func.apply(context, args);
			};

			if (timeout) {
				clearTimeout(timeout);
			}
			timeout = setTimeout(later, wait);
		};
	};

	/**
	 * Get object keys (polyfill for IE7)
	 * @param {Object} obj - The object to get keys from
	 * @returns {Array} Array of object keys
	 */
	FormUtils.getKeys = function (obj) {
		if (Object.keys) {
			return Object.keys(obj);
		}

		// Polyfill for IE7
		var keys = [];
		for (var key in obj) {
			if (obj.hasOwnProperty(key)) {
				keys.push(key);
			}
		}
		return keys;
	};

	/**
	 * Check if value is an array (IE7 compatible)
	 * @param {*} val - The value to check
	 * @returns {boolean} True if value is an array
	 */
	FormUtils.isArray = function (val) {
		if (Array.isArray) {
			return Array.isArray(val);
		}

		// Polyfill for IE7
		return Object.prototype.toString.call(val) === "[object Array]";
	};

	/**
	 * Trim whitespace from a string (IE7 compatible)
	 * @param {string} str - The string to trim
	 * @returns {string} The trimmed string
	 */
	FormUtils.trim = function (str) {
		if (!str) {
			return str;
		}

		if (String.prototype.trim) {
			return str.trim();
		}

		// Polyfill for IE7
		return str.replace(/^\s+|\s+$/g, "");
	};

	/**
	 * Parse JSON safely (IE7 compatible)
	 * @param {string} jsonString - The JSON string to parse
	 * @returns {*} The parsed object or null on error
	 */
	FormUtils.parseJSON = function (jsonString) {
		if (!jsonString) {
			return null;
		}

		try {
			if (window.JSON && window.JSON.parse) {
				return JSON.parse(jsonString);
			}

			// Fallback for IE7 (eval is safe here as we control the source)
			return eval("(" + jsonString + ")");
		} catch (e) {
			return null;
		}
	};

	/**
	 * Stringify object to JSON (IE7 compatible)
	 * @param {*} obj - The object to stringify
	 * @returns {string} The JSON string
	 */
	FormUtils.stringifyJSON = function (obj) {
		if (window.JSON && window.JSON.stringify) {
			return JSON.stringify(obj);
		}

		// Fallback for IE7 - basic implementation
		return FormUtils._stringifyValue(obj);
	};

	/**
	 * Internal helper for JSON stringification
	 * @private
	 */
	FormUtils._stringifyValue = function (val) {
		if (val === null || val === undefined) {
			return "null";
		}

		var type = typeof val;

		if (type === "boolean" || type === "number") {
			return String(val);
		}

		if (type === "string") {
			return '"' + val.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
		}

		if (FormUtils.isArray(val)) {
			var arrStr = "[";
			for (var i = 0; i < val.length; i++) {
				if (i > 0) arrStr += ",";
				arrStr += FormUtils._stringifyValue(val[i]);
			}
			return arrStr + "]";
		}

		if (type === "object") {
			var objStr = "{";
			var first = true;
			for (var key in val) {
				if (val.hasOwnProperty(key)) {
					if (!first) objStr += ",";
					objStr += '"' + key + '":' + FormUtils._stringifyValue(val[key]);
					first = false;
				}
			}
			return objStr + "}";
		}

		return "null";
	};

	// Expose to window
	window.FormUtils = FormUtils;
})(window);
