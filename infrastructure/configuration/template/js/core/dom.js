// ABOUTME: DOM utility helpers for cross-browser compatibility (IE7+)
// ABOUTME: Provides common DOM manipulation functions used throughout the config dialog

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var dom = {};

	// Helper to get element by ID
	dom.get = function(id) {
		return document.getElementById(id);
	};

	// Helper to get elements by name
	dom.getByName = function(name) {
		return document.getElementsByName(name);
	};

	// Helper to add event listener (IE7 compatible)
	dom.addEvent = function(element, event, handler) {
		if (element.addEventListener) {
			element.addEventListener(event, handler, false);
		} else if (element.attachEvent) {
			element.attachEvent("on" + event, handler);
		} else {
			element["on" + event] = handler;
		}
	};

	// Helper to remove class (IE7 compatible)
	dom.removeClass = function(element, className) {
		if (!element) return;
		var reg = new RegExp("(\\s|^)" + className + "(\\s|$)");
		element.className = element.className.replace(reg, " ");
	};

	// Helper to add class (IE7 compatible)
	dom.addClass = function(element, className) {
		if (!element) return;
		if (element.className.indexOf(className) === -1) {
			element.className += " " + className;
		}
	};

	window.ConfigApp.dom = dom;
})();
