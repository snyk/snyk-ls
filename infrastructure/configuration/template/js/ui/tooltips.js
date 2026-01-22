// ABOUTME: Tooltip initialization for Bootstrap tooltips
// ABOUTME: Initializes Bootstrap 4 tooltips on elements with data-toggle="tooltip"

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var tooltips = {};

	tooltips.initialize = function() {
		// Initialize Bootstrap 4 tooltips
		if (typeof $ !== "undefined" && $.fn && $.fn.tooltip) {
			// All elements with data-toggle="tooltip" (spans inside labels, checkboxes, and buttons)
			$('[data-toggle="tooltip"]').tooltip({
				placement: 'top',
				boundary: 'window',
				trigger: 'hover'
			});
		}
	};

	window.ConfigApp.tooltips = tooltips;
})();
