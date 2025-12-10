// ABOUTME: Form validation functions for endpoint and risk score fields
// ABOUTME: Provides validation logic used throughout the configuration dialog

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var validation = {};

	// Validate Endpoint
	validation.validateEndpoint = function(url) {
		if (!url) return true; // Empty URL allows default
		// Regex for api.*.snyk.io or api.*.snykgov.io
		var snykRegex = /^https:\/\/api\..*\.snyk\.io/;
		var snykgovRegex = /^https:\/\/api\..*\.snykgov\.io/;

		return (
			snykRegex.test(url) ||
			snykgovRegex.test(url) ||
			url === "https://api.snyk.io"
		);
	};

	// Validate risk score
	validation.validateRiskScore = function(value) {
		if (value === "" || value === null || value === undefined) {
			return true; // Empty is valid (will use default)
		}

		var num = parseInt(value);
		return !isNaN(num) && num >= 0 && num <= 1000;
	};

	// Validate endpoint on input
	validation.validateEndpointOnInput = function() {
		var helpers = window.ConfigApp.helpers;
		var endpointInput = helpers.get("endpoint");
		var endpointError = helpers.get("endpoint-error");

		if (!endpointInput || !endpointError) return;

		var currentEndpoint = endpointInput.value;

		if (currentEndpoint && !validation.validateEndpoint(currentEndpoint)) {
			helpers.removeClass(endpointError, "hidden");
		} else {
			helpers.addClass(endpointError, "hidden");
		}
	};

	// Validate risk score on input
	validation.validateRiskScoreOnInput = function() {
		var helpers = window.ConfigApp.helpers;
		var riskScoreInput = helpers.get("riskScoreThreshold");
		var riskScoreError = helpers.get("riskScore-error");

		if (!riskScoreInput || !riskScoreError) return;

		var currentValue = riskScoreInput.value;

		if (!validation.validateRiskScore(currentValue)) {
			helpers.removeClass(riskScoreError, "hidden");
		} else {
			helpers.addClass(riskScoreError, "hidden");
		}
	};

	// Validate additional environment variables format
	validation.validateAdditionalEnv = function(value) {
		if (!value || value.trim() === "") {
			return true; // Empty is valid
		}

		// Split by semicolon to get individual env vars
		var envVars = value.split(";");

		for (var i = 0; i < envVars.length; i++) {
			var envVar = envVars[i].trim();

			// Skip empty segments
			if (envVar === "") {
				continue;
			}

			// Check if it contains exactly one '=' separator
			var parts = envVar.split("=");
			if (parts.length !== 2) {
				return false;
			}

			var key = parts[0].trim();
			var val = parts[1].trim();

			// Key must not be empty and should be a valid env var name (alphanumeric + underscore)
			if (key === "" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
				return false;
			}

			// Value can be empty but key cannot
			if (val === undefined) {
				return false;
			}
		}

		return true;
	};

	// Validate additional env on input
	validation.validateAdditionalEnvOnInput = function() {
		var helpers = window.ConfigApp.helpers;
		var additionalEnvInput = helpers.get("additionalEnv");
		var additionalEnvError = helpers.get("additionalEnv-error");

		if (!additionalEnvInput || !additionalEnvError) return;

		var currentValue = additionalEnvInput.value;

		if (!validation.validateAdditionalEnv(currentValue)) {
			helpers.removeClass(additionalEnvError, "hidden");
		} else {
			helpers.addClass(additionalEnvError, "hidden");
		}
	};

	window.ConfigApp.validation = validation;
})();
