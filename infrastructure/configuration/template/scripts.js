(function() {
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
            element.attachEvent('on' + event, handler);
        } else {
            element['on' + event] = handler;
        }
    }

    // Helper to remove class (IE7 compatible)
    function removeClass(element, className) {
        if (!element) return;
        var reg = new RegExp('(\\s|^)' + className + '(\\s|$)');
        element.className = element.className.replace(reg, ' ');
    }

    // Helper to add class (IE7 compatible)
    function addClass(element, className) {
        if (!element) return;
        if (element.className.indexOf(className) === -1) {
            element.className += ' ' + className;
        }
    }

    // Validate Endpoint
    function validateEndpoint(url) {
        if (!url) return true; // Empty URL allows default
        // Regex for api.*.snyk.io or api.*.snykgov.io
        var snykRegex = /^https:\/\/api\..*\.snyk\.io/;
        var snykgovRegex = /^https:\/\/api\..*\.snykgov\.io/;
        
        return snykRegex.test(url) || snykgovRegex.test(url) || url === "https://app.snyk.io/api";
    }

    // Collect form data
    function collectData() {
        var data = {
            folderConfigs: []
        };

        var form = get('configForm');
        var inputs = form.getElementsByTagName('input');
        var selects = form.getElementsByTagName('select');
        var textareas = form.getElementsByTagName('textarea');
        
        // Process all elements
        processElements(inputs, data);
        processElements(selects, data);
        processElements(textareas, data);

        // Process complex objects
        processFilterSeverity(data);
        processIssueViewOptions(data);
        processTrustedFolders(data);

        return data;
    }

    function processElements(elements, data) {
        for (var i = 0; i < elements.length; i++) {
            var el = elements[i];
            var name = el.name;

            if (!name) continue;

            // Skip complex object fields (handled separately)
            if (name.indexOf('filterSeverity_') === 0 || 
                name.indexOf('issueViewOptions_') === 0) {
                continue;
            }

            // Folder logic: folder_INDEX_FIELD
            if (name.indexOf('folder_') === 0) {
                var parts = name.split('_');
                if (parts.length >= 3) {
                    var index = parseInt(parts[1]);
                    var field = parts.slice(2).join('_');
                    
                    if (!data.folderConfigs[index]) {
                        data.folderConfigs[index] = {};
                    }

                    setFieldValue(data.folderConfigs[index], field, el);
                }
            } else {
                // Global setting
                setFieldValue(data, name, el);
            }
        }
    }

    function setFieldValue(obj, field, el) {
        if (el.type === 'checkbox') {
            obj[field] = el.checked ? "true" : "false";
        } else if (el.type === 'number') {
            obj[field] = el.value ? parseInt(el.value) : null;
        } else if (el.tagName.toLowerCase() === 'textarea') {
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
        var critical = getByName('filterSeverity_critical')[0];
        var high = getByName('filterSeverity_high')[0];
        var medium = getByName('filterSeverity_medium')[0];
        var low = getByName('filterSeverity_low')[0];

        if (critical || high || medium || low) {
            data.filterSeverity = {
                critical: critical ? critical.checked : false,
                high: high ? high.checked : false,
                medium: medium ? medium.checked : false,
                low: low ? low.checked : false
            };
        }
    }

    function processIssueViewOptions(data) {
        var openIssues = getByName('issueViewOptions_openIssues')[0];
        var ignoredIssues = getByName('issueViewOptions_ignoredIssues')[0];

        if (openIssues || ignoredIssues) {
            data.issueViewOptions = {
                openIssues: openIssues ? openIssues.checked : false,
                ignoredIssues: ignoredIssues ? ignoredIssues.checked : false
            };
        }
    }

    function processTrustedFolders(data) {
        var trustedFoldersEl = get('trustedFolders');
        if (trustedFoldersEl && trustedFoldersEl.value) {
            var value = trustedFoldersEl.value;
            // Split by comma and filter out empty strings
            var folders = [];
            var parts = value.split(',');
            for (var i = 0; i < parts.length; i++) {
                var folder = parts[i].replace(/^\s+|\s+$/g, ''); // trim
                if (folder) {
                    folders.push(folder);
                }
            }
            data.trustedFolders = folders;
        }
    }

    var originalEndpoint = "";

    // Save handler
    function saveConfig() {
        var endpointInput = get('endpoint');
        var endpointError = get('endpoint-error');
        var currentEndpoint = endpointInput.value;

        if (currentEndpoint && !validateEndpoint(currentEndpoint)) {
            removeClass(endpointError, 'hidden');
            return;
        } else {
            addClass(endpointError, 'hidden');
        }

        var data = collectData();
        var jsonString = JSON.stringify(data);
        
        // Call IDE injected function
        try {
            ${ideSaveConfig}(jsonString);
            
            // If endpoint changed, trigger logout
            if (originalEndpoint && currentEndpoint !== originalEndpoint) {
                 // We might need to wait for save to complete, but here we just trigger it.
                 // Ideally the IDE extension handles the logout if it detects the change, 
                 // but the requirement says "logout command should be called".
                 // Since we are in the webview, we can't call the command directly unless we have a binding.
                 // We can use another injected function or rely on the save handler in the extension to check.
                 // Requirement: "when the endpoint (snyk api url) is changed, logout command should be called"
                 // I'll assume we can call a function.
                 if (typeof ${ideLogout} !== 'undefined') {
                     ${ideLogout}();
                 }
            }
        } catch (e) {
            alert('Error saving configuration: ' + e.message);
        }
    }

    function authenticate() {
        // First save
        saveConfig();
        
        // Then trigger login
        try {
            ${ideLogin}();
        } catch (e) {
            alert('Error initiating authentication: ' + e.message);
        }
    }

    // Initialize
    addEvent(window, 'load', function() {
        var saveBtn = get('save-config-btn');
        if (saveBtn) {
            addEvent(saveBtn, 'click', saveConfig);
        }

        var authBtn = get('authenticate-btn');
        if (authBtn) {
            addEvent(authBtn, 'click', authenticate);
        }

        var endpointInput = get('endpoint');
        if (endpointInput) {
            originalEndpoint = endpointInput.value;
        }
    });

})();
