/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ABOUTME: Tab switching and folder dropdown logic for the settings UI.
// ABOUTME: Handles static tab navigation (Bootstrap, Global Fallbacks),
// ABOUTME: single-folder tab display, and multi-folder dropdown selection.
(function() {
    window.ConfigApp = window.ConfigApp || {};
    var tabs = {};
    var dom = window.ConfigApp.dom;

    // IE11-safe closest() polyfill
    function closestParent(el, selector) {
        if (el.closest) return el.closest(selector);
        var current = el;
        while (current && current !== document) {
            if (current.matches ? current.matches(selector) : current.msMatchesSelector(selector)) {
                return current;
            }
            current = current.parentElement;
        }
        return null;
    }

    function deactivateAllTabs() {
        var navLinks = document.querySelectorAll('.settings-tabs .nav-link');
        for (var i = 0; i < navLinks.length; i++) {
            dom.removeClass(navLinks[i], 'active');
        }
        var panes = document.querySelectorAll('.tab-content > .tab-pane');
        for (var j = 0; j < panes.length; j++) {
            dom.removeClass(panes[j], 'active');
        }
    }

    tabs.initialize = function() {
        var i;

        // Tab switching for static tabs (Bootstrap, Global Fallbacks, single-folder)
        var tabLinks = document.querySelectorAll('.settings-tabs .nav-link[data-tab-target]');
        for (i = 0; i < tabLinks.length; i++) {
            dom.addEvent(tabLinks[i], 'click', function(e) {
                e.preventDefault();
                deactivateAllTabs();
                // Activate clicked tab
                dom.addClass(this, 'active');
                var targetSelector = this.getAttribute('data-tab-target');
                var target = targetSelector ? document.querySelector(targetSelector) : null;
                if (target) {
                    dom.addClass(target, 'active');
                }
                // Reset folder dropdown state when switching to non-folder tab
                var dropdownToggle = document.getElementById('folder-dropdown-btn');
                if (dropdownToggle && !closestParent(this, '.folder-selector-item')) {
                    dom.removeClass(dropdownToggle, 'active');
                    var label = document.getElementById('folderDropdownLabel');
                    if (label) { label.textContent = label.getAttribute('data-default-label') || label.textContent; }
                    var folderItems = document.querySelectorAll('.folder-dropdown-item');
                    for (var k = 0; k < folderItems.length; k++) {
                        dom.removeClass(folderItems[k], 'selected');
                    }
                }
            });
        }

        // Folder dropdown logic (multi-folder)
        var dropdownBtn = document.getElementById('folder-dropdown-btn');
        var dropdownMenu = document.getElementById('folderDropdownMenu');
        var dropdownLabelEl = document.getElementById('folderDropdownLabel');

        if (dropdownBtn && dropdownMenu) {
            // Store default label
            if (dropdownLabelEl) {
                dropdownLabelEl.setAttribute('data-default-label', dropdownLabelEl.textContent);
            }

            // Toggle dropdown
            dom.addEvent(dropdownBtn, 'click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (dom.hasClass(dropdownMenu, 'show')) {
                    dom.removeClass(dropdownMenu, 'show');
                } else {
                    dom.addClass(dropdownMenu, 'show');
                }
            });

            // Close on outside click
            dom.addEvent(document, 'click', function(e) {
                if (!closestParent(e.target, '.folder-dropdown')) {
                    dom.removeClass(dropdownMenu, 'show');
                }
            });

            // Folder selection
            var folderItems = dropdownMenu.querySelectorAll('.folder-dropdown-item');
            for (i = 0; i < folderItems.length; i++) {
                dom.addEvent(folderItems[i], 'click', function(e) {
                    e.preventDefault();
                    var index = this.getAttribute('data-folder-index');
                    var nameSpan = this.querySelector('.folder-item-name');
                    var itemName = nameSpan ? nameSpan.textContent : '';

                    deactivateAllTabs();

                    // Activate folder pane
                    var pane = document.getElementById('folder-pane-' + index);
                    if (pane) {
                        dom.addClass(pane, 'active');
                    }

                    // Update dropdown label and style
                    var settingsTabs = document.getElementById('settingsTabs');
                    var folderLabel = settingsTabs ? settingsTabs.getAttribute('data-folder-label') || 'Folder' : 'Folder';
                    dom.addClass(dropdownBtn, 'active');
                    if (dropdownLabelEl) {
                        dropdownLabelEl.textContent = itemName + ' - ' + folderLabel;
                    }

                    // Mark selected item
                    var allItems = dropdownMenu.querySelectorAll('.folder-dropdown-item');
                    for (var m = 0; m < allItems.length; m++) {
                        dom.removeClass(allItems[m], 'selected');
                    }
                    dom.addClass(this, 'selected');

                    // Close dropdown
                    dom.removeClass(dropdownMenu, 'show');
                });
            }
        }
    };

    window.ConfigApp.tabs = tabs;
})();
