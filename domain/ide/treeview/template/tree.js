// ES5 compatible — expand/collapse logic
(function() {
  function executeCommand(cmd, args, callback) {
    if (typeof window.__ideExecuteCommand__ === 'function') {
      window.__ideExecuteCommand__(cmd, args, callback);
    }
  }

  function hasClass(el, cls) {
    return !!el && !!el.classList && el.classList.contains(cls);
  }

  function findAncestor(el, className, stopEl) {
    var current = el;
    while (current && current !== stopEl) {
      if (hasClass(current, className)) {
        return current;
      }
      current = current.parentElement;
    }
    return null;
  }

  function findChildrenContainer(node) {
    if (!node) return null;
    var childElements = node.childNodes;
    for (var i = 0; i < childElements.length; i++) {
      if (hasClass(childElements[i], 'tree-node-children')) {
        return childElements[i];
      }
    }
    return null;
  }

  function parseIntSafe(value, fallback) {
    var parsed = parseInt(value, 10);
    return isNaN(parsed) ? fallback : parsed;
  }

  var container = document.getElementById('treeContainer');
  if (!container) return;

  function selectNodeRow(row) {
    if (!row) return;
    var prev = container.querySelector('.tree-node-row.selected');
    if (prev && prev !== row) {
      prev.classList.remove('selected');
    }
    if (!row.classList.contains('selected')) {
      row.classList.add('selected');
    }
  }

  window.__selectTreeNode__ = function(issueId) {
    if (!issueId) return;
    var row = container.querySelector('[data-issue-id="' + issueId + '"]');
    if (!row) return;
    // Expand all ancestor tree-node elements so the issue is visible
    var parent = row.parentElement;
    while (parent && parent !== container) {
      if (hasClass(parent, 'tree-node') && !parent.classList.contains('expanded')) {
        parent.classList.add('expanded');
        var parentNodeId = parent.getAttribute('data-node-id');
        if (parentNodeId) {
          executeCommand('snyk.setNodeExpanded', [parentNodeId, true]);
        }
      }
      parent = parent.parentElement;
    }
    selectNodeRow(row);
    if (row.scrollIntoView) row.scrollIntoView(false);
  };

  // Scan error overlay for product error nodes.
  var activeErrorOverlay = null;
  var activeErrorKeyDown = null;
  var activeErrorOutsideClick = null;

  function dismissErrorOverlay() {
    if (activeErrorOverlay && activeErrorOverlay.parentNode) {
      activeErrorOverlay.parentNode.removeChild(activeErrorOverlay);
    }
    if (activeErrorKeyDown) {
      document.removeEventListener('keydown', activeErrorKeyDown);
      activeErrorKeyDown = null;
    }
    if (activeErrorOutsideClick) {
      document.removeEventListener('click', activeErrorOutsideClick);
      activeErrorOutsideClick = null;
    }
    activeErrorOverlay = null;
  }

  function showErrorOverlay(row, productLabel, errorMessage) {
    dismissErrorOverlay();
    dismissRefPicker();

    var overlay = document.createElement('div');
    overlay.className = 'error-overlay';

    var title = document.createElement('div');
    title.className = 'error-overlay-title';
    title.textContent = (productLabel ? productLabel + ' — ' : '') + 'Scan Error';
    overlay.appendChild(title);

    var pre = document.createElement('pre');
    pre.className = 'error-overlay-message';
    pre.textContent = errorMessage;
    overlay.appendChild(pre);

    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'error-overlay-close';
    closeBtn.textContent = 'Close';
    closeBtn.addEventListener('click', function(ev) {
      ev.stopPropagation();
      dismissErrorOverlay();
    });
    overlay.appendChild(closeBtn);

    // Position below the clicked row using fixed positioning so the overlay is
    // viewport-relative and not clipped by the scrollable tree container.
    var rect = row.getBoundingClientRect();
    var vw = window.innerWidth || document.documentElement.clientWidth || 600;
    var vh = window.innerHeight || document.documentElement.clientHeight || 400;
    var overlayW = Math.min(520, vw - 16);
    var topPos = rect.bottom + 4;
    // Flip above the row if not enough space below
    if (topPos + 200 > vh) { topPos = Math.max(4, rect.top - 4); }
    var leftPos = Math.max(4, Math.min(rect.left, vw - overlayW - 8));
    overlay.style.position = 'fixed';
    overlay.style.top = topPos + 'px';
    overlay.style.left = leftPos + 'px';
    overlay.style.width = overlayW + 'px';

    document.body.appendChild(overlay);
    activeErrorOverlay = overlay;

    activeErrorKeyDown = function(ev) {
      if (ev.key === 'Escape' || ev.key === 'Esc' || ev.keyCode === 27) {
        dismissErrorOverlay();
      }
    };
    document.addEventListener('keydown', activeErrorKeyDown);

    setTimeout(function() {
      if (!activeErrorOverlay) return;
      activeErrorOutsideClick = function(ev) {
        if (activeErrorOverlay && !activeErrorOverlay.contains(ev.target)) {
          dismissErrorOverlay();
        }
      };
      document.addEventListener('click', activeErrorOutsideClick);
    }, 0);
  }

  // Delta reference picker overlay for folder nodes.
  var activeRefPicker = null;
  var activeRefPickerKeyDown = null;
  var activeRefPickerOutsideClick = null;

  function dismissRefPicker() {
    if (activeRefPicker && activeRefPicker.parentNode) {
      activeRefPicker.parentNode.removeChild(activeRefPicker);
    }
    if (activeRefPickerKeyDown) {
      document.removeEventListener('keydown', activeRefPickerKeyDown);
      activeRefPickerKeyDown = null;
    }
    if (activeRefPickerOutsideClick) {
      document.removeEventListener('click', activeRefPickerOutsideClick);
      activeRefPickerOutsideClick = null;
    }
    activeRefPicker = null;
  }

  function showRefPicker(folderNode, row) {
    dismissRefPicker();

    var folderPath = folderNode.getAttribute('data-file-path') || '';
    var baseBranch = folderNode.getAttribute('data-base-branch') || '';
    var refFolderPath = folderNode.getAttribute('data-reference-folder-path') || '';
    var branchesStr = folderNode.getAttribute('data-local-branches') || '';
    var branches = branchesStr ? branchesStr.split(',') : [];

    var overlay = document.createElement('div');
    overlay.className = 'ref-picker-overlay';

    // Branch section
    var branchTitle = document.createElement('div');
    branchTitle.className = 'ref-picker-section-title';
    branchTitle.textContent = 'Base Branch';
    overlay.appendChild(branchTitle);

    if (branches.length > 0) {
      for (var i = 0; i < branches.length; i++) {
        var item = document.createElement('div');
        item.className = 'ref-picker-item';
        if (branches[i] === baseBranch && !refFolderPath) {
          item.classList.add('ref-picker-item-active');
        }
        item.setAttribute('data-branch', branches[i]);
        item.textContent = branches[i];
        overlay.appendChild(item);
      }
    } else {
      var noBranches = document.createElement('div');
      noBranches.className = 'ref-picker-current';
      noBranches.textContent = 'No local branches found';
      overlay.appendChild(noBranches);
    }

    // Separator
    var sep = document.createElement('div');
    sep.className = 'ref-picker-separator';
    overlay.appendChild(sep);

    // Reference folder section
    var folderTitle = document.createElement('div');
    folderTitle.className = 'ref-picker-section-title';
    folderTitle.textContent = 'Reference Folder';
    overlay.appendChild(folderTitle);

    if (refFolderPath) {
      var currentRef = document.createElement('div');
      currentRef.className = 'ref-picker-current';
      currentRef.textContent = 'Current: ' + refFolderPath;
      overlay.appendChild(currentRef);
    }

    var folderRow = document.createElement('div');
    folderRow.className = 'ref-picker-folder-row';

    var folderInput = document.createElement('input');
    folderInput.type = 'text';
    folderInput.className = 'ref-picker-folder-input';
    folderInput.placeholder = 'Enter folder path...';
    folderInput.value = refFolderPath || '';
    folderRow.appendChild(folderInput);

    var selectBtn = document.createElement('button');
    selectBtn.type = 'button';
    selectBtn.className = 'ref-picker-folder-btn';
    selectBtn.textContent = 'Select';
    folderRow.appendChild(selectBtn);

    if (refFolderPath) {
      var clearBtn = document.createElement('button');
      clearBtn.type = 'button';
      clearBtn.className = 'ref-picker-folder-btn ref-picker-folder-btn-clear';
      clearBtn.textContent = 'Clear';
      folderRow.appendChild(clearBtn);

      clearBtn.addEventListener('click', function(ev) {
        ev.stopPropagation();
        executeCommand('snyk.updateFolderConfig', [folderPath, { referenceFolderPath: '' }]);
        dismissRefPicker();
      });
    }

    overlay.appendChild(folderRow);

    // Position overlay near the clicked row
    var rect = row.getBoundingClientRect();
    var containerRect = container.getBoundingClientRect();
    overlay.style.position = 'absolute';
    overlay.style.top = (rect.bottom - containerRect.top + container.scrollTop) + 'px';
    overlay.style.left = (rect.left - containerRect.left + 16) + 'px';

    container.style.position = 'relative';
    container.appendChild(overlay);
    activeRefPicker = overlay;

    // Handle branch item click (selects branch, clears folder ref via command)
    overlay.addEventListener('click', function(ev) {
      var target = ev.target;
      while (target && target !== overlay) {
        if (hasClass(target, 'ref-picker-item') && target.getAttribute('data-branch')) {
          var selectedBranch = target.getAttribute('data-branch');
          if (selectedBranch) {
            executeCommand('snyk.updateFolderConfig', [folderPath, { baseBranch: selectedBranch }]);
          }
          dismissRefPicker();
          return;
        }
        target = target.parentElement;
      }
    });

    // Handle folder select button
    selectBtn.addEventListener('click', function(ev) {
      ev.stopPropagation();
      var path = folderInput.value.trim();
      if (path) {
        executeCommand('snyk.updateFolderConfig', [folderPath, { referenceFolderPath: path }]);
        dismissRefPicker();
      }
    });

    // Handle Enter key in folder input
    folderInput.addEventListener('keydown', function(ev) {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        var path = folderInput.value.trim();
        if (path) {
          executeCommand('snyk.updateFolderConfig', [folderPath, { referenceFolderPath: path }]);
          dismissRefPicker();
        }
      }
    });

    // Prevent input clicks from dismissing or propagating
    folderInput.addEventListener('click', function(ev) { ev.stopPropagation(); });

    // Dismiss on Escape — stored so dismissRefPicker can clean up
    activeRefPickerKeyDown = function(ev) {
      // IE11 reports Escape as "Esc" and may only provide keyCode.
      if (ev.key === 'Escape' || ev.key === 'Esc' || ev.keyCode === 27) {
        dismissRefPicker();
      }
    };
    document.addEventListener('keydown', activeRefPickerKeyDown);

    // Dismiss on click outside (delayed to avoid catching the triggering click).
    // Guard against the picker being dismissed before the timeout fires.
    setTimeout(function() {
      if (!activeRefPicker) return;
      activeRefPickerOutsideClick = function(ev) {
        if (activeRefPicker && !activeRefPicker.contains(ev.target)) {
          dismissRefPicker();
        }
      };
      document.addEventListener('click', activeRefPickerOutsideClick);
    }, 0);
  }

  container.addEventListener('click', function(e) {
    var row = null;
    var el = e.target;
    // Walk up to find the tree-node-row (use hasClass for SVG compatibility)
    while (el && el !== container) {
      if (hasClass(el, 'tree-node-row')) {
        row = el;
        break;
      }
      el = el.parentElement;
    }
    if (!row) return;

    var node = row.parentElement;
    if (!node) return;

    // Handle issue node click — navigate to range in file and show issue details.
    // The bridge function signature matches snyk.navigateToRange command args:
    //   args[0] = filePath (string)
    //   args[1] = range ({ start: { line, character }, end: { line, character } })
    //   args[2] = issueId (string, optional) — triggers issue detail panel
    //   args[3] = product (string, optional) — product context for detail panel
    if (hasClass(node, 'tree-node-issue') || hasClass(node, 'tree-node-location')) {
      selectNodeRow(row);

      var filePath = row.getAttribute('data-file-path');
      var startLine = parseIntSafe(row.getAttribute('data-start-line'), 0);
      var endLine = parseIntSafe(row.getAttribute('data-end-line'), 0);
      var startChar = parseIntSafe(row.getAttribute('data-start-char'), 0);
      var endChar = parseIntSafe(row.getAttribute('data-end-char'), 0);
      var issueId = row.getAttribute('data-issue-id');
      var fileNode = findAncestor(node, 'tree-node-file', container);
      var product = fileNode ? fileNode.getAttribute('data-product') : '';
      if (filePath) {
        var cmdArgs = [filePath, {
          start: { line: startLine, character: startChar },
          end: { line: endLine, character: endChar }
        }];
        if (issueId) {
          cmdArgs.push(issueId);
          cmdArgs.push(product || '');
        }
        executeCommand('snyk.navigateToRange', cmdArgs);
      }
      return;
    }

    // Handle folder node click — show reference picker overlay when delta is enabled.
    // Do NOT return early so the expand/collapse logic below still runs.
    if (node.getAttribute('data-delta-enabled') === 'true') {
      selectNodeRow(row);
      showRefPicker(node, row);
    }

    // Handle product node with scan error — show inline error overlay.
    var errorMessage = node.getAttribute('data-error-message');
    if (errorMessage && hasClass(node, 'tree-node-error')) {
      selectNodeRow(row);
      var productLabel = '';
      var labelEl = row.querySelector('.tree-label');
      if (labelEl) { productLabel = labelEl.textContent.trim(); }
      showErrorOverlay(row, productLabel, errorMessage);
      var productAttr = '';
      var nodeId = node.getAttribute('data-node-id') || '';
      var parts = nodeId.split(':');
      productAttr = parts.length >= 3 ? parts[parts.length - 1] : '';
      executeCommand('snyk.showScanErrorDetails', [productAttr, errorMessage]);
    }

    // Toggle expand/collapse for non-leaf nodes
    var children = findChildrenContainer(node);
    if (!children) return;

    var wasExpanded = node.classList.contains('expanded');
    if (wasExpanded) {
      node.classList.remove('expanded');
    } else {
      node.classList.add('expanded');
    }

    // Persist expand/collapse state in the LS so it survives re-renders.
    var nodeId = node.getAttribute('data-node-id');
    if (nodeId) {
      executeCommand('snyk.setNodeExpanded', [nodeId, !wasExpanded]);
    }
  });

  // Auto-expand is handled server-side by the LS via ExpandState.
  // The LS renders the correct "expanded" class on each node based on:
  //   - user overrides (persisted via snyk.setNodeExpanded)
  //   - auto-expand for file nodes in small trees (totalIssues <= threshold)
  // No client-side auto-expand is needed — this prevents collapsing user
  // state when new product scan results trigger a re-render.

  // Filter toolbar click handler.
  // Walk up from click target to find the <button> since SVG icon buttons
  // may have <svg>/<rect>/<path> elements as the actual e.target.
  var filterToolbar = document.getElementById('filterToolbar');
  if (filterToolbar) {
    filterToolbar.addEventListener('click', function(e) {
      var btn = e.target;
      while (btn && btn !== filterToolbar) {
        if (hasClass(btn, 'filter-btn')) break;
        btn = btn.parentElement;
      }
      if (!btn || !hasClass(btn, 'filter-btn')) return;

      var filterType = btn.getAttribute('data-filter-type');
      var filterValue = btn.getAttribute('data-filter-value');
      if (!filterType || !filterValue) return;

      var isActive = hasClass(btn, 'filter-active');
      var enabled = !isActive;

      executeCommand('snyk.toggleTreeFilter', [filterType, filterValue, enabled]);
    });
  }

  // Expand All / Collapse All toolbar buttons.
  // Suppresses reflows by hiding the container during bulk DOM mutations.
  function expandAllNodes() {
    var allNodes = container.querySelectorAll('.tree-node');
    var batch = [];
    container.style.display = 'none';
    for (var i = 0; i < allNodes.length; i++) {
      var node = allNodes[i];
      if (findChildrenContainer(node) && !node.classList.contains('expanded')) {
        node.classList.add('expanded');
        var nodeId = node.getAttribute('data-node-id');
        if (nodeId) batch.push([nodeId, true]);
      }
    }
    container.style.display = '';
    if (batch.length > 0) executeCommand('snyk.setNodeExpanded', [batch]);
  }

  function collapseAllNodes() {
    var allNodes = container.querySelectorAll('.tree-node');
    var batch = [];
    container.style.display = 'none';
    for (var i = 0; i < allNodes.length; i++) {
      var node = allNodes[i];
      if (node.classList.contains('expanded')) {
        node.classList.remove('expanded');
        var nodeId = node.getAttribute('data-node-id');
        if (nodeId) batch.push([nodeId, false]);
      }
    }
    container.style.display = '';
    if (batch.length > 0) executeCommand('snyk.setNodeExpanded', [batch]);
  }

  var expandAllBtn = document.getElementById('expandAllBtn');
  if (expandAllBtn) {
    expandAllBtn.addEventListener('click', function() { expandAllNodes(); });
  }

  var collapseAllBtn = document.getElementById('collapseAllBtn');
  if (collapseAllBtn) {
    collapseAllBtn.addEventListener('click', function() { collapseAllNodes(); });
  }
})();
