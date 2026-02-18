// ES5 compatible — expand/collapse logic
(function() {
  var ISSUE_CHUNK_SIZE = 100;
  var pendingIssueChunkRequests = {};

  function executeCommand(cmd, args, callback) {
    if (typeof window.__ideExecuteCommand__ === 'function') {
      window.__ideExecuteCommand__(cmd, args, callback);
    }
  }

  function hasClass(el, className) {
    if (!el) return false;
    var cn = typeof el.className === 'string' ? el.className : (el.getAttribute && el.getAttribute('class')) || '';
    return cn.indexOf(className) !== -1;
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

  function appendLoadingRow(childrenContainer) {
    if (!childrenContainer) return;
    childrenContainer.innerHTML = '<div class="tree-node tree-node-info"><div class="tree-node-row tree-node-loading">Loading issues...</div></div>';
  }

  function clearLoadingRow(childrenContainer) {
    if (!childrenContainer) return;
    if (childrenContainer.innerHTML.indexOf('tree-node-loading') !== -1) {
      childrenContainer.innerHTML = '';
    }
  }

  function requestIssueChunk(fileNode, start, end, append) {
    if (!fileNode) return;

    var nodeId = fileNode.getAttribute('data-node-id');
    var filePath = fileNode.getAttribute('data-file-path');
    var product = fileNode.getAttribute('data-product');
    if (!nodeId || !filePath || !product) {
      return;
    }

    var requestId = nodeId + '-' + String(start) + '-' + String(new Date().getTime());
    pendingIssueChunkRequests[requestId] = {
      nodeId: nodeId,
      append: append
    };

    var childrenContainer = findChildrenContainer(fileNode);
    if (!append) {
      appendLoadingRow(childrenContainer);
    } else if (childrenContainer) {
      var loadMoreRows = childrenContainer.getElementsByClassName('tree-node-load-more');
      if (loadMoreRows.length > 0) {
        var row = loadMoreRows[0];
        if (row.parentNode) {
          row.parentNode.removeChild(row);
        }
      }
    }

    fileNode.setAttribute('data-issues-loading', 'true');
    try {
      executeCommand('snyk.getTreeViewIssueChunk', [requestId, filePath, product, start, end]);
    } catch (err) {
      fileNode.setAttribute('data-issues-loading', 'false');
      clearLoadingRow(childrenContainer);
    }
  }

  function maybeLoadIssuesForFileNode(fileNode) {
    if (!fileNode) return;
    var alreadyLoaded = fileNode.getAttribute('data-issues-loaded') === 'true';
    var loading = fileNode.getAttribute('data-issues-loading') === 'true';
    if (!alreadyLoaded && !loading) {
      requestIssueChunk(fileNode, 0, ISSUE_CHUNK_SIZE, false);
    }
  }

  window.__onIdeTreeIssueChunk__ = function(requestId, payload) {
    var pending = pendingIssueChunkRequests[requestId];
    if (!pending) return;
    delete pendingIssueChunkRequests[requestId];

    var selector = '[data-node-id="' + pending.nodeId + '"]';
    var fileNode = container.querySelector(selector);
    if (!fileNode) return;

    var childrenContainer = findChildrenContainer(fileNode);
    if (!childrenContainer) return;

    var chunk = payload;
    if (typeof payload === 'string') {
      try {
        chunk = JSON.parse(payload);
      } catch (err) {
        chunk = null;
      }
    }
    if (!chunk) {
      fileNode.setAttribute('data-issues-loading', 'false');
      clearLoadingRow(childrenContainer);
      return;
    }

    clearLoadingRow(childrenContainer);
    if (!pending.append) {
      childrenContainer.innerHTML = '';
    }
    if (chunk.issueNodesHtml) {
      childrenContainer.insertAdjacentHTML('beforeend', chunk.issueNodesHtml);
    }

    fileNode.setAttribute('data-issues-loading', 'false');
    fileNode.setAttribute('data-issues-loaded', 'true');
    if (chunk.hasMore) {
      fileNode.setAttribute('data-next-start', String(chunk.nextStart));
    } else {
      fileNode.removeAttribute('data-next-start');
    }
  };

  var container = document.getElementById('treeContainer');
  if (!container) return;

  function selectNodeRow(row) {
    if (!row) return;
    var prev = container.querySelector('.tree-node-row.selected');
    if (prev && prev !== row) {
      prev.className = prev.className.replace(/\s*selected/g, '');
    }
    if (!hasClass(row, 'selected')) {
      row.className = row.className + ' selected';
    }
  }

  window.__selectTreeNode__ = function(issueId) {
    if (!issueId) return;
    var row = container.querySelector('[data-issue-id="' + issueId + '"]');
    if (!row) return;
    // Expand all ancestor tree-node elements so the issue is visible
    var parent = row.parentElement;
    while (parent && parent !== container) {
      if (parent.className && parent.className.indexOf('tree-node') !== -1 && !hasClass(parent, 'expanded')) {
        parent.className = parent.className + ' expanded';
      }
      parent = parent.parentElement;
    }
    selectNodeRow(row);
    if (row.scrollIntoView) row.scrollIntoView(false);
  };

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
          item.className += ' ref-picker-item-active';
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
      if (ev.key === 'Escape') {
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
    // Walk up to find the tree-node-row
    while (el && el !== container) {
      if (el.className && el.className.indexOf('tree-node-row') !== -1) {
        row = el;
        break;
      }
      el = el.parentElement;
    }
    if (!row) return;

    var node = row.parentElement;
    if (!node) return;

    // Handle load more click
    if (hasClass(node, 'tree-node-load-more')) {
      var fileNode = findAncestor(node, 'tree-node-file', container);
      if (!fileNode) return;

      var nextStart = parseIntSafe(fileNode.getAttribute('data-next-start'), 0);
      requestIssueChunk(fileNode, nextStart, nextStart + ISSUE_CHUNK_SIZE, true);
      return;
    }

    // Handle issue node click — navigate to range in file and show issue details.
    // The bridge function signature matches snyk.navigateToRange command args:
    //   args[0] = filePath (string)
    //   args[1] = range ({ start: { line, character }, end: { line, character } })
    //   args[2] = issueId (string, optional) — triggers issue detail panel
    //   args[3] = product (string, optional) — product context for detail panel
    if (hasClass(node, 'tree-node-issue')) {
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
    if (node.getAttribute('data-delta-enabled') === 'true') {
      selectNodeRow(row);
      showRefPicker(node, row);
      return;
    }

    // Handle product node with scan error — show error details in detail panel.
    var errorMessage = node.getAttribute('data-error-message');
    if (errorMessage && hasClass(node, 'tree-node-error')) {
      selectNodeRow(row);
      var productAttr = '';
      var productIcon = row.querySelector('.product-icon');
      if (productIcon) {
        var nodeId = node.getAttribute('data-node-id') || '';
        var parts = nodeId.split(':');
        productAttr = parts.length >= 3 ? parts[2] : '';
      }
      executeCommand('snyk.showScanErrorDetails', [productAttr, errorMessage]);
    }

    // Toggle expand/collapse for non-leaf nodes
    var children = findChildrenContainer(node);
    if (!children) return;

    var wasExpanded = hasClass(node, 'expanded');
    if (wasExpanded) {
      node.className = node.className.replace(/\s*expanded/g, '');
    } else {
      node.className = node.className + ' expanded';
    }

    // Persist expand/collapse state in the LS so it survives re-renders.
    var nodeId = node.getAttribute('data-node-id');
    if (nodeId) {
      executeCommand('snyk.setNodeExpanded', [nodeId, !wasExpanded]);
    }

    // Lazy-load issue nodes when a file node is expanded for the first time.
    if (!wasExpanded && hasClass(node, 'tree-node-file')) {
      maybeLoadIssuesForFileNode(node);
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
  function expandAllNodes() {
    var allNodes = container.getElementsByClassName('tree-node');
    for (var i = 0; i < allNodes.length; i++) {
      var node = allNodes[i];
      if (findChildrenContainer(node) && !hasClass(node, 'expanded')) {
        node.className = node.className + ' expanded';
        var nodeId = node.getAttribute('data-node-id');
        if (nodeId) {
          executeCommand('snyk.setNodeExpanded', [nodeId, true]);
        }
        if (hasClass(node, 'tree-node-file')) {
          maybeLoadIssuesForFileNode(node);
        }
      }
    }
  }

  function collapseAllNodes() {
    var allNodes = container.getElementsByClassName('tree-node');
    for (var i = 0; i < allNodes.length; i++) {
      var node = allNodes[i];
      if (hasClass(node, 'expanded')) {
        node.className = node.className.replace(/\s*expanded/g, '');
        var nodeId = node.getAttribute('data-node-id');
        if (nodeId) {
          executeCommand('snyk.setNodeExpanded', [nodeId, false]);
        }
      }
    }
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
