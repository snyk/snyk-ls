// ES5 compatible — expand/collapse logic
(function() {
  // Keep expansion thresholds aligned with IntelliJ TreeNodeExpander defaults.
  var MAX_AUTO_EXPAND_NODES = 50;
  var EXPANSION_CHUNK_SIZE = 15;
  var ISSUE_CHUNK_SIZE = 100;
  var pendingIssueChunkRequests = {};

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
    if (typeof window.__ideTreeRequestIssueChunk__ !== 'function') {
      return;
    }

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
      // remove existing load-more row before appending next chunk
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
      window.__ideTreeRequestIssueChunk__(requestId, filePath, product, start, end);
    } catch (err) {
      fileNode.setAttribute('data-issues-loading', 'false');
      clearLoadingRow(childrenContainer);
    }
  }

  function ensureExpanded(node) {
    if (!node || hasClass(node, 'expanded')) return;
    node.className = node.className + ' expanded';
  }

  function maybeLoadIssuesForFileNode(fileNode) {
    if (!fileNode) return;
    var alreadyLoaded = fileNode.getAttribute('data-issues-loaded') === 'true';
    var loading = fileNode.getAttribute('data-issues-loading') === 'true';
    if (!alreadyLoaded && !loading) {
      requestIssueChunk(fileNode, 0, ISSUE_CHUNK_SIZE, false);
    }
  }

  function expandFileNodesInChunks(fileNodes, index) {
    if (!fileNodes || index >= fileNodes.length) return;
    var end = index + EXPANSION_CHUNK_SIZE;
    if (end > fileNodes.length) {
      end = fileNodes.length;
    }
    for (var i = index; i < end; i++) {
      ensureExpanded(fileNodes[i]);
      maybeLoadIssuesForFileNode(fileNodes[i]);
    }
    if (end < fileNodes.length) {
      // Yield between chunks to keep UI responsive.
      setTimeout(function() {
        expandFileNodesInChunks(fileNodes, end);
      }, 0);
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

    // Handle issue node click — navigate to range in file.
    // The bridge function signature matches snyk.navigateToRange command args:
    //   args[0] = filePath (string)
    //   args[1] = range ({ start: { line, character }, end: { line, character } })
    if (hasClass(node, 'tree-node-issue')) {
      var filePath = row.getAttribute('data-file-path');
      var startLine = parseIntSafe(row.getAttribute('data-start-line'), 0);
      var endLine = parseIntSafe(row.getAttribute('data-end-line'), 0);
      var startChar = parseIntSafe(row.getAttribute('data-start-char'), 0);
      var endChar = parseIntSafe(row.getAttribute('data-end-char'), 0);
      if (filePath && typeof window.__ideTreeNavigateToRange__ === 'function') {
        window.__ideTreeNavigateToRange__(filePath, {
          start: { line: startLine, character: startChar },
          end: { line: endLine, character: endChar }
        });
      }
      return;
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

    // Lazy-load issue nodes when a file node is expanded for the first time.
    if (!wasExpanded && hasClass(node, 'tree-node-file')) {
      maybeLoadIssuesForFileNode(node);
    }
  });

  // IntelliJ-like behavior:
  // - small/medium trees auto-expand progressively
  // - large trees stay collapsed at lower levels for responsiveness
  var totalIssues = parseIntSafe(container.getAttribute('data-total-issues'), 0);
  if (totalIssues > 0 && totalIssues <= MAX_AUTO_EXPAND_NODES) {
    var fileNodeCollection = container.getElementsByClassName('tree-node-file');
    var fileNodes = [];
    for (var idx = 0; idx < fileNodeCollection.length; idx++) {
      fileNodes.push(fileNodeCollection[idx]);
    }
    expandFileNodesInChunks(fileNodes, 0);
  }

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

      if (typeof window.__ideTreeToggleFilter__ === 'function') {
        window.__ideTreeToggleFilter__(filterType, filterValue, enabled);
      }
    });
  }
})();
