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

  function scrollRowIntoViewVerticalOnly(row) {
    if (!row) return;
    if (!row.scrollIntoView) return;
    // Preserve horizontal scroll — scrollIntoView may shift it even with inline:'nearest'
    // if the row is horizontally out of view. Capture and restore unconditionally.
    var savedScrollLeft = container.scrollLeft;
    // block:'nearest' is a no-op when the row is already fully visible, so manual clicks
    // that trigger a programmatic __selectTreeNode__ round-trip don't cause any scroll jump.
    // inline:'nearest' minimises horizontal movement, but we restore scrollLeft anyway.
    row.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    // scroll-behavior: smooth on #treeContainer would run after this line and overwrite
    // the restored value. tree.css must not set scroll-behavior: smooth on this element.
    container.scrollLeft = savedScrollLeft;
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
    scrollRowIntoViewVerticalOnly(row);
  };

  // Scan error overlay for product error nodes.
  var activeErrorOverlay = null;
  var activeErrorKeyDown = null;
  var activeErrorOutsideClick = null;
  var activeErrorResize = null;
  var activeErrorScroll = null;
  var activeErrorRow = null;

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
    if (activeErrorResize) {
      window.removeEventListener('resize', activeErrorResize);
      activeErrorResize = null;
    }
    if (activeErrorScroll) {
      // Match the `capture: true` used when adding the listener.
      document.removeEventListener('scroll', activeErrorScroll, true);
      activeErrorScroll = null;
    }
    activeErrorOverlay = null;
    activeErrorRow = null;
  }

  // Computes and applies the final overlay position using its measured height,
  // so a tall overlay against a row at the bottom of the viewport flips above
  // the row instead of being clipped (IDE-1808). Prefers above whenever there
  // is room above: tree views in IDEs typically have more chrome below them
  // (status bars, help panels) than above, so above is the safer default and
  // matches the behavior of the previous VS Code-side shim.
  // Clears `bottom` and `transform` defensively so future style sources can't
  // stretch the overlay between opposing anchors.
  function positionErrorOverlay(overlay, row) {
    if (!overlay || !row) return;
    var rect = row.getBoundingClientRect();
    // 600 = sensible fallback viewport width when neither window.innerWidth
    // nor documentElement.clientWidth is reported (very old WebViews / tests).
    var vw = window.innerWidth || document.documentElement.clientWidth || 600;

    // 520 = preferred max overlay width (keeps error text at a comfortable
    // reading width); 16 = total horizontal viewport padding (8px each side)
    // so a narrow viewport still leaves a small margin.
    var overlayW = Math.min(520, vw - 16);

    // Apply width and clear stale top/bottom before measuring height: the
    // <pre> message wraps, so width determines height. Measuring height first
    // would use the pre-wrap layout and place the overlay incorrectly once
    // the width is applied.
    overlay.style.position = 'fixed';
    overlay.style.bottom = '';
    overlay.style.transform = '';
    overlay.style.width = overlayW + 'px';

    var overlayH = overlay.getBoundingClientRect().height;
    if (overlayH <= 0) return;

    // 4 = gap in px between the row and the overlay (and a minimum margin
    // from the viewport edge).
    var gap = 4;
    var topPos = rect.bottom + gap;
    if (rect.top - overlayH - gap >= gap) {
      topPos = rect.top - overlayH - gap;
    }
    topPos = Math.max(gap, topPos);

    // 8 = right-edge margin: when the row is far right, pin the overlay so
    // there is still ~8px between its right edge and the viewport.
    var leftPos = Math.max(gap, Math.min(rect.left, vw - overlayW - 8));

    overlay.style.top = topPos + 'px';
    overlay.style.left = leftPos + 'px';
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

    // Insert offscreen so we can measure the real height without a visible
    // flash, then reposition correctly using `positionErrorOverlay`.
    overlay.style.position = 'fixed';
    overlay.style.top = '0px';
    overlay.style.left = '0px';
    overlay.style.visibility = 'hidden';
    document.body.appendChild(overlay);
    positionErrorOverlay(overlay, row);
    overlay.style.visibility = '';

    activeErrorOverlay = overlay;
    activeErrorRow = row;

    activeErrorKeyDown = function(ev) {
      if (ev.key === 'Escape' || ev.key === 'Esc' || ev.keyCode === 27) {
        dismissErrorOverlay();
      }
    };
    document.addEventListener('keydown', activeErrorKeyDown);

    activeErrorResize = function() {
      if (activeErrorOverlay && activeErrorRow) {
        positionErrorOverlay(activeErrorOverlay, activeErrorRow);
      }
    };
    window.addEventListener('resize', activeErrorResize);

    // Reposition on scroll so the overlay tracks its row when any scrollable
    // ancestor (e.g. the tree container) scrolls. `capture: true` is required
    // because scroll events do not bubble; capturing on the document catches
    // them from any element.
    activeErrorScroll = function() {
      if (activeErrorOverlay && activeErrorRow) {
        positionErrorOverlay(activeErrorOverlay, activeErrorRow);
      }
    };
    document.addEventListener('scroll', activeErrorScroll, true);

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

      // Optimistically reflect the toggle in the button's class so the active
      // state updates immediately, rather than waiting for the LS to re-render
      // the tree in response to the command below. A "mixed" button (open folders
      // disagree) counts as not-active, so the first click enables the severity
      // for every folder, resolving the mismatch.
      // Note: this optimistic flip does NOT account for org-locked folders. When
      // a folder has the severity org-locked (Locked Remote > User Folder
      // Override), the button flips active here but snaps back to filter-mixed on
      // the next LS re-render (a brief flicker). The resolved state is always
      // correct — only the transient optimistic state may be wrong.
      btn.classList.remove('filter-mixed');
      if (enabled) {
        btn.classList.add('filter-active');
      } else {
        btn.classList.remove('filter-active');
      }

      executeCommand('snyk.toggleTreeFilter', [filterType, filterValue, enabled]);
    });
  }

  // Filter popover (Risk Score + Issue View Options).
  // The funnel button opens a small popover whose controls write per-folder
  // settings to EVERY open folder (workspace-wide), mirroring the severity
  // buttons. When open folders disagree on a setting it renders "mixed":
  // indeterminate checkboxes / a "Mixed" risk-score label, plus a dot on the
  // funnel. The first change aligns all folders, resolving the mismatch.
  // Note: each change triggers a server-side re-render that replaces this view,
  // so the popover closes after a change — same model as the severity buttons.
  var popoverBtn = document.getElementById('filtersPopoverBtn');
  var popover = document.getElementById('filtersPopover');
  if (popoverBtn && popover) {
    var openPopover = function() {
      popover.hidden = false;
      popoverBtn.setAttribute('aria-expanded', 'true');
    };
    var closePopover = function() {
      if (popover.hidden) return;
      popover.hidden = true;
      popoverBtn.setAttribute('aria-expanded', 'false');
    };

    popoverBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      if (popover.hidden) { openPopover(); } else { closePopover(); }
    });

    // Keep clicks inside the popover from reaching the document dismiss handler.
    popover.addEventListener('click', function(e) { e.stopPropagation(); });

    document.addEventListener('click', function() { closePopover(); });
    document.addEventListener('keydown', function(e) {
      if (popover.hidden) return;
      if (e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) { closePopover(); }
    });

    // The DOM `indeterminate` flag can't be expressed in HTML markup, so apply it
    // here on load from the server-set data-mixed attribute.
    var issueViewChecks = popover.querySelectorAll('input[type="checkbox"][data-filter-type="issueView"]');
    for (var ci = 0; ci < issueViewChecks.length; ci++) {
      if (issueViewChecks[ci].getAttribute('data-mixed') === 'true') {
        issueViewChecks[ci].indeterminate = true;
      }
      issueViewChecks[ci].addEventListener('change', function(e) {
        var chk = e.target;
        chk.indeterminate = false;
        chk.removeAttribute('data-mixed');
        executeCommand('snyk.toggleTreeFilter', ['issueView', chk.getAttribute('data-filter-value'), chk.checked]);
      });
    }

    // Risk-score slider: update the label live on input, commit on change (avoids
    // a command per drag step). Reads "All" at 0, otherwise "≥ N".
    var slider = document.getElementById('riskScoreSlider');
    var riskValue = document.getElementById('riskScoreValue');
    var updateRiskLabel = function(v) {
      if (riskValue) { riskValue.textContent = (v === 0) ? 'All' : ('≥ ' + v); }
    };
    if (slider) {
      slider.addEventListener('input', function() {
        slider.removeAttribute('data-mixed');
        updateRiskLabel(parseIntSafe(slider.value, 0));
      });
      slider.addEventListener('change', function() {
        executeCommand('snyk.toggleTreeFilter', ['riskScore', '', parseIntSafe(slider.value, 0)]);
      });
    }

    // Reset: restore defaults (risk score 0, open issues on, ignored off). The
    // controls are updated optimistically, then a SINGLE 'reset' command writes all
    // defaults to every folder server-side — one config-change cycle / re-render for
    // the whole reset rather than one per control.
    var resetBtn = document.getElementById('filtersResetBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        if (slider) {
          slider.value = '0';
          slider.removeAttribute('data-mixed');
          updateRiskLabel(0);
        }
        for (var ri = 0; ri < issueViewChecks.length; ri++) {
          var chk = issueViewChecks[ri];
          chk.indeterminate = false;
          chk.removeAttribute('data-mixed');
          chk.checked = (chk.getAttribute('data-filter-value') === 'openIssues');
        }
        executeCommand('snyk.toggleTreeFilter', ['reset']);
      });
    }
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

  // File-path middle truncation.
  // File rows show the full project-relative path as the label
  // (e.g. "frontend/src/app/app.component.ts"). When the sidebar narrows, the
  // CSS fallback clips the right edge — hiding the filename, which is usually
  // the most informative part. This block measures the label's available
  // width and rewrites the text into a middle-truncated form that keeps the
  // filename intact: "frontend/…/app.component.ts". The companion flex
  // layout in styles.css gives us label.clientWidth directly.
  var measureCanvas = null;
  var measureCtx = null;
  var measureFontKey = '';
  var retruncatePending = false;

  function getMeasureCtx() {
    if (!measureCtx) {
      measureCanvas = document.createElement('canvas');
      measureCtx = measureCanvas.getContext('2d');
    }
    return measureCtx;
  }

  function ensureMeasureFont(labelEl) {
    if (!labelEl) return;
    var cs = window.getComputedStyle(labelEl);
    // `cs.font` returns "" in Firefox when longhand values diverge from the
    // shorthand defaults, so compose the shorthand by hand for portability.
    var font = (cs.fontStyle || 'normal') + ' ' +
               (cs.fontVariant || 'normal') + ' ' +
               (cs.fontWeight || 'normal') + ' ' +
               (cs.fontSize || '13px') + ' ' +
               (cs.fontFamily || 'sans-serif');
    if (font !== measureFontKey) {
      var ctx = getMeasureCtx();
      if (!ctx) return; // canvas 2d unavailable (restricted webview) — skip
      measureFontKey = font;
      ctx.font = font;
    }
  }

  function measureWidth(text) {
    var ctx = getMeasureCtx();
    // No 2d context (canvas disabled in some webview hosts): report 0 so callers
    // treat everything as "fits" and middle-truncation no-ops, leaving CSS
    // end-truncation in charge rather than throwing.
    if (!ctx) return 0;
    return ctx.measureText(text).width;
  }

  function truncateMiddleByWidth(text, maxWidth) {
    if (maxWidth <= 0) return text;
    if (measureWidth(text) <= maxWidth) return text;

    var lastSlash = text.lastIndexOf('/');
    if (lastSlash < 0) return text; // no path structure — let CSS end-truncate
    // Filename includes the leading slash so the ellipsis sits flush:
    // "foo/…/bar.ts" rather than "foo…/bar.ts".
    var filename = text.substring(lastSlash);
    var prefix = text.substring(0, lastSlash);
    var ellipsis = '…';
    var reserved = measureWidth(filename) + measureWidth(ellipsis);
    if (reserved >= maxWidth) return text;

    var availForPrefix = maxWidth - reserved;
    var lo = 0;
    var hi = prefix.length;
    var best = 0;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (measureWidth(prefix.substring(0, mid)) <= availForPrefix) {
        best = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (best === prefix.length) return text;
    // When best === 0 no prefix character fits: swapping nothing for an "…"
    // saves nothing — the string is still too long. Fall back and let CSS
    // end-truncate rather than producing "…/bar.ts" with no useful context.
    if (best === 0) return text;
    return prefix.substring(0, best) + ellipsis + filename;
  }

  function applyTruncation() {
    retruncatePending = false;
    // File rows + any opt-in label marked data-truncate-middle (used by the
    // untrusted-folder path list so each line stays middle-truncated rather
    // than end-clipped — keeping the folder basename visible).
    var labels = container.querySelectorAll(
      '.tree-node-file > .tree-node-row > .tree-label, .tree-label[data-truncate-middle]'
    );
    if (!labels.length) return;
    for (var i = 0; i < labels.length; i++) {
      var label = labels[i];
      // Skip labels in collapsed branches — clientWidth is 0 so a measurement
      // round-trip would be wasted, and they'll be re-evaluated on expand.
      if (label.clientWidth === 0) continue;
      // File rows and the untrusted-folder path list use different font families;
      // ensure the canvas font matches each label before measuring. The call
      // short-circuits when the font key hasn't changed, so the only real cost
      // is one getComputedStyle per visible label.
      ensureMeasureFont(label);
      var full = label.getAttribute('data-full-label');
      if (full === null) {
        full = label.textContent;
        label.setAttribute('data-full-label', full);
        label.setAttribute('title', full);
      }
      var next = truncateMiddleByWidth(full, label.clientWidth);
      if (label.textContent !== next) {
        label.textContent = next;
      }
    }
  }

  function scheduleRetruncate() {
    if (retruncatePending) return;
    retruncatePending = true;
    if (window.requestAnimationFrame) {
      window.requestAnimationFrame(applyTruncation);
    } else {
      setTimeout(applyTruncation, 16);
    }
  }

  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(scheduleRetruncate).observe(container);
  } else {
    window.addEventListener('resize', scheduleRetruncate);
  }

  // Expand/collapse mutates .expanded on .tree-node elements, which changes
  // which file rows are laid out. Watch class changes on tree-node elements
  // and re-run; selection toggling on .tree-node-row is filtered out below.
  // Note: there is no fallback when MutationObserver is unavailable. Unlike
  // ResizeObserver (which falls back to the 'resize' event), there is no DOM
  // event for "a node's class changed", so expand/collapse re-truncation is
  // simply skipped in environments that do not support MutationObserver.
  if (typeof MutationObserver !== 'undefined') {
    new MutationObserver(function(records) {
      for (var i = 0; i < records.length; i++) {
        var t = records[i].target;
        if (t && t.classList && t.classList.contains('tree-node')) {
          scheduleRetruncate();
          return;
        }
      }
    }).observe(container, { attributes: true, attributeFilter: ['class'], subtree: true });
  }

  // Re-run once webfonts settle so measurements aren't off by a few pixels.
  if (document.fonts && document.fonts.ready && typeof document.fonts.ready.then === 'function') {
    document.fonts.ready.then(scheduleRetruncate);
  }

  scheduleRetruncate();

  // Tooltips.
  // Native `title` tooltips render inconsistently inside IDE webviews, so we
  // draw our own from the same `title` attributes (disabled/errored scanner
  // hints, full file paths from the truncation pass above, untrusted folder
  // paths). While our tooltip is shown the title is moved to data-tooltip so
  // the native one can't also fire, and restored on mouse-out so it stays
  // available for accessibility and any non-webview host.
  var tooltipEl = null;
  var tooltipTarget = null;

  function findTitledAncestor(el) {
    while (el && el !== document.body) {
      if (el.getAttribute && el.getAttribute('title')) return el;
      el = el.parentElement;
    }
    return null;
  }

  function positionTooltip(tip, target) {
    var rect = target.getBoundingClientRect();
    var vw = window.innerWidth || document.documentElement.clientWidth || 600;
    var vh = window.innerHeight || document.documentElement.clientHeight || 600;
    var gap = 4;
    var tw = tip.offsetWidth;
    var th = tip.offsetHeight;
    // Prefer below the row; flip above if there isn't room.
    var top = rect.bottom + gap;
    if (top + th > vh - gap) {
      top = rect.top - th - gap;
    }
    top = Math.max(gap, top);
    var left = Math.max(gap, Math.min(rect.left, vw - tw - gap));
    tip.style.top = top + 'px';
    tip.style.left = left + 'px';
  }

  function showTooltip(target) {
    var text = target.getAttribute('title');
    if (!text) return;
    // Stash + remove title so the native tooltip can't also appear.
    target.setAttribute('data-tooltip', text);
    target.removeAttribute('title');
    tooltipTarget = target;

    if (!tooltipEl) {
      tooltipEl = document.createElement('div');
      tooltipEl.className = 'tree-tooltip';
      tooltipEl.setAttribute('role', 'tooltip');
      document.body.appendChild(tooltipEl);
    }
    tooltipEl.textContent = text;
    // Measure with content + max-width applied, then position, then reveal.
    tooltipEl.style.visibility = 'hidden';
    tooltipEl.style.display = 'block';
    positionTooltip(tooltipEl, target);
    tooltipEl.style.visibility = '';
  }

  function hideTooltip() {
    if (tooltipTarget) {
      var stored = tooltipTarget.getAttribute('data-tooltip');
      if (stored !== null) {
        tooltipTarget.setAttribute('title', stored);
        tooltipTarget.removeAttribute('data-tooltip');
      }
      tooltipTarget = null;
    }
    if (tooltipEl) tooltipEl.style.display = 'none';
  }

  // Bound to document so it also covers titled elements outside the tree
  // container (e.g. the severity filter-toolbar buttons).
  document.addEventListener('mouseover', function(e) {
    // Still hovering within the current target (e.g. moved onto a child) — keep it.
    if (tooltipTarget && tooltipTarget.contains(e.target)) return;
    var t = findTitledAncestor(e.target);
    if (!t) {
      hideTooltip();
      return;
    }
    if (t !== tooltipTarget) {
      hideTooltip();
      showTooltip(t);
    }
  });
  document.addEventListener('mouseout', function(e) {
    // Ignore moves between descendants of the same titled element.
    if (tooltipTarget && !tooltipTarget.contains(e.relatedTarget)) {
      hideTooltip();
    }
  });
})();
