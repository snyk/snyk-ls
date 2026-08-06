import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function loadRuntimeScript() {
  const scriptPath = join(__dirname, "../domain/ide/treeview/template/tree.js");
  return readFile(scriptPath, "utf8");
}

function buildHtml({ totalIssues, nodesHtml, runtimeScript, filterToolbar = "", searchBar = "" }) {
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"></head>
  <body>
    ${filterToolbar}
    ${searchBar}
    <div class="tree-container" id="treeContainer" data-total-issues="${String(totalIssues)}">
      ${nodesHtml}
    </div>
    <script>${runtimeScript}</script>
  </body>
</html>`;
}

// Mirrors the search toggle + (hidden) search box + no-results element emitted
// by tree.html when TotalIssues > 0. tree.js finds the elements by id, so their
// exact position does not matter for tests. The box starts hidden, opened by the
// toggle — matching the real toolbar affordance.
function treeSearchHtml() {
  return `<button type="button" id="treeSearchToggle" class="tree-search-toggle" aria-expanded="false" aria-controls="treeSearch"><svg width="14" height="14" viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5"/></svg></button>
  <div class="tree-search" id="treeSearch" hidden>
    <input type="search" id="treeSearchInput" class="tree-search-input" placeholder="Search files and issues" aria-label="Search files and issues" autocomplete="off" spellcheck="false">
  </div>
  <div class="tree-search-empty" id="treeSearchEmpty" hidden>No files or issues match your search.</div>`;
}

function fileNodeHtml(nodeId = "file-1", opts = {}) {
  const expandedClass = opts.expanded ? " expanded" : "";
  const label = opts.label || "main.go";
  return `<div class="tree-node tree-node-file${expandedClass}"
      data-node-id="${nodeId}"
      data-file-path="${opts.filePath || "/workspace/main.go"}"
      data-product="${opts.product || "oss"}">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label">${label}</span>
    </div>
    <div class="tree-node-children">${opts.childrenHtml || ""}</div>
  </div>`;
}

function issueNodeHtml(issueId = "vuln-1", label = "Test Vulnerability") {
  return `<div class="tree-node tree-node-issue" data-node-id="issue-${issueId}">
    <div class="tree-node-row"
         data-file-path="/workspace/main.go"
         data-start-line="10"
         data-end-line="15"
         data-start-char="4"
         data-end-char="20"
         data-issue-id="${issueId}">
      <span class="severity-icon severity-high">H</span>
      <span class="tree-label">${label}</span>
    </div>
  </div>`;
}

function productNodeHtml(nodesHtml) {
  return `<div class="tree-node expanded" data-node-id="product-1">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label">Snyk Open Source</span>
    </div>
    <div class="tree-node-children">${nodesHtml}</div>
  </div>`;
}

function filterToolbarHtml() {
  return `<div class="tree-filters" id="filterToolbar">
    <span class="filter-group">
      <button data-filter-type="severity" data-filter-value="critical" class="filter-btn filter-active">C</button>
      <button data-filter-type="severity" data-filter-value="high" class="filter-btn filter-active">H</button>
      <button data-filter-type="severity" data-filter-value="low" class="filter-btn filter-active">L</button>
    </span>
    <span class="filter-separator"></span>
    <span class="filter-group">
      <button id="expandAllBtn" class="action-btn" title="Expand All"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3 3l5 4.5L13 3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 8.5l5 4.5L13 8.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
      <button id="collapseAllBtn" class="action-btn" title="Collapse All"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3 13l5-4.5L13 13" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 7.5L8 3l5 4.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
    </span>
  </div>`;
}

function untrustedBannerHtml(paths = ["/repo/a", "/repo/b"]) {
  const items = paths
    .map(
      (p) =>
        `<li class="untrusted-folder-path" title="${p}"><span class="tree-label">${p}</span><button type="button" class="untrusted-trust-btn" data-action="trust-folder" data-folder-path="${p}">Trust folder</button></li>`
    )
    .join("");
  return `<div class="tree-node tree-node-info tree-node-info--untrusted-folder" data-node-id="info:untrusted-folder">
    <div class="tree-node-row tree-node-row-info untrusted-rationale-row"><span class="tree-label">You should only scan folders you trust.</span></div>
    <div class="tree-node-row tree-node-row-info untrusted-folder-list-row">
      <span class="untrusted-folder-list-heading">Untrusted Folders:</span>
      <ul class="untrusted-folder-paths">${items}</ul>
    </div>
  </div>`;
}

// Mirrors the dimmed, non-expandable untrusted folder node the Go builder emits:
// class tree-node-untrusted, NO tree-node-has-children, but the folder template
// still emits an empty tree-node-children container (the source of the
// spurious-expand bug the row handler must guard against). (IDE-1882)
function untrustedFolderNodeHtml(path = "/repo/untrusted", name = "untrusted") {
  return `<div class="tree-node tree-node-untrusted" data-node-id="folder:${path}">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="folder-icon"></span>
      <span class="tree-label">${name}</span>
    </div>
    <div class="tree-node-children"></div>
  </div>`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function ideBridge(calls) {
  return function(cmd, args, cb) {
    calls.push({ cmd, args, cb });
  };
}

test("LS-rendered expanded file node stays expanded and does not trigger JS auto-expand", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 5,
      nodesHtml: fileNodeHtml("file-1", { expanded: true }),
      runtimeScript,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  await sleep(20);
  const node = dom.window.document.querySelector(".tree-node-file");
  assert.ok(node.className.includes("expanded"), "LS-rendered expanded node should stay expanded");
  // No setNodeExpanded calls should be made — the LS already set the state.
  const expandCalls = calls.filter(c => c.cmd === "snyk.setNodeExpanded");
  assert.equal(expandCalls.length, 0, "JS should not re-send expand commands for LS-rendered state");
});

test("initialization does not auto-expand over threshold", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 51,
      nodesHtml: fileNodeHtml(),
      runtimeScript,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  await sleep(20);
  const node = dom.window.document.querySelector(".tree-node-file");
  assert.ok(!node.className.includes("expanded"), "file node should remain collapsed");
  assert.equal(calls.length, 0, "no initial command calls expected");
});

test("clicking a non-leaf node toggles expand/collapse", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: productNodeHtml(fileNodeHtml()),
      runtimeScript,
    }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  const { document } = dom.window;
  const productNode = document.querySelector('[data-node-id="product-1"]');
  const productRow = productNode.querySelector(":scope > .tree-node-row");

  assert.ok(productNode.className.includes("expanded"), "product node starts expanded");

  productRow.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.ok(!productNode.className.includes("expanded"), "product node collapsed after click");

  productRow.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.ok(productNode.className.includes("expanded"), "product node re-expanded after second click");
});

test("clicking an issue node calls snyk.navigateToRange via __ideExecuteCommand__", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: fileNodeHtml("file-1", { childrenHtml: issueNodeHtml("vuln-1") }),
      runtimeScript,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const issueRow = document.querySelector(".tree-node-issue .tree-node-row");
  issueRow.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const navCalls = calls.filter(c => c.cmd === "snyk.navigateToRange");
  assert.equal(navCalls.length, 1, "one navigation expected");
  assert.equal(navCalls[0].args[0], "/workspace/main.go", "filePath");
  const range = navCalls[0].args[1];
  assert.equal(range.start.line, 10, "start line");
  assert.equal(range.start.character, 4, "start character");
  assert.equal(range.end.line, 15, "end line");
  assert.equal(range.end.character, 20, "end character");
});

test("filter toolbar click calls snyk.toggleTreeFilter via __ideExecuteCommand__", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: "",
      runtimeScript,
      filterToolbar: filterToolbarHtml(),
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;

  const highBtn = document.querySelector('[data-filter-value="high"]');
  highBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const filterCalls = calls.filter(c => c.cmd === "snyk.toggleTreeFilter");
  assert.equal(filterCalls.length, 1, "one filter call expected");
  assert.equal(filterCalls[0].args[0], "severity_high", "combined token in args[0]");
  assert.equal(filterCalls[0].args[1], false, "active button click should pass enabled=false");
});

test("filter toolbar click on inactive button passes enabled=true", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const toolbarHtml = `<div class="tree-filters" id="filterToolbar">
    <button data-filter-type="severity" data-filter-value="medium" class="filter-btn">M</button>
  </div>`;
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: "",
      runtimeScript,
      filterToolbar: toolbarHtml,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const medBtn = document.querySelector('[data-filter-value="medium"]');
  medBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const filterCalls = calls.filter(c => c.cmd === "snyk.toggleTreeFilter");
  assert.equal(filterCalls.length, 1);
  assert.equal(filterCalls[0].args[0], "severity_medium", "combined token in args[0]");
  assert.equal(filterCalls[0].args[1], true, "inactive button click should pass enabled=true");
});

test("clicking a per-folder Trust button calls snyk.trustWorkspaceFolders with that folder path", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: untrustedBannerHtml(["/repo/a", "/repo/b"]),
      runtimeScript,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const btn = document.querySelector('[data-folder-path="/repo/b"]');
  btn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const trustCalls = calls.filter((c) => c.cmd === "snyk.trustWorkspaceFolders");
  assert.equal(trustCalls.length, 1, "one trust call expected");
  assert.equal(trustCalls[0].args.length, 1, "exactly one argument expected");
  assert.equal(trustCalls[0].args[0], "/repo/b", "should pass only the clicked folder path");

  // The button lives inside a tree-node-row, so the handler must not also toggle
  // expand/collapse on the banner.
  const expandCalls = calls.filter((c) => c.cmd === "snyk.setNodeExpanded");
  assert.equal(expandCalls.length, 0, "trust click must not toggle expand/collapse");
});

test("clicking an untrusted folder node row does not toggle or persist expand state", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: untrustedFolderNodeHtml("/repo/untrusted", "untrusted"),
      runtimeScript,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const node = document.querySelector(".tree-node-untrusted");
  const row = node.querySelector(".tree-node-row");
  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  // The node is non-expandable: no setNodeExpanded command and no expanded class,
  // even though the folder template emits an empty children container.
  const expandCalls = calls.filter((c) => c.cmd === "snyk.setNodeExpanded");
  assert.equal(expandCalls.length, 0, "untrusted folder row must not persist expand state");
  assert.ok(!node.className.includes("expanded"), "untrusted folder node must not gain the expanded class");
});

test("clicking an info node does not expand or collapse it", async () => {
  const runtimeScript = await loadRuntimeScript();
  const infoHtml = `<div class="tree-node tree-node-info" data-node-id="info-1">
    <div class="tree-node-row tree-node-row-info">
      <span class="tree-label">✋ 5 issues</span>
    </div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: infoHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  const { document } = dom.window;
  const infoNode = document.querySelector(".tree-node-info");
  const row = infoNode.querySelector(".tree-node-row-info");

  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(!infoNode.className.includes("expanded"), "info node should not become expanded");
});

test("clicking SVG inside filter button still triggers filter toggle", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const filterToolbar = `<div class="tree-filters" id="filterToolbar">
    <button data-filter-type="severity" data-filter-value="critical" class="filter-btn filter-btn-icon filter-active">
      <svg width="16" height="16"><rect fill="#AB1A1A"/></svg>
    </button>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: "", runtimeScript, filterToolbar }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const svg = document.querySelector(".filter-btn-icon svg");
  svg.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const filterCalls = calls.filter(c => c.cmd === "snyk.toggleTreeFilter");
  assert.equal(filterCalls.length, 1, "filter toggle should fire even when SVG clicked");
  assert.equal(filterCalls[0].args[0], "severity_critical", "combined token in args[0]");
  assert.equal(filterCalls[0].args[1], false, "active button should toggle to disabled");
});

test("expand all button expands all collapsible nodes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: productNodeHtml(fileNodeHtml("file-1", { childrenHtml: issueNodeHtml() })),
      runtimeScript,
      filterToolbar: filterToolbarHtml(),
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const productNode = document.querySelector('[data-node-id="product-1"]');
  const fileNode = document.querySelector(".tree-node-file");

  productNode.className = productNode.className.replace(/\s*expanded/g, "");
  assert.ok(!productNode.className.includes("expanded"), "product node collapsed");

  const expandBtn = document.getElementById("expandAllBtn");
  expandBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(productNode.className.includes("expanded"), "product node should be expanded after expand all");
  assert.ok(fileNode.className.includes("expanded"), "file node should be expanded after expand all");
});

test("collapse all button collapses all expanded nodes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: productNodeHtml(fileNodeHtml("file-1", { childrenHtml: issueNodeHtml() })),
      runtimeScript,
      filterToolbar: filterToolbarHtml(),
    }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  const { document } = dom.window;
  const productNode = document.querySelector('[data-node-id="product-1"]');
  assert.ok(productNode.className.includes("expanded"), "product node starts expanded");

  const collapseBtn = document.getElementById("collapseAllBtn");
  collapseBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(!productNode.className.includes("expanded"), "product node should be collapsed after collapse all");
});

test("clicking an issue node applies .selected to its row and removes from previous", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const nodesHtml = fileNodeHtml("file-1", {
    childrenHtml: issueNodeHtml("vuln-1") + issueNodeHtml("vuln-2"),
  });
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml, runtimeScript }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const rows = document.querySelectorAll(".tree-node-issue .tree-node-row");
  const row1 = rows[0];
  const row2 = rows[1];

  row1.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.ok(row1.className.includes("selected"), "first row should be selected after click");

  row2.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.ok(row2.className.includes("selected"), "second row should be selected after click");
  assert.ok(!row1.className.includes("selected"), "first row should lose selection when second is clicked");
});

test("window.__selectTreeNode__ selects the node row programmatically by data-issue-id", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodesHtml = productNodeHtml(
    fileNodeHtml("file-1", {
      childrenHtml: issueNodeHtml("vuln-1"),
    })
  );
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  const { document } = dom.window;

  assert.equal(typeof dom.window.__selectTreeNode__, "function", "__selectTreeNode__ should be exposed");

  dom.window.__selectTreeNode__("vuln-1");

  const row = document.querySelector('[data-issue-id="vuln-1"]');
  assert.ok(row.className.includes("selected"), "row should have .selected class after programmatic selection");
});

test("window.__selectTreeNode__ with unknown issueId does nothing (no crash)", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: fileNodeHtml(), runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  assert.doesNotThrow(() => {
    dom.window.__selectTreeNode__("nonexistent-issue-id");
  }, "should not throw for unknown issueId");
});

test("window.__selectTreeNode__ expands collapsed ancestor nodes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodesHtml = productNodeHtml(
    fileNodeHtml("file-1", {
      childrenHtml: issueNodeHtml("vuln-1"),
    })
  );
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  const { document } = dom.window;
  const productNode = document.querySelector('[data-node-id="product-1"]');
  const fileNode = document.querySelector('.tree-node-file');

  // Collapse both ancestors
  productNode.className = productNode.className.replace(/\s*expanded/g, '');
  fileNode.className = fileNode.className.replace(/\s*expanded/g, '');
  assert.ok(!productNode.className.includes('expanded'), 'product collapsed before select');
  assert.ok(!fileNode.className.includes('expanded'), 'file collapsed before select');

  dom.window.__selectTreeNode__('vuln-1');

  assert.ok(productNode.className.includes('expanded'), 'product node should be expanded after selectTreeNode');
  assert.ok(fileNode.className.includes('expanded'), 'file node should be expanded after selectTreeNode');
  const row = document.querySelector('[data-issue-id="vuln-1"]');
  assert.ok(row.className.includes('selected'), 'issue row should be selected');
});

test("__selectTreeNode__ preserves container.scrollLeft after programmatic select", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodesHtml = productNodeHtml(
    fileNodeHtml("file-1", { childrenHtml: issueNodeHtml("vuln-1") })
  );
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const container = document.getElementById("treeContainer");
  const row = document.querySelector('[data-issue-id="vuln-1"]');

  // Stub scrollIntoView to simulate it shifting scrollLeft (as browsers may do)
  var scrollIntoViewCalled = false;
  row.scrollIntoView = function() {
    scrollIntoViewCalled = true;
    container.scrollLeft = 0; // simulate browser shifting horizontal scroll
  };
  container.scrollLeft = 100;

  dom.window.__selectTreeNode__("vuln-1");

  assert.ok(scrollIntoViewCalled, "scrollIntoView should be called");
  assert.equal(container.scrollLeft, 100, "scrollLeft must be restored after scrollIntoView");
});

test("__selectTreeNode__ calls scrollIntoView with block:nearest", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodesHtml = productNodeHtml(
    fileNodeHtml("file-1", { childrenHtml: issueNodeHtml("vuln-1") })
  );
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const row = document.querySelector('[data-issue-id="vuln-1"]');

  var scrollArgs = null;
  row.scrollIntoView = function(opts) { scrollArgs = opts; };

  dom.window.__selectTreeNode__("vuln-1");

  assert.ok(scrollArgs !== null, "scrollIntoView should be called");
  assert.equal(scrollArgs.block, "nearest", "block should be 'nearest' — no-op when row is already visible, scrolls minimum otherwise");
  assert.equal(scrollArgs.inline, "nearest", "inline should be 'nearest' to minimise horizontal movement");
});

test("__selectTreeNode__ does not throw when scrollIntoView absent", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodesHtml = productNodeHtml(
    fileNodeHtml("file-1", { childrenHtml: issueNodeHtml("vuln-1") })
  );
  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const row = document.querySelector('[data-issue-id="vuln-1"]');

  // Remove scrollIntoView to simulate older environment
  delete row.scrollIntoView;

  assert.doesNotThrow(() => {
    dom.window.__selectTreeNode__("vuln-1");
  }, "should not throw when scrollIntoView is absent");
  assert.ok(row.className.includes("selected"), "row should still be selected");
});

test("clicking delta-enabled folder node still toggles expand/collapse", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const folderHtml = `<div class="tree-node expanded" data-node-id="folder-1" data-delta-enabled="true" data-file-path="/workspace" data-base-branch="main" data-local-branches="main,develop">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label">/workspace</span>
    </div>
    <div class="tree-node-children">${productNodeHtml(fileNodeHtml())}</div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: folderHtml, runtimeScript }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const folderNode = document.querySelector('[data-node-id="folder-1"]');
  const folderRow = folderNode.querySelector(":scope > .tree-node-row");

  assert.ok(folderNode.className.includes("expanded"), "folder starts expanded");

  folderRow.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(!folderNode.className.includes("expanded"),
    "folder should collapse after click even with delta-enabled");
});

test("clicking SVG icon inside tree-node-row finds the row correctly", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const nodeHtml = `<div class="tree-node" data-node-id="product-svg">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="product-icon"><svg xmlns="http://www.w3.org/2000/svg" class="icon-svg" width="16" height="16"><rect fill="#333"/></svg></span>
      <span class="tree-label">Open Source</span>
    </div>
    <div class="tree-node-children">${fileNodeHtml()}</div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: nodeHtml, runtimeScript }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const svg = document.querySelector(".icon-svg");
  const productNode = document.querySelector('[data-node-id="product-svg"]');

  assert.ok(!productNode.className.includes("expanded"), "node starts collapsed");

  assert.doesNotThrow(() => {
    svg.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  }, "clicking SVG should not throw TypeError");

  assert.ok(productNode.className.includes("expanded"),
    "node should expand after clicking SVG icon inside row");
});

test("clicking product node with error triggers showScanErrorDetails", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const nodeHtml = `<div class="tree-node tree-node-error" data-node-id="product:/project:oss" data-error-message="dependency graph failed">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="product-icon"><svg class="icon-svg" width="16" height="16"><rect fill="#333"/></svg></span>
      <span class="tree-label">Snyk Open Source</span>
    </div>
    <div class="tree-node-children"></div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: nodeHtml, runtimeScript }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  await sleep(20);
  const row = dom.window.document.querySelector(".tree-node-row");
  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const errorCalls = calls.filter(c => c.cmd === "snyk.showScanErrorDetails");
  assert.equal(errorCalls.length, 1, "should call showScanErrorDetails");
  assert.equal(errorCalls[0].args[0], "oss", "product should be extracted from node ID");
  assert.equal(errorCalls[0].args[1], "dependency graph failed", "error message should be passed");
});

test("clicking product node with error shows inline error overlay with the error message", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodeHtml = `<div class="tree-node tree-node-error" data-node-id="product:/project:oss" data-error-message="dependency graph failed: cannot resolve pkg">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="product-icon"><svg width="16" height="16"><rect fill="#333"/></svg></span>
      <span class="tree-label"><strong>Snyk Open Source</strong></span>
    </div>
    <div class="tree-node-children"></div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: nodeHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  await sleep(20);
  const row = dom.window.document.querySelector(".tree-node-row");
  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const overlay = dom.window.document.querySelector(".error-overlay");
  assert.ok(overlay, "error overlay should appear after clicking error node");
  assert.ok(
    overlay.textContent.includes("dependency graph failed: cannot resolve pkg"),
    "overlay should contain the full error message"
  );
  // Overlay must be attached to body so it uses viewport space, not clipped inside the tree container
  assert.equal(overlay.parentNode, dom.window.document.body, "overlay must be a direct child of body to avoid container clipping");
  assert.equal(overlay.style.position, "fixed", "overlay must use position:fixed to break out of scrollable container");
});

test("error overlay is dismissed on Escape key", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodeHtml = `<div class="tree-node tree-node-error" data-node-id="product:/project:code" data-error-message="analysis failed">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label"><strong>Snyk Code</strong></span>
    </div>
    <div class="tree-node-children"></div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: nodeHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  await sleep(20);
  dom.window.document.querySelector(".tree-node-row")
    .dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(dom.window.document.querySelector(".error-overlay"), "overlay should be present");

  dom.window.document.dispatchEvent(
    new dom.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true })
  );

  assert.equal(
    dom.window.document.querySelector(".error-overlay"),
    null,
    "overlay should be removed after Escape"
  );
});

test("error overlay is dismissed on click outside", async () => {
  const runtimeScript = await loadRuntimeScript();
  const nodeHtml = `<div class="tree-node tree-node-error" data-node-id="product:/project:oss" data-error-message="scan timed out">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label"><strong>Snyk Open Source</strong></span>
    </div>
    <div class="tree-node-children"></div>
  </div>`;

  const dom = new JSDOM(
    buildHtml({ totalIssues: 0, nodesHtml: nodeHtml, runtimeScript }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  await sleep(20);
  dom.window.document.querySelector(".tree-node-row")
    .dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(dom.window.document.querySelector(".error-overlay"), "overlay should be present");

  // Click outside the overlay (on the body)
  await sleep(10);
  dom.window.document.body.dispatchEvent(
    new dom.window.MouseEvent("click", { bubbles: true })
  );

  assert.equal(
    dom.window.document.querySelector(".error-overlay"),
    null,
    "overlay should be removed after clicking outside"
  );
});

function typeSearch(dom, value) {
  const input = dom.window.document.getElementById("treeSearchInput");
  input.value = value;
  input.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
}

function twoFileTree() {
  return productNodeHtml(
    fileNodeHtml("file-a", {
      label: "alpha.go",
      filePath: "/workspace/alpha.go",
      childrenHtml: issueNodeHtml("v1", "SQL Injection"),
    }) +
    fileNodeHtml("file-b", {
      label: "beta.go",
      filePath: "/workspace/beta.go",
      childrenHtml: issueNodeHtml("v2", "Cross-site Scripting"),
    })
  );
}

test("typing a file name hides non-matching file nodes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "alpha");
  await sleep(20);

  const { document } = dom.window;
  const fileA = document.querySelector('[data-node-id="file-a"]');
  const fileB = document.querySelector('[data-node-id="file-b"]');
  assert.ok(!fileA.className.includes("tree-search-hidden"), "matching file should stay visible");
  assert.ok(fileB.className.includes("tree-search-hidden"), "non-matching file should be hidden");
});

test("search matches against the full file path, not only the label", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  // "/workspace/beta.go" contains "workspace/beta" but the label "beta.go" does not.
  typeSearch(dom, "workspace/beta");
  await sleep(20);

  const { document } = dom.window;
  assert.ok(document.querySelector('[data-node-id="file-b"]').className.includes("tree-search-hidden") === false, "file matched by path stays visible");
  assert.ok(document.querySelector('[data-node-id="file-a"]').className.includes("tree-search-hidden"), "other file hidden");
});

test("search is case-insensitive", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "ALPHA");
  await sleep(20);

  const { document } = dom.window;
  assert.ok(!document.querySelector('[data-node-id="file-a"]').className.includes("tree-search-hidden"), "uppercase query should still match");
  assert.ok(document.querySelector('[data-node-id="file-b"]').className.includes("tree-search-hidden"), "non-matching file hidden");
});

test("matching an issue title keeps its ancestor file visible and hides sibling files", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "cross-site");
  await sleep(20);

  const { document } = dom.window;
  const fileA = document.querySelector('[data-node-id="file-a"]');
  const fileB = document.querySelector('[data-node-id="file-b"]');
  const issue = document.querySelector('[data-node-id="issue-v2"]');
  assert.ok(fileB.className.includes("tree-search-hidden") === false, "file containing matching issue stays visible");
  assert.ok(!issue.className.includes("tree-search-hidden"), "matching issue stays visible");
  assert.ok(fileA.className.includes("tree-search-hidden"), "file with no matching issue is hidden");
});

test("search auto-expands ancestors of matches without persisting expand state", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  // Product node starts collapsed, file node collapsed too.
  const collapsedProduct = `<div class="tree-node" data-node-id="product-1">
    <div class="tree-node-row"><span class="tree-chevron"></span><span class="tree-label">Snyk Open Source</span></div>
    <div class="tree-node-children">${fileNodeHtml("file-b", { label: "beta.go", filePath: "/workspace/beta.go", childrenHtml: issueNodeHtml("v2", "Cross-site Scripting") })}</div>
  </div>`;
  const dom = new JSDOM(
    buildHtml({ totalIssues: 1, nodesHtml: collapsedProduct, runtimeScript, searchBar: treeSearchHtml() }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  typeSearch(dom, "cross-site");
  await sleep(20);

  const { document } = dom.window;
  const product = document.querySelector('[data-node-id="product-1"]');
  const file = document.querySelector('[data-node-id="file-b"]');
  assert.ok(product.className.includes("expanded"), "ancestor product should be auto-expanded to reveal the match");
  assert.ok(file.className.includes("expanded"), "ancestor file should be auto-expanded to reveal the match");
  const expandCalls = calls.filter((c) => c.cmd === "snyk.setNodeExpanded");
  assert.equal(expandCalls.length, 0, "search auto-expand must not persist expand state to the LS");
});

test("clearing the search restores visibility and prior expand state", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const collapsedProduct = `<div class="tree-node" data-node-id="product-1">
    <div class="tree-node-row"><span class="tree-chevron"></span><span class="tree-label">Snyk Open Source</span></div>
    <div class="tree-node-children">${fileNodeHtml("file-b", { label: "beta.go", filePath: "/workspace/beta.go", childrenHtml: issueNodeHtml("v2", "Cross-site Scripting") })}</div>
  </div>`;
  const dom = new JSDOM(
    buildHtml({ totalIssues: 1, nodesHtml: collapsedProduct, runtimeScript, searchBar: treeSearchHtml() }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  const { document } = dom.window;
  const product = document.querySelector('[data-node-id="product-1"]');
  assert.ok(!product.className.includes("expanded"), "product starts collapsed");

  typeSearch(dom, "cross-site");
  await sleep(20);
  assert.ok(product.className.includes("expanded"), "product expanded during search");

  typeSearch(dom, "");
  await sleep(20);

  assert.ok(!product.className.includes("expanded"), "product returns to its original collapsed state after clearing");
  const hidden = document.querySelectorAll(".tree-search-hidden");
  assert.equal(hidden.length, 0, "no nodes remain hidden after clearing the search");
  const expandCalls = calls.filter((c) => c.cmd === "snyk.setNodeExpanded");
  assert.equal(expandCalls.length, 0, "restoring expand state must not persist to the LS");
});

test("switching queries recomputes auto-expansion without leaving stale expands", async () => {
  const runtimeScript = await loadRuntimeScript();
  const collapsedProduct = `<div class="tree-node" data-node-id="product-1">
    <div class="tree-node-row"><span class="tree-chevron"></span><span class="tree-label">Snyk Open Source</span></div>
    <div class="tree-node-children">${
      fileNodeHtml("file-a", { label: "alpha.go", filePath: "/workspace/alpha.go", childrenHtml: issueNodeHtml("v1", "SQL Injection") }) +
      fileNodeHtml("file-b", { label: "beta.go", filePath: "/workspace/beta.go", childrenHtml: issueNodeHtml("v2", "Cross-site Scripting") })
    }</div>
  </div>`;
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: collapsedProduct, runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const fileA = document.querySelector('[data-node-id="file-a"]');
  const fileB = document.querySelector('[data-node-id="file-b"]');

  typeSearch(dom, "cross-site");
  await sleep(20);
  assert.ok(fileB.className.includes("expanded"), "beta auto-expanded for its matching issue");

  typeSearch(dom, "sql");
  await sleep(20);
  assert.ok(fileA.className.includes("expanded"), "alpha auto-expanded for the new query");
  assert.ok(!fileB.className.includes("expanded"), "beta's stale auto-expand is reverted when the query changes");
  assert.ok(fileB.className.includes("tree-search-hidden"), "beta hidden for the new query");
});

test("a manual expand during search is preserved after clearing", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const collapsedProduct = `<div class="tree-node" data-node-id="product-1">
    <div class="tree-node-row"><span class="tree-chevron"></span><span class="tree-label">Snyk Open Source</span></div>
    <div class="tree-node-children">${fileNodeHtml("file-b", { label: "beta.go", filePath: "/workspace/beta.go", childrenHtml: issueNodeHtml("v2", "Cross-site Scripting") })}</div>
  </div>`;
  const dom = new JSDOM(
    buildHtml({ totalIssues: 1, nodesHtml: collapsedProduct, runtimeScript, searchBar: treeSearchHtml() }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );
  const { document } = dom.window;
  const product = document.querySelector('[data-node-id="product-1"]');
  const file = document.querySelector('[data-node-id="file-b"]');

  typeSearch(dom, "beta");
  await sleep(20);
  assert.ok(product.className.includes("expanded"), "product auto-expanded to reveal matched file");
  assert.ok(!file.className.includes("expanded"), "self-matched file is left for the user to open");

  // User manually expands the matched file mid-search.
  file.querySelector(":scope > .tree-node-row").dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.ok(file.className.includes("expanded"), "file expanded by manual click");

  typeSearch(dom, "");
  await sleep(20);
  assert.ok(!product.className.includes("expanded"), "auto-expanded product collapses back on clear");
  assert.ok(file.className.includes("expanded"), "manual expand is preserved after clearing the search");
});

test("a query with no matches shows the no-results message", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "zzz-nothing-matches");
  await sleep(20);

  const { document } = dom.window;
  const empty = document.getElementById("treeSearchEmpty");
  assert.ok(!empty.hidden, "no-results message should be visible when nothing matches");
  const visibleTops = Array.from(document.querySelectorAll('#treeContainer > .tree-node'))
    .filter((n) => !n.className.includes("tree-search-hidden"));
  assert.equal(visibleTops.length, 0, "all top-level nodes hidden when nothing matches");

  typeSearch(dom, "");
  await sleep(20);
  assert.ok(empty.hidden, "no-results message hidden again when the query is cleared");
});

test("the no-results message stays hidden while there are matches", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "alpha");
  await sleep(20);

  const empty = dom.window.document.getElementById("treeSearchEmpty");
  assert.ok(empty.hidden, "no-results message should be hidden while a match exists");
});

test("a partial substring matches file paths and issue titles alike", async () => {
  const runtimeScript = await loadRuntimeScript();
  // Andrew's example: "ite" should match "cross-site scripting" issues as well as
  // files whose path contains "website"/"sites".
  const tree = productNodeHtml(
    fileNodeHtml("file-login", { label: "login.js", filePath: "/src/website/login/login.js", childrenHtml: issueNodeHtml("i1", "SQL Injection") }) +
    fileNodeHtml("file-office", { label: "our-office-sites.html", filePath: "/src/website/about/our-office-sites.html", childrenHtml: issueNodeHtml("i2", "Improper Input Validation") }) +
    fileNodeHtml("file-users", { label: "users.js", filePath: "/src/api/users.js", childrenHtml: issueNodeHtml("i3", "Cross-site Scripting") }) +
    fileNodeHtml("file-config", { label: "config.go", filePath: "/src/api/config.go", childrenHtml: issueNodeHtml("i4", "Hardcoded Secret") })
  );
  const dom = new JSDOM(
    buildHtml({ totalIssues: 4, nodesHtml: tree, runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "ite");
  await sleep(20);

  const { document } = dom.window;
  const hidden = (id) => document.querySelector('[data-node-id="' + id + '"]').className.includes("tree-search-hidden");
  assert.ok(!hidden("file-login"), "path .../website/... matches 'ite'");
  assert.ok(!hidden("file-office"), "path .../website/...-sites.html matches 'ite'");
  assert.ok(!hidden("file-users"), "file kept visible because its issue title 'Cross-site Scripting' matches 'ite'");
  assert.ok(!document.querySelector('[data-node-id="issue-i3"]').className.includes("tree-search-hidden"), "the matching cross-site issue stays visible");
  assert.ok(hidden("file-config"), "file with no 'ite' in path/label/issues is hidden");
});

test("nodes hidden via the hidden attribute never count as matches", async () => {
  const runtimeScript = await loadRuntimeScript();
  // A hidden info node whose text would match must not suppress the no-results
  // message nor become visible.
  const hiddenInfo = `<div class="tree-node tree-node-info" data-node-id="info-empty" hidden>
    <div class="tree-node-row tree-node-row-info"><span class="tree-label">no filter matches placeholder</span></div>
  </div>`;
  const tree = productNodeHtml(fileNodeHtml("file-a", { label: "alpha.go", filePath: "/w/alpha.go", childrenHtml: issueNodeHtml("v1", "SQL Injection") })) + hiddenInfo;
  const dom = new JSDOM(
    buildHtml({ totalIssues: 1, nodesHtml: tree, runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  // "placeholder" only appears in the hidden info node.
  typeSearch(dom, "placeholder");
  await sleep(20);

  const { document } = dom.window;
  const info = document.querySelector('[data-node-id="info-empty"]');
  assert.ok(info.hidden, "hidden node stays hidden");
  assert.ok(!info.className.includes("tree-search-hidden"), "hidden node is untouched, not force-shown");
  assert.ok(!document.getElementById("treeSearchEmpty").hidden, "no-results shown: the hidden node did not count as a match");
});

test("search matches the full pre-truncation label via data-full-label", async () => {
  const runtimeScript = await loadRuntimeScript();
  // Simulate the truncation pass having replaced the visible label text while
  // stashing the full path in data-full-label. The query matches only the full
  // label (not the visible text nor data-file-path), exercising that fallback.
  const truncatedFile = `<div class="tree-node tree-node-file expanded" data-node-id="file-trunc" data-file-path="/x/y.js" data-product="code">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label" data-full-label="/alpha/beta/deep.js">…/deep.js</span>
    </div>
    <div class="tree-node-children">${issueNodeHtml("t1", "Some Issue")}</div>
  </div>`;
  const tree = productNodeHtml(truncatedFile);
  const dom = new JSDOM(
    buildHtml({ totalIssues: 1, nodesHtml: tree, runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );

  typeSearch(dom, "beta");
  await sleep(20);

  const file = dom.window.document.querySelector('[data-node-id="file-trunc"]');
  assert.ok(!file.className.includes("tree-search-hidden"), "file matched via its full (pre-truncation) label");
});

test("search runtime is a no-op when the search input is absent", async () => {
  const runtimeScript = await loadRuntimeScript();
  assert.doesNotThrow(() => {
    // No searchBar passed — tree.js must tolerate a missing input.
    new JSDOM(
      buildHtml({ totalIssues: 0, nodesHtml: fileNodeHtml(), runtimeScript }),
      { runScripts: "dangerously", pretendToBeVisual: true }
    );
  }, "tree.js must not throw when there is no search input");
});

test("the search box is hidden until the toolbar toggle is clicked", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const toggle = document.getElementById("treeSearchToggle");
  const row = document.getElementById("treeSearch");
  const input = document.getElementById("treeSearchInput");

  assert.ok(row.hidden, "search box starts hidden");
  assert.equal(toggle.getAttribute("aria-expanded"), "false", "toggle starts collapsed");

  toggle.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(!row.hidden, "search box is shown after clicking the toggle");
  assert.equal(toggle.getAttribute("aria-expanded"), "true", "toggle reflects expanded state");
  assert.equal(document.activeElement, input, "the input is focused when opened");
});

test("clicking the toggle again hides the box and resets the filter", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const toggle = document.getElementById("treeSearchToggle");
  const row = document.getElementById("treeSearch");
  const input = document.getElementById("treeSearchInput");
  const fileB = document.querySelector('[data-node-id="file-b"]');

  toggle.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  typeSearch(dom, "alpha");
  await sleep(20);
  assert.ok(fileB.className.includes("tree-search-hidden"), "filter is active while searching");

  // Second click: hide + reset.
  toggle.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.ok(row.hidden, "search box hidden after second toggle click");
  assert.equal(toggle.getAttribute("aria-expanded"), "false", "toggle collapsed again");
  assert.equal(input.value, "", "query is cleared on close");
  assert.equal(document.querySelectorAll(".tree-search-hidden").length, 0, "filter is reset on close");
});

test("Escape in the search box closes it and resets the filter", async () => {
  const runtimeScript = await loadRuntimeScript();
  const dom = new JSDOM(
    buildHtml({ totalIssues: 2, nodesHtml: twoFileTree(), runtimeScript, searchBar: treeSearchHtml() }),
    { runScripts: "dangerously", pretendToBeVisual: true }
  );
  const { document } = dom.window;
  const toggle = document.getElementById("treeSearchToggle");
  const row = document.getElementById("treeSearch");
  const input = document.getElementById("treeSearchInput");

  toggle.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  typeSearch(dom, "alpha");
  await sleep(20);

  input.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

  assert.ok(row.hidden, "Escape hides the search box");
  assert.equal(input.value, "", "Escape clears the query");
  assert.equal(document.querySelectorAll(".tree-search-hidden").length, 0, "Escape resets the filter");
});

test("expand all sends batch setNodeExpanded with all node IDs", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const nodesHtml = productNodeHtml(
    fileNodeHtml("file-1") + fileNodeHtml("file-2")
  );

  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml,
      runtimeScript,
      filterToolbar: filterToolbarHtml(),
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideExecuteCommand__ = ideBridge(calls);
      },
    }
  );

  await sleep(20);
  const expandBtn = dom.window.document.getElementById("expandAllBtn");
  expandBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const batchCalls = calls.filter(c => c.cmd === "snyk.setNodeExpanded");
  assert.ok(batchCalls.length >= 1, "should send at least one setNodeExpanded call");

  const batchArg = batchCalls[0].args[0];
  assert.ok(Array.isArray(batchArg), "expand all should use batch format [[nodeId, expanded], ...]");
  assert.ok(batchArg.length >= 2, "batch should contain entries for multiple nodes");
  for (const entry of batchArg) {
    assert.equal(entry[1], true, "all entries should be expanded=true");
  }
});
