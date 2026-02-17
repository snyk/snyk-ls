import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function loadRuntimeScript() {
  const scriptPath = join(__dirname, "..", "tree.js");
  return readFile(scriptPath, "utf8");
}

function buildHtml({ totalIssues, nodesHtml, runtimeScript, filterToolbar = "" }) {
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"></head>
  <body>
    ${filterToolbar}
    <div class="tree-container" id="treeContainer" data-total-issues="${String(totalIssues)}">
      ${nodesHtml}
    </div>
    <script>${runtimeScript}</script>
  </body>
</html>`;
}

function fileNodeHtml(nodeId = "file-1", opts = {}) {
  const loaded = opts.loaded || "false";
  const expandedClass = opts.expanded ? " expanded" : "";
  return `<div class="tree-node tree-node-file${expandedClass}"
      data-node-id="${nodeId}"
      data-file-path="${opts.filePath || "/workspace/main.go"}"
      data-product="${opts.product || "Snyk Open Source"}"
      data-issues-loaded="${loaded}"
      data-issues-loading="false">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label">main.go</span>
    </div>
    <div class="tree-node-children">${opts.childrenHtml || ""}</div>
  </div>`;
}

function issueNodeHtml(issueId = "vuln-1") {
  return `<div class="tree-node tree-node-issue" data-node-id="issue-${issueId}">
    <div class="tree-node-row"
         data-file-path="/workspace/main.go"
         data-start-line="10"
         data-end-line="15"
         data-start-char="4"
         data-end-char="20"
         data-issue-id="${issueId}">
      <span class="severity-icon severity-high">H</span>
      <span class="tree-label">Test Vulnerability</span>
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
  assert.equal(calls.length, 0, "no initial chunk request expected");
});

test("clicking load-more requests next chunk using nextStart", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
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

  const { document } = dom.window;
  const node = document.querySelector(".tree-node-file");
  const row = node.querySelector(".tree-node-row");

  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  const chunkCalls = calls.filter(c => c.cmd === "snyk.getTreeViewIssueChunk");
  assert.equal(chunkCalls.length, 1, "first expand should request first chunk");
  const requestId = chunkCalls[0].args[0];

  dom.window.__onIdeTreeIssueChunk__(requestId, {
    issueNodesHtml:
      '<div class="tree-node tree-node-issue"><div class="tree-node-row" data-issue-id="a-1"></div></div>' +
      '<div class="tree-node tree-node-load-more"><div class="tree-node-row tree-load-more-row">Load more issues...</div></div>',
    hasMore: true,
    nextStart: 7,
  });

  const loadMoreRow = document.querySelector(".tree-load-more-row");
  assert.ok(loadMoreRow, "load-more row should be rendered");
  loadMoreRow.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  const allChunkCalls = calls.filter(c => c.cmd === "snyk.getTreeViewIssueChunk");
  assert.equal(allChunkCalls.length, 2, "load-more click should request next chunk");
  assert.equal(allChunkCalls[1].args[3], 7, "start should come from nextStart");
  assert.equal(allChunkCalls[1].args[4], 107, "end should be nextStart + chunk size");
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
      nodesHtml: fileNodeHtml("file-1", { loaded: "true", childrenHtml: issueNodeHtml("vuln-1") }),
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
  assert.equal(filterCalls[0].args[0], "severity");
  assert.equal(filterCalls[0].args[1], "high");
  assert.equal(filterCalls[0].args[2], false, "active button click should pass enabled=false");
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
  assert.equal(filterCalls[0].args[0], "severity");
  assert.equal(filterCalls[0].args[1], "medium");
  assert.equal(filterCalls[0].args[2], true, "inactive button click should pass enabled=true");
});

test("__onIdeTreeIssueChunk__ injects HTML and updates data attributes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
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

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  const row = fileNode.querySelector(".tree-node-row");

  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  const chunkCalls = calls.filter(c => c.cmd === "snyk.getTreeViewIssueChunk");
  assert.equal(chunkCalls.length, 1);

  const requestId = chunkCalls[0].args[0];

  dom.window.__onIdeTreeIssueChunk__(requestId, {
    issueNodesHtml: '<div class="tree-node tree-node-issue"><div class="tree-node-row">Issue A</div></div>',
    hasMore: false,
  });

  assert.equal(fileNode.getAttribute("data-issues-loaded"), "true");
  assert.equal(fileNode.getAttribute("data-issues-loading"), "false");
  assert.equal(fileNode.getAttribute("data-next-start"), null, "no next-start when hasMore=false");

  const children = fileNode.querySelector(".tree-node-children");
  assert.ok(children.innerHTML.includes("Issue A"), "chunk HTML should be injected");
});

test("__onIdeTreeIssueChunk__ with hasMore sets data-next-start", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
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

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  fileNode.querySelector(".tree-node-row").dispatchEvent(
    new dom.window.MouseEvent("click", { bubbles: true })
  );

  const chunkCalls = calls.filter(c => c.cmd === "snyk.getTreeViewIssueChunk");
  dom.window.__onIdeTreeIssueChunk__(chunkCalls[0].args[0], {
    issueNodesHtml: '<div class="tree-node tree-node-issue"><div class="tree-node-row">Chunk 1</div></div>',
    hasMore: true,
    nextStart: 100,
  });

  assert.equal(fileNode.getAttribute("data-next-start"), "100");
});

test("already-loaded file node does not re-request issues on expand", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: fileNodeHtml("file-1", { loaded: "true", childrenHtml: issueNodeHtml() }),
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
  const fileNode = document.querySelector(".tree-node-file");
  const row = fileNode.querySelector(".tree-node-row");

  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  const chunkCalls = calls.filter(c => c.cmd === "snyk.getTreeViewIssueChunk");
  assert.equal(chunkCalls.length, 0, "already-loaded file should not request chunks");
});

test("__onIdeTreeIssueChunk__ with string payload parses JSON", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
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

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  fileNode.querySelector(".tree-node-row").dispatchEvent(
    new dom.window.MouseEvent("click", { bubbles: true })
  );

  const chunkCalls = calls.filter(c => c.cmd === "snyk.getTreeViewIssueChunk");
  const payload = JSON.stringify({
    issueNodesHtml: '<div class="tree-node tree-node-issue"><div class="tree-node-row">From JSON</div></div>',
    hasMore: false,
  });
  dom.window.__onIdeTreeIssueChunk__(chunkCalls[0].args[0], payload);

  const children = fileNode.querySelector(".tree-node-children");
  assert.ok(children.innerHTML.includes("From JSON"), "string payload should be parsed and injected");
  assert.equal(fileNode.getAttribute("data-issues-loaded"), "true");
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
  assert.equal(filterCalls[0].args[0], "severity");
  assert.equal(filterCalls[0].args[1], "critical");
  assert.equal(filterCalls[0].args[2], false, "active button should toggle to disabled");
});

test("expand all button expands all collapsible nodes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const calls = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 0,
      nodesHtml: productNodeHtml(fileNodeHtml("file-1", { loaded: "true", childrenHtml: issueNodeHtml() })),
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
      nodesHtml: productNodeHtml(fileNodeHtml("file-1", { loaded: "true", childrenHtml: issueNodeHtml() })),
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
