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
  return `<div class="tree-node tree-node-file"
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
      <button data-filter-type="issueView" data-filter-value="openIssues" class="filter-btn filter-active">Open</button>
    </span>
  </div>`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("initialization auto-expands and requests first chunk under threshold", async () => {
  const runtimeScript = await loadRuntimeScript();
  const requests = [];
  const dom = new JSDOM(
    buildHtml({
      totalIssues: 5,
      nodesHtml: fileNodeHtml(),
      runtimeScript,
    }),
    {
      runScripts: "dangerously",
      pretendToBeVisual: true,
      beforeParse(window) {
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  await sleep(20);
  const node = dom.window.document.querySelector(".tree-node-file");
  assert.ok(node.className.includes("expanded"), "file node should be auto-expanded");
  assert.equal(requests.length, 1, "exactly one initial chunk request expected");
  assert.equal(requests[0][1], "/workspace/main.go");
  assert.equal(requests[0][2], "Snyk Open Source");
  assert.equal(requests[0][3], 0);
  assert.equal(requests[0][4], 100);
});

test("initialization does not auto-expand over threshold", async () => {
  const runtimeScript = await loadRuntimeScript();
  const requests = [];
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
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  await sleep(20);
  const node = dom.window.document.querySelector(".tree-node-file");
  assert.ok(!node.className.includes("expanded"), "file node should remain collapsed");
  assert.equal(requests.length, 0, "no initial chunk request expected");
});

test("clicking load-more requests next chunk using nextStart", async () => {
  const runtimeScript = await loadRuntimeScript();
  const requests = [];
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
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  const { document } = dom.window;
  const node = document.querySelector(".tree-node-file");
  const row = node.querySelector(".tree-node-row");

  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.equal(requests.length, 1, "first expand should request first chunk");
  const requestId = requests[0][0];

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

  assert.equal(requests.length, 2, "load-more click should request next chunk");
  assert.equal(requests[1][3], 7, "start should come from nextStart");
  assert.equal(requests[1][4], 107, "end should be nextStart + chunk size");
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

test("clicking an issue node calls __ideTreeNavigateToRange__ with structured range", async () => {
  const runtimeScript = await loadRuntimeScript();
  const navigations = [];
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
        window.__ideTreeNavigateToRange__ = (...args) => navigations.push(args);
      },
    }
  );

  const { document } = dom.window;
  const issueRow = document.querySelector(".tree-node-issue .tree-node-row");
  issueRow.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.equal(navigations.length, 1, "one navigation expected");
  assert.equal(navigations[0][0], "/workspace/main.go", "filePath");
  const range = navigations[0][1];
  assert.equal(range.start.line, 10, "start line");
  assert.equal(range.start.character, 4, "start character");
  assert.equal(range.end.line, 15, "end line");
  assert.equal(range.end.character, 20, "end character");
});

test("filter toolbar click calls __ideTreeToggleFilter__ with correct args", async () => {
  const runtimeScript = await loadRuntimeScript();
  const filterCalls = [];
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
        window.__ideTreeToggleFilter__ = (...args) => filterCalls.push(args);
      },
    }
  );

  const { document } = dom.window;

  // Click an active filter button — should toggle off (enabled=false)
  const highBtn = document.querySelector('[data-filter-value="high"]');
  highBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.equal(filterCalls.length, 1, "one filter call expected");
  assert.equal(filterCalls[0][0], "severity");
  assert.equal(filterCalls[0][1], "high");
  assert.equal(filterCalls[0][2], false, "active button click should pass enabled=false");
});

test("filter toolbar click on inactive button passes enabled=true", async () => {
  const runtimeScript = await loadRuntimeScript();
  const filterCalls = [];
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
        window.__ideTreeToggleFilter__ = (...args) => filterCalls.push(args);
      },
    }
  );

  const { document } = dom.window;
  const medBtn = document.querySelector('[data-filter-value="medium"]');
  medBtn.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.equal(filterCalls.length, 1);
  assert.equal(filterCalls[0][0], "severity");
  assert.equal(filterCalls[0][1], "medium");
  assert.equal(filterCalls[0][2], true, "inactive button click should pass enabled=true");
});

test("__onIdeTreeIssueChunk__ injects HTML and updates data attributes", async () => {
  const runtimeScript = await loadRuntimeScript();
  const requests = [];
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
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  const row = fileNode.querySelector(".tree-node-row");

  // Expand to trigger chunk request
  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.equal(requests.length, 1);

  const requestId = requests[0][0];

  // Deliver chunk without hasMore
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
  const requests = [];
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
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  fileNode.querySelector(".tree-node-row").dispatchEvent(
    new dom.window.MouseEvent("click", { bubbles: true })
  );

  dom.window.__onIdeTreeIssueChunk__(requests[0][0], {
    issueNodesHtml: '<div class="tree-node tree-node-issue"><div class="tree-node-row">Chunk 1</div></div>',
    hasMore: true,
    nextStart: 100,
  });

  assert.equal(fileNode.getAttribute("data-next-start"), "100");
});

test("already-loaded file node does not re-request issues on expand", async () => {
  const runtimeScript = await loadRuntimeScript();
  const requests = [];
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
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  const row = fileNode.querySelector(".tree-node-row");

  // Expand
  row.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
  assert.equal(requests.length, 0, "already-loaded file should not request chunks");
});

test("__onIdeTreeIssueChunk__ with string payload parses JSON", async () => {
  const runtimeScript = await loadRuntimeScript();
  const requests = [];
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
        window.__ideTreeRequestIssueChunk__ = (...args) => requests.push(args);
      },
    }
  );

  const { document } = dom.window;
  const fileNode = document.querySelector(".tree-node-file");
  fileNode.querySelector(".tree-node-row").dispatchEvent(
    new dom.window.MouseEvent("click", { bubbles: true })
  );

  // Deliver as JSON string instead of object
  const payload = JSON.stringify({
    issueNodesHtml: '<div class="tree-node tree-node-issue"><div class="tree-node-row">From JSON</div></div>',
    hasMore: false,
  });
  dom.window.__onIdeTreeIssueChunk__(requests[0][0], payload);

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
  const filterCalls = [];
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
        window.__ideTreeToggleFilter__ = (...args) => filterCalls.push(args);
      },
    }
  );

  const { document } = dom.window;
  // Click the <svg> inside the button, not the button itself
  const svg = document.querySelector(".filter-btn-icon svg");
  svg.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

  assert.equal(filterCalls.length, 1, "filter toggle should fire even when SVG clicked");
  assert.equal(filterCalls[0][0], "severity");
  assert.equal(filterCalls[0][1], "critical");
  assert.equal(filterCalls[0][2], false, "active button should toggle to disabled");
});
