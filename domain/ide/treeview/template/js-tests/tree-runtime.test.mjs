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

function buildHtml({ totalIssues, nodesHtml, runtimeScript }) {
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"></head>
  <body>
    <div class="tree-container" id="treeContainer" data-total-issues="${String(totalIssues)}">
      ${nodesHtml}
    </div>
    <script>${runtimeScript}</script>
  </body>
</html>`;
}

function fileNodeHtml(nodeId = "file-1") {
  return `<div class="tree-node tree-node-file"
      data-node-id="${nodeId}"
      data-file-path="/workspace/main.go"
      data-product="Snyk Open Source"
      data-issues-loaded="false"
      data-issues-loading="false">
    <div class="tree-node-row">
      <span class="tree-chevron"></span>
      <span class="tree-label">main.go</span>
    </div>
    <div class="tree-node-children"></div>
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
