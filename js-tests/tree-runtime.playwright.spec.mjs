import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function loadRuntimeScript() {
  const scriptPath = join(__dirname, "../domain/ide/treeview/template/tree.js");
  return readFile(scriptPath, "utf8");
}

function fileNodeHtml(nodeId = "file-1", opts = {}) {
  const expandedClass = opts.expanded ? " expanded" : "";
  return `<div class="tree-node tree-node-file${expandedClass}" data-node-id="${nodeId}" data-file-path="${opts.filePath || "/workspace/main.go"}" data-product="${opts.product || "oss"}">
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
function treeHtmlWithIDEPlaceholders(runtimeScript, nodesHtml) {
  return `<!doctype html>
  <html>
    <head>
      \${ideStyle}
    </head>
    <body>
      <div class="tree-container" id="treeContainer" data-total-issues="1">
        ${nodesHtml}
      </div>
      <script nonce="\${nonce}">${runtimeScript}</script>
      \${ideScript}
    </body>
  </html>`;
}

const ideVariants = [
  { name: "vscode", background: "rgb(30, 30, 30)", foreground: "rgb(204, 204, 204)" },
  { name: "intellij", background: "rgb(43, 43, 43)", foreground: "rgb(187, 187, 187)" },
  { name: "visualStudio", background: "rgb(37, 37, 38)", foreground: "rgb(241, 241, 241)" },
  { name: "eclipse", background: "rgb(27, 30, 35)", foreground: "rgb(216, 221, 229)" },
];

function replaceIDEPlaceholders(html, ideName) {
  const nonce = "playwright-ide-nonce";
  const config = ideVariants.find((v) => v.name === ideName);
  if (!config) {
    throw new Error(`unknown IDE variant: ${ideName}`);
  }

  const ideStyle = `<style nonce="${nonce}">
    body {
      background-color: ${config.background};
      color: ${config.foreground};
    }
  </style>`;
  const ideScript = `<script nonce="${nonce}">
    window.__calls = [];
    window.__activeIDE = "${ideName}";
    window.__ideExecuteCommand__ = function(cmd, args) {
      window.__calls.push({ cmd, args, ide: window.__activeIDE });
    };
  </script>`;

  return html
    .replaceAll("${nonce}", nonce)
    .replace("${ideStyle}", ideStyle)
    .replace("${ideScript}", ideScript);
}

for (const ide of ideVariants) {
  test(`IDE placeholder replacement works for ${ide.name}`, async ({ page }) => {
    const runtimeScript = await loadRuntimeScript();
    const htmlTemplate = treeHtmlWithIDEPlaceholders(
      runtimeScript,
      fileNodeHtml("file-1", { childrenHtml: issueNodeHtml("vuln-1") })
    );
    const html = replaceIDEPlaceholders(htmlTemplate, ide.name);

    await page.setContent(html);

    const content = await page.content();
    expect(content).not.toContain("${ideStyle}");
    expect(content).not.toContain("${ideScript}");
    expect(content).not.toContain("${nonce}");

    const backgroundColor = await page.evaluate(
      () => getComputedStyle(document.body).backgroundColor
    );
    expect(backgroundColor).toBe(ide.background);

    await page.locator(".tree-node-issue .tree-node-row").click();
    const bridgeCalls = await page.evaluate(() => window.__calls);
    expect(bridgeCalls).toHaveLength(1);
    expect(bridgeCalls[0].cmd).toBe("snyk.navigateToRange");
    expect(bridgeCalls[0].ide).toBe(ide.name);
  });
}

test("issue click emits navigateToRange through IDE bridge", async ({ page }) => {
  const runtimeScript = await loadRuntimeScript();

  await page.setContent(`<!doctype html>
  <html>
    <body>
      <div class="tree-container" id="treeContainer" data-total-issues="1">
        ${fileNodeHtml("file-1", { childrenHtml: issueNodeHtml("vuln-1") })}
      </div>
      <script>
        window.__calls = [];
        window.__ideExecuteCommand__ = function(cmd, args) {
          window.__calls.push({ cmd, args });
        };
      </script>
      <script>${runtimeScript}</script>
    </body>
  </html>`);

  await page.locator('.tree-node-issue .tree-node-row').click();
  const bridgeCalls = await page.evaluate(() => window.__calls);

  expect(bridgeCalls).toHaveLength(1);
  expect(bridgeCalls[0].cmd).toBe("snyk.navigateToRange");
  expect(bridgeCalls[0].args[0]).toBe("/workspace/main.go");
  expect(bridgeCalls[0].args[1]).toEqual({
    start: { line: 10, character: 4 },
    end: { line: 15, character: 20 },
  });
});

test("clicking a product row toggles expanded state", async ({ page }) => {
  const runtimeScript = await loadRuntimeScript();
  await page.setContent(`<!doctype html>
  <html>
    <body>
      <div class="tree-container" id="treeContainer" data-total-issues="1">
        ${productNodeHtml(fileNodeHtml())}
      </div>
      <script>${runtimeScript}</script>
    </body>
  </html>`);

  const node = page.locator('[data-node-id="product-1"]');
  await expect(node).toHaveClass(/expanded/);

  await page.locator('[data-node-id="product-1"] > .tree-node-row').click();
  await expect(node).not.toHaveClass(/expanded/);
});
