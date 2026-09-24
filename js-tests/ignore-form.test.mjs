import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const ignoreDir = join(dirname(fileURLToPath(import.meta.url)), "..", "internal", "html", "ignore");

async function buildIgnoreForm() {
  const templates = await readFile(join(ignoreDir, "ignore_templates.html"), "utf8");
  const form = templates
    .match(/\{\{define "ignore-form"\}\}([\s\S]*?)\{\{end\}\}\s*\{\{end\}\}/)[1]
    .replace(/\{\{[^}]*\}\}/g, "");
  const script = (await readFile(join(ignoreDir, "ignore_scripts.js"), "utf8")).replace(
    "${ideSubmitIgnoreRequest}",
    "window.submitted.push({ ignoreType: ignoreType, ignoreReason: ignoreReason, ignoreExpirationDate: ignoreExpirationDate });",
  );
  const dom = new JSDOM(
    `<body><button id="ignore-create">Create ignore</button>${form}` +
      `<script>window.submitted = [];</script><script>${script}</script></body>`,
    { runScripts: "dangerously" },
  );
  const win = dom.window;
  win.HTMLElement.prototype.scrollIntoView = () => {};
  return win;
}

function isoDateFromToday(win, days) {
  const d = new win.Date();
  d.setDate(d.getDate() + days);
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}

function submitTemporaryIgnore(win, expiration) {
  const doc = win.document;
  const type = doc.getElementById("ignore-form-type");
  type.value = "temporary-ignore";
  type.dispatchEvent(new win.Event("change", { bubbles: true }));
  doc.getElementById("ignore-form-expiration-date").value = expiration;
  doc.getElementById("ignore-form-ignore-reason").value = "Test";
  doc.getElementById("ignore-form-submit").click();
}

const expirationError = (win) => win.document.getElementById("ignore-expiration-error");

for (const [label, value] of [["empty", ""], ["today", 0], ["in the past", -1]]) {
  test(`a temporary ignore with an expiration date ${label} is not submitted and shows the error`, async () => {
    const win = await buildIgnoreForm();

    submitTemporaryIgnore(win, typeof value === "number" ? isoDateFromToday(win, value) : value);

    assert.equal(win.submitted.length, 0);
    assert.ok(expirationError(win), "the expiration error badge exists");
    assert.ok(!expirationError(win).className.includes("hidden"), "the expiration error is visible");
  });
}

test("a temporary ignore expiring tomorrow is submitted", async () => {
  const win = await buildIgnoreForm();
  const tomorrow = isoDateFromToday(win, 1);

  submitTemporaryIgnore(win, tomorrow);

  assert.equal(win.submitted.length, 1);
  assert.equal(win.submitted[0].ignoreExpirationDate, tomorrow);
  assert.ok(expirationError(win).className.includes("hidden"));
});

test("changing the expiration date hides the error", async () => {
  const win = await buildIgnoreForm();
  submitTemporaryIgnore(win, "");

  const date = win.document.getElementById("ignore-form-expiration-date");
  date.value = isoDateFromToday(win, 1);
  date.dispatchEvent(new win.Event("change", { bubbles: true }));

  assert.ok(expirationError(win).className.includes("hidden"));
});

test("an ignore that never expires is submitted with no date", async () => {
  const win = await buildIgnoreForm();
  win.document.getElementById("ignore-form-ignore-reason").value = "Test";
  win.document.getElementById("ignore-form-submit").click();

  assert.equal(win.submitted.length, 1);
  assert.equal(win.submitted[0].ignoreExpirationDate, "");
});
