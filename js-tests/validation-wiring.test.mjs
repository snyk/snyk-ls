import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// Guards against template ↔ JS selector drift in validation.js. For each field
// listed below, the test dispatches the wired event and asserts that
// validateAndShowError fired at least once. A failure means the template
// renamed/removed the field, or initializeAllValidation stopped attaching
// the listener. The test is value-agnostic — it does not care whether the
// input is valid or invalid, nor which field id the listener ultimately
// validates (e.g. authentication_method change re-validates token).

// Global fields wired by validation.initializeAllValidation
const globalListeners = [
	{ id: "token", event: "input" },
	{ id: "authentication_method", event: "change" },
	{ id: "api_endpoint", event: "input" },
	{ id: "risk_score_threshold", event: "input" },
	{ id: "cli_release_channel_custom", event: "input" },
];

// Per-folder fields: validation.js queries every matching element by suffix.
// The validateAndShowError call uses the element's full id (folder_X_<suffix>).
const folderListenerSuffixes = [
	"_additional_environment",
	"_risk_score_threshold",
];

async function setupSpy() {
	const win = await buildDom();
	const calls = [];
	const orig = win.ConfigApp.validation.validateAndShowError;
	win.ConfigApp.validation.validateAndShowError = function (fieldId) {
		calls.push(fieldId);
		return orig.apply(this, arguments);
	};
	return { win, calls };
}

for (const { id, event } of globalListeners) {
	test(`validation listener wired for #${id} (${event})`, async () => {
		const { win, calls } = await setupSpy();
		const el = win.document.getElementById(id);
		assert.ok(el, `expected #${id} in fixture`);

		const before = calls.length;
		el.dispatchEvent(new win.Event(event, { bubbles: true }));

		assert.ok(
			calls.length > before,
			`validateAndShowError did not fire after ${event} on #${id} — listener not wired?`,
		);
	});
}

for (const suffix of folderListenerSuffixes) {
	test(`validation listener wired for every folder field with suffix ${suffix}`, async () => {
		const { win, calls } = await setupSpy();
		const inputs = win.document.querySelectorAll(`[id^="folder_"][id$="${suffix}"]`);
		assert.ok(
			inputs.length > 0,
			`selector [id^="folder_"][id$="${suffix}"] matched 0 elements — template field renamed?`,
		);

		for (const input of inputs) {
			const before = calls.length;
			input.dispatchEvent(new win.Event("input", { bubbles: true }));
			assert.ok(
				calls.length > before,
				`validateAndShowError did not fire for ${input.id} — initializeFolder*Validation drift?`,
			);
		}
	});
}
