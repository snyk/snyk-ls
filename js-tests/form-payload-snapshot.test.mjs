// ABOUTME: Snapshot test for the form save payload produced by formHandler.collectData().
// ABOUTME: Catches accidental field renames, type-coercion shifts, and structural changes.
//
// Regenerate snapshot when an intentional change shifts the payload:
//   UPDATE_SNAPSHOT=1 npm test --prefix js-tests -- --test-name-pattern="form payload"

import assert from "node:assert/strict";
import test from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildDom } from "./helpers.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT_PATH = join(__dirname, "snapshots", "form-payload.json");

function stableStringify(value) {
	return JSON.stringify(value, (_key, val) => {
		if (val && typeof val === "object" && !Array.isArray(val)) {
			return Object.keys(val)
				.sort()
				.reduce((acc, k) => {
					acc[k] = val[k];
					return acc;
				}, {});
		}
		return val;
	}, 2) + "\n";
}

test("form payload snapshot: collectData() output matches fixture", async () => {
	const win = await buildDom();
	const data = win.ConfigApp.formHandler.collectData();
	const actual = stableStringify(data);

	if (process.env.UPDATE_SNAPSHOT === "1") {
		await writeFile(SNAPSHOT_PATH, actual, "utf8");
		return;
	}

	let expected;
	try {
		expected = await readFile(SNAPSHOT_PATH, "utf8");
	} catch (err) {
		if (err.code === "ENOENT") {
			throw new Error(
				`snapshot missing at ${SNAPSHOT_PATH}; run UPDATE_SNAPSHOT=1 npm test to create`
			);
		}
		throw err;
	}

	assert.equal(
		actual,
		expected,
		"form payload changed — review diff; if intentional re-run with UPDATE_SNAPSHOT=1"
	);
});
