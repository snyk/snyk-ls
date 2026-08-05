// ABOUTME: Tests for the "Autonomous remediation" LLM provider/model/endpoint fields
// ABOUTME: (IDE-2274, INT-1) — rendering, form collection, and section reset defaults.

import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

test("Autonomous remediation section renders provider options, model and endpoint fields", async () => {
	const win = await buildDom();
	const doc = win.document;

	assert.match(doc.body.textContent, /Autonomous remediation/);

	const providerSelect = doc.getElementById("llm_provider");
	assert.ok(providerSelect, "llm_provider select should exist");
	const optionValues = Array.from(providerSelect.options).map((o) => o.value);
	assert.deepEqual(optionValues, ["", "anthropic", "openai", "ollama", "vertex", "litellm"]);

	const modelInput = doc.getElementById("llm_model");
	assert.ok(modelInput, "llm_model input should exist");
	assert.equal(modelInput.placeholder, "e.g. llama3.1");

	const endpointInput = doc.getElementById("llm_base_url");
	assert.ok(endpointInput, "llm_base_url input should exist");
	assert.equal(endpointInput.placeholder, "https://llm-gateway.internal");

	assert.match(
		doc.body.textContent,
		/Your LLM API key is never stored or sent by Snyk/,
		"must tell the developer their API key stays in their own environment"
	);
});

test("collectData() includes the provider, model and endpoint the developer chose", async () => {
	const win = await buildDom();
	const doc = win.document;

	doc.getElementById("llm_provider").value = "litellm";
	doc.getElementById("llm_model").value = "llama3.1";
	doc.getElementById("llm_base_url").value = "https://llm-gateway.internal";

	const data = win.ConfigApp.formHandler.collectData();

	assert.equal(data.llm_provider, "litellm");
	assert.equal(data.llm_model, "llama3.1");
	assert.equal(data.llm_base_url, "https://llm-gateway.internal");
});

test("collectData() never includes an API key field for the LLM provider section", async () => {
	const win = await buildDom();
	const data = win.ConfigApp.formHandler.collectData();
	const keys = Object.keys(data).join(" ");
	assert.doesNotMatch(keys, /llm.*key/i, "no API key field must ever be part of the payload");
});

test("resetting the Autonomous remediation section clears provider, model and endpoint", async () => {
	const win = await buildDom();
	const doc = win.document;

	doc.getElementById("llm_provider").value = "litellm";
	doc.getElementById("llm_model").value = "llama3.1";
	doc.getElementById("llm_base_url").value = "https://llm-gateway.internal";

	const resetButton = doc.querySelector('.reset-section-btn[data-section="autonomousRemediation"]');
	assert.ok(resetButton, "autonomousRemediation reset button should exist");
	resetButton.dispatchEvent(new win.Event("click", { bubbles: true }));

	assert.equal(doc.getElementById("llm_provider").value, "");
	assert.equal(doc.getElementById("llm_model").value, "");
	assert.equal(doc.getElementById("llm_base_url").value, "");
});
