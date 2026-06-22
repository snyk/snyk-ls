import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// Guards validateAdditionalEnv against the Go backend's parsing semantics.
// The backend splits each ";"-separated pair on the FIRST "=" (strings.Cut /
// SplitN(..., "=", 2) in infrastructure/oss/cli_scanner.go and
// application/server/configuration.go), so a VALUE may itself contain "=".
// The validator must accept anything the runtime accepts, otherwise the UI
// blocks legitimate inputs the scan would happily consume.

async function getValidator() {
  const win = await buildDom();
  return win.ConfigApp.validation.validateAdditionalEnv;
}

const validCases = [
  ["empty string", ""],
  ["whitespace only", "   "],
  ["single pair", "FOO=bar"],
  ["two pairs", "FOO=bar;BAZ=qux"],
  ["empty value", "FOO="],
  ["surrounding whitespace", "  FOO = bar  "],
  ["trailing separator", "FOO=bar;"],
  ["underscore-leading key", "_FOO=bar"],
  // Values containing "=" — must be accepted (split on first "=" only).
  ["base64-padded value", "B64=Zm9v=="],
  ["value with equals", "MY_KEY=val=with=equals"],
  ["jwt-like value", "TOKEN=aaa.bbb=.ccc"],
  ["query-string value", "Q=a=1&b=2"],
];

const invalidCases = [
  ["missing equals", "FOO"],
  ["key starts with digit", "1FOO=bar"],
  ["key with dash", "FO-O=bar"],
  ["semicolon in value", "FOO=a;b"], // splits into "FOO=a" + "b"; second has no '='
  ["empty key", "=bar"],
];

test("validateAdditionalEnv accepts valid formats incl. '=' in value", async () => {
  const validateAdditionalEnv = await getValidator();
  for (const [name, input] of validCases) {
    assert.equal(validateAdditionalEnv(input), true, `expected valid: ${name} (${input})`);
  }
});

test("validateAdditionalEnv rejects malformed formats", async () => {
  const validateAdditionalEnv = await getValidator();
  for (const [name, input] of invalidCases) {
    assert.equal(validateAdditionalEnv(input), false, `expected invalid: ${name} (${input})`);
  }
});
