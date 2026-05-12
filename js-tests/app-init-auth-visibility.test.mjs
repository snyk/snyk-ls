import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

function isHidden(el) {
  return el.className.includes("hidden");
}

function assertInitState(win, expected) {
  const tokenFieldGroup = win.document.getElementById("token-field-group");
  const getTokenLink = win.document.getElementById("get-token-link");
  const authBtn = win.document.getElementById("authenticate-btn");
  const logoutBtn = win.document.getElementById("logout-btn");

  assert.equal(isHidden(tokenFieldGroup), expected.tokenFieldHidden, "token field visibility mismatch");
  assert.equal(isHidden(getTokenLink), expected.getTokenLinkHidden, "get-token link visibility mismatch");
  assert.equal(isHidden(authBtn), expected.authenticateHidden, "authenticate button visibility mismatch");
  assert.equal(isHidden(logoutBtn), expected.logoutHidden, "logout button visibility mismatch");

  assert.equal(authBtn.disabled, expected.authenticateDisabled, "authenticate button disabled state mismatch");
  assert.equal(logoutBtn.disabled, expected.logoutDisabled, "logout button disabled state mismatch");
}

const cases = [
  {
    name: "oauth with token",
    input: { initialAuthMethod: "oauth", initialToken: "legacy-token" },
    expected: {
      tokenFieldHidden: true,
      getTokenLinkHidden: true,
      authenticateHidden: false,
      logoutHidden: false,
      authenticateDisabled: true,
      logoutDisabled: false,
    },
  },
  {
    name: "oauth without token",
    input: { initialAuthMethod: "oauth", initialToken: "" },
    expected: {
      tokenFieldHidden: true,
      getTokenLinkHidden: true,
      authenticateHidden: false,
      logoutHidden: true,
      authenticateDisabled: false,
      logoutDisabled: true,
    },
  },
  {
    name: "pat with token",
    input: { initialAuthMethod: "pat", initialToken: "pat-token" },
    expected: {
      tokenFieldHidden: false,
      getTokenLinkHidden: false,
      authenticateHidden: true,
      logoutHidden: false,
      authenticateDisabled: true,
      logoutDisabled: false,
    },
  },
  {
    name: "pat without token",
    input: { initialAuthMethod: "pat", initialToken: "" },
    expected: {
      tokenFieldHidden: false,
      getTokenLinkHidden: false,
      authenticateHidden: true,
      logoutHidden: true,
      authenticateDisabled: false,
      logoutDisabled: true,
    },
  },
  {
    name: "legacy token auth with token",
    input: { initialAuthMethod: "token", initialToken: "legacy-token" },
    expected: {
      tokenFieldHidden: false,
      getTokenLinkHidden: false,
      authenticateHidden: true,
      logoutHidden: false,
      authenticateDisabled: true,
      logoutDisabled: false,
    },
  },
  {
    name: "legacy token auth without token",
    input: { initialAuthMethod: "token", initialToken: "" },
    expected: {
      tokenFieldHidden: false,
      getTokenLinkHidden: false,
      authenticateHidden: true,
      logoutHidden: true,
      authenticateDisabled: false,
      logoutDisabled: true,
    },
  },
];

for (const tc of cases) {
  test(`init visibility and disabled states: ${tc.name}`, async () => {
    const win = await buildDom(tc.input);
    assertInitState(win, tc.expected);
  });
}
