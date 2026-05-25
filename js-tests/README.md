# JS tests

Two suites live here:

- **Node tests** (`*.test.mjs`) — fast unit tests of webview helpers (tree runtime, dirty tracker, tabs, bridge, form/auth handlers). Run via `node --test` with jsdom.
- **Playwright tests** (`*.playwright.spec.mjs`) — browser tests that load the real `domain/ide/treeview/template/tree.js` runtime in headless Chromium and assert on rendered DOM, computed CSS, and the `__ideExecuteCommand__` bridge calls each IDE would receive.

The Playwright suite is **opt-in** because it requires a Chromium download (~150 MB) and is slower than `node --test`.

## One-time setup

```sh
make test-js-browser-setup
```

This runs `npm install` in `js-tests/` and downloads the Chromium build Playwright drives.

## Running locally

| Command                       | What it runs                                                     |
| ----------------------------- | ---------------------------------------------------------------- |
| `make test-js`                | Node tests + ES5 lint. Default for JS work.                      |
| `make test-js-browser`        | Playwright tests only (requires `test-js-browser-setup` first).  |
| `make test-js-all`            | Node tests + Playwright tests.                                   |

Direct npm equivalents (from `js-tests/`):

```sh
npm test                       # node --test
npm run test:playwright        # playwright test (headless)
npm run test:playwright:headed # playwright test --headed (watch the browser)
```

## Visual regression baselines

`panel-screenshots.playwright.spec.mjs` renders each panel HTML fixture (`fixtures/tree-view.html`, `fixtures/config-page.html`) under each IDE's body bg/fg colors and compares against committed PNG baselines under `screenshots/`.

Baselines are **per-platform** (`<name>-{darwin,linux}.png`) because Chromium's font rendering differs across OSes. Tests use `threshold: 0.2` and `maxDiffPixelRatio: 0.02` to absorb minor antialiasing noise.

After an intentional UI change (panel HTML, CSS, or fixture content), regenerate the baselines for your platform and commit them:

```sh
cd js-tests
npx playwright test panel-screenshots.playwright.spec.mjs --update-snapshots
git add screenshots/
```

CI runs on Linux, so Linux baselines (`*-linux.png`) must also be committed when the visual changes. Generate them by running `--update-snapshots` in a Linux environment (CI container, Docker, etc.) and committing the result.

When a screenshot diff fails unintentionally, the HTML report (`npx playwright show-report`) shows the expected, actual, and diff PNGs side-by-side under "Attachments".

## Inspecting failures

When a Playwright test fails, the config retains a trace, screenshot, and video for that run:

```sh
cd js-tests
npx playwright show-report           # opens playwright-report/ (HTML)
npx playwright show-trace test-results/<failing-test>/trace.zip
```

Use headed mode to step through interactively:

```sh
cd js-tests
npx playwright test --headed --debug
```

Both `playwright-report/` and `test-results/` are gitignored.

## CI/CD

Today, `.github/workflows/build.yaml` runs `make clean test`, which depends on `test-js` (Node tests + ES5 lint). The Playwright suite is **not** in the default CI path.

To add it, run `test-js-browser` after the existing test step on Linux. Chromium download is cached by `actions/setup-node` between runs:

```yaml
- name: Set up Node.js
  uses: actions/setup-node@v6
  with:
    node-version: '20'
    cache: 'npm'
    cache-dependency-path: js-tests/package-lock.json

- name: Install Playwright browser
  run: make test-js-browser-setup

- name: Run Playwright browser tests
  run: make test-js-browser
```

Recommended placement: a new `js-browser-tests` job in `build.yaml` that runs in parallel with `integration-tests` (Linux-only — Chromium launch on macOS/Windows runners adds time without meaningful additional coverage for these tests).
