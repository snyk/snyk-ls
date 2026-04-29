# Megaproject real-scan profiling (IDE-1940)

Canonical notes for **megaproject-scale** runs of `Test_SmokeRealScanMonorepoFixture` (`application/server/server_smoke_test.go`): wall time, CPU profile shape, heap snapshots, and how that compares across work sessions. Implementation-plan detail for checkpoints **cp8** and branch work lives in the repo’s local IDE-1940 plan; this file is **versioned** under `docs/` (plan files matching `*IDE-*` are gitignored).

## Fixture and harness (all sessions below)

- **Fixture:** `BENCHMARK_REALSCAN_FULL_FIXTURE=1` → **500 `code_*` + 500 `oss_*`** leaves (1000 total). When `code+oss leaves > 100`, the harness **skips per-leaf `publishDiagnostics` assertions** but still runs real Code + OSS work.
- **Harness:** real LS + CLI/API paths; CPU + heap profiles from `withMonorepoRealScanPprof` (or equivalent) under a configurable output dir (often `build/…`, gitignored).
- **Issue cache:** megaproject reprofile Session 24 used **`BENCHMARK_ISSUE_CACHE_BACKEND=bolt`** (default bolt-backed cache + index-backed diagnostics).

## Session 3 — baseline (2026-04-16)

| Field | Value |
|-------|--------|
| Wall time | ~**26–27 min** |
| CPU samples / duration | ~**718 s / ~1605 s** → **~44.7%** on-CPU |
| Dominant CPU story | **`internal/delta.findMatches`** + fuzzy **`Levenshtein`** + **`FindingsDiffer.Diff`** / path normalization — diffing **working-directory vs reference** issue sets at OSS scale (**~74k findings** logged on the 500× lockfile tree). |
| Heap (before→after diff narrative) | ~**9.08 GiB** inuse growth; top flat: **`encoding/json.(*RawMessage).UnmarshalJSON`** (~44%), **`literalStore`** (~27%), OSS **`toIssue` / GetExtendedMessage / fmt / regexp`** on rich issue materialization. |

## Session 5 — post checkpoint 8 (fuzzy_matcher / cp8) (2026-04-17)

| Field | Value |
|-------|--------|
| Wall time | ~**1312 s (~21.9 min)** |
| CPU samples / duration | ~**438 s / ~1304 s** → **~33.6%** on-CPU |
| Delta vs Session 3 | **`findMatches` / Levenshtein / checkDirs** drop out of top cumulative frames; **`FindingsDiffer.Diff`** and **`Issue.GetGlobalIdentity`** rise relatively as the diff path short-circuits. |
| Heap | Session 5 write-up targeted **CPU**; heap growth vs baseline essentially **unchanged** (still dominated by large JSON + OSS pipeline). |
| Flake note | One megaproject run hit **transient OSS CLI “Failed to get vulns”**; retry passed — treat as **CLI/service** noise at this scale. |

## Session 24 — current branch reprofile (2026-04-29)

| Field | Value |
|-------|--------|
| Artifacts (example) | `build/real_scan_pprof_full_500/real_scan_cpu.pprof`, `real_scan_heap_{before,after}.pprof`, `heap_samples.csv` |
| Wall time | ~**1232 s (~20.5 min)** |
| CPU samples / duration | ~**464 s / ~1219 s** → **~38.1%** on-CPU |
| Dominant CPU story (cumulative, excerpt) | **`encoding/json.Unmarshal`** (~51%); **`DelegatingConcurrentScanner.IssuesForFile` → `IssueCache.IssuesForFile` → `BoltBackend.Get` → `unmarshalIssues`** (~35.5%); **`Issue.UnmarshalJSON`** (~31%); **`Folder.IssuesForFile`** (~22%); **`memclr`** flat (~18.5%); **`CLIScanner.Scan`** (~17%); **`TreeScanStateEmitter` / `ProcessResults`** (~14%). **No `findMatches` in top cum.** |
| Heap (`heap_after`, pprof `inuse_space`) | Order **~1.34 GiB** total in snapshot; large **`literalStore`**, **`Issue.UnmarshalJSON`**, **`AddQuickFixAction`**, **`IssueIndex.Upsert`**, hover/learn helpers — consistent with **persisted rich `Issue` JSON** + **re-decode on read**. |
| `heap_samples.csv` (`runtime.MemStats`) | **Peak `HeapSys` ~33.6 GiB**, **peak `HeapInuse` ~25.1 GiB** during the run (allocator **arena reservation**); **final** sample **`HeapInuse` ~2.9 GiB**, **`HeapAlloc` ~1.3 GiB** after wind-down. **Do not conflate** pprof **`inuse_space`** (live objects at one snapshot) with **`HeapSys`** peaks (OS-facing arena pressure). |

### Historical comparison (summary)

| Session | Wall | CPU busy | Top story |
|---------|------|----------|-----------|
| 3 | ~26–27 min | ~45% | Delta / fuzzy on huge issue sets |
| 5 (cp8) | ~21.9 min | ~34% | Delta collapsed; JSON + runtime remain |
| 24 | ~20.5 min | ~38% | JSON + **bolt read/unmarshal** + OSS scan + tree/UI |

Wall time improved **Session 3 → 24** by ~**5–6 min**; **Session 5 vs 24** within **~1–2 min** noise (machine, CLI, network).

---

## cp26 — bolt read path: call-pattern analysis (not “lazy fields”)

**Why “lazy JSON fields” are unlikely to help much:** hot paths already materialize **`types.Issue`** (diagnostics, hovers, code actions, tree) from stored snapshots. Skipping unused JSON keys would only win if a large fraction of reads **did not** need the rich body; megaproject profiles show **`Issue.UnmarshalJSON`**, **`IssuesForFile`**, and **OSS UI** on the same objects — the dominant cost is **full value decode + allocation**, not a few optional attributes.

**Actual call pattern (worth optimizing):**

1. **`BoltBackend.Get(path)`** (`infrastructure/issuecache/backend/bolt_backend.go`): each call runs a **bbolt read transaction**, loads **one KV value** (JSON array of issues for that path), and runs **`json.Unmarshal` → `[]*snyk.Issue`**. There is **no in-process decode cache**: every **`IssueCache.IssuesForFile`** / **`IssuesForRange`** / **`Issue(...)`** that hits the backend **re-decodes the entire array** for that file.
2. **`IssueCache.IssuesForFile`** then **`materializeIssues` → `mergeCodeActionsCopy`**: if the side table has code actions for keys, each issue may be **`Clone()`**’d and code-action slices copied — extra allocations **on top of** JSON decode.
3. **`BoltBackend.GetAll`**: cursor over the whole product bucket → **one unmarshal per stored path** — extremely expensive if something calls **`Issues()`** on a megaproject workspace during a scan or refresh.
4. **Fan-in:** **`Folder.IssuesForFile`** aggregates **per product**; a single LSP query can trigger **multiple** `IssuesForFile` / backend reads for the same logical file across products.

**Directions that match this shape (ordered by leverage vs risk):**

- **Reduce decode frequency:** process-level **LRU of decoded `[]types.Issue` by path+generation** (invalidate on `Set`/`ClearIssues` for that path), or ensure high-level callers **batch** file reads instead of N× redundant `IssuesForFile` for the same path in one tick.
- **Shrink wire size / struct cost:** fewer large strings on the persisted `Issue` JSON, or **splitting storage** (index row for LSP deltas vs blob for hover) so **diagnostics-only** paths avoid hydrating **FormattedMessage** / references — this is **schema / storage layout**, not field-laziness inside one JSON object.
- **Instrumentation first:** count **`BoltBackend.Get` / `Set` / `unmarshalIssues` bytes and calls per scan phase** to see whether the hotspot is **repeated reads** vs **one-shot giant unmarshals**.

---

## cp28 — description / extended message / related string work

- **`GetExtendedMessage`** (`infrastructure/oss/types.go`) is already memoized via **`extendedMessageCache`** (`sync.Map`, vuln-scoped key including CVE/CWE lists and format).
- **`AddSnykLearnAction`** (`infrastructure/oss/code_actions.go`): process-global **`learnCodeActionLookupCache`** keys **`(packageManager, vulnId, first CWE, first CVE)`** — aligned with **`learn.Service`** lookup — and stores only **whether a lesson URL exists** plus the URL; the **“Learn more about …”** title is **rebuilt** on each hit from the caller’s current vuln title. **`GetLesson` errors are not cached.** A **negative** result (no lesson / empty URL) is cached until process restart (same trade-off class as other memoization).
- **Open-browser OSS description action:** **`memoOpenBrowserOSSDescriptionTitle`** deduplicates the long title string for repeated **(vuln title, package name)** pairs.
- **Tests** reset these maps via **`resetOSSCodeActionMemoCachesForTest`** so **`go test -count=2`** does not flake on stale `sync.Map` entries.

---

## Operational notes

- **`SMOKE_TESTS`:** do not leak `SMOKE_TESTS=1` into shells when running **`go test ./...`** unless you intend to run smoke tests (they dominate runtime).
- **Profiling reports:** when publishing numbers, pair **pprof `inuse_space`** with **`MemStats` peaks** (`HeapSys` / `HeapInuse`) so readers do not mix **live graph** vs **allocator pressure**.
