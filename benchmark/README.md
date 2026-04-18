# Benchmarks (IDE-1940)

## Real Snyk scans (required for optimization baseline)

**IDE-1940 optimization decisions must be driven by benchmarks that run the same product paths as production** — real Snyk Code and Open Source (and optionally IaC) scans against the generated monorepo fixture — not by populating `issuecache` with synthetic `types.Issue` values alone.

**Reference:** `application/server/server_smoke_test.go` — especially `runSmokeTest`, `setupServer`, `testutil.SmokeTestWithEngine`, `waitForScan`, workspace initialization, post-scan diagnostics, and **`Test_SmokeRealScanMonorepoFixture`** (opt-in monorepo real scan + optional **`runtime/pprof`**).

**Prerequisites (same as smoke tests, plus opt-in for the monorepo test):**

- `SMOKE_TESTS=1` (see `internal/testsupport/helpers.go` — `SmokeTestEnvVar`)
- `BENCHMARK_REAL_SCAN_MONOREPO=1` to run **`Test_SmokeRealScanMonorepoFixture`** (constant `testsupport.BenchmarkRealScanMonorepoEnvVar`). Default smoke runs skip it.
- Optional: `BENCHMARK_REAL_SCAN_PROFILE_DIR=/path/to/dir` (`testsupport.BenchmarkRealScanMonorepoProfileDirEnvVar`) — writes **`runtime/pprof`** CPU and heap profiles (`real_scan_cpu.pprof`, `real_scan_heap_before.pprof`, `real_scan_heap_after.pprof`) around the **scan phase** for `go tool pprof` / heap diff (IDE-1940).
- Valid `SNYK_TOKEN` (and optional `SNYK_API`; default `https://api.snyk.io` when unset, as in smoke tests)
- Snyk CLI available on `PATH` (binary search paths as configured for smoke tests)

**Status:** Real-scan integration lives in **`application/server/server_smoke_test.go`** as **`Test_SmokeRealScanMonorepoFixture`**. Use **pprof** (and `go tool pprof`) for CPU and memory attribution; use **`./benchmark/...`** `BenchmarkIssue*` / fixture benches for synthetic micro-benchmarks only.

**Verification:** After `git init` / initial commit, the test calls **`benchmark.AssertMonorepoFixtureLayout`** (exact `code_*` / `oss_*` counts and expected leaf files; `.git` at repo root is ignored). When the total number of code + OSS leaf folders is **≤ 100**, the test also waits until **`textDocument/publishDiagnostics`** includes at least one diagnostic path under **each** leaf folder for the matching product (so a fast “root-only” success cannot satisfy the test). Above 100 leaves, only the on-disk layout and existing scan / delta assertions run (per-leaf diagnostics would be slow and may not surface one finding per identical leaf).

### Run real-scan monorepo test (assertions + optional profiles)

```bash
SMOKE_TESTS=1 BENCHMARK_REAL_SCAN_MONOREPO=1 go test ./application/server/... -run Test_SmokeRealScanMonorepoFixture -count=1 -timeout=30m
```

With profiles (example: gitignored `build/`):

```bash
mkdir -p build/real_scan_pprof
SMOKE_TESTS=1 BENCHMARK_REAL_SCAN_MONOREPO=1 BENCHMARK_REAL_SCAN_PROFILE_DIR="$PWD/build/real_scan_pprof" \
  go test ./application/server/... -run Test_SmokeRealScanMonorepoFixture -count=1 -timeout=30m
go tool pprof -http=:0 ./build/real_scan_pprof/real_scan_cpu.pprof
# Heap diff: go tool pprof -http=:0 -base=build/real_scan_pprof/real_scan_heap_before.pprof build/real_scan_pprof/real_scan_heap_after.pprof
```

Or:

```bash
make benchmark-real
```

**Fixture size (default: 2 code + 2 OSS folders; override with env):**

| Variable | Effect |
|----------|--------|
| `BENCHMARK_REALSCAN_FIXTURE_CODE` | Integer > 0 — number of `code_*` folders |
| `BENCHMARK_REALSCAN_FIXTURE_OSS` | Integer > 0 — number of `oss_*` folders |
| `BENCHMARK_REALSCAN_FULL_FIXTURE=1` | Full `benchmark.CodeFolderCount` + `benchmark.OSSFolderCount` (500+500): **long runtime and real API/token cost** |

The `BenchmarkIssue*` benches in this package remain **synthetic** micro-benchmarks — not a substitute for the smoke test above.

## Run

```bash
make benchmark
```

This runs `go test -bench=. -benchmem -benchtime=1s -timeout=30m ./benchmark/...` and writes output to `build/benchmark-results.txt` (the `build/` directory is gitignored).

For a production-sized on-disk fixture during benchmarks, set:

```bash
BENCHMARK_FULL_FIXTURE=1 make benchmark
```

## Fixture layout

`GenerateMonorepoFixture` writes:

- `code_000` … `code_499` — each directory contains `index.js` (template from megaproject).
- `oss_000` … `oss_499` — each directory contains `package.json` and `package-lock.json` (templates from megaproject).

Template sources (read-only on a developer machine when refreshing `benchmark/testdata/`):

- `~/workspace/megaproject/code-index_1/index.js` → `benchmark/testdata/code_template.js`
- `~/workspace/megaproject/nodejs_1/package.json` → `benchmark/testdata/oss_package.json`
- `~/workspace/megaproject/nodejs_1/package-lock.json` → `benchmark/testdata/oss_package-lock.json`

## Tests

- Default `go test ./benchmark/...` runs a small smoke layout test (2+2 folders).
- Full 500+500 layout verification (heavy disk use, ~390 MiB):

  ```bash
  FULL_FIXTURE_VERIFY=1 go test -timeout=30m ./benchmark/...
  ```

## Scenarios (current code)

| Benchmark | Purpose |
|-----------|---------|
| `BenchmarkGenerateMonorepoFixture` | Time + allocs to materialize the fixture (default scale 20+20; use `BENCHMARK_FULL_FIXTURE=1` for 500+500). |
| `BenchmarkMonorepoWalk` | `filepath.WalkDir` over the generated tree (disk I/O only). |
| `BenchmarkIssueCache*` | **Synthetic** issue-cache micro-benchmarks — **not** real Snyk scans; see top of this README. |
| `BenchmarkCp11r_*` | **IDE-1940 cp11r perf-regression gate.** Scale-parameterised (`N=1_000 / 10_000 / 80_000`) IssueCache benches covering `AddToCache`, `IssuesForFile`, `Issue(key)`, `Issues()`, `Clear`, `ClearIssuesByPath`, plus the `IssueByActionUUID` path and two contention mixes (`ParallelDidOpen`, `IngestWhileReading`). |
| `BenchmarkIssueIndex_*` | **IDE-1940 cp11r index gate** (lives in `infrastructure/issuecache/`). Covers `UpsertFromIssue`, `EntryByKey`, `KeyForActionUUID`, `KeysForPath`, `RemoveByPath`, plus `ConcurrentReadHeavy` and `MixedWriteReadContention`. |
| `BenchmarkProgressChannelCapacity` | Channel slot allocation only. |

## cp11r regression gate

`make benchmark-cp11r` runs the cp11r-scoped gate with `-count=5 -benchtime=2s` so the output is `benchstat`-friendly:

```bash
# baseline before your change
git stash; make benchmark-cp11r; mv build/benchmark-cp11r.txt build/cp11r-baseline.txt; git stash pop

# current after your change
make benchmark-cp11r; mv build/benchmark-cp11r.txt build/cp11r-current.txt

# diff
benchstat build/cp11r-baseline.txt build/cp11r-current.txt
```

What to watch for when reading the numbers:

- `BenchmarkIssueIndex_EntryByKey` / `BenchmarkIssueIndex_KeyForActionUUID` must stay **flat across N** (O(1) map hit, 0 allocs). A slope means the lookup stopped being O(1).
- `BenchmarkCp11r_IssueCache_IssuesForFile` must stay **flat across N** (~50 ns, 0 allocs).
- `BenchmarkCp11r_IssueCache_IssueByKey` today scales with N (cp11r.3+ replaces the `GetAll()` walk with an index hit); once that lands the curve should flatten.
- `BenchmarkCp11r_IssueCache_AddToCache` and `_Clear` are expected to be O(N) (they touch every issue); their ns/issue metric is the comparable number.
- `BenchmarkCp11r_IssueCache_ParallelDidOpen` / `BenchmarkIssueIndex_ConcurrentReadHeavy` guard against the `IssueIndex` RWMutex turning into a contention point for IDE hot paths.

