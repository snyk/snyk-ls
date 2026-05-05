# Performance Measurement And Analysis Guide

This guide explains how to run performance measurements with the test suite and how to analyze the resulting profiles. It is written for the IDE-1940 megaproject workflow, where performance decisions must be based on the same real Snyk Code and Open Source paths used by production.

Use this together with:

- `benchmark/README.md` for fixture details and benchmark commands.
- `docs/megaproject-real-scan-profiling-history.md` for historical measurement results.

## What To Measure

The primary performance gate is:

```text
Test_SmokeRealScanMonorepoFixture
```

The test lives in `application/server/server_smoke_test.go` and exercises a real language server scan against a generated monorepo fixture.

For a full megaproject measurement, always use the full fixture scale:

```bash
SMOKE_TESTS=1
BENCHMARK_REAL_SCAN_MONOREPO=1
BENCHMARK_REALSCAN_FULL_FIXTURE=1
```

`BENCHMARK_REALSCAN_FULL_FIXTURE=1` is important. Without it, the test uses a smaller default fixture and is not comparable to the megaproject profiling history.

## Prerequisites

- Valid Snyk credentials in the local environment.
- Snyk CLI available on `PATH`.
- Network access to the configured Snyk API.
- Enough local disk space for the generated fixture and profiles under `build/`.
- Enough time for the full run. A full 500 Code + 500 OSS run can take 15-30 minutes depending on machine, network, CLI, and API behavior.
- Do not run in CI mode. Explicitly unset `CI`.

For normal unit work, explicitly unset smoke and benchmark variables. For this guide, set them only for the measurement command.

## Quick Full Measurement

Run this from the repository root:

```bash
unset CI
export SMOKE_TESTS=1
export BENCHMARK_REAL_SCAN_MONOREPO=1
export BENCHMARK_REALSCAN_FULL_FIXTURE=1
export BENCHMARK_REAL_SCAN_PROFILE_DIR="$PWD/build/real_scan_pprof_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$BENCHMARK_REAL_SCAN_PROFILE_DIR"

go test -timeout=180m -count=1 \
  -run '^Test_SmokeRealScanMonorepoFixture$' ./application/server -v \
  2>&1 | tee "$BENCHMARK_REAL_SCAN_PROFILE_DIR/test.log"
```

Expected artifacts:

```text
build/real_scan_pprof_<timestamp>/
  test.log
  real_scan_cpu.pprof
  real_scan_heap_before.pprof
  real_scan_heap_after.pprof
  heap_samples.csv
```

`heap_samples.csv` contains periodic `runtime.MemStats` samples. The heap pprof files contain live heap snapshots around the scan phase.

## What The Artifacts Mean

Use both pprof and `heap_samples.csv`; they answer different questions.

| Artifact | Use it for | Do not use it for |
| --- | --- | --- |
| `real_scan_cpu.pprof` | CPU hotspots during the profiled scan phase | Wall-clock time by itself |
| `real_scan_heap_before.pprof` | Heap baseline before the scan phase | Peak RSS |
| `real_scan_heap_after.pprof` | Live heap after the scan phase | Peak arena pressure |
| `heap_samples.csv` | Peak `HeapSys`, `HeapInuse`, `HeapAlloc` during the whole profiled interval | Allocation call stacks |
| `test.log` | Wall time, issue counts, fixture scale confirmation, test failures | Allocation attribution |

Important distinction:

- pprof `inuse_space` shows live objects at the time the heap profile was written.
- `runtime.MemStats.HeapSys` shows Go heap arena reservation from the OS.
- `runtime.MemStats.HeapInuse` and `HeapAlloc` are better peak-live indicators during the run.

Always report pprof heap and `heap_samples.csv` peaks separately.

## Basic Manual Analysis

Set the profile directory first:

```bash
PROFILE_DIR=build/real_scan_pprof_20260504_160000
```

CPU top cumulative:

```bash
go tool pprof -top -cum "$PROFILE_DIR/real_scan_cpu.pprof" | tee "$PROFILE_DIR/cpu_top_cum.txt"
```

CPU top flat:

```bash
go tool pprof -top "$PROFILE_DIR/real_scan_cpu.pprof" | tee "$PROFILE_DIR/cpu_top_flat.txt"
```

Heap after top cumulative:

```bash
go tool pprof -top -cum "$PROFILE_DIR/real_scan_heap_after.pprof" | tee "$PROFILE_DIR/heap_after_top_cum.txt"
```

Heap after top flat:

```bash
go tool pprof -top "$PROFILE_DIR/real_scan_heap_after.pprof" | tee "$PROFILE_DIR/heap_after_top_flat.txt"
```

Heap growth from before to after:

```bash
go tool pprof -top -cum \
  -base "$PROFILE_DIR/real_scan_heap_before.pprof" \
  "$PROFILE_DIR/real_scan_heap_after.pprof" \
  | tee "$PROFILE_DIR/heap_delta_top_cum.txt"
```

Interactive CPU browser:

```bash
go tool pprof -http=:0 "$PROFILE_DIR/real_scan_cpu.pprof"
```

Interactive heap-delta browser:

```bash
go tool pprof -http=:0 \
  -base "$PROFILE_DIR/real_scan_heap_before.pprof" \
  "$PROFILE_DIR/real_scan_heap_after.pprof"
```

## Report Template

Use this shape when publishing results:

```markdown
## Megaproject Measurement

- Command:
- Commit:
- Fixture: 500 code + 500 OSS (`BENCHMARK_REALSCAN_FULL_FIXTURE=1`)
- Result:
- Wall time:
- Code issues:
- OSS issues:
- Profile directory:

| Metric | Value |
| --- | ---: |
| Peak HeapSys | |
| Peak HeapInuse | |
| Peak HeapAlloc | |
| Final HeapSys | |
| Final HeapInuse | |
| Final HeapAlloc | |
| Heap after inuse_space | |
| Total CPU samples | |

### CPU Summary

### Heap Summary

### Interpretation

### Follow-up
```

## Script: Run Full Measurement

Save this as `build/run-megaproject-profile.sh` or run it through a here-doc. It creates a timestamped profile directory and runs the full fixture with the required environment.

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d .git ]]; then
  echo "run this from the repository root" >&2
  exit 1
fi

unset CI

stamp="$(date +%Y%m%d_%H%M%S)"
profile_dir="${1:-$PWD/build/real_scan_pprof_$stamp}"

mkdir -p "$profile_dir"

export SMOKE_TESTS=1
export BENCHMARK_REAL_SCAN_MONOREPO=1
export BENCHMARK_REALSCAN_FULL_FIXTURE=1
export BENCHMARK_REAL_SCAN_PROFILE_DIR="$profile_dir"

echo "profile_dir=$profile_dir"
echo "commit=$(git rev-parse --short HEAD)" | tee "$profile_dir/metadata.txt"
echo "branch=$(git branch --show-current)" | tee -a "$profile_dir/metadata.txt"
echo "started_at=$(date -Is)" | tee -a "$profile_dir/metadata.txt"

go test -timeout=180m -count=1 \
  -run '^Test_SmokeRealScanMonorepoFixture$' ./application/server -v \
  2>&1 | tee "$profile_dir/test.log"

echo "finished_at=$(date -Is)" | tee -a "$profile_dir/metadata.txt"
echo "artifacts written to $profile_dir"
```

Example:

```bash
bash build/run-megaproject-profile.sh build/real_scan_pprof_candidate
```

## Script: Analyze Profiles

Save this as `build/analyze-megaproject-profile.sh`. It extracts pprof text reports, heap peak summaries, common focus views, and a markdown summary.

```bash
#!/usr/bin/env bash
set -euo pipefail

profile_dir="${1:?usage: $0 PROFILE_DIR}"

cpu="$profile_dir/real_scan_cpu.pprof"
heap_before="$profile_dir/real_scan_heap_before.pprof"
heap_after="$profile_dir/real_scan_heap_after.pprof"
heap_samples="$profile_dir/heap_samples.csv"
log_file="$profile_dir/test.log"

for file in "$cpu" "$heap_before" "$heap_after" "$heap_samples"; do
  if [[ ! -f "$file" ]]; then
    echo "missing artifact: $file" >&2
    exit 1
  fi
done

go tool pprof -top -cum "$cpu" > "$profile_dir/cpu_top_cum.txt"
go tool pprof -top "$cpu" > "$profile_dir/cpu_top_flat.txt"
go tool pprof -top -cum "$heap_after" > "$profile_dir/heap_after_top_cum.txt"
go tool pprof -top "$heap_after" > "$profile_dir/heap_after_top_flat.txt"
go tool pprof -top -cum -base "$heap_before" "$heap_after" > "$profile_dir/heap_delta_top_cum.txt"
go tool pprof -top -base "$heap_before" "$heap_after" > "$profile_dir/heap_delta_top_flat.txt"

go tool pprof -top -cum -focus 'encoding/json|Issue.UnmarshalJSON|unmarshalIssues' "$cpu" > "$profile_dir/cpu_focus_json.txt" || true
go tool pprof -top -cum -focus 'IssueCache|BoltBackend|IssuesForFile|IssuesByCachedPath|Folder.Issues' "$cpu" > "$profile_dir/cpu_focus_issuecache.txt" || true
go tool pprof -top -cum -focus 'jrpc2|publishDiagnostics|TreeScanStateEmitter|TreeHtmlRenderer' "$cpu" > "$profile_dir/cpu_focus_lsp_tree.txt" || true

go tool pprof -top -cum -focus 'encoding/json|Issue.UnmarshalJSON|unmarshalIssues' "$heap_after" > "$profile_dir/heap_focus_json.txt" || true
go tool pprof -top -cum -focus 'IssueCache|BoltBackend|IssuesForFile|IssuesByCachedPath|Folder.Issues' "$heap_after" > "$profile_dir/heap_focus_issuecache.txt" || true
go tool pprof -top -cum -focus 'jrpc2|publishDiagnostics|TreeScanStateEmitter|TreeHtmlRenderer|GitPersistenceProvider|persist' "$heap_after" > "$profile_dir/heap_focus_lsp_tree_persist.txt" || true

awk -F, '
  NR == 1 { next }
  {
    hs=$2+0; hi=$3+0; ha=$4+0
    if (hs > max_hs) max_hs=hs
    if (hi > max_hi) max_hi=hi
    if (ha > max_ha) max_ha=ha
    last_hs=hs; last_hi=hi; last_ha=ha
  }
  END {
    printf "peak_heap_sys_mb %.2f\n", max_hs/1024/1024
    printf "peak_heap_inuse_mb %.2f\n", max_hi/1024/1024
    printf "peak_heap_alloc_mb %.2f\n", max_ha/1024/1024
    printf "final_heap_sys_mb %.2f\n", last_hs/1024/1024
    printf "final_heap_inuse_mb %.2f\n", last_hi/1024/1024
    printf "final_heap_alloc_mb %.2f\n", last_ha/1024/1024
  }
' "$heap_samples" > "$profile_dir/heap_samples_summary.txt"

wall_result="$(rg -o 'PASS: .*|PASS$|FAIL: .*|FAIL$|ok\\s+github.com/snyk/snyk-ls/application/server\\s+[^ ]+' "$log_file" 2>/dev/null | tail -n 5 || true)"
code_issues="$(rg -o 'Code scan reported [0-9,]+ issues|Code scan.*[0-9,]+ issues' "$log_file" 2>/dev/null | tail -n 1 || true)"
oss_issues="$(rg -o 'OSS scan reported [0-9,]+ issues|Open Source scan reported [0-9,]+ issues|OSS scan.*[0-9,]+ issues' "$log_file" 2>/dev/null | tail -n 1 || true)"
fixture_line="$(rg 'code\\+oss leaves|BENCHMARK_REALSCAN_FULL_FIXTURE|full fixture|500' "$log_file" 2>/dev/null | head -n 5 || true)"

{
  echo "# Megaproject Profile Summary"
  echo
  echo "- Profile directory: \`$profile_dir\`"
  echo "- Commit: \`$(git rev-parse --short HEAD 2>/dev/null || echo unknown)\`"
  echo "- Branch: \`$(git branch --show-current 2>/dev/null || echo unknown)\`"
  echo
  echo "## Test Result"
  echo
  echo '```text'
  echo "$wall_result"
  echo "$fixture_line"
  echo "$code_issues"
  echo "$oss_issues"
  echo '```'
  echo
  echo "## Heap Samples"
  echo
  echo '```text'
  cat "$profile_dir/heap_samples_summary.txt"
  echo '```'
  echo
  echo "## CPU Top Cumulative"
  echo
  echo '```text'
  sed -n '1,40p' "$profile_dir/cpu_top_cum.txt"
  echo '```'
  echo
  echo "## Heap After Top Cumulative"
  echo
  echo '```text'
  sed -n '1,40p' "$profile_dir/heap_after_top_cum.txt"
  echo '```'
  echo
  echo "## Heap Delta Top Cumulative"
  echo
  echo '```text'
  sed -n '1,40p' "$profile_dir/heap_delta_top_cum.txt"
  echo '```'
} > "$profile_dir/summary.md"

echo "analysis written to $profile_dir"
echo "open $profile_dir/summary.md first"
```

Example:

```bash
bash build/analyze-megaproject-profile.sh build/real_scan_pprof_candidate
```

## Script: Visualize Heap Samples

Save this as `build/visualize-heap-samples.py`. It reads `heap_samples.csv` and writes a standalone SVG line chart plus a small HTML wrapper.

```python
#!/usr/bin/env python3
import csv
import html
import pathlib
import sys

if len(sys.argv) != 2:
    print("usage: visualize-heap-samples.py PROFILE_DIR", file=sys.stderr)
    sys.exit(1)

profile_dir = pathlib.Path(sys.argv[1])
csv_path = profile_dir / "heap_samples.csv"
svg_path = profile_dir / "heap_samples.svg"
html_path = profile_dir / "heap_samples.html"

rows = []
with csv_path.open(newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        unix_ns = int(row["unix_ns"])
        rows.append(
            {
                "t": unix_ns,
                "heap_sys": int(row["heap_sys_bytes"]) / 1024 / 1024,
                "heap_inuse": int(row["heap_inuse_bytes"]) / 1024 / 1024,
                "heap_alloc": int(row["heap_alloc_bytes"]) / 1024 / 1024,
            }
        )

if not rows:
    raise SystemExit(f"no samples in {csv_path}")

t0 = rows[0]["t"]
for row in rows:
    row["seconds"] = (row["t"] - t0) / 1_000_000_000

width = 1200
height = 620
left = 80
right = 30
top = 40
bottom = 70
plot_w = width - left - right
plot_h = height - top - bottom

max_x = max(row["seconds"] for row in rows) or 1
max_y = max(max(row["heap_sys"], row["heap_inuse"], row["heap_alloc"]) for row in rows) or 1
max_y *= 1.05

def x(value):
    return left + (value / max_x) * plot_w

def y(value):
    return top + plot_h - (value / max_y) * plot_h

def points(key):
    return " ".join(f"{x(row['seconds']):.2f},{y(row[key]):.2f}" for row in rows)

series = [
    ("HeapSys", "heap_sys", "#7c3aed"),
    ("HeapInuse", "heap_inuse", "#2563eb"),
    ("HeapAlloc", "heap_alloc", "#16a34a"),
]

grid = []
for i in range(0, 6):
    value = max_y * i / 5
    yy = y(value)
    grid.append(f'<line x1="{left}" y1="{yy:.2f}" x2="{width-right}" y2="{yy:.2f}" stroke="#e5e7eb"/>')
    grid.append(f'<text x="{left-10}" y="{yy+4:.2f}" text-anchor="end" font-size="12">{value:.0f} MB</text>')

for i in range(0, 6):
    value = max_x * i / 5
    xx = x(value)
    grid.append(f'<line x1="{xx:.2f}" y1="{top}" x2="{xx:.2f}" y2="{height-bottom}" stroke="#f3f4f6"/>')
    grid.append(f'<text x="{xx:.2f}" y="{height-bottom+24}" text-anchor="middle" font-size="12">{value/60:.1f} min</text>')

polylines = []
legend = []
for idx, (label, key, color) in enumerate(series):
    polylines.append(
        f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{points(key)}"/>'
    )
    lx = left + idx * 170
    ly = height - 20
    legend.append(f'<rect x="{lx}" y="{ly-12}" width="14" height="14" fill="{color}"/>')
    legend.append(f'<text x="{lx+22}" y="{ly}" font-size="14">{label}</text>')

title = html.escape(str(profile_dir))
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="white"/>
  <text x="{left}" y="24" font-size="18" font-weight="700">Heap samples: {title}</text>
  {''.join(grid)}
  <line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" stroke="#111827"/>
  <line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" stroke="#111827"/>
  {''.join(polylines)}
  {''.join(legend)}
</svg>
'''

svg_path.write_text(svg)
html_path.write_text(
    f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Heap samples</title>
  <style>body {{ font-family: system-ui, sans-serif; margin: 24px; }}</style>
</head>
<body>
  <h1>Heap samples</h1>
  <p>{html.escape(str(profile_dir))}</p>
  {svg}
</body>
</html>
"""
)

print(f"wrote {svg_path}")
print(f"wrote {html_path}")
```

Example:

```bash
python3 build/visualize-heap-samples.py build/real_scan_pprof_candidate
open build/real_scan_pprof_candidate/heap_samples.html
```

## Script: Compare Two Measurements

Save this as `build/compare-megaproject-profiles.py`. It compares two profile directories using `heap_samples.csv` and whatever pprof summaries have already been generated by `analyze-megaproject-profile.sh`.

```python
#!/usr/bin/env python3
import csv
import pathlib
import re
import subprocess
import sys

if len(sys.argv) != 3:
    print("usage: compare-megaproject-profiles.py BASELINE_DIR CANDIDATE_DIR", file=sys.stderr)
    sys.exit(1)

baseline = pathlib.Path(sys.argv[1])
candidate = pathlib.Path(sys.argv[2])

def heap_metrics(profile_dir):
    rows = []
    with (profile_dir / "heap_samples.csv").open(newline="") as f:
        for row in csv.DictReader(f):
            rows.append({k: int(v) for k, v in row.items()})
    if not rows:
        raise RuntimeError(f"no heap samples in {profile_dir}")
    return {
        "peak_heap_sys_mb": max(r["heap_sys_bytes"] for r in rows) / 1024 / 1024,
        "peak_heap_inuse_mb": max(r["heap_inuse_bytes"] for r in rows) / 1024 / 1024,
        "peak_heap_alloc_mb": max(r["heap_alloc_bytes"] for r in rows) / 1024 / 1024,
        "final_heap_sys_mb": rows[-1]["heap_sys_bytes"] / 1024 / 1024,
        "final_heap_inuse_mb": rows[-1]["heap_inuse_bytes"] / 1024 / 1024,
        "final_heap_alloc_mb": rows[-1]["heap_alloc_bytes"] / 1024 / 1024,
    }

def pprof_total(profile_path, base_path=None):
    cmd = ["go", "tool", "pprof", "-top"]
    if base_path:
        cmd.extend(["-base", str(base_path)])
    cmd.append(str(profile_path))
    output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    # Example: Showing nodes accounting for 1.23GB, 80.00% of 1.54GB total
    match = re.search(r"of\\s+([0-9.]+)([a-zA-Z]+)\\s+total", output)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2)
    factors = {
        "B": 1 / 1024 / 1024,
        "kB": 1 / 1024,
        "KB": 1 / 1024,
        "MB": 1,
        "GB": 1024,
        "KiB": 1 / 1024,
        "MiB": 1,
        "GiB": 1024,
        "s": 1,
        "ms": 0.001,
    }
    return value * factors.get(unit, 1)

base_metrics = heap_metrics(baseline)
candidate_metrics = heap_metrics(candidate)

rows = []
for key in base_metrics:
    b = base_metrics[key]
    c = candidate_metrics[key]
    delta = c - b
    pct = (delta / b * 100) if b else 0
    rows.append((key, b, c, delta, pct))

base_heap_after = pprof_total(baseline / "real_scan_heap_after.pprof")
candidate_heap_after = pprof_total(candidate / "real_scan_heap_after.pprof")
if base_heap_after is not None and candidate_heap_after is not None:
    b = base_heap_after
    c = candidate_heap_after
    rows.append(("heap_after_inuse_space_mb", b, c, c - b, ((c - b) / b * 100) if b else 0))

base_heap_delta = pprof_total(
    baseline / "real_scan_heap_after.pprof",
    baseline / "real_scan_heap_before.pprof",
)
candidate_heap_delta = pprof_total(
    candidate / "real_scan_heap_after.pprof",
    candidate / "real_scan_heap_before.pprof",
)
if base_heap_delta is not None and candidate_heap_delta is not None:
    b = base_heap_delta
    c = candidate_heap_delta
    rows.append(("heap_delta_inuse_space_mb", b, c, c - b, ((c - b) / b * 100) if b else 0))

print("| Metric | Baseline | Candidate | Delta | Delta % |")
print("| --- | ---: | ---: | ---: | ---: |")
for key, b, c, delta, pct in rows:
    print(f"| `{key}` | {b:,.2f} | {c:,.2f} | {delta:,.2f} | {pct:,.1f}% |")
```

Example:

```bash
python3 build/compare-megaproject-profiles.py \
  build/real_scan_pprof_baseline \
  build/real_scan_pprof_candidate \
  | tee build/profile-comparison.md
```

## Analysis Checklist

When reviewing a candidate optimization, answer these questions before calling it a win:

- Did the run use `BENCHMARK_REALSCAN_FULL_FIXTURE=1`?
- Did the log confirm the expected 500 Code + 500 OSS layout?
- Did the test pass?
- Did Code and OSS issue counts look comparable to the baseline?
- Did wall time improve enough to be outside likely network/API noise?
- Did peak `HeapSys`, `HeapInuse`, and `HeapAlloc` improve?
- Did `heap_after` pprof improve, regress, or stay flat?
- Did total allocation move, or did only live heap move?
- Did CPU move to a new hotspot, or just flatten an existing one?
- Did a test-only artifact dominate the profile, such as recorder retention?
- Is the change still valid under normal unit/integration/smoke tests?

## Common Focus Patterns

JSON decode and issue rehydration:

```bash
go tool pprof -top -cum \
  -focus 'encoding/json|Issue.UnmarshalJSON|unmarshalIssues' \
  "$PROFILE_DIR/real_scan_cpu.pprof"
```

Issue cache reads:

```bash
go tool pprof -top -cum \
  -focus 'IssueCache|BoltBackend|IssuesForFile|IssuesByCachedPath|Folder.Issues' \
  "$PROFILE_DIR/real_scan_heap_after.pprof"
```

Tree, LSP, and publish diagnostics:

```bash
go tool pprof -top -cum \
  -focus 'jrpc2|publishDiagnostics|TreeScanStateEmitter|TreeHtmlRenderer' \
  "$PROFILE_DIR/real_scan_cpu.pprof"
```

Persistence:

```bash
go tool pprof -top -cum \
  -focus 'GitPersistenceProvider|persistToDisk|persistScanResults|json.Marshal' \
  "$PROFILE_DIR/real_scan_heap_after.pprof"
```

CLI execution and stdout buffering:

```bash
go tool pprof -top -cum \
  -focus 'os/exec|SnykCli|ExecuteStreaming|legacyScan|bytes.growSlice' \
  "$PROFILE_DIR/real_scan_heap_after.pprof"
```

Shared OSS and IaC description text:

```bash
env -u CI -u SMOKE_TESTS -u BENCHMARK_REAL_SCAN_MONOREPO \
  -u BENCHMARK_REAL_SCAN_PROFILE_DIR -u BENCHMARK_REALSCAN_FULL_FIXTURE \
  -u BENCHMARK_REALSCAN_FIXTURE_CODE -u BENCHMARK_REALSCAN_FIXTURE_OSS \
  go test -count=1 ./infrastructure/issuecache \
    -run 'TestIssueCache_SharedText' -v
```

This focused gate verifies that repeated OSS and IaC description payload strings are interned by `IssueCache`, hydrated on read, and pruned after the final referencing issue is cleared. Pair it with the OSS/IaC/converter regression package set before taking a megaproject profile:

```bash
env -u CI -u SMOKE_TESTS -u BENCHMARK_REAL_SCAN_MONOREPO \
  -u BENCHMARK_REAL_SCAN_PROFILE_DIR -u BENCHMARK_REALSCAN_FULL_FIXTURE \
  -u BENCHMARK_REALSCAN_FIXTURE_CODE -u BENCHMARK_REALSCAN_FIXTURE_OSS \
  go test -count=1 ./infrastructure/oss ./infrastructure/iac ./domain/ide/converter -v
```

For concurrent read safety, run the focused race canary:

```bash
env -u CI -u SMOKE_TESTS -u BENCHMARK_REAL_SCAN_MONOREPO \
  -u BENCHMARK_REAL_SCAN_PROFILE_DIR -u BENCHMARK_REALSCAN_FULL_FIXTURE \
  -u BENCHMARK_REALSCAN_FIXTURE_CODE -u BENCHMARK_REALSCAN_FIXTURE_OSS \
  go test -race -count=1 ./infrastructure/issuecache \
    -run 'TestIssueCache_SharedTextConcurrentMemoryReadsDoNotMutateInternedOssIssue' -v
```

## Interpreting Regressions

A candidate can be a mixed result. For example:

- Peak `HeapSys` and `HeapInuse` improve, but `heap_after` regresses.
- CPU samples drop, but wall time stays flat because network or CLI time dominates.
- Total alloc-space drops, but live heap does not move because retained objects are unchanged.
- pprof improves, but `HeapSys` stays high because Go keeps arenas reserved.

Do not hide mixed results. Report the trade-off and decide whether the change helps the actual target.

## Cleanup

Profiles and generated scripts should stay under `build/`, which is gitignored:

```bash
rm -rf build/real_scan_pprof_candidate
rm -f build/run-megaproject-profile.sh
rm -f build/analyze-megaproject-profile.sh
rm -f build/visualize-heap-samples.py
rm -f build/compare-megaproject-profiles.py
```
