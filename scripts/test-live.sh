#!/usr/bin/env bash
# Local dev helper: run `go test` and print each failure the moment it happens,
# instead of waiting for the package to finish. `go test` buffers a package's
# output until it exits, so a 40-minute run shows nothing until it is over —
# by which point a fixable failure has been sitting there unfixed for 40 minutes.
#
#   scripts/test-live.sh ./application/server/ -race
#   scripts/test-live.sh ./... -failfast
#
# The complete -json stream is always written to $TEST_LIVE_LOG (default
# $TMPDIR/test-live.json) so the run stays write-once, grep-many. While it runs:
#   grep '"Action":"run"' "$TEST_LIVE_LOG" | tail -1     # what is running now
set -uo pipefail

log="${TEST_LIVE_LOG:-${TMPDIR:-/tmp}/test-live.json}"
echo "raw stream: $log" >&2

go test -json "$@" | tee "$log" | python3 -u -c '
import json, sys
from collections import defaultdict

output = defaultdict(list)
failed = passed = 0

for line in sys.stdin:
    try:
        event = json.loads(line)
    except ValueError:
        sys.stdout.write(line)  # build errors are not JSON
        continue
    action, test, pkg = event.get("Action"), event.get("Test"), event.get("Package", "")
    key = (pkg, test)
    if action == "output" and test:
        output[key].append(event.get("Output", ""))
    elif action == "fail" and test:
        failed += 1
        print("\n=== FAIL %s %s" % (pkg, test), flush=True)
        print("".join(output.pop(key, [])), end="", flush=True)
    elif action in ("pass", "skip") and test:
        passed += action == "pass"
        output.pop(key, None)
    elif action == "fail" and not test:
        print("=== package FAILED: %s" % pkg, flush=True)

print("\n%d passed, %d failed" % (passed, failed), flush=True)
sys.exit(1 if failed else 0)
'
exit "${PIPESTATUS[2]}"
