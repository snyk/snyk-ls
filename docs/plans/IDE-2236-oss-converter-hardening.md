# IDE-2236 — OSS unified converter: harden `populateMatchingIssues` + fix dormant `SetFindingId` RLock

**Parent epic:** IDE-2052  
**Provenance:** Deferred follow-up from IDE-2207/2208 finding-identity review (PRs #1373/#1374).  
**Scope:** Standalone — not stacked on config-parity (PR #138) or folder-lifecycle (PR #140).

---

## Root causes

### Defect 1 — `populateMatchingIssues` (`infrastructure/oss/unified_converter.go:193–210`)

**(a) nil-deref:** `finding.Attributes` is a nil-able `*testapi.FindingAttributes`. A
finding with nil Attributes makes `finding.Attributes.Evidence` panic. Masked today because
the upstream grouper (`getIntroducingFinding`) returns the first finding regardless of its
attributes, and `processIssue` returns `nil` before reaching `populateMatchingIssues` when
`buildOssIssueData` fails. However, `populateMatchingIssues` iterates `trIssue.GetFindings()`
**directly** with no nil guard.

**(b) zero-value append:** `buildOssIssueData` returns `(snyk.OssIssueData{}, error)` when
`finding.Attributes == nil` (unified_converter.go:483). Without a `continue` after the error
log in `populateMatchingIssues`, a degenerate empty `OssIssueData{}` is appended to
`MatchingIssues`. Defense-in-depth fix; the nil guard (fix a) prevents reaching this path
in practice, but the missing `continue` is a latent bug for any future error path added to
`buildOssIssueData`.

**Fix:**
```go
for _, finding := range trIssue.GetFindings() {
    if finding == nil || finding.Attributes == nil {
        continue
    }
    for _, evidence := range finding.Attributes.Evidence {
        ...
        issueData, err := buildOssIssueData(...)
        if err != nil {
            logger.Warn().Err(err).Msg("failed to build oss issue data")
            continue   // ← fix (b)
        }
        matching = append(matching, issueData)
    }
}
```

### Defect 2 — `SetFindingId` (`domain/snyk/issues.go:253–257`)

`SetFindingId` takes `RLock()/RUnlock()` around a WRITE to `i.FindingId`. `sync.RWMutex`
allows multiple concurrent `RLock` holders, so concurrent `SetFindingId` calls race with
no exclusion. Correct sibling: `SetIgnored` (`:241–245`) uses `Lock()/Unlock()`.

**Fix:** Replace `i.m.RLock()` / `defer i.m.RUnlock()` with `i.m.Lock()` / `defer i.m.Unlock()`.

---

## Tests

| ID | Layer | Name | File | RED before fix |
|----|-------|------|------|---------------|
| T1 | Integration | `TestConvertTestResultToIssues_NilAttributeFinding_NoPanic` | `unified_converter_populate_matching_test.go` | Masked upstream (ecosystem filter) — GREEN even before fix; documents dormant nature |
| T2 | Unit | `TestPopulateMatchingIssues_SkipsFindingWithNilAttributes` | `unified_converter_populate_matching_test.go` | RED — panics at `finding.Attributes.Evidence` |
| T3 | Unit | `TestPopulateMatchingIssues_OmitsDegenerateEntryOnBuildError` | `unified_converter_populate_matching_test.go` | RED — panics before fix (a); after fix (a) only, GREEN trivially (nil guard prevents reaching fix b's path) |
| T4 | Unit (`-race`) | `TestIssue_SetFindingId_NoDataRace` | `domain/snyk/issues_findingid_race_test.go` | RED under `go test -race` — data race reported |

**Note on T1:** `convertTestResultToIssues` calls `testapi.NewIssuesFromTestResult` which
groups findings by issue. The nil-attrs finding is filtered at the `ecosystem()` / primary
problem level inside `processIssue` before `populateMatchingIssues` is reached. T1 documents
this masking. White-box coverage for the nil-deref lives in T2 and T3.

**Note on T3:** The `continue` fix (b) is defense-in-depth. There is currently no code path
that reaches the missing `continue` without first triggering the nil panic (fix a's domain).
T3 verifies the combined behavior and is a regression test for any future `buildOssIssueData`
error path.

---

## Files modified

| File | Change |
|------|--------|
| `infrastructure/oss/unified_converter.go` | +4 lines: nil guard in `populateMatchingIssues` outer loop + `continue` after error log |
| `domain/snyk/issues.go` | +0 net (swap `RLock` → `Lock`, `RUnlock` → `Unlock`) |
| `infrastructure/oss/unified_converter_populate_matching_test.go` | NEW — T1, T2, T3 |
| `domain/snyk/issues_findingid_race_test.go` | NEW — T4 |
| `docs/plans/IDE-2236-oss-converter-hardening.md` | NEW — this file |
