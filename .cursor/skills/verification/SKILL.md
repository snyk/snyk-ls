---
name: verification
description: Deep verification of code changes before committing. Traces code paths, detects semantic changes, identifies code smells and security issues. Reads GitHub PR reviews to propose implementation decisions. Use before commits, after implementation, or when asked to verify/review changes.
---

# Code Verification

Verify generated code in depth before committing. This skill complements the pre-commit checklist by adding semantic analysis.

## When to Use

- Before committing implementation changes
- After completing implementation steps
- When PR review feedback needs to be addressed
- When explicitly asked to verify code
- When starting a new session of an implementation plan

## Verification Workflow

Copy this checklist and track progress:

```
Verification Progress:
- [ ] Step 1: Load project rules and standards
- [ ] Step 2: Trace code paths for modified files
- [ ] Step 3: Check for semantic changes
- [ ] Step 4: Identify code smells
- [ ] Step 5: Run security scans
- [ ] Step 6: Review PR feedback (if PR exists) including the pr-review-bot comments
- [ ] Step 7: Get check results from github with gh cli
- [ ] Step 8: Update implementation plan with findings
- [ ] Step 9: Fix issues (TDD REQUIRED - test first, then fix)
- [ ] Step 10: Check coverage of changed files > 80%
- [ ] Step 11: Add tests if coverage not sufficient
- [ ] Step 12: Commit changes (use commit skill for details)
- [ ] Step 13: Push changes to remote repository
- [ ] Step 14: run verification skill again
```

---

## Step 1: Load Project Rules

Read and apply these project standards:

1. `.cursor/rules/general.mdc` - critical rules and workflow
2. `.github/CONTRIBUTING.md` - coding standards

Key rules to verify against:

- Outside-in TDD followed
- Minimum necessary changes
- No workarounds or commented-out code
- gomock used for mocking (no custom mocks)
- Generated types used for mock responses

---

## Step 2: Trace Code Paths

For each modified file, trace the execution flow:

1. **Identify entry points**: API handlers, public functions, exported methods
2. **Follow the call chain**: Map function calls through the codebase
3. **Verify dependencies**: Check that all called functions exist and have correct signatures
4. **Check return paths**: Ensure all code paths return appropriate values/errors

### Verification Questions

- Does the new code integrate correctly with existing callers?
- Are all error cases handled?
- Do interface implementations satisfy their contracts?
- Are there unreachable code paths?

---

## Step 3: Check for Semantic Changes

Detect unintended behavioral changes:

### Breaking Changes

- Modified function signatures
- Changed return types or error conditions
- Altered struct field types or tags
- Modified interface definitions

### Behavioral Changes

- Different error messages (may break client parsing)
- Changed response structure
- Modified validation logic
- Altered default values

### Database/API Impact

- Schema changes requiring migrations
- API contract changes requiring versioning
- Query behavior changes

**Action**: Flag any semantic changes and ask if they are intentional.

---

## Step 4: Identify Code Smells

Check for these patterns:

### Structural Smells

- [ ] Functions longer than 50 lines
- [ ] Deeply nested conditionals (>3 levels)
- [ ] Duplicate code blocks
- [ ] God objects/functions doing too much
- [ ] Long parameter lists (>5 params)

### Go-Specific Smells

- [ ] Naked returns in functions with named return values
- [ ] Ignored errors (especially from deferred calls)
- [ ] Context not propagated correctly
- [ ] Goroutine leaks (unbounded spawning, no cleanup)
- [ ] Race conditions (shared state without synchronization)
- [ ] Use testing.T for context, tempDir and helpers

### Design Smells

- [ ] Circular dependencies between packages
- [ ] Leaky abstractions (implementation details exposed)
- [ ] Inappropriate intimacy (packages knowing too much about each other)
- [ ] Feature envy (functions using other package's data excessively)

### Copy-Paste Code (Refactoring Candidates)

Identify duplicated code that should be extracted:

- [ ] Similar code blocks across multiple files (extract to shared function)
- [ ] Repeated struct transformations (extract to mapper/converter)
- [ ] Duplicated validation logic (extract to validator)
- [ ] Repeated error handling patterns (extract to helper)
- [ ] Similar test setup code (extract to test helpers)
- [ ] Copy-pasted handler logic (extract to shared middleware or base handler)

**Detection approach**:

1. Search for similar function names across packages
2. Look for identical error messages or log statements
3. Check for repeated struct field assignments
4. Compare new code against existing patterns in the codebase

**Action**: For duplicated code, propose extraction with:

- Suggested function/package location
- Shared interface if applicable
- Impact on existing callers

**Action**: For each smell found, propose a specific fix or flag for discussion.

---

## Step 5: Run Security Scans

Execute security checks using Snyk:

```bash
# Get absolute path
pwd
```

Then run:

1. `snyk_sca_scan` - dependency vulnerabilities
2. `snyk_code_scan` - code security issues

### Manual Security Checklist

- [ ] No hardcoded secrets, tokens, or credentials
- [ ] Input validation on all external data
- [ ] SQL queries use parameterized statements
- [ ] No path traversal vulnerabilities
- [ ] Proper authentication/authorization checks
- [ ] Sensitive data not logged
- [ ] HTTPS/TLS used for external calls

**Action**: Fix security issues using the `implementation` skill. If in test data, note but don't fix.

---

## Step 6: Review PR Feedback

If a GitHub PR exists for the current branch:

### Fetch PR Information

```bash
# Check if PR exists
gh pr view --json number,reviews,comments,url 2>/dev/null
```

### Process Feedback

For each review comment:

1. **Categorize**: Bug | Enhancement | Style | Question | Blocker
2. **Assess**: Is this actionable? Does it require a decision?
3. **Prioritize**: Critical (must fix) | Should fix | Nice to have

### Create Decision Proposals

For feedback requiring decisions, add to implementation plan:

```markdown
## PR Feedback Decisions Required

### [Comment summary]

- **Reviewer**: @username
- **Category**: [Bug/Enhancement/etc]
- **Context**: [Quote relevant comment]
- **Options**:
  1. [Option A with pros/cons]
  2. [Option B with pros/cons]
- **Recommendation**: [Your recommendation]
- **Decision**: [ ] Pending
```

---

## Step 7: Update Implementation Plan

Add verification findings to the implementation plan:

```markdown
## Verification Results

### Code Path Analysis

- [List traced paths and any issues found]

### Semantic Changes

- [List any behavioral changes detected]

### Code Smells

- [List smells found with proposed fixes]

### Refactoring Candidates

- [List duplicated code with extraction proposals]

### Security Findings

- [List security issues and resolutions]

### PR Feedback Items

- [List items requiring decisions]
```

---

## Quick Reference

### Commands

| Task      | Command                                     |
| --------- | ------------------------------------------- |
| Check PR  | `gh pr view --json number,reviews,comments` |
| SCA scan  | `snyk_sca_scan` with absolute path          |
| Code scan | `snyk_code_scan` with absolute path         |
| Run tests | `make cover && make test-integration-local` |

### Red Flags (Stop and Discuss)

- Breaking API changes without versioning
- Security vulnerabilities in non-test code
- Significant behavioral changes
- Unresolved PR blockers
- Significant code duplication (>20 lines copied)

---

## Step 9: Fix Issues (TDD Required)

**CRITICAL: ALL fixes MUST follow TDD. NEVER implement a fix without writing a failing test first.**
**CRITICAL: Use implementation skill.**

When verification identifies issues to fix:

### 8.1 Write Failing Test First

Before touching production code:

1. Write a test that exposes the issue
2. Run the test - confirm it FAILS (or would fail to catch the issue)
3. The test proves the fix is needed and will prevent regression

Example for security fix (URL sanitization):

```go
func TestSanitizeURLForLogging_StripsCredentialsInAllLogStatements(t *testing.T) {
    // Test that URLs with credentials are sanitized before logging
    urlWithCreds := "https://user:token@github.com/org/repo"

    // Capture log output and verify no credentials appear
    // This test should FAIL before the fix is applied
}
```

### 8.2 Implement Minimal Fix

Only after the test exists:

1. Apply the minimum change to make the test pass
2. Run the test - confirm it PASSES
3. Run all test suites to verify no regressions (read `commit` skill for details)

### 8.3 TDD Violation Check

Before applying ANY code fix, ask yourself:

- [ ] Did I write a test first? If NO, STOP and write the test.
- [ ] Does the test fail without my fix? If NO, improve the test.
- [ ] Is my fix minimal? If NO, reduce scope.

**If you catch yourself implementing before testing, STOP, revert, and start with the test.**
