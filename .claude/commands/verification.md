# Code Verification

Deep verification of code changes before committing. Traces code paths, detects semantic changes, identifies code smells and security issues. Reviews GitHub PR feedback.

## When to Use

- Before committing implementation changes
- After completing implementation steps
- When PR review feedback needs to be addressed
- When explicitly asked to verify or review changes
- When starting a new session of an implementation plan

## Verification Workflow

Track progress against this checklist:

```
Verification Progress:
- [ ] Step 1: Load project rules and standards
- [ ] Step 2: Trace code paths for modified files
- [ ] Step 3: Check for semantic changes
- [ ] Step 4: Identify code smells
- [ ] Step 5: Run security scans
- [ ] Step 6: If PR exists — trigger /review in PR, wait for bot, review ALL comments
- [ ] Step 7: Get check results from GitHub with gh cli; wait until checks complete
- [ ] Step 8: Update implementation plan with findings
- [ ] Step 9: Fix issues (TDD REQUIRED — test first, then fix)
- [ ] Step 10: Check coverage of changed files > 80%
- [ ] Step 11: Add tests if coverage insufficient
- [ ] Step 12: Commit changes (use /commit for details)
- [ ] Step 13: Push changes to remote repository
- [ ] Step 14: Run verification again
```

---

## Step 1: Load Project Rules

Read and apply these project standards:

1. `CLAUDE.md` — critical rules and workflow
2. `.github/CONTRIBUTING.md` — coding standards

Key rules to verify against:

- Outside-in TDD followed
- Minimum necessary changes only
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

**Action**: Flag any semantic changes and ask if they are intentional.

---

## Step 4: Identify Code Smells

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
- [ ] Use `testing.T` for context, tempDir and helpers

### Design Smells

- [ ] Circular dependencies between packages
- [ ] Leaky abstractions (implementation details exposed)
- [ ] Inappropriate intimacy (packages knowing too much about each other)
- [ ] Feature envy (functions using other package's data excessively)

### Copy-Paste Code (Refactoring Candidates)

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

**Action**: For duplicated code, propose extraction with suggested function/package location, shared interface if applicable, and impact on existing callers.

---

## Step 5: Run Security Scans

Get absolute path first:

```bash
pwd
```

Then run:

1. `snyk_sca_scan` with absolute project path — dependency vulnerabilities
2. `snyk_code_scan` with absolute project path — code security issues

### Manual Security Checklist

- [ ] No hardcoded secrets, tokens, or credentials
- [ ] Input validation on all external data
- [ ] SQL queries use parameterized statements
- [ ] No path traversal vulnerabilities
- [ ] Proper authentication/authorization checks
- [ ] Sensitive data not logged
- [ ] HTTPS/TLS used for external calls

**Action**: Fix security issues using TDD. If in test data, note but don't fix.

---

## Step 6: Review PR Feedback

```bash
# Check if PR exists
gh pr view --json number,reviews,comments,url 2>/dev/null
```

If PR exists:

1. Trigger feedback by commenting `/review` in the PR
2. Wait for the bot to review
3. Review ALL comments including the pr-review-bot comments

For each review comment:

1. **Categorize**: Bug | Enhancement | Style | Question | Blocker
2. **Assess**: Is this actionable? Does it require a decision?
3. **Prioritize**: Critical (must fix) | Should fix | Nice to have

**CRITICAL**: Do not check if comments are related to our changes. Identify the root cause and fix it.

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

## Step 8: Update Implementation Plan

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

## Step 9: Fix Issues (TDD Required)

**CRITICAL: ALL fixes MUST follow TDD. NEVER implement a fix without writing a failing test first.**

1. Write a test that exposes the issue
2. Run the test — confirm it FAILS
3. Apply the minimum change to make the test pass
4. Run the test — confirm it PASSES
5. Run all test suites to verify no regressions

Before applying ANY code fix:

- [ ] Did I write a test first? If NO, STOP and write the test.
- [ ] Does the test fail without my fix? If NO, improve the test.
- [ ] Is my fix minimal? If NO, reduce scope.

---

## Quick Reference

| Task       | Command                                          |
| ---------- | ------------------------------------------------ |
| Check PR   | `gh pr view --json number,reviews,comments,url`  |
| SCA scan   | `snyk_sca_scan` with absolute path               |
| Code scan  | `snyk_code_scan` with absolute path              |
| Unit tests | `make test`                                      |
| Integ tests| `INTEG_TESTS=1 make test`                        |
| Smoke tests| `SMOKE_TESTS=1 make test`                        |

### Red Flags (Stop and Discuss)

- Breaking API changes without versioning
- Security vulnerabilities in non-test code
- Significant behavioral changes
- Unresolved PR blockers
- Significant code duplication (>20 lines copied)
