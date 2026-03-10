# Commit Workflow

Prepare, verify, and commit code changes following project standards.

```
Verify → Fix Issues (TDD) → Pre-commit Checks → Commit → Tests → [Push]
```

## Quick Start Checklist

```
Commit Progress:
- [ ] Step 1: Run /verification
- [ ] Step 2: Fix issues using TDD
- [ ] Step 3: Run pre-commit checks
- [ ] Step 4: Create atomic commit
- [ ] Step 5: Run ALL test suites (3 REQUIRED):
      - [ ] make test
      - [ ] INTEG_TESTS=1 make test
      - [ ] SMOKE_TESTS=1 make test
- [ ] Step 6: Push (optional, ask first)
```

**CRITICAL: Step 5 has THREE mandatory test suites. Skipping any is FORBIDDEN.**

---

## Step 1: Run Verification

Execute `/verification` to analyze code changes. Output: list of issues found, categorized by severity.

---

## Step 2: Fix Issues Using TDD

For each issue identified by verification:

### TDD Gate (MANDATORY)

Before ANY fix:

- [ ] Write failing test first
- [ ] Confirm test fails without fix
- [ ] Implement minimal fix
- [ ] Confirm test passes

**Never skip TDD.**

### Issue Priority

1. **Security vulnerabilities** — fix immediately (except test data)
2. **Breaking changes** — confirm intentional, add tests
3. **Code smells** — fix immediately
4. **PR feedback** — address blockers first

---

## Step 3: Pre-commit Checks

```bash
make generate
make lint-fix
make test
INTEG_TESTS=1 make test
SMOKE_TESTS=1 make test
```

### Security Scans

```bash
pwd  # get absolute path first
```

Then run:

1. `snyk_sca_scan` with absolute project path
2. `snyk_code_scan` with absolute project path

**Fix any security issues** (skip test data false positives).

---

## Step 4: Create Atomic Commit

### Pre-commit Verification

- [ ] Linting clean (`make lint-fix` shows no changes)
- [ ] Security scans clean
- [ ] No implementation plan files staged
- [ ] Documentation updated (if needed)
- [ ] `make generate` has run

### Commit Format

```
type(scope): description [XXX-XXXX]

Body explaining what and why.
```

**Types**: feat, fix, refactor, test, docs, chore, perf

**Extract issue ID from branch:**

```bash
git branch --show-current
```

### Staged Files Check

```bash
git status
git diff --staged
```

**Never commit**:

- Implementation plan files (`*_implementation_plan/`)
- Secrets or credentials
- Generated diagram source (`.mmd` files)

### Execute Commit

```bash
git add <specific-files>
git commit -m "$(cat <<'EOF'
type(scope): description [XXX-XXXX]

Body explaining what and why.
EOF
)"
```

**NEVER use `--no-verify`. NEVER amend commits.**

---

## Step 5: Run All Test Suites (After Commit, Before Push)

**CRITICAL: ALL three test suites MUST run after commit. Skipping ANY is FORBIDDEN.**

Run IN ORDER and wait for each to complete:

```bash
make test
INTEG_TESTS=1 make test
SMOKE_TESTS=1 make test
```

### Test Gate Enforcement

Before Step 6, verify:

1. Did `make test` complete with all tests passing?
2. Did `INTEG_TESTS=1 make test` complete with all tests passing?
3. Did `SMOKE_TESTS=1 make test` complete with all tests passing?

If ANY answer is "no" — STOP and run the missing tests.

### Test Failure Protocol

If tests fail:

1. Do NOT proceed to push
2. Identify root cause
3. Apply TDD fix (test first, then implementation)
4. Create new commit with fix
5. Re-run ALL test suites
6. Continue only when ALL three pass

---

## Step 6: Push (Optional)

**Always ask before pushing.**

If approved:

```bash
git push --set-upstream origin $(git branch --show-current)
```

### After Push

Offer to:

1. Create draft PR (if none exists) using `.github/PULL_REQUEST_TEMPLATE.md`
2. Update PR description (if PR exists)
3. Check snyk-pr-review-bot comments

---

## Command Reference

| Task              | Command                                            |
| ----------------- | -------------------------------------------------- |
| Format & lint     | `make lint-fix`                                    |
| Generate          | `make generate`                                    |
| Unit tests        | `make test`                                        |
| Integration tests | `INTEG_TESTS=1 make test`                          |
| Smoke tests       | `SMOKE_TESTS=1 make test`                          |
| SCA scan          | `snyk_sca_scan` with absolute path                 |
| Code scan         | `snyk_code_scan` with absolute path                |
| Current branch    | `git branch --show-current`                        |
| Push              | `git push --set-upstream origin $(git branch ...)` |

---

## Red Flags (STOP)

- Tests failing
- Any test suite skipped
- Security vulnerabilities unfixed
- Implementation plan files staged
- Unresolved PR blockers
- TDD not followed for fixes
- `--no-verify` being considered
