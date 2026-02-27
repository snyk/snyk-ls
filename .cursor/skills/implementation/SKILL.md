---
name: implementation
description: Start an implementation task with proper planning, TDD workflow, and session hand-off. Use when beginning work on a Jira issue, starting a new feature, or resuming implementation work. Triggers on phrases like "start task", "begin implementation", "work on issue", or "implement feature".
---

# Start Implementation Task

## Workflow Overview

```
Check Plan → [Create if missing] → TEST FIRST → Implement → Test & Lint → Commit → Session Hand-off
```

**TDD is NON-NEGOTIABLE**: Every code change requires a failing test BEFORE implementation.

## Phase 1: Initialize

### 1.1 Get Issue Context

```bash
# Extract issue ID from branch
git branch --show-current
```

The `issueID` follows format `XXX-XXXX` (e.g., `IDE-1718`).

### 1.2 Check for Implementation Plan

Look for: `${issueID}_implementation_plan/${issueID}_implementation_plan.md`

**If plan exists:** Read it, note current progress, continue from last checkpoint.

**If no plan:** use skill `create-implementation-plan` to create one

---

## Phase 1: Planning

### Analysis

- **Files to modify:** [list files]
- **Files to create:** [list files]
- **Packages affected:** [list packages]

### Flow Diagrams

See: `docs/diagrams/${issueID}_*.png`

---

## Phase 2: Implementation (TDD)

** read and use testing skill for TDD instructions **

### Steps

- [ ] Step 1: [description]
- [ ] Step 2: [description]
- [ ] Step 3: [description]

---

## Phase 3: Review

- [ ] All tests pass (`make test`)
- [ ] Smoke tests pass (`SMOKE_TESTS=1 make test`)
- [ ] Linting clean (`make format`)
- [ ] Security scan clean (snyk_code_scan, snyk_sca_scan)
- [ ] Documentation updated

---

## Progress Tracking

| Step   | Status  | Notes |
| ------ | ------- | ----- |
| Step 1 | pending |       |

---

## Session Log

### Session 1 - [DATE]

**Started:** [time]
**Completed:** [list of completed items]
**Next:** [next steps for hand-off]

````

### Create Diagrams

1. Create mermaid files in `docs/diagrams/${issueID}_*.mmd`
2. Run: `make generate-diagrams`
3. Reference PNGs in implementation plan

### Get Confirmation

**Stop here.** Present the plan and wait for user confirmation before proceeding.

## Phase 3: Implementation (Outside-In TDD)

### CRITICAL: TDD is MANDATORY

**NEVER write production code before writing a failing test.**


This applies to:
- New features
- Bug fixes
- Security fixes
- Refactoring
- ANY code change

### TDD Gate Check

** ALWAYS use the testing skill. **

Before writing ANY production code, verify:

- [ ] **Test exists?** Have I written a test for this change?
- [ ] **Test fails?** Does the test fail without my change?
- [ ] **Test is specific?** Does the test target the exact behavior I'm changing?

**If ANY answer is NO → STOP and write the test first.**

### TDD Cycle

For each feature/change:

1. **STOP** - Do not touch production code yet
2. **READ and USE testing skill.**
2. **Write failing test first** (outside-in: ensure smoke tests. also write unit tests)
3. **Run test** - confirm it fails for the right reason
4. **Write minimal code** to make test pass
5. **Run test** - confirm it passes
6. **Refactor** if needed (tests must still pass)

### Commands

```bash
# Run unit tests
make test

# Run smoke tests
SMOKE_TESTS=1 make test

# Format and lint
make format
```

### Progress Updates

Before each step:

```markdown
## Progress Tracking

| Step 1 | **in-progress** | Started [time] |
```

After each step:

```markdown
## Progress Tracking

| Step 1 | **completed** | Finished [time] |
```

## Phase 4: Finalize

### 4.1 Run All Tests

```bash
make test
INTEG_TESTS=1 make test
SMOKE_TESTS=1 make test
```

All tests must pass. Fix any failures before proceeding.

### 4.2 Lint

```bash
make format
```

Zero linting errors required. Fix any issues.

### 4.3 Security Scan

Run before commit:

- `snyk_code_scan` with absolute project path
- `snyk_sca_scan` with absolute project path

Fix any security issues (except in test data).

### 4.4 Generate & Update Docs

```bash
make generate
make generate-diagrams
```

Update documentation in `./docs` as needed.

### 4.5 Commit

Pre-commit checklist:

- [ ] Tests pass (pre-existing issues MUST be fixed)
- [ ] Linting clean
- [ ] Generate has run
- [ ] Security scans clean
- [ ] Docs updated

Commit format:

```
type(scope): description [XXX-XXXX]

Body explaining what and why.
```

**Never skip hooks. Never use --no-verify.**

## Phase 5: Session Hand-off

Update implementation plan with session summary according to the plan session handoff section.

---

## Quick Reference

| Action            | Command                       |
| ----------------- | ----------------------------- |
| Unit tests        | `make test`                  |
| Integration tests s| `INTEG_TESTS=1 make test` |
| Smoke tests       | `SMOKE_TESTS=1 make test` |
| Format & lint     | `make format`                 |
