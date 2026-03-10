# Start Implementation Task

Start or resume implementation of a Jira issue following a confirmed plan with outside-in TDD.

```
Check Plan → [Create if missing] → TEST FIRST → Implement → Test & Lint → Commit → Session Hand-off
```

**TDD is NON-NEGOTIABLE**: Every code change requires a failing test BEFORE implementation.

---

## Phase 1: Initialize

### 1.1 Get Issue Context

```bash
git branch --show-current
```

The `issueID` follows format `XXX-XXXX` (e.g., `IDE-1718`).

### 1.2 Check for Implementation Plan

Look for: `${issueID}_implementation_plan/${issueID}_implementation_plan.md`

- **Plan exists and confirmed:** Read progress tracking, resume from last checkpoint.
- **Plan exists but NOT confirmed:** Stop. Ask user to confirm.
- **No plan exists:** Run `/create-implementation-plan` first.

### 1.3 Validate Requirements

Before writing any code, verify the current step's requirements are clear and complete.

- **Requirements clear:** Proceed to implementation.
- **Requirements unclear:** Stop. Ask for clarification or run `/create-implementation-plan` to update the plan.

Do NOT guess or invent requirements.

---

## Phase 2: Implementation (Outside-In TDD)

### CRITICAL: TDD is MANDATORY

**NEVER write production code before writing a failing test.**

This applies to:
- New features
- Bug fixes
- Security fixes
- Refactoring
- ANY code change

### TDD Gate Check

Before writing ANY production code, verify:

- [ ] **Test exists?** Have I written a test for this change?
- [ ] **Test fails?** Does the test fail without my change?
- [ ] **Test is specific?** Does the test target the exact behavior I'm changing?

**If ANY answer is NO → STOP and write the test first.**

### TDD Cycle

For each feature/change:

1. **STOP** — Do not touch production code yet
2. **Write failing test first** (outside-in: smoke tests → integration tests → unit tests)
3. **Run test** — confirm it fails for the right reason
4. **Write minimal code** to make test pass
5. **Run test** — confirm it passes
6. **Refactor** if needed (tests must still pass)

### Commands

```bash
# Unit tests
make test

# Integration tests
INTEG_TESTS=1 make test

# Smoke tests
SMOKE_TESTS=1 make test

# Format and lint
make lint-fix

# Generate code
make generate
```

### Progress Updates

Before each step, update the implementation plan:

```markdown
| Step N | **in-progress** | Started [time] |
```

After each step:

```markdown
| Step N | **completed** | Finished [time] |
```

---

## Phase 3: Finalize

### 3.1 Run All Tests

```bash
make test
INTEG_TESTS=1 make test
SMOKE_TESTS=1 make test
```

All tests must pass. Fix any failures before proceeding.

### 3.2 Lint

```bash
make lint-fix
```

Zero linting errors required.

### 3.3 Security Scan

```bash
pwd  # get absolute path
```

Then run:

- `snyk_code_scan` with absolute project path
- `snyk_sca_scan` with absolute project path

Fix any security issues (except in test data).

### 3.4 Generate & Update Docs

```bash
make generate
make generate-diagrams
```

Update documentation in `./docs` as needed.

### 3.5 Commit

Use `/commit` for the full commit workflow.

Pre-commit checklist:

- [ ] Tests pass
- [ ] Linting clean
- [ ] `make generate` has run
- [ ] Security scans clean
- [ ] Docs updated

---

## Phase 4: Session Hand-off

Update implementation plan with session summary:

```markdown
### Session N - [DATE]

**Started:** [time]
**Completed:** [list of completed items]
**Next:** [next steps for hand-off]
```

---

## Critical Rules

- **NEVER skip TDD.** Test first, always.
- **NEVER skip commit hooks.** Never use `--no-verify`.
- **NEVER guess requirements.** Ask for clarification when unclear.
- **NEVER commit implementation plan files, diagrams, or secrets.**
- **ALWAYS follow the implementation plan step-by-step.** Do not skip or reorder steps.
- **ALWAYS update progress tracking** before starting and after completing each step.
- **ALWAYS use `/commit`** for committing — never commit ad-hoc.

---

## Quick Reference

| Action             | Command                    |
| ------------------ | -------------------------- |
| Unit tests         | `make test`                |
| Integration tests  | `INTEG_TESTS=1 make test`  |
| Smoke tests        | `SMOKE_TESTS=1 make test`  |
| Format & lint      | `make lint-fix`            |
| Generate           | `make generate`            |
| Generate diagrams  | `make generate-diagrams`   |
