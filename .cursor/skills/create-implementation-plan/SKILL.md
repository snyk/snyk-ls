---
name: create-implementation-plan
description: Create structured implementation plans for Jira issues using the project template. Use when starting a new task, implementing a feature, when asked to create a plan, or when the implementation skill detects no existing plan.
---

# Create Implementation Plan

Creates implementation plans using the official project template with session hand-off support, TDD workflow, and progress tracking.

## Quick Start

1. Extract issue ID from branch: `git branch --show-current` (format: `XXX-XXXX`)
2. Read Jira issue for context and acceptance criteria
3. Create plan file: `${issueID}_implementation_plan.md` (root directory)
4. Create `tests.json` for test scenario tracking
5. Create mermaid diagrams in `docs/diagrams/`
6. **STOP and wait for user confirmation**

## Template Location

Use template from: `.github/IMPLEMENTATION_PLAN_TEMPLATE.md`

Replace all `{{TICKET_ID}}` and `{{TICKET_TITLE}}` placeholders with actual values.

## Files to Create

| File                | Location                            | Purpose                              |
| ------------------- | ----------------------------------- | ------------------------------------ |
| Implementation plan | `${issueID}_implementation_plan.md` | Main plan document                   |
| Test tracking       | `tests.json`                        | Track test scenarios across sessions |
| Flow diagrams       | `docs/diagrams/${issueID}_*.mmd`    | Mermaid source files                 |

**All these files are gitignored - NEVER commit them.**

## Key Sections to Complete

### 1. SESSION RESUME (Critical for hand-off)

- Update Quick Context with ticket info and branch
- Fill Current State table
- List Next Actions
- Update Current Working Files table

### 2. Phase 1: Planning

- **1.1 Requirements Analysis**: List changes, error handling, files to modify/create
- **1.2 Schema/Architecture Design**: Add schemas, data structures
- **1.3 Flow Diagrams**: Create mermaid files, generate PNGs

### 3. Phase 2: Implementation (Outside-in TDD)

- Use testing skill
- **CRITICAL: use outside-in TDD**
- Enforce strict test order:
  1. Smoke tests (E2E behavior)
  2. Integration tests (cross operating system behaviour, integrative behaviour)
  3. Unit tests
- Break into checkpoint steps (completable in one session)
- Each step: tasks, tests to write FIRST, commit message
- Reference test IDs from `tests.json`
- Add a plan self-check: integration tests must appear before unit tests

### 4. Phase 3: Review

- Code review prep checklist
- Documentation updates
- Pre-commit checks

### 5. Progress Tracking

- Update status table at end of each session
- Add entry to Session Log

## tests.json Structure

```json
{
  "ticket": "IDE-XXXX",
  "description": "Ticket title",
  "lastUpdated": "YYYY-MM-DD",
  "lastSession": {
    "date": "YYYY-MM-DD",
    "sessionNumber": 1,
    "completedSteps": [],
    "currentStep": "1.1 Requirements Analysis",
    "nextStep": "1.2 Schema Design"
  },
  "testSuites": {
    "unit": {},
    "integration": { "scenarios": [] },
    "regression": { "scenarios": [] }
  }
}
```

## Diagram Creation

1. Create: `docs/diagrams/${issueID}_description.mmd`
3. Reference PNG in plan: `![Name](docs/diagrams/${issueID}_description.png)`

## Critical Rules

- **NEVER commit** implementation plan, tests.json, or plan diagrams
- **WAIT for confirmation** after creating the plan before implementing
- **Use Outside-in TDD** - write tests FIRST
- **Update progress** at end of EVERY session (hand-off support)
- **Update Jira** with progress comments
- **Sync** plan changes to Jira ticket description and Confluence (if applicable)

## Workflow Integration

This skill is called by `implementation` when no plan exists. After creating the plan:

1. Present plan summary to user
2. Wait for confirmation
3. `implementation` continues with Phase 2 (Implementation)
