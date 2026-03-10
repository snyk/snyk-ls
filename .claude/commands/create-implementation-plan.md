# Create Implementation Plan

Creates implementation plans using the official project template with session hand-off support, TDD workflow, and progress tracking.

## Quick Start

1. Extract issue ID from branch: `git branch --show-current` (format: `XXX-XXXX`)
2. Read the Jira issue for context and acceptance criteria (use Atlassian MCP or ask user)
3. Create plan file: `${issueID}_implementation_plan/${issueID}_implementation_plan.md` (project root)
4. Create `tests.json` for test scenario tracking
5. Create mermaid diagrams in `docs/diagrams/`
6. **STOP and wait for user confirmation**

## Template Location

Use template from: `.github/IMPLEMENTATION_PLAN_TEMPLATE.md`

Replace all `{{TICKET_ID}}` and `{{TICKET_TITLE}}` placeholders with actual values.

## Files to Create

| File                | Location                                                   | Purpose                              |
| ------------------- | ---------------------------------------------------------- | ------------------------------------ |
| Implementation plan | `${issueID}_implementation_plan/${issueID}_implementation_plan.md` | Main plan document        |
| Test tracking       | `tests.json`                                               | Track test scenarios across sessions |
| Flow diagrams       | `docs/diagrams/${issueID}_*.mmd`                           | Mermaid source files                 |

**All these files are gitignored — NEVER commit them.**

## Step 1: Gather Context

```bash
git branch --show-current
```

Extract the issue ID (format `XXX-XXXX`) from the branch name. Read the Jira issue for context, acceptance criteria, and scope.

## Step 2: Analyze the Codebase

- Identify all files, packages, and functions that need modification or creation
- Trace existing code paths that will be affected
- Identify test files that need updating or creation
- Note architectural patterns and conventions already in use

## Step 3: Create the Implementation Plan

Fill in these key sections:

### SESSION RESUME (Critical for hand-off)

- Quick Context with ticket info and branch
- Current State table
- List of Next Actions
- Current Working Files table

### Phase 1: Planning

- **1.1 Requirements Analysis**: List changes, error handling, files to modify/create
- **1.2 Schema/Architecture Design**: Add schemas, data structures
- **1.3 Flow Diagrams**: Create mermaid files, generate PNGs

### Phase 2: Implementation (Outside-in TDD)

- **CRITICAL: use outside-in TDD**
- Enforce strict test order:
  1. Smoke tests (E2E behavior)
  2. Integration tests (cross-OS behaviour, integrative behaviour)
  3. Unit tests
- Break into checkpoint steps (completable in one session)
- Each step must include: tasks, tests to write FIRST, and a commit message
- Reference test IDs from `tests.json`

### Phase 3: Review

- Code review prep checklist
- Documentation updates
- Pre-commit checks

### Progress Tracking

- Status table updated at end of each session
- Session log entry per session

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
2. Run: `make generate-diagrams`
3. Reference PNG in plan: `![Name](docs/diagrams/${issueID}_description.png)`

## Step 4: Present and Wait

Present a summary of the plan to the user. **STOP and wait for confirmation before any implementation begins.**

After user confirms:

> Planning complete. Use `/implementation` or the **coder** agent to begin Phase 2 (Implementation) with TDD.

## Critical Rules

- **NEVER commit** implementation plan, tests.json, or plan diagrams
- **WAIT for confirmation** after creating the plan before implementing
- **Use Outside-in TDD** — write tests FIRST
- **Update progress** at end of EVERY session (hand-off support)
- **Always structure steps as completable checkpoints** for session hand-off support
