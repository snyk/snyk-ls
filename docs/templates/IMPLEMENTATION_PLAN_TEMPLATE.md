# Implementation Plan — {{TICKET_ID}}: {{TICKET_TITLE}}

## SESSION RESUME

**Quick Context:** {{TICKET_ID}} — {{TICKET_TITLE}}
**Branch:** `feat/{{TICKET_ID}}-description`
**Confluence:** [link if applicable]

| State | Value |
|-------|-------|
| Phase | 1.1 Requirements Analysis |
| Last completed | — |
| Next action | Fill requirements |

**Current Working Files:**

| File | Purpose |
|------|---------|

---

## Phase 1: Planning

### 1.1 Requirements Analysis

- Changes required:
- Error handling:
- Files to modify:
- Files to create:

### 1.2 Schema / Architecture Design

[schemas, data structures, interface contracts]

### 1.3 Flow Diagrams

Create: `docs/diagrams/{{TICKET_ID}}_description.mmd`
Reference in plan: `![Name](docs/diagrams/{{TICKET_ID}}_description.png)`

---

## Phase 2: Implementation (Outside-in TDD)

**Strict test order per checkpoint:**
1. Smoke tests (E2E behavior)
2. Integration tests (cross-component, protocol)
3. Unit tests

**PR size gate: 700 changed lines max.** Split into a stacked PR when exceeded.

### Checkpoint 2.1 — [Name]

**Tasks:**
- [ ] task

**Tests to write FIRST (TDD):**
- [ ] [TEST-ID] description — layer (smoke/integration/unit)

**Commit message:** `fix(scope): description [{{TICKET_ID}}]`

### Checkpoint 2.2 — [Name]

[repeat pattern]

---

## Test Scenarios (REQUIRED)

Layer definitions:
- **Unit** — isolated, no external deps; CI on every PR
- **Integration** — cross-component, LS protocol roundtrips; CI on every PR
- **Smoke** — E2E with real CLI + LS; runs on main merge / release candidates (30–90 min; not counted as elapsed)
- **Manual** — IDE UI rendering, theme, interactive workflows; run per milestone gate

Can/Will/Must:
- **Can** — automatable but not committed in this PR
- **Will** — committed: test written in this PR
- **Must (manual)** — cannot be automated; requires human IDE testing

| Test ID | Scenario | Layer | Can/Will/Must | Notes |
|---------|----------|-------|---------------|-------|
| {{TICKET_ID}}-INTEG-001 | [scenario] | Integration | Will | |
| {{TICKET_ID}}-UNIT-001 | [scenario] | Unit | Will | |
| {{TICKET_ID}}-MANUAL-001 | [scenario] | Manual | Must | |

**Self-check:** Integration tests appear before unit tests in Phase 2. Every PR has at least one "Will" row at integration or unit level. Every UI/theme/interactive story has at least one Manual row.

---

## Effort Estimates (REQUIRED)

Rules: agent dev ~0.5d per 100–150 lines; PR verification = 1d flat per PR; manual = 0.5d per IDE per workflow.

| PR | Scope | Agent dev | PR review (1d flat) | Manual | Total |
|----|-------|-----------|---------------------|--------|-------|
| PR 1 | [description] | Xd | 1d | Xd | Xd |
| **Total** | | | | | |

---

## Phase 3: Review

- [ ] Code review prep checklist complete
- [ ] Documentation updated
- [ ] Pre-commit checks pass (`make lint`, focused package tests)
- [ ] verification agent run with zero blocking findings
- [ ] PR has stack diagram and sibling PR links

---

## Progress Tracking

| Session | Date | Phase | Completed | Next |
|---------|------|-------|-----------|------|
| 1 | YYYY-MM-DD | 1.1 | — | 1.2 |

---

## Session Log

### Session 1 — YYYY-MM-DD

[notes]
