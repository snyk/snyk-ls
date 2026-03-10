# General Development Rules

## General

- Always be concise, direct, and don't try to appease me.
- Use `.github/CONTRIBUTING.md` and the links in there to find standards and contributing guidelines.
- DOUBLE CHECK THAT YOUR CHANGES ARE REALLY NEEDED. ALWAYS STICK TO THE GIVEN GOAL, NOT MORE.
- Don't optimize, don't refactor if not needed.
- Adhere to the rules, fix linting & test issues that are newly introduced.
- The `issueID` is usually specified in the current branch in the format `XXX-XXXX`.

## Process

- Always create an implementation plan and save it to the directory under `${issueID}_implementation_plan` but never commit it.
- It should have the phases: planning, implementation (including testing through TDD), review.
- Get confirmation that the plan is ok. Wait until you get it.
- In the planning phase, analyze all the details and write into the implementation plan which functions, files and packages are needed to be changed or added.
- Be detailed: add steps to the phases and prepare a tracking section with checkboxes for progress tracking of each detailed step.
- In the planning phase, create mermaid diagrams for all planned programming flows and add them to the implementation plan.
- Use the same name for the diagrams as the implementation plan, but the right extension (`.mmd`), so that they are ignored via `.gitignore`.
- Never commit the diagrams generated for the implementation plan.

## Coding Guidelines

- Follow the implementation plan step-by-step, phase-by-phase.
- Never proceed to the next step until the current step is fully implemented and confirmed.
- Never jump a step. Always follow the plan.
- Use atomic commits.
- Update progress of the step before starting and when ending.
- USE TDD — always write and update test cases BEFORE writing the implementation. Iterate until they pass.
- After changing `.go` files, run `make lint` to check for linting errors. Only continue once they are fixed. The only acceptable outcome is 0 linting errors.
- Always verify if fixes worked by running the tests and `make lint`.
- Do atomic commits (ask before committing).
- Update current status in the implementation plan (in progress work, finished work, next steps).
- Maintain existing code patterns and conventions.
- Use gomock to mock. Writing your own mocks is forbidden if gomock can be used.
- Re-use mocks.
- Use generated types for mock responses, don't use custom structs.
- Don't change code that does not need to be changed. Only do the minimum changes.
- Don't comment what is done, instead comment why something is done if the code is not clear.
- Use `make test` to run go tests.
- Use `INTEG_TESTS=1 make test` to run integration tests.
- Use `SMOKE_TESTS=1 make test` to run smoke tests.
- Always run unit and integration tests after generating code.
- Always run unit and integration tests before committing.
- Achieve 80% test coverage of added or changed code.
- If files are not used or needed anymore, delete them instead of deprecating them.
- Ask the human whether to maintain backwards compatibility or not.
- If a tool call fails, analyze why it failed and correct your approach.
- If you don't know something, read the code instead of assuming it.
- Commenting out code to fix errors is NEVER a solution. Fix the error.
- Disabling or removing tests IS NOT ALLOWED.
- Disabling linters is not allowed unless the human EXPLICITLY allows it for that single instance.
- Don't do workarounds.
- ALWAYS create production-ready code.

## Security

- Run `snyk_sca_scan` after updating `go.mod`.
- Run `snyk_sca_scan` and `snyk_code_scan` before committing. Fix issues before committing (skip test data false positives).
- Fix security issues if they are fixable.
- Don't fix test data.

## Committing

- NEVER commit implementation plan and implementation plan diagrams.
- NEVER NEVER NEVER skip the commit hooks.
- NEVER use `--no-verify`. DO NOT DO IT. NEVER. THIS IS CRITICAL.
- Run `make generate` before committing.
- Run `make lint-fix` before committing and fix issues.
- Update the documentation before committing.
- When asked to commit, always use conventional commit messages (Conventional Commit Style: Subject + Body). Be descriptive in the body. If you find a JIRA issue (`XXX-XXXX`) in the branch name, use it as a postfix to the subject line in the format `[XXX-XXXX]`.
- Consider all commits in the current branch when committing, to have the context of the current changes.

## Pushing

- Never push without asking.
- Never force push.
- When asked to push, always use `git push --set-upstream origin $(git branch --show-current)`.
- Regularly fetch main branch and offer to merge it into the current branch.
- After pushing, offer to create a PR on GitHub if no PR already exists. Analyze the changes by comparing the current branch with `origin/main`, and craft a PR description and title.
- Use the GitHub template in `.github/PULL_REQUEST_TEMPLATE.md`.

## PR Creation

- Use `gh` command line util for PR creation.
- Always create draft PRs.
- Update the GitHub PR description with the current status using `gh` command line util.
- Use the diff between the current branch and main to generate the description and title.
- Respect the PR template.
- Get the PR review comments, analyze them and propose fixes. Check before each commit.

## Documenting

- Always keep the documentation up-to-date in `./docs`.
- Don't create summary mds unless asked.
- Create mermaid syntax for all programming flows and add it to the documentation in `./docs`.
- Use `make generate-diagrams` to generate diagrams.
- Document the tested scenarios for all testing stages (unit, integration, e2e) in `./docs`.

## Available Slash Commands

- `/commit` — Prepare and commit with full verification (verification → TDD fixes → pre-commit checks → atomic commit → all test suites).
- `/create-implementation-plan` — Create a structured implementation plan for the current Jira issue.
- `/implementation` — Start or resume implementation of a Jira issue following the confirmed plan with TDD.
- `/verification` — Deep code verification before committing (trace code paths, semantic changes, code smells, security scans, PR feedback).

## Available Agents

Use the Agent tool to invoke these specialized agents:

- **planner** — Creates structured implementation plans. Use when starting a new task or when requirements are unclear.
- **coder** — Implements features using TDD. Use after a plan is confirmed.
- **qa** — Deep QA analysis of code changes. Use after implementation is complete.
