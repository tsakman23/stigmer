# Instructions for coding agents

Stigmer is a self-hostable message board and task queue for people and their coding agents. It is a Rust workspace plus a TypeScript SDK. This file is for any agent working in this repo. [CONTRIBUTING.md](CONTRIBUTING.md) is the working agreement for everyone and is binding for agents too; this file adds what agents most often get wrong. Read both before you start.

## Where things are

- [docs/design.md](docs/design.md): what Stigmer is and the milestone plan. [docs/roadmap.md](docs/roadmap.md): status per milestone.
- [docs/adr/](docs/adr/README.md): every design decision, with the reason. Read the ones that touch your task before changing behaviour.
- `docs/superpowers/specs/` and `docs/superpowers/plans/`: the design and the task-by-task plan of the milestone in progress. Your task's section of the plan is your spec.
- `crates/stigmer-core` (pure domain types, no I/O), `stigmer-store` (the `Store` and `IdentityStore` traits), `stigmer-store-sqlite` and `stigmer-store-postgres` (backends), `stigmer-store-conformance` (one shared test suite that defines "correct" for any backend), `stigmer-api`, `stigmerd` (server), `stigmer-cli`, `sdk/typescript`.
- `.superpowers/` is a git-ignored scratch area for briefs, reports and progress notes. Never commit it.

## Workflow

1. **One small pull request per task, merged before the next task starts.** Never bundle a milestone into one PR. A milestone's design and plan ride in its first task's PR.
2. Work in a worktree: `scripts/dev/wt new <type>/m<N>-t<NN>-<slug>`. Branch names must match that pattern. Never edit the main checkout by hand, never commit to `main`, never force-push.
3. After a PR merges, run `scripts/dev/tidy --apply`.
4. Use your own worktree's `git stash` only with a unique message; the stash stack is shared across worktrees. Prefer a WIP commit.
5. Commits are Conventional (`type(scope): summary`, checked by `scripts/ci/check-commit-messages.sh`). Code and the tests that cover it go in the same commit. Every commit ends with the `Co-Authored-By:` line naming the model that wrote it; every PR description ends with the attribution line your harness gives you.
6. Write tests first and watch them fail for the right reason. When a test guards a risky behaviour (a lock, an ordering, a security property), plant the fault it should catch, see the test fail, then revert. A test that cannot fail proves nothing.

## Verify before you say "done"

Run these yourself and read the output. A subagent's or your own earlier "all green" is not evidence.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
STIGMER_TEST_DATABASE_URL=postgres://localhost/stigmer_test cargo test --workspace --locked --no-fail-fast
cargo deny --locked check
scripts/ci/check-commit-messages.sh main HEAD
```

- Postgres tests need a local Postgres 17 (see CONTRIBUTING). Without `STIGMER_TEST_DATABASE_URL` they skip loudly; with `CI` set they fail. That is deliberate.
- Run one `cargo` at a time in a checkout. Two cargo processes sharing a target directory can make the CLI end-to-end tests fail with "spawn child: not found".
- A flaky test is a bug. Run it many times (30 is the habit), find the cause, fix the cause. Do not add a retry, a longer sleep or an `#[ignore]`.
- Do not synchronise tests with sleeps. Wait on a condition, or loop the scenario over every interleaving (see the wake scenarios in `stigmer-store-conformance`). Timeouts are only upper bounds.
- Check that CI is green on the pushed branch before reporting the PR as ready. If a job fails, read its log and say what failed.

## Review (the agent side)

- **Independent review before every PR.** The agent that wrote the code does not review it. Give the reviewer the diff, the spec (your plan section), the relevant ADRs and CONTRIBUTING, and ask for findings by severity with file and line. Fix Critical and Important findings; list the rest in the PR.
- **Two axes.** Review against the standards (CONTRIBUTING, the ADRs, common code smells such as duplication, long parameter lists and unclear names) and against the spec separately, so one cannot hide the other.
- **Review the tests, not just the code.** Do they fail without the fix? Do they use sleeps? Is a duplicate really covered elsewhere?
- **Do not trust claims.** Reproduce numbers (test counts, timings), re-run the checks and read the diff stat. If a report says "no deviations" and the diff shows one, the report is wrong.
- When review changes the design, write it down in an ADR in the same PR.

## Invariants you must not break

- **The event log is hash-chained, gapless per board, and its format is frozen.** A change to hashing or the stored shape needs an ADR and a version bump, never a quiet edit.
- **Migrations are append-only.** Add a numbered file; never edit a shipped one. Fingerprint tests pin the shipped SQL byte for byte. SQLite and Postgres migrations must stay semantically equal.
- **Wait and cursors (ADR 0005):** subscribe, then read the head, then wait. Read the head before every scan. A wait must never hold a transaction or a pooled connection while it sleeps.
- **Audit rows are written inside the mutation's transaction** (ADR 0014), never in a second step.
- **Lock order:** multi-row writes lock the board row first. Single-credential writes lock only that row. Do not introduce the reverse order anywhere.
- **Secrets:** a secret, token, invite secret or database password must never appear in an error, a log line, `Debug` output or a test failure message. Compare secrets in constant time. A refused invite or token looks identical to an unknown one (same error, same cost).
- **Message text is untrusted data** and is always framed as such when shown to agents (ADR 0006). Do not add paths that print it raw.
- **Both backends obey one conformance suite.** A behaviour fix lands in the shared suite first, then in each backend. Do not special-case a backend in the suite to make it pass.
- **`stigmer-core` does no I/O.** Product code has no `unwrap()`, `expect()` or `unsafe` unless the invariant is documented on that line.
- **ADRs are frozen once released.** Before a release you may amend one and say so; after, write a new one. Check `docs/adr/README.md` and the milestone plan for the next free number; a plan can set numbers aside for later tasks.

## Working with the maintainer

- The maintainer reads outcomes, not Rust. Report what shipped and what it means for a user, in plain language: what now works, what does not yet, how it was checked, what needs a decision. Put code detail in the PR, not the summary.
- Be honest about state: say when something is unverified, skipped, flaky or failing, with the output. Do not describe a plan as done.
- Ask before anything outward-facing or hard to undo: repository settings, branch protection, releases and tags, deleting branches that are not merged, installing software or starting services on the maintainer's machine, anything that sends content to an outside service.
- Keep the maintainer's personal details (name, email, employer) out of the repo, PRs, issue text and any outside request.
- Credit honestly. Stigmer is inspired by Board, and its maintainer acknowledges openboard (a colleague's project) as an inspiration. Do not copy another project's code, text or assets; write original work and credit ideas openly.

## Subagent-driven development

When a task is split across agents:

- **Brief**: write one file per task with the goal, the exact interfaces, the files to touch, the verification commands, the commit scopes and the trailer. Name the rulings already made so they are not re-litigated.
- **Implementer** works only in the task's worktree and does not push. **Reviewer** is a different agent, read-only. **Controller** (you) re-runs the checks, relays findings, owns the PR.
- Send fixes back to the implementer as a precise list; re-verify after each round. Keep a progress note in `.superpowers/` so a new session can resume.
- Record deviations and concerns in the PR description, not only in chat.

## Do not

- Commit secrets, `.env` files or anything from `.superpowers/`.
- Disable a failing check, loosen a lint, add `#[allow]` or lower coverage to get green; fix the cause. A narrowly scoped `#[allow]` with a reason is acceptable only when the lint is wrong.
- Add a dependency without running `cargo deny` and saying why in the PR.
- Widen public API for the sake of a test; test helpers go in the `#[doc(hidden)]` testing modules.
- Leave stray processes, databases, schemas or files behind (test schemas drop themselves; check).
