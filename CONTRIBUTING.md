# Contributing and workflow

This is the working agreement for the repo. It is short on purpose.

## Branches

| Branch | Purpose | Lifetime |
|---|---|---|
| `main` | Always green and releasable. Nothing is committed to it directly. | permanent |
| `<type>/m<N>-t<NN>-<slug>` | One task from the milestone plan, for example `feat/m2-t01-audit-in-transaction`. One pull request per task. | until its PR is merged |

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`. Slugs are lowercase kebab-case. Only these names are accepted by `scripts/dev/wt`.

## Worktrees

Every task is built in its own worktree under `.worktrees/` (git-ignored), branched from `main` (or from the previous task's branch only when that task's PR is not merged yet and the next one depends on it). The main checkout stays on `main` and is never edited by hand.

```
scripts/dev/wt new feat/m2-t01-audit-in-transaction [base]  # branch + worktree from the current branch, or from base
scripts/dev/tidy                              # dry run: list stale worktrees and merged branches
scripts/dev/tidy --apply                      # prune them
```

## Pull requests: one per task

Each task is pushed on its own branch and opened as its own small pull request; the next task starts when the previous PR is merged. A PR description says what the one task does, how it was tested, which rulings were made and the review result. A milestone's design and plan are not PRs of their own: they ride in the first task's PR. After a PR merges, run `scripts/dev/tidy --apply`.

Run `scripts/dev/tidy --apply` after every merged PR. It only removes branches that are fully merged and worktrees that are clean, and it never touches `main`.

## Commits

- Conventional Commits: `type(scope): summary`. Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `perf`, `build`. The scope is optional and names the crate or area: `core`, `store`, `store-conformance`, `store-sqlite`, `store-postgres`, `api`, `server`, `cli`, `sdk`, `e2e`, `skill`, `workspace`, `docs`, `adr`, `design`, `readme`, `ci`. Summary is imperative, lowercase, no trailing period, at most 72 characters.
- Pull requests are checked by `.github/workflows/pr-checks.yml`, which runs `scripts/ci/check-branch-name.sh` (branch names, as above) and `scripts/ci/check-commit-messages.sh` (every commit subject must match `^(feat|fix|refactor|test|docs|chore|ci|perf|build)(\([a-z0-9-]+\))?!?: .{1,72}$`). Run them locally before pushing.
- One logical change per commit. Tests and the code they cover go in the same commit.
- A task PR merges into `main` with a merge commit so each task stays visible in history; a release is tagged `v0.<N>.0` on the merge commit that completes the milestone.

## Definition of done for a task

1. Tests written first, seen failing, then passing.
2. `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` all pass; `cargo deny check` passes.
3. No `unsafe`, no `unwrap()` or `expect()` in non-test code unless the invariant is documented on that line. `stigmer-store-conformance` is test-support code whose assertion mechanism is panicking through the `ok` and `fail` helpers in `support.rs`, so this rule applies to product code, not to that crate's assertions.
4. Reviewed (spec compliance and code quality) before merge.

## Principles

- **YAGNI and DRY.** Build what the milestone needs. Extract on the third repetition, not the second.
- **Make invalid states unrepresentable.** Validate in constructors; domain types in `stigmer-core` cannot hold bad values.
- **Boundaries with traits.** Storage sits behind `Store`; backends are tested by one shared conformance suite.
- **Errors are values.** Library crates return typed errors (`thiserror`); only binaries print them.
- **No I/O in `stigmer-core`.** Pure logic is unit-tested without a runtime. The only I/O in core is `stigmer_core::now_ms`; everything else takes time as a parameter.
- **Decisions are written down.** Anything that changes the design goes in `docs/adr/NNNN-title.md` (context, decision, consequences) in the same branch that makes the change. See [docs/adr/](docs/adr/README.md) for the index and the template.
- **Small public surface.** Items are private unless another crate needs them.
