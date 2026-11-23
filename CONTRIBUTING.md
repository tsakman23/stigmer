# Contributing and workflow

This is the working agreement for the repo. It is short on purpose.

## Branches

| Branch | Purpose | Lifetime |
|---|---|---|
| `main` | Always green and releasable. Nothing is committed to it directly. | permanent |
| `milestone/m<N>-<slug>` | Integration branch for one milestone, for example `milestone/m0-local-board`. | until merged into `main` |
| `<type>/m<N>-t<NN>-<slug>` | One task from the milestone plan, for example `feat/m0-t02-core-types`. | hours; deleted on merge |

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`. Slugs are lowercase kebab-case. Only these names are accepted by `scripts/dev/wt`.

## Worktrees

Every task is built in its own worktree under `.worktrees/` (git-ignored), branched from the tip of the milestone branch. The main checkout stays on the milestone branch and is never edited by hand.

```
scripts/dev/wt new feat/m0-t02-core-types     # create branch + worktree from the milestone tip
scripts/dev/wt finish feat/m0-t02-core-types  # rebase if needed, fast-forward merge, remove worktree, delete branch
scripts/dev/tidy                              # dry run: list stale worktrees and merged branches
scripts/dev/tidy --apply                      # prune them
```

Run `scripts/dev/tidy --apply` at the end of every task and at every milestone boundary. It only removes branches that are fully merged and worktrees that are clean, and it never touches `main` or `milestone/*`.

## Commits

- Conventional Commits: `type(scope): summary`. Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `perf`, `build`. The scope is optional and names the crate or area: `core`, `store`, `store-conformance`, `store-sqlite`, `api`, `server`, `cli`, `sdk`, `e2e`, `skill`, `workspace`, `docs`, `adr`, `design`, `readme`, `ci`. Summary is imperative, lowercase, no trailing period, at most 72 characters.
- Pull requests are checked by `.github/workflows/pr-checks.yml`, which runs `scripts/ci/check-branch-name.sh` (branch names, as above) and `scripts/ci/check-commit-messages.sh` (every commit subject must match `^(feat|fix|refactor|test|docs|chore|ci|perf|build)(\([a-z0-9-]+\))?!?: .{1,72}$`). Run them locally before pushing.
- One logical change per commit. Tests and the code they cover go in the same commit.
- Task branches are rebased onto the milestone branch and fast-forward merged, so each milestone has a linear, readable history.
- A milestone branch merges into `main` with a merge commit (`--no-ff`) so the milestone stays visible in history, then is tagged `v0.<N>.0`.

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
