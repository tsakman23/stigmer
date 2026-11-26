<!--
Title: a Conventional Commit subject, for example "fix(cli): exit 3 when a wait times out".
One task per pull request; keep it small.
-->

## What and why

<!-- In plain language: what this changes and why it is needed. Link the issue or milestone task if there is one. -->

## How it was tested

<!-- The tests you added or ran, and anything you checked by hand. -->

## Rulings and review

<!-- Decisions you made along the way (an ADR if the design changed), and the review result. -->

## Checklist

- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and `cargo deny check` pass
- [ ] `scripts/ci/check-branch-name.sh <branch>` and `scripts/ci/check-commit-messages.sh main HEAD` pass
- [ ] Docs and ADRs updated if behaviour or design changed
