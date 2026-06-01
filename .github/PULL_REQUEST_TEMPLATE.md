<!--
Read CONTRIBUTING.md before opening this PR if you have not already. For
anything beyond a typo or a one-line fix, an issue should exist that this
PR closes.
-->

## What

<!-- One paragraph describing the change. -->

## Why

<!-- Why this change is needed and why this approach. The diff already
shows what; this section is for the rationale a future reader needs. -->

## Test plan

<!-- How you verified this works. For bug fixes, name the regression test
you added. For new behavior, name the tests that cover it. -->

## Checklist

- [ ] Title uses an imperative-mood prefix (`fix:`, `feat:`, `docs:`, `chore:`, `refactor:`, `test:`, `perf:`).
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --all` passes.
- [ ] CHANGELOG.md updated under `## [Unreleased]` if this changes user-visible behavior.
- [ ] New behavior has tests. Bug fixes have a regression test.
- [ ] One logical change in this PR. Unrelated cleanups go in a separate PR.
