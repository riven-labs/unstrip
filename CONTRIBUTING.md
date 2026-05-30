# Contributing to unstrip

Thanks for the interest.

## Before you start

For anything beyond a typo or a one-line fix, open an issue first. It saves time on both sides if we agree on the approach before code is written.

## Reporting bugs

Open a GitHub issue with:

1. `unstrip --version`.
2. Host platform.
3. `unstrip <bin> --info` output for the target binary (or as much of it as you can share).
4. The exact command you ran and the output you got.
5. What you expected instead.

A minimal Go reproducer (`main.go` plus the build command) is the best attachment when the original binary cannot be shared.

## Reporting vulnerabilities

Do not open a public issue. See [SECURITY.md](./SECURITY.md).

## Development setup

```
git clone https://github.com/riven-labs/unstrip
cd unstrip
cargo build
cargo test
```

Integration tests need fixtures built from a local Go toolchain:

```
cd testdata && ./build-fixtures.sh && cd ..
cargo test --features integration
```

Requirements: Rust 1.85 or newer, Go 1.18 or newer on `$PATH` for the integration fixtures.

## Before you open a PR

Run the same checks CI runs:

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets
cargo test --all
```

If any fails locally, it will fail in CI.

## Pull request conventions

- One logical change per PR.
- Title in imperative mood with a `fix:` / `feat:` / `docs:` / `chore:` / `refactor:` / `test:` / `perf:` prefix.
- PR body explains why the change is needed and why this approach.
- New behavior has tests. Bug fixes have a regression test.
- Update [CHANGELOG.md](./CHANGELOG.md) under `## Unreleased`.
- Match the existing voice in any text changes: short, concrete, builder-to-builder.

## License

By contributing, you agree your contribution is licensed under the [MIT License](./LICENSE).
