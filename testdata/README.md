# testdata

Source for the fixtures the integration tests use. The compiled binaries are
not checked in — they're large and per-platform. Build them locally before
running `cargo test --features integration`.

```
cd testdata
./build-fixtures.sh
```

This writes `hello.{linux,darwin,windows}-{amd64,arm64}.stripped[.exe]` next
to `hello.go`. The tests look for these names; missing fixtures are skipped
with a note rather than failing, so partial coverage is fine.

The Go toolchain version on $PATH determines what gets exercised. v0.1
targets Go 1.20+; older binaries should fail with `UnsupportedPclntabVersion`.
