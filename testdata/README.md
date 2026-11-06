# testdata

Source for the fixtures the integration tests use. The compiled binaries are not checked in; they are large and per-platform. Build them locally before running `cargo test`.

```
cd testdata
./build-fixtures.sh
```

This writes `hello.{linux,darwin,windows}-{amd64,arm64}.stripped[.exe]` next to `hello.go`. The tests look for these names. Missing fixtures are skipped with a note rather than failing, so partial coverage is fine.

The Go toolchain version on `$PATH` determines what gets exercised. unstrip reads Go 1.16 and newer. Older binaries fail with `UnsupportedPclntabVersion`. Versioned builds use the matching `goX.Y.Z` command when it is on `$PATH` (`go install golang.org/dl/go1.20.14@latest && go1.20.14 download`) and are skipped otherwise.
