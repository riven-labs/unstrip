# testdata

Source for the fixtures the integration tests use. The compiled binaries are not checked in; they are large and per-platform. Build them locally before running `cargo test`.

```
cd testdata
./build-fixtures.sh
```

This writes `hello.{linux,darwin,windows}-{amd64,arm64}.stripped[.exe]` next to `hello.go`. The tests look for these names. Missing fixtures are skipped with a note rather than failing, so partial coverage is fine.

The Go toolchain version on `$PATH` determines what gets exercised. Versioned builds use the matching `goX.Y.Z` command when it is on `$PATH` (`go install golang.org/dl/go1.20.14@latest && go1.20.14 download`) and are skipped otherwise.

Go 1.2 to 1.15 builds of `typeset.go` (`typeset.go12` to `typeset.go115`, for linux and windows, amd64 and 386) come from `~/sdk/goX.Y.Z` or the `goX.Y.Z` wrapper. For releases without a working wrapper, unpack the archive from https://go.dev/dl/ there (`~/sdk/go1.2.2/bin/go`). Go 1.4 and older cannot cross-compile, so they build only for the host: their Linux fixtures need a Linux host and the linux-amd64 archive. Each fixture is 0.9 to 1.8 MB.
