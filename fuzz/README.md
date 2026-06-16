# unstrip fuzzing

libFuzzer targets over the code that reads attacker-controlled bytes. unstrip
parses hostile input by design, so the bar is: a malformed or crafted sample
returns an error, never a panic.

## Targets

- `parse_container`: the ELF / Mach-O / PE loader and the pclntab magic scan.
- `recover`: pclntab functions, the module data, the type and itab catalogs,
  and the build info.

## Running (needs the nightly toolchain and cargo-fuzz)

    cargo install cargo-fuzz
    cargo +nightly fuzz run parse_container
    cargo +nightly fuzz run recover

Bound a run with libFuzzer flags, e.g. a 60-second pass:

    cargo +nightly fuzz run recover -- -max_total_time=60

Seed the corpus with real Go binaries under `corpus/<target>/`: vary the Go
release, the container, and the architecture, and include PIE and garble builds.
The outputs of `testdata/build-fixtures.sh` are good seeds. A crash is written to
`artifacts/<target>/` and replays by passing the file back to the target.

Linux and macOS are the supported platforms. On Windows-MSVC the instrumented
binary links against the dynamic AddressSanitizer runtime, which is not on PATH
by default, so the run fails with STATUS_DLL_NOT_FOUND. Put the Visual Studio
copy on PATH first (adjust the version):

    PATH="$PATH:/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/<ver>/bin/Hostx64/x64"
