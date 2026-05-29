#!/usr/bin/env python3
"""Head-to-head benchmark for unstrip vs GoReSym.

For each input binary, runs both tools with comparable flags, captures:
  - wall-clock time (multiple runs, mean + min + max)
  - peak RSS (memory)
  - function count recovered
  - type count recovered
  - itab/interface count recovered
  - exit status

Writes a JSON report to stdout. Designed to be wrapped by a shell script
that runs it across a corpus and feeds the output into a markdown table.

Usage:
    python3 compare-runner.py --unstrip <PATH> --goresym <PATH> <BINARY> [<BINARY>...]
"""

import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import time


def run_timed(cmd: list[str], runs: int = 3) -> dict:
    """Run cmd `runs` times. Return wall times (s) and peak RSS (KB)."""
    times = []
    rss_peak_kb = 0
    last_stdout = b""
    last_stderr = b""
    last_returncode = 0
    for _ in range(runs):
        start = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate(timeout=600)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        last_stdout = out
        last_stderr = err
        last_returncode = proc.returncode
        # RSS via getrusage of children (cumulative; use difference per call
        # for a rough peak. Linux reports max RSS in KB.)
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        rss_peak_kb = max(rss_peak_kb, usage.ru_maxrss)
    return {
        "mean_s": sum(times) / len(times),
        "min_s": min(times),
        "max_s": max(times),
        "runs": runs,
        "rss_peak_kb": rss_peak_kb,
        "exit": last_returncode,
        "stdout_bytes": len(last_stdout),
        "stderr_tail": last_stderr.decode("utf-8", errors="replace")[-200:] if last_stderr else "",
        "stdout": last_stdout,
    }


def count_unstrip_functions(stdout: bytes) -> int:
    """unstrip default mode: one function per line, lines starting with 0x."""
    n = 0
    for line in stdout.splitlines():
        if line.startswith(b"0x"):
            n += 1
    return n


def count_unstrip_types(stdout: bytes) -> int:
    """unstrip --types: header lines start with 0x; field-detail lines start
    with whitespace. Count just the type headers."""
    n = 0
    for line in stdout.splitlines():
        if line.startswith(b"0x"):
            n += 1
    return n


def count_unstrip_itabs(stdout: bytes) -> int:
    """unstrip --itabs: header lines start with 0x; method-detail lines indented."""
    n = 0
    for line in stdout.splitlines():
        if line.startswith(b"0x"):
            n += 1
    return n


def parse_goresym(stdout: bytes) -> dict:
    """GoReSym emits a JSON blob. Return counts; None on parse error."""
    try:
        d = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "user_functions": None,
            "std_functions": None,
            "types": None,
            "interfaces": None,
            "files": None,
            "go_version": None,
            "parse_ok": False,
        }
    def L(k):
        v = d.get(k)
        return len(v) if v else 0
    return {
        "user_functions": L("UserFunctions"),
        "std_functions": L("StdFunctions"),
        "types": L("Types"),
        "interfaces": L("Interfaces"),
        "files": L("Files"),
        "go_version": d.get("Version"),
        "parse_ok": True,
    }


def bench_binary(unstrip: str, goresym: str, binary: str, runs: int) -> dict:
    """Run both tools against a single binary."""
    sz = os.path.getsize(binary)
    result = {
        "binary": binary,
        "size_bytes": sz,
        "unstrip": {},
        "goresym": {},
    }

    # unstrip: separate runs for functions, types, itabs, info.
    r_fn = run_timed([unstrip, binary], runs=runs)
    result["unstrip"]["functions"] = {
        "mean_s": r_fn["mean_s"], "min_s": r_fn["min_s"], "rss_peak_kb": r_fn["rss_peak_kb"],
        "count": count_unstrip_functions(r_fn["stdout"]) if r_fn["exit"] == 0 else 0,
        "exit": r_fn["exit"], "stderr_tail": r_fn["stderr_tail"],
    }

    r_types = run_timed([unstrip, binary, "--types"], runs=runs)
    result["unstrip"]["types"] = {
        "mean_s": r_types["mean_s"], "min_s": r_types["min_s"], "rss_peak_kb": r_types["rss_peak_kb"],
        "count": count_unstrip_types(r_types["stdout"]) if r_types["exit"] == 0 else 0,
        "exit": r_types["exit"], "stderr_tail": r_types["stderr_tail"],
    }

    r_itabs = run_timed([unstrip, binary, "--itabs"], runs=runs)
    result["unstrip"]["itabs"] = {
        "mean_s": r_itabs["mean_s"], "min_s": r_itabs["min_s"], "rss_peak_kb": r_itabs["rss_peak_kb"],
        "count": count_unstrip_itabs(r_itabs["stdout"]) if r_itabs["exit"] == 0 else 0,
        "exit": r_itabs["exit"], "stderr_tail": r_itabs["stderr_tail"],
    }

    # GoReSym: one invocation gives everything when called with -t -d -p.
    r_gr_full = run_timed([goresym, "-t", "-d", "-p", binary], runs=runs)
    parsed = parse_goresym(r_gr_full["stdout"]) if r_gr_full["exit"] == 0 else {
        "user_functions": None, "std_functions": None, "types": None,
        "interfaces": None, "files": None, "go_version": None, "parse_ok": False,
    }
    result["goresym"]["full"] = {
        "mean_s": r_gr_full["mean_s"], "min_s": r_gr_full["min_s"], "rss_peak_kb": r_gr_full["rss_peak_kb"],
        "exit": r_gr_full["exit"], "stderr_tail": r_gr_full["stderr_tail"],
        **parsed,
    }

    # GoReSym default mode (functions only, faster, more comparable to
    # `unstrip` default).
    r_gr_default = run_timed([goresym, binary], runs=runs)
    parsed_d = parse_goresym(r_gr_default["stdout"]) if r_gr_default["exit"] == 0 else {
        "user_functions": None, "std_functions": None, "types": None,
        "interfaces": None, "files": None, "go_version": None, "parse_ok": False,
    }
    result["goresym"]["default"] = {
        "mean_s": r_gr_default["mean_s"], "min_s": r_gr_default["min_s"], "rss_peak_kb": r_gr_default["rss_peak_kb"],
        "exit": r_gr_default["exit"], "stderr_tail": r_gr_default["stderr_tail"],
        **parsed_d,
    }

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unstrip", required=True, help="path to unstrip binary")
    ap.add_argument("--goresym", required=True, help="path to GoReSym binary")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("binaries", nargs="+")
    args = ap.parse_args()

    if not shutil.which(args.unstrip) and not os.path.exists(args.unstrip):
        print(f"unstrip not found: {args.unstrip}", file=sys.stderr)
        sys.exit(2)
    if not shutil.which(args.goresym) and not os.path.exists(args.goresym):
        print(f"goresym not found: {args.goresym}", file=sys.stderr)
        sys.exit(2)

    results = []
    for b in args.binaries:
        if not os.path.exists(b):
            print(f"skipping missing: {b}", file=sys.stderr)
            continue
        print(f"benching {os.path.basename(b)} ({os.path.getsize(b)//1024//1024} MiB)...", file=sys.stderr)
        results.append(bench_binary(args.unstrip, args.goresym, b, args.runs))

    json.dump({"results": results}, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
