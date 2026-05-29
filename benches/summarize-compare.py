#!/usr/bin/env python3
"""Read compare-runner JSON, emit a markdown comparison report."""
import json
import os
import sys

data = json.load(open(sys.argv[1]))
results = data["results"]

# Recovery table
print("## Recovery counts (functions / types / interfaces)\n")
print("| Binary | Size | unstrip fns | GoReSym fns | unstrip types | GoReSym types | unstrip itabs | GoReSym ifaces |")
print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for r in results:
    name = os.path.basename(r["binary"])
    sz_mb = r["size_bytes"] / (1024 * 1024)
    u_fns = r["unstrip"]["functions"]["count"]
    u_types = r["unstrip"]["types"]["count"]
    u_itabs = r["unstrip"]["itabs"]["count"]
    g = r["goresym"]["full"]
    g_user = g.get("user_functions") or 0
    g_std = g.get("std_functions") or 0
    g_fns = g_user + g_std
    g_types = g.get("types") or 0
    g_ifaces = g.get("interfaces") or 0
    print(f"| {name} | {sz_mb:.1f} MiB | {u_fns} | {g_fns} | {u_types} | {g_types} | {u_itabs} | {g_ifaces} |")

print()
print("## Wall-clock time (mean of 3 runs, ms)\n")
print("| Binary | unstrip fns | GoReSym default | unstrip --types | GoReSym -t | speedup (types) |")
print("| --- | ---: | ---: | ---: | ---: | ---: |")
for r in results:
    name = os.path.basename(r["binary"])
    u_fn = r["unstrip"]["functions"]["mean_s"] * 1000
    u_t = r["unstrip"]["types"]["mean_s"] * 1000
    g_d = r["goresym"]["default"]["mean_s"] * 1000
    g_f = r["goresym"]["full"]["mean_s"] * 1000
    speedup = g_f / u_t if u_t > 0 else 0
    print(f"| {name} | {u_fn:.1f} | {g_d:.1f} | {u_t:.1f} | {g_f:.1f} | {speedup:.1f}x |")

print()
print("## Peak RSS (KB)\n")
print("| Binary | unstrip fns | unstrip --types | GoReSym -t |")
print("| --- | ---: | ---: | ---: |")
for r in results:
    name = os.path.basename(r["binary"])
    u_fn = r["unstrip"]["functions"]["rss_peak_kb"]
    u_t = r["unstrip"]["types"]["rss_peak_kb"]
    g_f = r["goresym"]["full"]["rss_peak_kb"]
    print(f"| {name} | {u_fn} | {u_t} | {g_f} |")

print()
print("## Exit status (0 = OK)\n")
print("| Binary | unstrip fns | unstrip --types | unstrip --itabs | GoReSym default | GoReSym -t |")
print("| --- | ---: | ---: | ---: | ---: | ---: |")
for r in results:
    name = os.path.basename(r["binary"])
    print(f"| {name} | {r['unstrip']['functions']['exit']} | {r['unstrip']['types']['exit']} | {r['unstrip']['itabs']['exit']} | {r['goresym']['default']['exit']} | {r['goresym']['full']['exit']} |")
