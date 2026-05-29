#!/usr/bin/env python3
"""Sample what GoReSym recovers vs unstrip. Diagnostic only."""
import json
import subprocess
import sys

binary = sys.argv[1]
gr = subprocess.run(["/home/mohamed/go/bin/GoReSym", "-t", "-d", "-p", binary],
                    capture_output=True)
d = json.loads(gr.stdout)
types = d.get("Types") or []
ifaces = d.get("Interfaces") or []

print(f"GoReSym: Types={len(types)} Interfaces={len(ifaces)}")
print()
print("=== Types sample (first 15) ===")
for t in types[:15]:
    name = t.get("Str", "?")
    kind = t.get("Kind", "?")
    print(f"  kind={kind:8}  {name}")

print()
print("=== Interfaces sample (first 10) ===")
for i in ifaces[:10]:
    if isinstance(i, dict):
        print(f"  {i.get('Name', i)}")
    else:
        print(f"  {i}")

# Count by kind
from collections import Counter
kinds = Counter()
for t in types:
    kinds[t.get("Kind", "?")] += 1
print()
print("=== Types by kind ===")
for k, n in kinds.most_common():
    print(f"  {k:20} {n}")
