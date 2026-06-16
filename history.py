#!/usr/bin/env python3
"""history — show the evidence history (JSONL) as a timeline + changes.

Every time filtertest runs it appends a compact record to ~/.filterscope/history.jsonl.
This tool shows the per-network timeline and the changes between runs
(new block / lifted block) — "what changed and when".

Usage:
  ./history.py
  ./history.py /path/history.jsonl
"""
import json
import os
import sys
from collections import defaultdict


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
        "~/.filterscope/history.jsonl")
    if not os.path.exists(path):
        sys.exit(f"no history: {path}")

    runs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                runs.append(json.loads(line))
    if not runs:
        sys.exit("history is empty")

    by_net = defaultdict(list)
    for r in runs:
        by_net[(r.get("net", "?"), r.get("label", ""))].append(r)

    print(f"\n  EVIDENCE HISTORY — {len(runs)} runs, {len(by_net)} networks\n")
    for (net, label), items in by_net.items():
        items.sort(key=lambda r: r["ts"])
        head = label or net
        print(f"  ═══ network: {head}  [id {net}] — {len(items)} records ═══")
        prev = None
        for r in items:
            blocked = set(r.get("blocked", [])) | \
                {f"port {p}" for p in r.get("ports_blocked", [])}
            if r.get("udp", "").startswith("BLOCKED"):
                blocked.add("udp egress")
            if r.get("tor") not in ("ok", "", "tor-missing"):
                blocked.add(f"tor={r.get('tor')}")
            print(f"  {r['ts']}  ({len(blocked)} blocks)")
            if prev is not None:
                added = sorted(blocked - prev)
                removed = sorted(prev - blocked)
                for x in added:
                    print(f"       + NEW block: {x}")
                for x in removed:
                    print(f"       - lifted:    {x}")
                if not added and not removed:
                    print("       (no change)")
            else:
                for x in sorted(blocked):
                    print(f"       · {x}")
            prev = blocked
        print()


if __name__ == "__main__":
    main()
