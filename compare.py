#!/usr/bin/env python3
"""compare — the filtering difference between two full reports (filtertest --json).

Classic evidence scenario: school network vs mobile data. Anything blocked on one
network but open on the other = evidence of filtering specific to that network.

Usage:
  ./compare.py school.json mobile.json
"""
import json
import sys


def load(p):
    with open(p) as f:
        return json.load(f)


def blocked_set(r):
    s = set()
    for dom, d in r.get("sites", {}).items():
        for k in ("dns", "sni", "blockpage"):
            v = d[k]["verdict"]
            if v not in ("ok", "?", "no-dns", "unreachable"):
                s.add(f"site {dom} [{k}={v}]")
    for label, st in r.get("ports", {}).items():
        if st.startswith("BLOCKED"):
            s.add(f"port {label}")
    if r.get("udp", "").startswith("BLOCKED"):
        s.add("udp egress")
    if r.get("tor", {}).get("verdict") not in ("ok", "", None, "tor-missing"):
        s.add("tor")
    return s


def name(r, fallback):
    n = r.get("net", {})
    return n.get("label") or n.get("id") or fallback


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: ./compare.py A.json B.json")
    a, b = load(sys.argv[1]), load(sys.argv[2])
    na, nb = name(a, sys.argv[1]), name(b, sys.argv[2])
    A, B = blocked_set(a), blocked_set(b)

    print(f"\n  COMPARISON: {na}  ↔  {nb}\n")
    only_a = sorted(A - B)
    only_b = sorted(B - A)
    both = sorted(A & B)

    print(f"  ⚑ Blocked only on '{na}' ({len(only_a)}):")
    for x in only_a:
        print(f"     - {x}")
    if not only_a:
        print("     (none)")
    print(f"\n  ⚑ Blocked only on '{nb}' ({len(only_b)}):")
    for x in only_b:
        print(f"     - {x}")
    if not only_b:
        print("     (none)")
    print(f"\n  ⓘ Blocked on both ({len(both)}):")
    for x in both:
        print(f"     - {x}")
    if not both:
        print("     (none)")
    if only_a and not only_b:
        print(f"\n  → filtering specific to '{na}'; '{nb}' is clean. Evidence.")
    print()


if __name__ == "__main__":
    main()
