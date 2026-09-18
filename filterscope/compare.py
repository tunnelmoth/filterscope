"""compare — the filtering difference between two full reports (scan --json).

Classic evidence scenario: school network vs mobile data. Anything blocked on one
network but open on the other = evidence of filtering specific to that network."""
from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape

from . import core

console = Console(highlight=False)


def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def blocked_set(r):
    s = set()
    for dom, d in r.get("sites", {}).items():
        for k in ("dns", "sni", "blockpage"):
            v = d[k]["verdict"]
            if v not in core.NEUTRAL:
                s.add(f"site {dom} [{k}={v}]")
    for label, st in r.get("ports", {}).items():
        if st.startswith("BLOCKED"):
            s.add(f"port {label}")
    if r.get("udp", "").startswith("BLOCKED"):
        s.add("udp egress")
    if r.get("quic", "").startswith("BLOCKED"):
        s.add("quic/udp-443")
    if r.get("tor", {}).get("verdict") not in ("ok", "", None, "tor-missing"):
        s.add("tor")
    for k, v in r.get("dns_encrypted", {}).items():
        if v.startswith("BLOCKED"):
            s.add(f"encrypted-dns {k}")
    if r.get("dns_intercept", {}).get("verdict") == "INTERCEPTED":
        s.add("dns-53 intercepted")
    if r.get("http_proxy", {}).get("verdict") == "PROXY":
        s.add("http transparent proxy")
    return s


def name(r, fallback):
    n = r.get("net", {})
    return n.get("label") or n.get("ssid") or n.get("id") or fallback


def compare(path_a, path_b) -> int:
    a, b = load(path_a), load(path_b)
    na, nb = name(a, path_a), name(b, path_b)
    A, B = blocked_set(a), blocked_set(b)
    only_a, only_b, both = sorted(A - B), sorted(B - A), sorted(A & B)

    console.print(f"\n[bold]  COMPARISON: {na}  ↔  {nb}[/]  [dim]{a.get('ts', '')} vs {b.get('ts', '')}[/]\n")
    for title, items in ((f"⚑ Blocked only on '{na}'", only_a), (f"⚑ Blocked only on '{nb}'", only_b)):
        console.print(f"[bold red]  {title} ({len(items)}):[/]" if items else f"[dim]  {title} (0)[/]")
        for x in items:
            console.print(f"     - {escape(x)}")
    console.print(f"\n[dim]  ⓘ Blocked on both ({len(both)}):[/]")
    for x in both:
        console.print(f"     - {escape(x)}")
    if only_a and not only_b:
        console.print(f"\n[bold green]  → filtering specific to '{na}'; '{nb}' is clean. Evidence.[/]")
    elif only_b and not only_a:
        console.print(f"\n[bold green]  → filtering specific to '{nb}'; '{na}' is clean. Evidence.[/]")
    console.print()
    return 2 if (only_a or only_b) else 0
