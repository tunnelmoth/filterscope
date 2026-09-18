"""history — the evidence history (JSONL) as a timeline + changes.

Every scan appends a compact record to ~/.filterscope/history.jsonl. This shows
the per-network timeline and the changes between runs (new block / lifted block)."""
from __future__ import annotations

import json
import os
from collections import defaultdict

from rich.console import Console
from rich.markup import escape

from . import sysinfo

console = Console(highlight=False)


def blocked_of(r) -> set:
    blocked = set(r.get("blocked", [])) | {f"port {p}" for p in r.get("ports_blocked", [])}
    if r.get("udp", "").startswith("BLOCKED"):
        blocked.add("udp egress")
    if r.get("quic", "").startswith("BLOCKED"):
        blocked.add("quic/udp-443")
    if r.get("tor") not in ("ok", "", "tor-missing", None):
        blocked.add(f"tor={r.get('tor')}")
    blocked |= {f"encrypted-dns {k}" for k in r.get("dns_encrypted_blocked", [])}
    if r.get("dns_intercept") == "INTERCEPTED":
        blocked.add("dns-53 intercepted")
    if r.get("http_proxy") == "PROXY":
        blocked.add("http transparent proxy")
    return blocked


def show(path=None, network=None, last=None) -> int:
    path = path or sysinfo.HISTORY_PATH
    if not os.path.exists(path):
        console.print(f"[red]no history: {path}[/]")
        return 1
    runs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    runs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not runs:
        console.print("[yellow]history is empty[/]")
        return 1

    by_net = defaultdict(list)
    for r in runs:
        by_net[(r.get("net", "?"), r.get("label", ""))].append(r)

    console.print(f"\n[bold]  EVIDENCE HISTORY[/] [dim]— {len(runs)} runs, {len(by_net)} networks, {path}[/]\n")
    for (net, label), items in by_net.items():
        head = label or net
        if network and network not in (net, label):
            continue
        items.sort(key=lambda r: r["ts"])
        if last:
            items = items[-last:]
        console.print(f"[bold]  ═══ network: {head}  [id {net}] — {len(items)} records ═══[/]")
        prev = None
        for r in items:
            blocked = blocked_of(r)
            console.print(f"  {r['ts']}  [dim]({len(blocked)} blocks)[/]")
            if prev is not None:
                added, removed = sorted(blocked - prev), sorted(prev - blocked)
                for x in added:
                    console.print(f"       [red]+ NEW block: {escape(x)}[/]")
                for x in removed:
                    console.print(f"       [green]- lifted:    {escape(x)}[/]")
                if not added and not removed:
                    console.print("       [dim](no change)[/]")
            else:
                for x in sorted(blocked):
                    console.print(f"       · {escape(x)}")
            prev = blocked
        console.print()
    return 0
