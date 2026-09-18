"""Host/network identity — Linux, Windows and macOS. Best effort; every probe
degrades to an empty string rather than failing."""
from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

HISTORY_PATH = os.path.join(os.path.expanduser("~"), ".filterscope", "history.jsonl")


def _run(cmd, timeout=4):
    try:
        kw = {}
        if IS_WIN:
            kw["creationflags"] = 0x08000000   # CREATE_NO_WINDOW
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", **kw).stdout
    except Exception:
        return ""


def resolver() -> str:
    """First configured nameserver."""
    if IS_WIN:
        out = _run(["ipconfig", "/all"])
        m = re.search(r"DNS Servers[ .]*:\s*(\S+)", out)
        return m.group(1) if m else _dnspython_ns()
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except OSError:
        pass
    return _dnspython_ns()


def _dnspython_ns() -> str:
    try:
        import dns.resolver
        ns = dns.resolver.get_default_resolver().nameservers
        return str(ns[0]) if ns else ""
    except Exception:
        return ""


def search_domain() -> str:
    if IS_WIN:
        out = _run(["ipconfig", "/all"])
        m = re.search(r"Connection-specific DNS Suffix[ .]*:\s*(\S+)", out)
        return m.group(1) if m else ""
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith(("search", "domain")):
                    return line.split(None, 1)[1].strip()
    except OSError:
        pass
    return ""


def gateway() -> str:
    if IS_WIN:
        out = _run(["route", "print", "-4", "0.0.0.0"])
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        return m.group(1) if m else ""
    if IS_MAC:
        out = _run(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*(\S+)", out)
        return m.group(1) if m else ""
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else ""


def ssid() -> str:
    if IS_WIN:
        out = _run(["netsh", "wlan", "show", "interfaces"])
        m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", out, re.M)
        return m.group(1) if m else ""
    if IS_MAC:
        for iface in ("en0", "en1"):
            out = _run(["ipconfig", "getsummary", iface])
            m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", out, re.M)
            if m:
                return m.group(1)
            out = _run(["networksetup", "-getairportnetwork", iface])
            m = re.search(r"Network:\s*(.+)$", out, re.M)
            if m:
                return m.group(1).strip()
        return ""
    if shutil.which("iwgetid"):
        s = _run(["iwgetid", "-r"]).strip()
        if s:
            return s
    if shutil.which("nmcli"):
        for line in _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).splitlines():
            if line.startswith("yes:"):
                return line[4:].strip()
    if shutil.which("iw"):
        m = re.search(r"^\s*ssid\s+(.+)$", _run(["iw", "dev"]), re.M)
        if m:
            return m.group(1).strip()
    return ""


def os_string() -> str:
    try:
        return f"{platform.system()} {platform.release()}"
    except Exception:
        return sys.platform


def net_fingerprint(label: str | None = None) -> dict:
    fp = {"label": label or "", "search": search_domain(), "gateway": gateway(),
          "resolver": resolver(), "ssid": ssid(), "os": os_string()}
    fp["id"] = hashlib.sha1(
        f"{fp['search']}|{fp['gateway']}|{fp['resolver']}|{fp['ssid']}".encode()
    ).hexdigest()[:8]
    return fp


def net_name(fp: dict) -> str:
    return fp.get("label") or fp.get("ssid") or fp.get("search") or "?"
