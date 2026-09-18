"""User configuration and local report store (~/.filterscope/)."""
from __future__ import annotations

import glob
import json
import os
import re

from . import sysinfo

DIR = os.path.dirname(sysinfo.HISTORY_PATH)
CONFIG_PATH = os.path.join(DIR, "config.json")
REPORTS_DIR = os.path.join(DIR, "reports")

DEFAULTS = {
    "label": "",             # default network label
    "timeout": 6.0,
    "tor": True,
    "categories": [],        # restrict to these site categories
    "domains": [],           # extra domains
    "steps_off": [],         # steps to skip
    "save_reports": True,    # keep full JSON of every scan under reports/
    "verify": True,          # re-check positives once before reporting them
    "workers": 20,
    "lang": "",              # "" = auto (system locale), "en" or "tr"
    "update_check": True,    # ask GitHub for a newer release (one request per start)
}

PROFILES = {
    "full":   {},
    "quick":  {"tor": False, "steps_off": ["tor", "proxy", "ssh", "ipv6", "mitm", "nxdomain", "urlfilter", "throttle"],
               "categories": ["info", "search", "social", "chat", "messaging", "video", "games", "ai", "vpn-api",
                              "vpn-info", "news", "news-tr", "education", "dev"]},
    "school": {"categories": ["games", "video", "music", "social", "chat", "messaging", "ai", "vpn-api", "vpn-info",
                              "webproxy", "circumvention", "education", "storage", "mail", "apps", "shopping", "info", "search"]},
    "isp":    {"categories": ["news", "news-tr", "rights", "privacy", "circumvention", "vpn-info", "vpn-api", "webproxy",
                              "social", "video", "crypto", "religion", "info", "search"]},
    "vpn":    {"categories": ["vpn-api", "vpn-info", "circumvention", "webproxy", "privacy"],
               "steps_off": ["proxy", "urlfilter", "nxdomain", "throttle"]},
}


def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            user = json.load(f)
        if isinstance(user, dict):
            cfg.update({k: v for k, v in user.items() if k in DEFAULTS})
    except (OSError, json.JSONDecodeError):
        pass
    return cfg


def save(cfg: dict):
    os.makedirs(DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in cfg.items() if k in DEFAULTS}, f, indent=2)


def set_value(key: str, raw: str) -> dict:
    if key not in DEFAULTS:
        raise KeyError(f"unknown key '{key}' (known: {', '.join(DEFAULTS)})")
    cfg = load()
    default = DEFAULTS[key]
    if isinstance(default, bool):
        val = raw.lower() in ("1", "true", "yes", "on")
    elif isinstance(default, float):
        val = float(raw)
    elif isinstance(default, int):
        val = int(raw)
    elif isinstance(default, list):
        val = [x.strip() for x in raw.split(",") if x.strip()]
    else:
        val = raw
    cfg[key] = val
    save(cfg)
    return cfg


def store_report(report: dict) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = re.sub(r"[^0-9]", "", report["ts"])[:14]
    path = os.path.join(REPORTS_DIR, f"{ts}-{report['net']['id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False)
    return path


def list_reports(net_id: str | None = None) -> list[str]:
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.json")))
    if net_id:
        files = [p for p in files if p.endswith(f"-{net_id}.json")]
    return files


def load_report(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def previous_report(net_id: str, before_ts: str | None = None) -> dict | None:
    for p in reversed(list_reports(net_id)):
        try:
            r = load_report(p)
        except (OSError, json.JSONDecodeError):
            continue
        if before_ts and r.get("ts", "") >= before_ts:
            continue
        return r
    return None
