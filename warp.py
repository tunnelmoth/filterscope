#!/usr/bin/env python3
"""warp — install/manage Cloudflare WARP without AUR (wgcf + wireguard-tools).

Manages the WARP WireGuard tunnel from one place to bypass filters like SNI-DPI.
NO AUR: uses wgcf from its GitHub release and wireguard from the official repo.

Commands:
  setup     download wgcf (if missing), register a WARP account, generate a profile
  test      handshake check: reachable on this network? (no sudo)
  up        bring the tunnel up (sudo) + verify
  down      bring the tunnel down (sudo)
  status    status + curl trace (warp=on?)
  autostart enable at boot (systemd, sudo)

Usage:  ./warp.py up    ./warp.py status
"""
import os
import shutil
import subprocess
import sys

import requests

HOME = os.path.expanduser("~")
WARP_DIR = os.path.join(HOME, ".warp")
PROFILE = os.path.join(WARP_DIR, "wgcf-profile.conf")
ACCOUNT = os.path.join(WARP_DIR, "wgcf-account.toml")
WGCF = os.path.join(HOME, ".local", "bin", "wgcf")
SYS_CONF = "/etc/wireguard/warp.conf"
IFACE = "warp"
HERE = os.path.dirname(os.path.abspath(__file__))

G, R, Y, D, X = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def say(c, m):
    print(f"{c}{m}{X}")


def run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def ensure_wgcf():
    if os.path.exists(WGCF) or shutil.which("wgcf"):
        return shutil.which("wgcf") or WGCF
    say(D, "wgcf missing → downloading from GitHub release (not AUR)…")
    rel = requests.get("https://api.github.com/repos/ViRb3/wgcf/releases/latest",
                       timeout=15).json()
    tag = rel["tag_name"]
    num = tag.lstrip("v")
    url = f"https://github.com/ViRb3/wgcf/releases/download/{tag}/wgcf_{num}_linux_amd64"
    os.makedirs(os.path.dirname(WGCF), exist_ok=True)
    with requests.get(url, timeout=60, stream=True) as r:
        r.raise_for_status()
        with open(WGCF, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
    os.chmod(WGCF, 0o755)
    say(G, f"installed wgcf {tag} → {WGCF}")
    return WGCF


def setup():
    wgcf = ensure_wgcf()
    os.makedirs(WARP_DIR, exist_ok=True)
    if not os.path.exists(ACCOUNT):
        say(D, "registering WARP account…")
        run([wgcf, "register", "--accept-tos"], cwd=WARP_DIR, check=True)
    if not os.path.exists(PROFILE):
        say(D, "generating WireGuard profile…")
        run([wgcf, "generate"], cwd=WARP_DIR, check=True)
    say(G, f"ready: {PROFILE}")


def test():
    if not os.path.exists(PROFILE):
        setup()
    say(D, "handshake test (using our own wgcheck tool)…")
    p = run([sys.executable, os.path.join(HERE, "wgcheck.py"),
             "--config", PROFILE], capture_output=True, text=True)
    print(p.stdout.strip())
    if p.returncode != 0:
        say(R, "WARP looks unreachable on this network.")
    return p.returncode == 0


# Known alternative UDP ports that WARP accepts WireGuard on
WARP_PORTS = [2408, 500, 1701, 4500, 853, 123, 880, 943]


def install_conf(port=None):
    if not os.path.exists(PROFILE):
        setup()
    # Drop the DNS line (on systems without openresolv integration wg-quick fails
    # with 'resolvconf signature mismatch') and instead point resolv.conf directly
    # at 1.1.1.1 via PostUp/PostDown; restore the original on teardown.
    # (the school's 8.8.8.8 doesn't resolve through the tunnel → use Cloudflare resolver.)
    post = ("PostUp = cp -f /etc/resolv.conf /etc/resolv.conf.warpbak && "
            "printf 'nameserver 1.1.1.1\\nnameserver 1.0.0.1\\n' > /etc/resolv.conf\n"
            "PostDown = mv -f /etc/resolv.conf.warpbak /etc/resolv.conf\n")
    lines = []
    for l in open(PROFILE):
        if l.strip().lower().startswith("dns"):
            continue
        if port and l.strip().lower().startswith("endpoint"):
            host = l.split("=", 1)[1].strip().rsplit(":", 1)[0]
            l = f"Endpoint = {host}:{port}\n"   # alternative port
        if l.strip() == "[Peer]":
            lines.append(post)          # keep PostUp/Down inside [Interface]
        lines.append(l)
    tmp = os.path.join(WARP_DIR, ".warp-sys.conf")
    with open(tmp, "w") as f:
        f.write("".join(lines))
    say(D, f"copying profile to system (sudo, DNS line stripped) → {SYS_CONF}")
    run(["sudo", "install", "-D", "-m", "600", tmp, SYS_CONF], check=True)
    os.remove(tmp)


def data_ok():
    """Does REAL data flow through the tunnel — DNS-free ping to 1.1.1.1."""
    import time
    time.sleep(1.5)
    r = run(["ping", "-c", "2", "-W", "2", "1.1.1.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def _up_raw(port=None):
    run(["sudo", "wg-quick", "down", IFACE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    install_conf(port)
    return run(["sudo", "wg-quick", "up", IFACE],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def up(port=None):
    install_conf(port)
    say(D, f"bringing tunnel up (sudo){f', port {port}' if port else ''}…")
    if run(["sudo", "wg-quick", "up", IFACE]).returncode != 0:
        say(Y, "may already be up; verifying…")
    if data_ok():
        verify()
    else:
        say(R, "✗ no data through the tunnel → starting automatic port search…")
        autoport()


def autoport():
    """Try WARP ports one by one; keep the first that actually passes data."""
    for p in WARP_PORTS:
        say(D, f"trying UDP port {p}…")
        if _up_raw(p) and data_ok():
            say(G, f"✓ port {p} WORKS — data is flowing.")
            verify()
            return p
        run(["sudo", "wg-quick", "down", IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    say(R, "✗ no WARP port passed data.")
    say(Y, "→ the network may be throttling WireGuard (UDP) entirely. Next option: "
           "WARP MASQUE (TCP/443) or Shadowsocks/wstunnel (443 open).")
    return None


def down():
    run(["sudo", "wg-quick", "down", IFACE])
    say(G, "tunnel down.")


def masque(action="up"):
    """Official Cloudflare client (MASQUE) — bypasses WireGuard-DPI. up|down|status."""
    if not action or action == "up":
        run(["sudo", "bash", os.path.join(HERE, "warp-masque.sh")])
    elif action == "down":
        run(["warp-cli", "disconnect"])
        say(G, "WARP MASQUE disconnected.")
    elif action == "status":
        run(["warp-cli", "status"])
        verify()
    else:
        sys.exit("masque: up | down | status")


def diagnose():
    """Is data flowing through the tunnel — handshake + transfer counters."""
    say(D, "diag: wg status (handshake + transfer)")
    run(["sudo", "wg", "show", IFACE, "latest-handshakes"])
    run(["sudo", "wg", "show", IFACE, "transfer"])
    say(D, "raw IP reachability (DNS-free): ping 1.1.1.1")
    run(["ping", "-c", "3", "-W", "2", "1.1.1.1"])


def verify():
    import time
    time.sleep(1.5)  # the first packet triggers the handshake, let it settle
    # DNS-free check: hit 1.1.1.1 directly (the cert is valid for 1.1.1.1)
    try:
        t = requests.get("https://1.1.1.1/cdn-cgi/trace", timeout=10).text
        kv = dict(l.split("=", 1) for l in t.splitlines() if "=" in l)
        warp, ip = kv.get("warp", "?"), kv.get("ip", "?")
        if warp in ("on", "plus"):
            say(G, f"✓ WARP ACTIVE (warp={warp}, exit IP {ip}) — SNI-DPI bypassed.")
        else:
            say(R, f"✗ WARP off (warp={warp}, IP {ip}).")
        return
    except Exception as e:
        say(R, f"✗ no data through the tunnel: {type(e).__name__}")
    diagnose()
    say(Y, "If handshake is present but transfer/ping is 0 → the network is dropping "
           "UDP 2408 data (lets the handshake through but throttles the tunnel). "
           "Fix: WARP MASQUE (443) or a different port/protocol tunnel.")


def status():
    run(["sudo", "wg", "show", IFACE])
    verify()


def autostart():
    install_conf()
    run(["sudo", "systemctl", "enable", f"wg-quick@{IFACE}"], check=True)
    say(G, "enabled at boot (wg-quick@warp).")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "up"
    fns = {"setup": setup, "test": test, "up": up, "down": down,
           "status": status, "autostart": autostart, "autoport": autoport,
           "masque": masque}
    fn = fns.get(cmd)
    if not fn:
        sys.exit(f"commands: {', '.join(fns)} (masque: up|down|status)")
    arg = sys.argv[2] if len(sys.argv) > 2 else None
    try:
        if cmd == "up":
            fn(int(arg) if arg else None)   # warp up [port]
        elif cmd == "masque":
            fn(arg or "up")                  # warp masque up|down|status
        else:
            fn()
    except subprocess.CalledProcessError as e:
        sys.exit(f"error: {e}")
    except KeyboardInterrupt:
        sys.exit("\naborted")


if __name__ == "__main__":
    main()
