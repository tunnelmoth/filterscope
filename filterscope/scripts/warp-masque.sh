#!/usr/bin/env bash
# Install the official Cloudflare WARP client in MASQUE mode (NO AUR — Cloudflare's own .deb).
# MASQUE/HTTP3 traffic looks like normal HTTPS → bypasses WireGuard-DPI.
# Run with sudo:  sudo bash warp-masque.sh
set -e
DEB_BASE="https://pkg.cloudflareclient.com"
WORK="/tmp/warp-masque"
G='\033[32m'; R='\033[31m'; D='\033[2m'; X='\033[0m'
say(){ echo -e "${1}${2}${X}"; }

[ "$(id -u)" = 0 ] || { say "$R" "run with sudo: sudo bash warp-masque.sh"; exit 1; }

if ! command -v warp-cli >/dev/null; then
  say "$D" "downloading the official Cloudflare WARP package (not AUR)…"
  mkdir -p "$WORK"; cd "$WORK"
  if [ ! -f warp.deb ]; then
    # verify the apt metadata chain: Release (signed) → Packages (sha256) → .deb (sha256)
    curl -fsSL "$DEB_BASE/dists/bookworm/Release" -o Release
    curl -fsSL "$DEB_BASE/dists/bookworm/Release.gpg" -o Release.gpg
    curl -fsSL "$DEB_BASE/pubkey.gpg" -o pubkey.gpg
    if command -v gpgv >/dev/null 2>&1; then
      gpg --dearmor < pubkey.gpg > keyring.gpg 2>/dev/null || cp pubkey.gpg keyring.gpg
      gpgv --keyring "$PWD/keyring.gpg" Release.gpg Release || { say "$R" "Release signature INVALID — aborting"; exit 1; }
    else
      say "$R" "gpgv not found: cannot verify the repository signature (hashes still checked over HTTPS)"
    fi
    curl -fsSL "$DEB_BASE/dists/bookworm/main/binary-amd64/Packages" -o Packages
    want=$(awk '/^SHA256:/{f=1;next} f && /main\/binary-amd64\/Packages$/{print $1; exit}' Release)
    have=$(sha256sum Packages | cut -d' ' -f1)
    [ -n "$want" ] && [ "$want" = "$have" ] || { say "$R" "Packages hash mismatch — aborting"; exit 1; }
    deb=$(awk -F': ' '/^Filename:/{print $2; exit}' Packages)
    debsum=$(awk -F': ' '/^SHA256:/{print $2; exit}' Packages)
    curl -fsSL "$DEB_BASE/$deb" -o warp.deb
    [ "$(sha256sum warp.deb | cut -d' ' -f1)" = "$debsum" ] || { rm -f warp.deb; say "$R" ".deb hash mismatch — aborting"; exit 1; }
    say "$G" "package verified (signature + sha256)"
  fi
  rm -rf root && mkdir root
  ar x warp.deb && tar xf data.tar.* -C root
  say "$D" "installing binaries → /usr/bin"
  install -m755 root/bin/warp-svc root/bin/warp-cli root/bin/warp-diag /usr/bin/
  [ -f root/bin/warp-dex ] && install -m755 root/bin/warp-dex /usr/bin/ || true
  install -m644 root/lib/systemd/system/warp-svc.service /etc/systemd/system/
  systemctl daemon-reload
  say "$G" "installed: $(warp-cli --version)"
fi

say "$D" "starting the warp-svc daemon…"
systemctl enable --now warp-svc
for i in $(seq 1 15); do warp-cli status >/dev/null 2>&1 && break; sleep 1; done

# bring down the wgcf-WARP tunnel if it's up (avoid a conflict)
wg-quick down warp 2>/dev/null || true

if ! warp-cli registration show >/dev/null 2>&1; then
  say "$D" "registering device…"
  out=$(warp-cli --accept-tos registration new 2>&1 || true)
  if echo "$out" | grep -qi "old registration"; then
    say "$D" "deleting the old registration…"; warp-cli registration delete || true
    warp-cli --accept-tos registration new
  fi
fi
warp-cli --accept-tos mode warp
warp-cli --accept-tos tunnel protocol set MASQUE
say "$D" "connecting (MASQUE)…"
warp-cli --accept-tos connect
sleep 4

ip=$(curl -fsS --max-time 10 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p')
warp=$(curl -fsS --max-time 10 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^warp=//p')
if [ "$warp" = on ] || [ "$warp" = plus ]; then
  say "$G" "✓ WARP MASQUE ACTIVE (warp=$warp, exit IP $ip) — WireGuard-DPI bypassed."
else
  say "$R" "✗ MASQUE failed to connect (warp=${warp:-?}). Check 'warp-cli status' and 'warp-diag'."
  warp-cli status 2>/dev/null || true
fi
