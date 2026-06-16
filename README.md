# filterscope

A small tool that measures the **filtering/censorship** behavior of the network you're connected to, legitimately. For digital rights / transparency — in the spirit of EFF & Tor.

> ⚠️ Run it only **from your own device, with your own traffic**. The tool uses a **clean allowlist** (well-known news / social / privacy / dev sites) — it does **not ping** inappropriate or illegal content. This is a deliberate choice to avoid the controversial-domain problem of global test lists like OONI.

## What it measures

| Test | Method |
|---|---|
| **DNS tampering / hijack** | Compares the system resolver + direct `@8.8.8.8` (port 53) answer against DoH (over HTTPS, unhijackable) as the reference. To reduce false positives, only private-IP redirection and NXDOMAIN injection are flagged; a mere IP difference is treated as CDN. |
| **TLS / SNI blocking (DPI)** | Connects to the real IP; if the handshake with the correct SNI gets an RST but a harmless SNI passes → SNI-based deep packet inspection. |
| **Block page** | Looks for signatures like BTK/5651, FortiGuard, Sophos, Squid. |
| **Outbound port / VPN protocol** | Tests outbound ports via `portquiz.net`. `timeout` = packet drop (real block); `refused`/`RST` = packet got through (no filter). |
| **UDP egress** | Multiple STUN servers/ports — does UDP egress work (indicator for WireGuard/IPsec). |
| **VPN diagnosis** | Whether VPN site/API domains (Proton, Mullvad, Nord, Windscribe) are blocked by SNI-DPI → if the app can't log in, explains why it fails + advice (TCP-443, Mullvad, manual config). |
| **AI tools** | Whether ChatGPT, Claude, Gemini, Perplexity, Copilot, HuggingFace are reachable (often blocked at schools). |
| **ECH / encrypted-SNI** | Whether the site publishes `ech` in its HTTPS/SVCB DNS record. Combined with SNI-DPI detection: infers "this block can be bypassed with ECH". |
| **Tor** | A real `tor` bootstrap — does it reach 100%. |

## Tools

| File | Job |
|---|---|
| `filtertest.py` | Main scan. Appends a compact record to the evidence history (JSONL) on every run. |
| `compare.py` | Compares two `--json` reports (e.g. school ↔ mobile) — reveals network-specific filtering. |
| `history.py` | Shows the evidence history as a timeline + changes (new/lifted blocks). |
| `wgcheck.py` | Tests whether a UDP VPN works on this network via a real WireGuard handshake (Noise_IKpsk2). Uses your own VPN config. |
| `tui.py` | Live TUI dashboard (Textual) — tests run in the background, tables fill in real time. Keys: `r` rescan, `t` toggle Tor, `q` quit. |
| `warp.py` | Install/manage Cloudflare WARP **without AUR** (wgcf + official wireguard-tools). SNI-DPI bypass tunnel. `setup`/`test`/`up`/`down`/`status`/`autostart`. |
| `warp-masque.sh` | Installs the official Cloudflare WARP client (from Cloudflare's own `.deb`, no AUR) in **MASQUE/HTTP3** mode — traffic looks like normal HTTPS, bypasses WireGuard-DPI. Driven by `filterscope warp masque`. |

## Install

```bash
pip install -r requirements.txt   # requests, dnspython, cryptography, textual, rich
# the Tor test needs `tor` installed on the system

./install.sh                       # installs the 'filterscope' terminal command (~/.local/bin)
```

After installing, from anywhere:

```bash
filterscope                 # live TUI
filterscope scan --label school --json school.json
filterscope compare school.json mobile.json
filterscope history
filterscope wg --config /etc/wireguard/wg0.conf
```

## Usage

```bash
./tui.py                                         # live TUI dashboard
./filtertest.py                                  # full scan (CLI)
./filtertest.py --no-tor                         # skip the Tor test (faster)
./filtertest.py --label school --json school.json   # labeled + JSON output
./filtertest.py --anon-json share.json           # PII-free shareable report
./filtertest.py --timeout 8                      # connection timeout (s)

# evidence: run the same test on two networks, compare
./filtertest.py --label school --json school.json
./filtertest.py --label mobile --json mobile.json   # after switching to mobile data
./compare.py school.json mobile.json
./history.py                                     # changes over time

# does WireGuard work on this network (with your own config)
./wgcheck.py --config /etc/wireguard/wg0.conf

# bypass the filter with Cloudflare WARP (no AUR, no server needed)
filterscope warp test         # reachable on this network?
filterscope warp up           # bring up the WireGuard tunnel (sudo); autoport if no data
filterscope warp status       # warp=on?
filterscope warp down         # stop

# if WireGuard is throttled by DPI → MASQUE (official client, looks like HTTP3)
filterscope warp masque up    # install official client + connect via MASQUE (sudo)
filterscope warp masque status
filterscope warp masque down
```

### Periodic evidence (cron)

```cron
*/30 * * * * cd /path/filterscope && ./filtertest.py --no-tor --label school >> ~/.filterscope/run.log 2>&1
```
Scans every half hour and writes to history. Use `./history.py` to track "what the school added and when".

## Interpreting the output

- **SNI-DPI** → the network reads the server name in the TLS ClientHello (DPI) and RSTs specific sites. Application-layer content filter.
- **HIJACK-blockpage** → DNS redirects to a private/local IP (block page server).
- **DNS-BLOCK** → the local resolver returns empty/NXDOMAIN while DoH resolves.
- `timeout` on an outbound port → that port is blocked.

To argue that filtering is "unauthorized/improper": capture a timestamped record with `--json`, run the same test on **a different network** (e.g. mobile data), and show the difference.

## Roadmap

- [x] Evidence mode: time-series JSONL + change tracking (`history.py`)
- [x] Network comparison (school ↔ mobile) (`compare.py`)
- [x] ECH / encrypted-SNI detection + SNI-DPI bypass inference
- [x] Real WireGuard handshake test (`wgcheck.py`)
- [x] Anonymized shareable report (`--anon-json`)
- [ ] Multi DoH/DoT comparison, IPv6 tests
- [ ] Anonymous aggregate report server (opt-in)

## License

GPL-3.0. Free software — use it, study it, modify it, share it.
