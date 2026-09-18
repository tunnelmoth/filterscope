# Changelog

## 2.0.0 — 2026-09-18

Major release: proper package, cross-platform, new probes, evidence-grade reports.

### New probes
- **Encrypted DNS reachability** — DoH (Cloudflare, Google, AdGuard) and DoT (Cloudflare, Google, Quad9): is encrypted DNS itself blocked.
- **Port-53 interception** — a plain DNS query sent to 192.0.2.1 (TEST-NET-1); any answer proves the network transparently proxies DNS, so "just use 8.8.8.8" does nothing.
- **QUIC / UDP-443** — a QUIC version-negotiation probe (RFC 9000 §6) against Cloudflare and Google; tells you whether HTTP/3 and QUIC-based tunnels can leave the network.
- **HTTP transparent proxy** — filter-appliance headers (`Via`, `X-Squid-*`, BlueCoat, FortiGate, Sophos…) on a neutral plain-HTTP fetch.
- **IPv6 egress**.
- **In-path RST injection** — time-to-RST is compared with the TCP RTT; an RST that arrives faster than a round trip was injected by a middlebox, not sent by the server.
- **Throughput** (`--speed`, opt-in).
- More block-page signatures (Umbrella, Lightspeed, Securly, GoGuardian, Netsweeper, Smoothwall, Palo Alto, Zscaler, Forcepoint, Barracuda…).

### Cross-platform
- Runs on **Windows** (console colours, `netsh`/`route`/`ipconfig` network fingerprint, `tor.exe` discovery incl. Tor Browser folders, UTF-8 everywhere), **macOS** and Linux.
- Single-file binaries for Windows, Linux and macOS built by CI on every tag.

### CLI / UX
- One `filterscope` command with sub-commands: `tui` (default), `scan`, `compare`, `history`, `report`, `categories`, `wg`, `warp`.
- `pip install .` / `pipx install .` — no more launcher script.
- Rich tables; results stream in as probes finish.
- `--html` self-contained evidence report; `report` re-renders any saved JSON.
- `--categories ai,vpn-api`, `--domain`, `--domains-file` to scope a scan; `--quick`, `--only`.
- Exit code 2 when interference is detected (cron / CI friendly), `--quiet`.
- TUI: `s` saves JSON + HTML; new rows for QUIC, IPv6, DoH/DoT, interception, proxy, SSH.
- History and compare understand the new probes; `history --last N --network X`.
- JSON report carries `schema: 2` and `version`.

### Internals
- Engine split into `core` (probes), `scan` (orchestrator with event stream), `render`, `htmlreport`.
- Offline test-suite (`pytest`), CI on Linux/Windows/macOS.
- DoH falls back to RFC 8484 GET when a resolver rejects HTTP/1.1 POST.

### Removed
- Top-level `filtertest.py`, `tui.py`, `compare.py`, `history.py`, `wgcheck.py`, `warp.py`, `install.sh` launcher (all live under the `filterscope` package now). `filterscope warp` is Linux-only and says so on other platforms.

## 1.0.0 — 2026-06-16

Initial public release under the tunnelmoth account: DNS hijack, SNI-DPI, block page, outbound ports, STUN UDP egress, ECH detection, Tor bootstrap, JSON/anonymized reports, evidence history, compare, WireGuard handshake test, WARP helper.
