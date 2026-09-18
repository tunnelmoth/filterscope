# filterscope

Measure the **filtering / censorship** behaviour of the network you are on — legitimately, with your own traffic. For digital rights and transparency, in the spirit of EFF and Tor.

> Run it only **from your own device, with your own traffic**. filterscope uses a **clean allowlist** (well-known news / social / privacy / dev / education sites) — it never touches inappropriate or illegal content. That is a deliberate choice to avoid the controversial-domain problem of global test lists.

**Website & downloads: https://tunnelmoth.github.io/filterscope/** · current stable: **v3.4.116**

Works on **Linux, Windows, macOS and Android**. Single-file binaries on the [releases page](https://github.com/tunnelmoth/filterscope/releases); or `pip install`.

```
╭───────────────────────────── filtering analysis ─────────────────────────────╮
│   17/100   █████░░░░░░░░░░░░░░░░░░░░░░░░░   LIGHT   confidence high          │
│                                                                              │
│ school shows light filtering (score 17/100). 4 of 279 sites are affected,     │
│ mostly chat (1/1), vpn-info (1/1), vpn-api (2/5). Techniques: TLS            │
│ server-name inspection, HTTP block page. The filter is application-layer     │
│ only; SNI-hiding tunnels and ECH get through.                                │
│                                                                              │
│ techniques: SNI-DPI (TLS server-name inspection) · block-page (HTTP block    │
│ page)                                                                        │
│ vantage: TR via Cloudflare FRA                                               │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## What it measures

| Probe | How |
|---|---|
| **DNS tampering / hijack** | System resolver and direct `@8.8.8.8` are compared with DoH as the reference. Only private-IP redirection and NXDOMAIN injection are flagged; a mere IP difference is treated as CDN (low false-positive rate). |
| **TLS / SNI blocking (DPI)** | TLS to the real IP with the real server name vs. a harmless control name. Reset/timeout only with the real name = SNI-based deep packet inspection. |
| **In-path RST injection** | Time-to-RST is compared with the TCP round trip. An RST that arrives faster than a round trip was injected by a middlebox, not sent by the server. |
| **TLS interception (MITM)** | Verified handshakes against the Mozilla CA bundle for four large public sites. A chain signed by a private issuer means the network decrypts HTTPS with its own CA. |
| **Block page** | Signatures of BTK/5651, FortiGuard, Sophos, Squid, Cisco Umbrella, Lightspeed, Securly, GoGuardian, Netsweeper, Smoothwall, Palo Alto, Zscaler, Forcepoint, Barracuda… |
| **Outbound TCP ports** | Via `portquiz.net` (listens on every port). `timeout` = packets dropped (real block); `refused`/`RST` = the packet got out. |
| **UDP egress** | STUN binding requests to several servers/ports (indicator for WireGuard / IPsec). |
| **QUIC / UDP-443** | A QUIC version-negotiation probe (RFC 9000 §6) to Cloudflare and Google — no crypto, unambiguous. |
| **Encrypted DNS** | Is DoH (Cloudflare, Google, AdGuard) / DoT (Cloudflare, Google, Quad9) itself reachable. |
| **Port-53 interception** | A plain DNS query is sent to `192.0.2.1` (TEST-NET-1, cannot run a resolver). Any answer proves the network transparently proxies DNS. |
| **NXDOMAIN hijack** | A random non-existent name under `example.com` must not resolve. |
| **HTTP transparent proxy** | Filter-appliance headers (`Via`, `X-Squid-*`, BlueCoat, FortiGate, Sophos…) on a neutral plain-HTTP fetch. |
| **URL keyword filter** | Benign words (vpn, proxy, tor, torrent…) in a query string to `example.com` must be served identically to a control word. |
| **ECH / encrypted SNI** | Does the site publish `ech` in its HTTPS record? Combined with SNI-DPI detection it infers "this block is bypassable with ECH". |
| **Throttling** | 4 MB Range downloads from five CDNs (Cloudflare, Google, Akamai, Microsoft, Fastly); a target far below the best one on the same link = selective throttling. |
| **IPv6 egress**, **SSH egress**, **vantage point** (country / Cloudflare colo) | |
| **VPN diagnosis** | Are VPN sites/APIs (Proton, Mullvad, Nord, Windscribe, AirVPN) blocked at the SNI layer — explains why an app fails at login, and what to do. |
| **Tor** | A real `tor` bootstrap to 100 %. |

**Verification**: every positive site result is re-tested once; a result that does not reproduce is marked *transient* and dropped.

**Analysis**: a filtering score (0–100, clean → severe), the techniques in use, a vendor signature guess, impact by category, confidence, and a plain-English verdict. Every finding feeds the VPN diagnosis and tunnel/circumvention advice.

## Install

**Windows, no terminal**: download and run `filterscope-<version>-Windows-Installer.exe` from [releases](https://github.com/tunnelmoth/filterscope/releases) — it puts *filterscope* in the Start menu. Press **Scan**, read the verdict, click **Open report**. (Or grab the portable `filterscope-<version>-Windows-Portable.exe`.)

**Android**: install `filterscope-<version>-Android.apk` from [releases](https://github.com/tunnelmoth/filterscope/releases) (sideload; Android 7+, 64-bit). Same engine, same score, **Open report** / **Share** for the HTML evidence. No Tor test on Android.

**Binary** (no Python needed): from [releases](https://github.com/tunnelmoth/filterscope/releases): `filterscope-<version>-Windows-Installer.exe` (or `-Windows-Portable.exe`), `-Android.apk`, `-Linux-App`, `-macOS-AppleSilicon.app.zip`; the `-Terminal` builds carry the TUI/CLI. Every release opens with a which-file-do-I-need table. Verify with `SHA256SUMS.txt`. Intel Macs: use the Python install below.

**Python** (3.10+):

```bash
pipx install git+https://github.com/tunnelmoth/filterscope     # or: pip install --user .
```

The Tor test needs a `tor` binary: `apt/pacman/brew install tor`, or on Windows the [Tor Expert Bundle](https://www.torproject.org/download/tor/) (`tor.exe` on PATH, next to the exe, or an installed Tor Browser is found automatically).

## Usage

```bash
filterscope gui                              # desktop window (also: filterscope-gui / the installer's shortcut)
filterscope                                  # live TUI: tabs, score, filter, detail, compare, save
filterscope scan                             # full CLI scan with progress; exit code 2 if interference
filterscope scan --profile quick             # sites + ports + UDP/QUIC + DNS, no Tor/MITM/proxy probes
filterscope scan --profile school            # categories a school filter usually touches
filterscope scan --categories ai,vpn-api     # scope to categories (filterscope categories lists them)
filterscope scan --domain example.org        # add your own domains (--domains-file too)
filterscope scan --label school --json school.json --html school.html
filterscope scan --anon-json share.json      # PII-free shareable report
filterscope scan --format json > r.json      # machine-readable to stdout
filterscope scan --watch 30                  # re-scan every 30 min, print what changed
filterscope scan --flagged-only              # only affected sites in the table
filterscope scan --card card.png --lang tr   # PNG share card; Turkish output
filterscope report school.json               # re-render a saved JSON (or --html out.html)
filterscope config set label school          # persistent defaults (timeout, categories, domains, …)
```

### Android

The app is a native (Jetpack Compose) front-end over the same Python engine (Chaquopy). A home-screen widget shows the last score; tapping it opens the app and scans. Pick a label and a profile, press **Scan**; the gauge, verdict, findings, per-site rows (tap for detail), egress probes and history mirror the desktop app. **Open report** renders the HTML report in the browser, **Share** sends it anywhere. Network identity comes from Android's connectivity API (gateway, resolver, SSID when the OS exposes it).

### Desktop window

**Scan** runs the same engine; the gauge and the sentence under it are the verdict. **Open report** renders the HTML evidence report in your browser; **Save ▾** writes HTML, JSON or a PNG share card; **Sites…** picks categories and adds your own domains; **Compare** diffs against the previous stored scan of this network; the *Sites* tab has a filter box, an *affected only* toggle and a detail panel per row. F5 rescans.

**Turkish**: everything is available in Turkish — auto from the system locale, or `--lang tr`, `filterscope config set lang tr`, the EN/TR button in the window.

**Update check**: one request to the GitHub releases API at start; disable with `filterscope config set update_check false`.

### TUI keys

`r` rescan · `t` toggle Tor · `s` save JSON+HTML · `/` filter sites · `f` affected only · `c` compare with previous scan · `1-5` tabs · `q` quit

### Evidence: two networks, one diff

```bash
filterscope scan --label school --json school.json
filterscope scan --label mobile --json mobile.json    # after switching to mobile data
filterscope compare school.json mobile.json
```

Anything blocked on one network but open on the other is filtering **specific to that network**.

### Evidence over time

Every scan appends a record to `~/.filterscope/history.jsonl` and stores the full report under `~/.filterscope/reports/`.

```cron
*/30 * * * * filterscope scan --no-tor --label school --format summary >> ~/.filterscope/run.log 2>&1
```

```bash
filterscope history                          # timeline + "new block / lifted" per network, with scores
filterscope history --html timeline.html     # sparkline timeline
filterscope diff                             # last two stored scans of this network
```

### Does my VPN work here?

```bash
filterscope wg --config /etc/wireguard/wg0.conf      # real WireGuard handshake (Noise_IKpsk2) to YOUR server
```

### Bypass with Cloudflare WARP (Linux)

```bash
filterscope warp test          # reachable on this network?
filterscope warp up            # WireGuard tunnel (sudo); automatic port search if no data flows
filterscope warp masque up     # official client in MASQUE/HTTP3 mode when WireGuard is throttled
filterscope warp status / down
```

On Windows and macOS use the official 1.1.1.1 app and pick MASQUE in its settings.

## Interpreting results

- **SNI-DPI** — the network reads the server name in the TLS ClientHello and resets specific sites. If the note says *in-path injection*, the RST came from a middlebox, not the server.
- **TLS-MITM** — HTTPS is decrypted by the network with its own CA. Assume every page and login is readable by the operator.
- **HIJACK-blockpage** — DNS answers with a private/local IP (a block-page server).
- **DNS-BLOCK** — the local resolver returns nothing while DoH resolves.
- **INTERCEPTED** (port 53) — the network answers DNS on behalf of every address; changing your resolver to 8.8.8.8 is ignored.
- **NXDOMAIN-HIJACK** — non-existent names resolve (search redirect / ad injection).
- **BLOCKED** on DoH/DoT — encrypted DNS is blocked; apps using it (Firefox DoH, Android Private DNS) fail.
- **BLOCKED** on a port / QUIC / UDP — packets to that port are dropped.
- **PROXY** / **URL-KEYWORD-FILTER** — a transparent HTTP proxy or filter appliance is rewriting plain HTTP.
- **Score**: 0 clean · 1–19 light · 20–44 moderate · 45–69 heavy · 70+ severe.

To argue that filtering is improper: keep the timestamped JSON, run the same scan on **a different network** and show the diff. The HTML report is self-contained and printable.

## JSON schema

`schema: 3`. Top level: `ts`, `version`, `net` (id/label/ssid/gateway/resolver/os), `geo`, `sites{domain: {cat, dns, sni, blockpage, ech, ms, confirmed?, transient?}}`, `ports`, `udp`, `udp_detail`, `quic`, `quic_detail`, `ipv6`, `dns_encrypted`, `dns_intercept`, `nxdomain`, `http_proxy`, `url_filter`, `tls_intercept`, `ssh`, `tor`, `speed`, `timings`, `flagged[]`, `analysis{score, level, techniques, vendor, categories, confidence, summary}`. The anonymized variant drops `net.*` except id/label, the public IP, resolver answers and proxy headers.

## Development

```bash
pip install -e ".[dev]"
pytest                                  # offline unit tests
pyinstaller packaging/filterscope.spec  # single-file binary → dist/
cd android && ./gradlew assembleDebug   # Android APK (JDK 17, Android SDK 34, python3.13 on PATH)
# landing page: docs/index.html (GitHub Pages: Settings → Pages → main /docs)
```

CI runs the tests on Linux, Windows and macOS; a `v*` tag builds and publishes the binaries.

## Roadmap

- [x] Evidence mode: time-series + change tracking, stored reports, diff, watch
- [x] Network comparison, anonymized reports, HTML report with score gauge
- [x] ECH detection + bypass inference, real WireGuard handshake test
- [x] Encrypted DNS, DNS interception, NXDOMAIN hijack, QUIC, transparent proxy, URL keyword filter, RST injection timing, TLS interception
- [x] Analysis engine: score, techniques, vendor signature, verification pass
- [x] Windows / macOS, single-file binaries
- [ ] DoQ (DNS over QUIC) and HTTP/3 page fetch
- [ ] Opt-in anonymous aggregate report server

## License

GPL-3.0-or-later. Free software — use it, study it, modify it, share it.
