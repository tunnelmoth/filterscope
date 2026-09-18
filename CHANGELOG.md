# Changelog

## 3.2.0 — 2026-09-18

### Android app
- `filterscope-android-<version>.apk` — native Jetpack Compose UI over the same Python engine
  (Chaquopy, Python 3.13, arm64-v8a + x86_64). Scan / Stop, label + profile, live progress, score
  gauge, verdict, technique chips, findings + advice, sites (filter, affected-only, tap for detail),
  egress probes, history, compare with previous, **Open report** / **Share** (HTML via FileProvider).
- Network identity from Android's connectivity API (`sysinfo.HINTS`), history under the app's
  private files dir. No Tor probe on Android.
- `android/` Gradle project; CI builds a release-signed APK on every tag (self-signed key in the
  repo — trust the GitHub release + SHA256SUMS, not the key).

## 3.1.0 — 2026-09-18

### Desktop app (no terminal needed)
- **`filterscope-gui`** — a Tkinter/ttk window: Scan button, score gauge, plain-English verdict,
  technique badges, tabs for findings & advice / sites (filter, affected-only, per-row detail) /
  egress & DNS / history, one-click **Open report** (HTML in the browser), Save HTML/JSON,
  Compare with the previous scan, F5 to rescan. Same engine, same history as the CLI/TUI.
- **Windows installer** `filterscope-setup-<version>.exe` (Inno Setup): Start-menu and optional
  desktop shortcut, optional PATH entry for the command-line tool, clean uninstall. No admin needed.
- Windowed binaries: `filterscope-gui-windows-x86_64.exe`, `filterscope-gui-linux-x86_64`,
  `filterscope-gui-macos-arm64.app.zip`. `filterscope gui` opens the same window from the CLI build.
- App icon.

### Fixes
- Advice no longer claims "UDP blocked" when the UDP step was skipped.

## 3.0.0 — 2026-09-18

Major release: analysis engine, verification pass, fully parallel scanner, TLS-interception
detection, and a new TUI.

### Analysis engine
- **Filtering score 0–100** with a level (clean / light / moderate / heavy / severe): share of affected
  sites + a weight per technique + blocked ports.
- **Technique badges** — SNI-DPI, RST-injection, TLS-MITM, DNS-hijack, DNS-block, DNS-intercept,
  encrypted-DNS-block, NXDOMAIN-hijack, block-page, HTTP-proxy, URL-keyword-filter, port-filter,
  UDP-block, QUIC-block, Tor-block, SSH-block, IPv6-block.
- **Vendor signature** from block pages, proxy headers and MITM issuers (FortiGate, Sophos, Squid,
  BlueCoat, Umbrella, Lightspeed, Securly, GoGuardian, Netsweeper, Smoothwall, Palo Alto, Zscaler,
  Forcepoint, Barracuda, McAfee, MikroTik, WatchGuard, SonicWall, Check Point, BTK…).
- **Impact by category**, a **confidence** rating and a one-paragraph plain-English verdict.
- `analysis.diff()` powers `filterscope diff`, `--watch`, and the TUI's compare key.

### Verification pass
- Every positive site result is re-tested once (only the failing sub-test). Results that do not
  reproduce are marked *transient* and dropped from findings. Confirmed ones say so.

### New probes
- **TLS interception / SSL inspection** — verified handshakes against the Mozilla CA bundle for four
  large public sites; a chain signed by a private issuer = the network decrypts HTTPS.
- **NXDOMAIN hijack** — random non-existent name under example.com must not resolve.
- **URL keyword filter** — benign words (vpn, proxy, tor, torrent, bypass, unblock) in a query string
  must be served identically to a control word.
- **Vantage point** — public country / Cloudflare colo (IP stripped from anonymized reports).

### Scanner
- One thread pool, every probe group in flight at once; Tor runs in its own thread from second zero.
  Full scans went from ~90 s to ~40 s (25 s without Tor). Per-site timings recorded.
- A probe exception can no longer abort a scan.
- Config file `~/.filterscope/config.json` (`filterscope config set KEY VALUE`): default label,
  timeout, categories, extra domains, steps to skip, workers, verify, save_reports.
- Profiles: `--profile full | quick | school | isp | vpn`.
- Every scan stores its full JSON under `~/.filterscope/reports/`; `filterscope diff` compares the
  last two of the current network.
- `--watch MIN` re-scans on an interval and prints what changed. `--format json` writes the report to
  stdout for scripting; `--format summary` prints only the analysis. `--skip`, `--no-verify`,
  `--flagged-only`.

### UI / UX
- **TUI rewritten**: tabs (Overview · Sites · Egress · History · Help), score bar + progress bar in
  the header, findings log, diagnosis panel, category impact table, site filter (`/`), affected-only
  toggle (`f`), row detail panel (resolver answers, RTT vs time-to-RST, ECH), compare with the
  previous stored scan (`c`), save JSON+HTML (`s`), toast notifications, history tab.
- **CLI**: live progress bar with findings as they land, analysis panel, category table, sites
  sorted with affected first, timings.
- **HTML report**: score gauge, technique badges, category cards, findings, collapsible method and
  raw JSON, print stylesheet. `filterscope history --html` renders a timeline with sparklines.
- Score shown in `history`, `compare` and the TUI history tab.

### Packaging
- macOS Intel binary dropped (GitHub retired the macos-13 runner); Intel Macs install via pip/pipx.

### Schema
- JSON `schema: 3`: adds `geo`, `tls_intercept`, `nxdomain`, `url_filter`, `analysis`, `timings`,
  `verified`, `steps`, per-site `ms` / `confirmed` / `transient`.

## 2.0.0 — 2026-09-18

Major release: proper package, cross-platform, new probes, evidence-grade reports.

- Package + single `filterscope` CLI (tui/scan/compare/history/report/categories/wg/warp).
- Windows / macOS support; single-file binaries built by CI.
- New probes: DoH/DoT reachability, port-53 interception, QUIC/UDP-443 version negotiation, HTTP
  transparent-proxy headers, IPv6 egress, in-path RST timing, optional throughput.
- HTML evidence report, category/domain scoping, exit code 2 on interference, TUI save key.
- Offline test-suite, CI on Linux/Windows/macOS.

## 1.0.0 — 2026-06-16

Initial public release under the tunnelmoth account: DNS hijack, SNI-DPI, block page, outbound ports,
STUN UDP egress, ECH detection, Tor bootstrap, JSON/anonymized reports, evidence history, compare,
WireGuard handshake test, WARP helper.
