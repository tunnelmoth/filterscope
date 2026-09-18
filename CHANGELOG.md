# Changelog

## 3.3.114 — 2026-09-19 · **stable**

### Much wider test list
- **279 sites in 27 categories** (was 58): games (Steam, Epic, Roblox, Minecraft, Riot, Battle.net,
  PlayStation, Xbox, Nintendo, GOG, itch.io…), streaming & music (Netflix, Disney+, Spotify, Twitch,
  Kick…), social, chat & calls (WhatsApp, Discord, Teams, Zoom, Signal, Telegram…), Turkish and
  international news, education, health, religion, dev/open-source, cloud storage & mail, privacy
  tools, VPN providers, circumvention projects, web proxies, shopping, crypto, app stores, misc.
  Still nothing inappropriate: mainstream services only.
- Every domain was resolved over DoH at authoring time; the test-suite checks the list for
  duplicates, malformed hosts and profile/category consistency.
- **Your own domains, everywhere**: GUI **Sites…** dialog (pick categories, add domains, persisted),
  Android "own domains" field, CLI `--domain/--domains-file`, TUI via `filterscope config`.
- Profiles updated (`quick` is now a curated subset; `school`, `isp`, `vpn` cover the new categories);
  default parallelism 20.

### Fewer false positives
- Block-page detection: generic wording (“access denied”, “5651”…) is only counted on a plain-HTTP
  final response, where a network can inject a page; over verified HTTPS the page came from the
  origin itself (Akamai 403s, Turkish legal footers). Filter-product signatures still count anywhere.

### Release assets renamed
- `filterscope-<version>-Windows-Installer.exe`, `-Windows-Portable.exe`, `-Windows-Terminal.exe`,
  `-Android.apk`, `-Linux-App`, `-Linux-Terminal`, `-macOS-AppleSilicon.app.zip`,
  `-macOS-AppleSilicon-Terminal`. Every release opens with a "which file do I need?" table.

## 3.2.112 — 2026-09-19 · **stable**

First release marked stable. Version scheme from here: `MAJOR.MINOR.BUILD`, where BUILD is a
monotonically increasing build number (100 + commit count at tag time).

### Security audit (fixes)
- `filterscope warp`: the wgcf binary is verified against the release's `checksums.txt`; the WARP
  `.deb` is verified through the apt chain (`Release` signature via `gpgv` when available →
  `Packages` SHA256 → `.deb` SHA256). Mismatch aborts the install.
- User-supplied labels are sanitized before they become file names (TUI/GUI/Android) — a label like
  `../x` could previously write a report outside the chosen folder.
- Network-derived strings (domains, SSID, resolver, probe labels) are escaped before reaching the
  rich console renderer (markup injection).
- GitHub Actions pinned to commit SHAs; CI workflow runs with read-only token.
- `SECURITY.md`: threat model, deliberate unverified-TLS probes, signing status, reporting.

### Website
- Four platform buttons side by side (this device's highlighted), disclaimer, Content-Security-Policy
  (external CSS/JS, no inline code).

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
