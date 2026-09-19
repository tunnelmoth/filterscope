# Changelog

## 3.6.126 — 2026-09-19 · **stable**

### Text
- All user-facing text follows one register now: short sentences, one name per concept, no dash
  asides, estimates marked as estimates. This covers the landing page (English and Turkish), the
  verdict and advice strings in every front-end, the About and help screens, SECURITY.md, the
  changelog and the release notes.
- README rewritten in the same register with the current feature set.
- Landing page: the artwork sits in its own column and no longer overlaps the text on wide
  screens. Screenshots refreshed from this version in dark mode.

## 3.6.117 — 2026-09-19 · **stable**

### Dark mode & accessibility
- Desktop window: **dark theme** (follows the OS, or forced), **high-contrast** palettes (light and
  dark), **text size** 100–175 %. *View ▾* menu, persisted (`theme`, `high_contrast`, `font_scale`).
- TUI: `d` toggles dark/light; follows the OS theme at start. Android: proper dark palette for
  cards, rows and the gauge; DayNight system theme.

### System tray / background mode
- `filterscope tray` (or `filterscope-gui --tray`): sits in the tray, detects **network changes**
  (gateway/resolver/SSID) and runs a quick scan automatically, then notifies “*wifi: blocked here -
  discord.com, roblox.com…*”. Menu: Open window · Scan now · Check ▸ (eight one-click services) ·
  Auto-scan on/off · Quit. Windows installer option: **start in the tray at login**.

### 113 service profiles + your own
- `check` now knows 113 services / 559 endpoints: CS2, Dota, Apex, EA FC, R6, Overwatch/Battle.net,
  Xbox Live, PSN, Nintendo, GTA Online, Among Us, Free Fire, Call of Duty, Mobile Legends, GeForce
  NOW, Prime Video, Disney+, Max, Crunchyroll, Exxen, BluTV, Apple Music, Facebook/Messenger,
  Snapchat, Reddit, Pinterest, LinkedIn, WeChat, Viber, Skype, Slack, Google Meet, Element, Copilot,
  Perplexity, DeepSeek, Mistral, Grok, Character.AI, Mullvad, NordVPN, ExpressVPN, Surfshark,
  Windscribe, Tor, Tailscale, WARP, Gmail/Workspace, Outlook/365, iCloud, Yandex, Dropbox, MEGA,
  EBA/MEB, Duolingo, Khan/Coursera, Trendyol/Hepsiburada, Amazon, PayPal/Binance, GitLab, PyPI/npm/
  Docker, VS Code, Cursor/Replit, Linux mirrors, BBC/DW/Reuters, Turkish independent news, Ekşi
  Sözlük, Wattpad, Imgur/Giphy, Speedtest… Every hostname resolved at authoring time.
- **User profiles**: `filterscope services --template` writes `~/.filterscope/services.json`; edit it
  and `filterscope check myschoolportal`. same shape as the built-in profiles (`tcp:PORT` hosts,
  ports, download target).

## 3.5.115 — 2026-09-19 · **stable**

### Ask by name: `filterscope check valorant`
- **Service profiles** for 30 popular services (Valorant, League, Discord, Roblox, Minecraft,
  Fortnite/Epic, Steam, Genshin, Brawl Stars/Clash, PUBG, YouTube, Twitch, Kick, Netflix, Spotify,
  WhatsApp, Telegram, Signal, Zoom, Teams, Instagram, TikTok, X, ChatGPT, Claude, Gemini, Proton VPN,
  WireGuard, GitHub, Wikipedia): the endpoints the service really needs (web, auth/API, CDN, game and
  chat servers, raw-protocol ports), the TCP ports it uses, UDP egress, and a **real download from the
  service's own CDN** compared with a Cloudflare baseline.
- Verdict per service: **OK / PARTIAL / BLOCKED / THROTTLED** with the reasons, localized.
- CLI `filterscope check valorant discord` (`--json`, `--lang`), `filterscope services`; GUI **Check…**
  dialog with one-tap service chips; Android **Check** tab.
- Positives are re-checked once; hosts that do not speak HTTPS (WhatsApp 5222, Supercell 9339, Riot chat
  5223, Telegram DC IPs) are tested with a plain TCP connect instead of a TLS probe.

## 3.4.116 — 2026-09-19 · **stable**

### Throttling detection
- New `throttle` step: 4 MB Range downloads from five CDNs (Cloudflare, Google, Akamai/Steam,
  Microsoft, Fastly/Debian). A target below 25 % of the best one on the same link is reported as
  **THROTTLED**. the sneaky filter that blocks nothing but makes video and games unusable. Shown in
  every UI, counted in the score (`throttling` technique). Off in the `quick` and `vpn` profiles.

### Turkish
- Full Turkish UI: desktop window, TUI, CLI headings, HTML report, share card and Android. including
  the verdict sentence and all advice. Auto from the system locale; `--lang tr|en`, config `lang`, the
  EN/TR button in the window, `FILTERSCOPE_LANG`.

### Share card
- `--card out.png`, **Save ▾ → Share card…** in the window, **Card** on Android: a 1200×630 PNG with
  the gauge, level, techniques and top affected categories (network name optional). Fonts bundled.

### Update check
- One request to the GitHub releases API at start (CLI: after a scan). Newer version → banner in the
  window / toast in the TUI / one line in the CLI / tap-to-download bar on Android. `config set
  update_check false` to disable.

### Shell integration
- Windows installer option: **"Measure this network with filterscope"** in the desktop right-click
  menu (opens the app and scans immediately; `filterscope-gui --autoscan`).
- Android **home-screen widget**: last score and level; tap = open and scan.

### Fixes
- Throughput values are no longer coloured as findings; confidence is translated; Turkish upper-case
  (İ) handled.

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
- User-supplied labels are sanitized before they become file names (TUI/GUI/Android). a label like
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
- `filterscope-android-<version>.apk`. native Jetpack Compose UI over the same Python engine
  (Chaquopy, Python 3.13, arm64-v8a + x86_64). Scan / Stop, label + profile, live progress, score
  gauge, verdict, technique chips, findings + advice, sites (filter, affected-only, tap for detail),
  egress probes, history, compare with previous, **Open report** / **Share** (HTML via FileProvider).
- Network identity from Android's connectivity API (`sysinfo.HINTS`), history under the app's
  private files dir. No Tor probe on Android.
- `android/` Gradle project; CI builds a release-signed APK on every tag (self-signed key in the
  repo. trust the GitHub release + SHA256SUMS, not the key).

## 3.1.0 — 2026-09-18

### Desktop app (no terminal needed)
- **`filterscope-gui`**. a Tkinter/ttk window: Scan button, score gauge, plain-English verdict,
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
- **Technique badges**. SNI-DPI, RST-injection, TLS-MITM, DNS-hijack, DNS-block, DNS-intercept,
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
- **TLS interception / SSL inspection**. verified handshakes against the Mozilla CA bundle for four
  large public sites; a chain signed by a private issuer = the network decrypts HTTPS.
- **NXDOMAIN hijack**. random non-existent name under example.com must not resolve.
- **URL keyword filter**. benign words (vpn, proxy, tor, torrent, bypass, unblock) in a query string
  must be served identically to a control word.
- **Vantage point**. public country / Cloudflare colo (IP stripped from anonymized reports).

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
